"""Artifact storage: one directory per tool invocation under ``<case_dir>/artifacts/<run-id>/``.

Each run owns a ``manifest.json`` (the canonical record), ``stdout.txt`` and
``stderr.txt`` captures, and an ``out/`` directory that the wrapper uses as its
``output_dir``. Every captured byte is hashed (chunked SHA-256) when the run is
closed so the chain-of-custody invariants hold: the manifest records the LITERAL
argv executed (never the LLM's stated intent), the real exit code when one was
returned, and the SHA-256 of each artifact produced. A runner/transport exception
closes the run with ``status='error'`` and ``exit_code=null`` rather than inventing
an exit code for a process that did not return one.

Manifest writes are atomic (``*.tmp`` + ``os.replace``) — a crash mid-write
never leaves a half-baked canonical record on disk.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from collections.abc import Iterable
from typing import Any, Literal

from agentopsy.i18n import Mensaje
from agentopsy.cases.manager import CaseManager, case_manager

# Baseline SHA-256 of the evidence a run acted on — 64 hex chars, always present in a
# new manifest (evidence provenance, FORENSIC INVARIANT 4). Mirrors the validation in
# ``agentopsy.evidence_context``.
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class ArtifactIntegrityError(RuntimeError):
    """A derived artifact's on-disk bytes no longer match the SHA-256 its producing run
    recorded in the manifest — the custody of the derivative is broken and it MUST NOT be
    used as an input (FORENSIC INVARIANTS 1-2). Raised by ``resolve_output_file``."""

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_CHUNK_SIZE = 1024 * 1024  # 1 MiB — never read whole files into memory.
# Topes de `read_run_output`: acotan lo que puede entrar en el contexto del modelo
# de una sola lectura. Superarlos NO trunca en silencio — la respuesta declara
# `hay_mas`/`siguiente_desde` para que el agente pagine (RULE 2).
_MAX_LINES_PER_READ = 400
_MAX_CHARS_PER_READ = 12000

RunStatus = Literal["running", "finished", "error"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_file(path: Path) -> tuple[str, int]:
    """Chunked SHA-256 + size in bytes. Never loads the file fully into memory."""
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _atomic_write_text(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _atomic_write_json(path: Path, data: dict) -> None:
    _atomic_write_text(path, json.dumps(data, sort_keys=True, indent=2))


@dataclass(frozen=True)
class OutputFile:
    relpath: str  # POSIX-style relative path inside ``out/``.
    sha256: str
    size: int


@dataclass(frozen=True)
class ArtifactRun:
    run_id: str
    case_id: str
    tool_id: str
    argv: list[str]  # literal argv as executed (NOT the LLM's intent)
    started_at: str  # ISO-8601 UTC
    finished_at: str | None  # None while in-flight
    status: RunStatus
    exit_code: int | None  # None while in-flight or when the runner did not return
    output_files: list[OutputFile] = field(default_factory=list)
    stdout_sha256: str | None = None
    stderr_sha256: str | None = None
    error_type: str | None = None
    error_message: str | None = None
    # Evidence PROVENANCE of the run (which evidence, at which baseline hash, the run
    # acted on — FORENSIC INVARIANT 4). Always written by ``start_run`` for new runs;
    # ``None`` only when reading a legacy manifest that predates provenance — consumers
    # of derived artifacts must REJECT such runs (no silent compatibility, RULE 2).
    evidence_id: str | None = None
    evidence_baseline_sha256: str | None = None
    # Authoritative version of the tool that executed (from the maletín's immutable
    # build manifest, resolved by the dispatcher BEFORE the start). ``None`` only on
    # legacy manifests.
    tool_version: str | None = None
    # Digest canónico de los campos de custodia del manifiesto, fijado al cerrar
    # el run. El dispatcher lo copia al ``tool_run_finish``, y la frontera de
    # lectura lo recomputa contra ese ancla: es lo que hace detectable una
    # reescritura COHERENTE de artefacto + manifiesto. ``None`` en manifiestos
    # anteriores al anclaje, que se leen declarando ``anclaje='sin_ancla'``.
    manifest_sha256: str | None = None


class ArtifactStore:
    """Filesystem-backed store for tool-invocation artifacts."""

    def __init__(self, case_manager: CaseManager) -> None:
        self._cases = case_manager

    # ---------- internal helpers ----------

    def _runs_dir(self, case_id: str) -> Path:
        # ``case_dir`` raises KeyError on unknown case_id — propagate.
        return self._cases.case_dir(case_id) / "artifacts"

    def case_artifacts_dir(self, case_id: str) -> Path:
        """``<case_dir>/artifacts`` — the run root of a case.

        Public because ``agentopsy.artifacts.lectura`` (the single verified-read
        boundary) needs it to resolve a run without reaching into a private
        attribute. Raises ``KeyError`` on an unknown case, like every other path
        accessor here.
        """
        return self._runs_dir(case_id)

    def _run_dir(self, case_id: str, run_id: str) -> Path:
        if not _UUID4_RE.match(run_id):
            raise ValueError(f"invalid run_id (expected UUID4): {run_id!r}")
        return self._runs_dir(case_id) / run_id

    @staticmethod
    def _scan_out_dir(out_dir: Path) -> list[OutputFile]:
        """Recursively walk ``out/`` and hash every regular file."""
        if not out_dir.exists():
            return []
        files: list[OutputFile] = []
        for path in sorted(out_dir.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            sha256, size = _hash_file(path)
            relpath = path.relative_to(out_dir).as_posix()
            files.append(OutputFile(relpath=relpath, sha256=sha256, size=size))
        return files

    def manifest_to_run(self, case_id: str, manifest: dict) -> ArtifactRun:
        """Build the canonical :class:`ArtifactRun` from an already-read manifest.

        Public sibling of ``_manifest_to_run`` for the verified-read boundary,
        which reads (and anchors) the manifest itself before handing it over.
        """
        return self._manifest_to_run(case_id, manifest)

    @staticmethod
    def _manifest_to_run(case_id: str, manifest: dict) -> ArtifactRun:
        output_files = [
            OutputFile(relpath=of["relpath"], sha256=of["sha256"], size=of["size"])
            for of in manifest.get("output_files", [])
        ]
        return ArtifactRun(
            run_id=manifest["run_id"],
            case_id=case_id,
            tool_id=manifest["tool_id"],
            argv=list(manifest["argv"]),
            started_at=manifest["started_at"],
            finished_at=manifest.get("finished_at"),
            status=manifest.get("status", "running"),
            exit_code=manifest.get("exit_code"),
            output_files=output_files,
            stdout_sha256=manifest.get("stdout_sha256"),
            stderr_sha256=manifest.get("stderr_sha256"),
            error_type=manifest.get("error_type"),
            error_message=manifest.get("error_message"),
            evidence_id=manifest.get("evidence_id"),
            evidence_baseline_sha256=manifest.get("evidence_baseline_sha256"),
            tool_version=manifest.get("tool_version"),
            manifest_sha256=manifest.get("manifest_sha256"),
        )

    def _open_manifest(self, case_id: str, run_id: str) -> tuple[Path, dict]:
        """Return ``(run_dir, manifest)`` for a still-running invocation."""
        run_dir = self._run_dir(case_id, run_id)
        manifest_path = run_dir / "manifest.json"
        if not manifest_path.exists():
            raise KeyError(f"unknown run_id for case {case_id}: {run_id}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("status") != "running":
            raise KeyError(f"run {run_id} for case {case_id} is already finalized")
        return run_dir, manifest

    def _close_run(
        self,
        case_id: str,
        run_id: str,
        *,
        status: Literal["finished", "error"],
        exit_code: int | None,
        stdout: str,
        stderr: str,
        error_type: str | None,
        error_message: str | None,
    ) -> ArtifactRun:
        """Persist streams/hashes and atomically close a running manifest."""
        if not isinstance(stdout, str) or not isinstance(stderr, str):
            raise ValueError("stdout/stderr must be str (decoded)")

        run_dir, manifest = self._open_manifest(case_id, run_id)

        # Persist stdout/stderr atomically, then hash from disk so the recorded
        # digest matches the bytes that actually live on the filesystem.
        stdout_path = run_dir / "stdout.txt"
        stderr_path = run_dir / "stderr.txt"
        _atomic_write_text(stdout_path, stdout)
        _atomic_write_text(stderr_path, stderr)
        stdout_sha256, _ = _hash_file(stdout_path)
        stderr_sha256, _ = _hash_file(stderr_path)

        output_files = self._scan_out_dir(run_dir / "out")
        manifest.update(
            {
                "finished_at": _now_iso(),
                "exit_code": exit_code,
                "status": status,
                "stdout_sha256": stdout_sha256,
                "stderr_sha256": stderr_sha256,
                "output_files": [asdict(of) for of in output_files],
                "error_type": error_type,
                "error_message": error_message,
            }
        )
        # ANCLAJE del manifiesto (auditoría 2026-09-07, F02). El digest canónico
        # de los campos de custodia se escribe aquí y el dispatcher lo copia al
        # ``tool_run_finish``, así que reescribir un artefacto Y su hash en el
        # manifiesto ya no basta para pasar por íntegro: haría falta reescribir
        # también la cadena encadenada. Import diferido porque
        # ``agentopsy.artifacts.lectura`` construye sobre este módulo.
        from agentopsy.artifacts.lectura import manifest_digest

        manifest["manifest_sha256"] = manifest_digest(manifest)
        _atomic_write_json(run_dir / "manifest.json", manifest)
        return self._manifest_to_run(case_id, manifest)

    # ---------- public API ----------

    def start_run(
        self,
        case_id: str,
        tool_id: str,
        argv: list[str],
        *,
        evidence_id: str,
        evidence_baseline_sha256: str,
        tool_version: str,
    ) -> tuple[str, Path]:
        """Open a new run and return ``(run_id, out_dir)``.

        Creates ``artifacts/<run-id>/out/`` and writes a half-baked
        ``manifest.json`` marking ``status='running'``. The returned ``out_dir``
        is the path the dispatcher must hand to the wrapper as ``output_dir``.

        ``evidence_id`` + ``evidence_baseline_sha256`` are the run's evidence
        PROVENANCE (the verified context the dispatcher validated against
        ``EvidenceManager``). They are REQUIRED — a manifest without provenance
        cannot anchor its outputs to an evidence, and downstream consumers of its
        derived artifacts would have nothing to verify against (INVARIANT 4).
        """
        if not isinstance(tool_id, str) or not tool_id:
            raise ValueError("tool_id must be a non-empty string")
        if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
            raise ValueError("argv must be a list[str] (literal executed argv)")
        if not isinstance(evidence_id, str) or not evidence_id.strip():
            raise ValueError("evidence_id must be a non-empty string (run provenance)")
        if not isinstance(evidence_baseline_sha256, str) or not _SHA256_RE.match(
            evidence_baseline_sha256
        ):
            raise ValueError(
                "evidence_baseline_sha256 must be a 64-hex SHA-256 digest "
                f"(got {evidence_baseline_sha256!r})"
            )
        forbidden = ("unknown", "latest", "null", "none")
        lowered = tool_version.strip().lower() if isinstance(tool_version, str) else ""
        if (
            not isinstance(tool_version, str)
            or not lowered
            or lowered in forbidden
            # An embedded placeholder ("hayabusa latest") is as unreproducible as a
            # bare one — reject it at the token level too (RULE 2).
            or any(token in forbidden for token in lowered.split())
        ):
            raise ValueError(
                "tool_version must be a non-empty, non-placeholder version string "
                f"(got {tool_version!r})"
            )

        run_id = str(uuid.uuid4())
        run_dir = self._runs_dir(case_id) / run_id
        out_dir = run_dir / "out"
        out_dir.mkdir(parents=True, exist_ok=False)

        manifest = {
            "run_id": run_id,
            "case_id": case_id,
            "tool_id": tool_id,
            "argv": list(argv),
            "started_at": _now_iso(),
            "finished_at": None,
            "exit_code": None,
            "status": "running",
            "output_files": [],
            "stdout_sha256": None,
            "stderr_sha256": None,
            "error_type": None,
            "error_message": None,
            "evidence_id": evidence_id,
            "evidence_baseline_sha256": evidence_baseline_sha256,
            "tool_version": tool_version.strip(),
        }
        _atomic_write_json(run_dir / "manifest.json", manifest)
        return run_id, out_dir

    def set_run_argv(self, case_id: str, run_id: str, argv: list[str]) -> ArtifactRun:
        """Persist the resolved literal argv while the run is still open.

        The dispatcher opens the run before building argv because wrappers may need
        ``output_dir``. Once the venue and exact argv are known, it calls this method
        before writing ``tool_run_start`` or invoking the runner.
        """
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
            raise ValueError("argv must be a non-empty list[str] (literal executed argv)")
        run_dir, manifest = self._open_manifest(case_id, run_id)
        manifest["argv"] = list(argv)
        _atomic_write_json(run_dir / "manifest.json", manifest)
        return self._manifest_to_run(case_id, manifest)

    def finalize_run(
        self,
        case_id: str,
        run_id: str,
        *,
        exit_code: int,
        stdout: str,
        stderr: str,
    ) -> ArtifactRun:
        """Close a run: persist stdout/stderr, hash every output, write the
        final manifest, and return the canonical :class:`ArtifactRun`.

        Hashes ``stdout.txt``, ``stderr.txt`` and every file under ``out/``
        (recursively, 1 MiB blocks). An empty ``out/`` is valid.

        Raises ``KeyError`` if the run does not exist or was already finalized.
        """
        if not isinstance(exit_code, int):
            raise ValueError("exit_code must be an int")
        return self._close_run(
            case_id,
            run_id,
            status="finished",
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            error_type=None,
            error_message=None,
        )

    def fail_run(
        self,
        case_id: str,
        run_id: str,
        *,
        error_type: str,
        error_message: str,
        stdout: str = "",
        stderr: str = "",
    ) -> ArtifactRun:
        """Close a run whose runner did not return an exit code.

        Partial streams and output files are still persisted and hashed. The
        canonical manifest records the actionable exception type/message and keeps
        ``exit_code`` as ``None``.
        """
        if not isinstance(error_type, str) or not error_type:
            raise ValueError("error_type must be a non-empty string")
        if not isinstance(error_message, str) or not error_message:
            raise ValueError("error_message must be a non-empty string")
        return self._close_run(
            case_id,
            run_id,
            status="error",
            exit_code=None,
            stdout=stdout,
            stderr=stderr,
            error_type=error_type,
            error_message=error_message,
        )

    def get_run(self, case_id: str, run_id: str) -> ArtifactRun:
        """Read ``manifest.json`` for the given run. Raises ``KeyError`` if missing."""
        manifest_path = self._run_dir(case_id, run_id) / "manifest.json"
        if not manifest_path.exists():
            raise KeyError(f"unknown run_id for case {case_id}: {run_id}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        return self._manifest_to_run(case_id, manifest)

    def resolve_output_file(
        self, case_id: str, run_id: str, relpath: str
    ) -> tuple[Path, str, int]:
        """Resolve one output file of a run to its on-disk path, RE-HASHED against the
        manifest — the custody gate for a derived-artifact input (FORENSIC INVARIANTS 1-2).

        Since 2026-09-08 this is a THIN ADAPTER over
        ``agentopsy.artifacts.lectura.abrir_verificado``, the single verified-read
        boundary: one implementation of the integrity policy, one place where the
        confinement, the manifest membership, the seal and the manifest anchor are
        checked. What this method adds is the legacy exception contract its callers
        (the dispatcher's derived-input handoff) already handle.

        Returns ``(resolved_path, sha256, size)``. Raises ``ValueError`` if
        ``relpath`` is not a confined relative path, ``KeyError`` if the run or the
        named output file is unknown (or the file is gone from disk, or the run is
        not sealed yet), and ``ArtifactIntegrityError`` if the bytes no longer match
        the manifest.
        """
        from agentopsy.artifacts import lectura

        try:
            with lectura.abrir_verificado(
                case_id, run_id, relpath, ambito=lectura.AMBITO_REST, store=self
            ) as leida:
                if leida.clase != "fichero":
                    raise ValueError(
                        f"resolve_output_file espera un fichero de salida declarado "
                        f"en el manifiesto, no {relpath!r}"
                    )
                return leida.ruta, leida.sha256, leida.size
        except (lectura.ArtefactoFueraDeAmbito, lectura.LocalizadorInvalido) as exc:
            raise ValueError(str(exc)) from exc
        except (lectura.ArtefactoInexistente, lectura.ArtefactoNoSellado) as exc:
            raise KeyError(str(exc)) from exc

    def resolve_output_dir(
        self, case_id: str, run_id: str, relpath: str
    ) -> tuple[Path, str, int]:
        """Resolve one output DIRECTORY of a run, re-hashing every file beneath it.

        The sibling of ``resolve_output_file`` for a tool that consumes a FOLDER rather
        than a file (``hindsight`` and a browser profile; ``tsk_recover`` is what
        produces one). The manifest is file-granular, so a directory is not an entry in
        it: it is the common prefix of one or more entries, and the custody gate has to
        cover the WHOLE subtree, not a representative file.

        Delegates to ``agentopsy.artifacts.lectura.verificar_directorio``, which checks
        the MEMBER SET in both directions: every manifest entry under the prefix must
        be on disk with its recorded hash, AND every file on disk under the prefix must
        be a manifest entry. Verifying only the known files would leave the door open
        to a tool consuming an extra file dropped in afterwards, which the manifest
        never saw (auditoría 2026-09-07, F02).

        Returns ``(resolved_path, tree_sha256, total_size)``. ``tree_sha256`` is a
        digest OF THE SUBTREE, not of any file: the SHA-256 of the manifest entries
        sorted by relpath, one ``"<relpath>\\0<sha256>\\n"`` line each. It is
        deterministic, it changes if any file changes, is added or is removed, and it
        is what travels into the audit as the derived input's digest so a third party
        can tell exactly which tree was consumed (FORENSIC INVARIANT 4).

        Same legacy exception contract as ``resolve_output_file``.
        """
        from agentopsy.artifacts import lectura

        try:
            return lectura.verificar_directorio(
                case_id, run_id, relpath, ambito=lectura.AMBITO_REST, store=self
            )
        except (lectura.ArtefactoFueraDeAmbito, lectura.LocalizadorInvalido) as exc:
            raise ValueError(str(exc)) from exc
        except (lectura.ArtefactoInexistente, lectura.ArtefactoNoSellado) as exc:
            raise KeyError(str(exc)) from exc

    def list_runs(self, case_id: str) -> list[ArtifactRun]:
        """Return every run with a manifest, sorted by ``started_at`` descending."""
        runs_dir = self._runs_dir(case_id)
        if not runs_dir.exists():
            return []
        runs: list[ArtifactRun] = []
        for entry in runs_dir.iterdir():
            if not entry.is_dir() or not _UUID4_RE.match(entry.name):
                continue
            manifest_path = entry / "manifest.json"
            if not manifest_path.exists():
                continue
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            runs.append(self._manifest_to_run(case_id, manifest))
        runs.sort(key=lambda r: r.started_at, reverse=True)
        return runs

    # ---------- lectura de la salida de un run (para el agente) ----------

    def read_run_output(
        self,
        case_id: str,
        run_id: str,
        *,
        fichero: str = "stdout",
        buscar: str | None = None,
        desde: int = 1,
        lineas: int = 200,
    ) -> dict[str, Any]:
        """Lee y filtra por LÍNEAS la salida VERIFICADA de un run ya ejecutado.

        Es lo que le faltaba al agente para poder mirar lo que él mismo produjo: hasta
        ahora solo veía un ``stdout_sample`` de 2000 chars, así que una salida de
        ``regripper`` o un árbol de ``fls`` eran practicamente opacos y acababa
        re-ejecutando la herramienta o infiriendo sin sostén.

        Equivale al ``grep``/``head`` sobre ``output/`` de un analista, pero SIN shell:
        el modelo pasa un ``run_id`` (no una ruta), el backend resuelve el fichero
        dentro del run y confina el acceso; ``buscar`` es una SUBCADENA literal
        (case-insensitive), nunca una expresión regular del modelo.

        ``fichero`` es ``"stdout"``/``"stderr"`` o el ``relpath`` de un fichero de
        salida declarado en el manifiesto. Los TRES pasan hoy por la misma frontera
        (``agentopsy.artifacts.lectura``), que re-hashea contra el manifiesto y contra
        el ancla auditada: antes solo lo hacía el derivado, y alterar ``stdout.txt``
        devolvía el texto alterado sin un error (auditoría 2026-09-07, F02).

        Devuelve un dict con el tramo pedido y CUÁNTO queda, para que el agente pueda
        paginar en vez de pedir "todo". Un fichero binario NO se sirve como texto: se
        devuelve un error accionable que nombra las herramientas adecuadas (RULE 2).
        """
        from agentopsy.artifacts import lectura

        try:
            desde = max(1, int(desde))
            lineas = max(1, min(int(lineas), _MAX_LINES_PER_READ))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"desde/lineas deben ser enteros: {exc}") from exc

        needle = (buscar or "").strip().lower() or None

        with lectura.abrir_verificado(
            case_id, run_id, fichero, ambito=lectura.AMBITO_AGENTE, store=self
        ) as leida:
            if leida.es_binario():
                raise ValueError(
                    Mensaje("artifacts.isBinary", file=repr(fichero), run_id=run_id)
                )
            pagina = _paginar(leida.lineas(), needle=needle, desde=desde, lineas=lineas)
            procedencia = leida.procedencia()

        return {
            "run_id": run_id,
            "tool_id": leida.tool_id,
            "fichero": fichero,
            "buscar": buscar,
            "procedencia": procedencia,
            **pagina,
        }


def _paginar(
    fuente: Iterable[str], *, needle: str | None, desde: int, lineas: int
) -> dict[str, Any]:
    """Pagina un flujo de líneas con un cursor que SIEMPRE progresa.

    El cursor (``desde`` / ``siguiente_desde``) es una posición inequívoca: el
    índice, 1-based, de la primera línea RELEVANTE que NO se ha devuelto. Antes
    no lo era, y ahí estaba el bloqueo que la auditoría reprodujo: una línea más
    larga que el presupuesto de caracteres se saltaba con ``continue``, así que
    la página salía vacía y ``siguiente_desde`` volvía a apuntar a la misma
    línea, indefinidamente (F02).

    Ahora una línea que no cabe se resuelve de dos maneras, y las dos avanzan:

    - Si la página ya lleva algo, se CORTA ahí. El cursor apunta a esa línea, que
      es exactamente la primera no devuelta, y la siguiente página la sirve.
    - Si la página está vacía, esa línea sola no cabe entera: se devuelve
      FRAGMENTADA (los primeros caracteres del presupuesto) y se declara en
      ``fragmentadas`` con cuántos caracteres tenía y cuántos van. Recortar en
      silencio sería peor que no devolverla; devolver cero y no avanzar era el
      bug.

    Los topes de memoria y de respuesta se conservan: se recorre en streaming y
    nunca entra en la respuesta más de ``_MAX_CHARS_PER_READ`` de contenido.
    """
    total = 0
    matched = 0
    picked: list[str] = []
    fragmentadas: list[dict[str, int]] = []
    chars = 0
    # Dos motivos DISTINTOS de cerrar la página, y no significan lo mismo: que se
    # llene por el número de líneas pedidas es paginación normal; que se corte
    # por el presupuesto de caracteres es un recorte, y eso es lo que declara
    # `truncado_por_tamano`. Fundirlos haría que toda página completa pareciera
    # recortada.
    cerrada = False
    por_tamano = False
    for raw in fuente:
        total += 1
        # `Lectura.lineas()` ya entrega la línea sin su marca de fin de línea.
        line = raw
        if needle is not None and needle not in line.lower():
            continue
        matched += 1
        # `desde` numera sobre las líneas RELEVANTES (las que casan con el
        # filtro), que es lo que el agente espera al paginar una búsqueda.
        if matched < desde:
            continue
        if cerrada or len(picked) >= lineas:
            cerrada = True
            continue  # se sigue recorriendo solo para contar `total`/`matched`
        if chars + len(line) > _MAX_CHARS_PER_READ:
            if picked:
                # Cabe en la página siguiente entera: se corta aquí y el cursor
                # apunta a ESTA línea.
                cerrada = True
                por_tamano = True
                continue
            # Ni sola cabe: se fragmenta y se DECLARA.
            trozo = line[:_MAX_CHARS_PER_READ]
            picked.append(trozo)
            fragmentadas.append(
                {
                    "linea": matched,
                    "chars_totales": len(line),
                    "chars_incluidos": len(trozo),
                }
            )
            chars += len(trozo) + 1
            continue
        picked.append(line)
        chars += len(line) + 1

    relevantes = matched if needle is not None else total
    siguiente = desde + len(picked)
    return {
        "total_lineas": total,
        "lineas_relevantes": relevantes,
        "desde": desde,
        "devueltas": len(picked),
        "hay_mas": siguiente <= relevantes,
        "siguiente_desde": siguiente if siguiente <= relevantes else None,
        # Se conserva el nombre histórico del campo (lo leen la SPA y los tests):
        # significa "esta página se ha recortado por el tope de TAMAÑO", no que
        # se haya llenado de líneas. `fragmentadas` dice además QUÉ línea se
        # sirvió a trozos.
        "truncado_por_tamano": bool(por_tamano or fragmentadas),
        "fragmentadas": fragmentadas,
        "lineas": picked,
    }


artifact_store = ArtifactStore(case_manager)
