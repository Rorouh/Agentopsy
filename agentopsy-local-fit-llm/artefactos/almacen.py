"""Artefactos: `artifacts/<run_id>/{stdout.txt, stderr.txt, out/, manifest.json}`.

La salida cruda de cada ejecución se persiste tal cual, antes de que ningún
modelo la lea (RA-10, RC-5). El manifiesto lleva los mismos campos que el del
api más los hashes, así la web y su timeline los entienden.

Lectura acotada: `leer` devuelve un trozo (desde línea, n líneas, tope de
caracteres) y nunca un fichero entero. `indice` devuelve referencias: id,
herramienta, tamaño, líneas, exit_code.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from custodia.registro import sha256_fichero

TOPE_CHARS_LECTURA = 2400
TOPE_LINEAS_LECTURA = 80


def _ahora() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Manifiesto:
    run_id: str
    case_id: str
    evidence_id: str | None
    tool_id: str
    argv: list[str]
    tool_version: str | None = None
    started_at: str = field(default_factory=_ahora)
    finished_at: str | None = None
    status: str = "running"
    exit_code: int | None = None
    timed_out: bool = False
    stdout_sha256: str | None = None
    stderr_sha256: str | None = None
    stdout_size: int | None = None
    stdout_lines: int | None = None
    output_files: list[dict[str, Any]] = field(default_factory=list)
    evidence_baseline_sha256: str | None = None
    error_type: str | None = None
    error_message: str | None = None
    engine: str = "local-fit-llm"
    agent: str | None = None


class Almacen:
    def __init__(self, dir_caso: Path) -> None:
        self.raiz = Path(dir_caso) / "artifacts"
        self.raiz.mkdir(parents=True, exist_ok=True)

    # -- ciclo de vida de un run ----------------------------------------------------
    def abrir(self, case_id: str, evidence_id: str | None, tool_id: str, argv: list[str],
              *, baseline_sha256: str | None, tool_version: str | None, agente: str | None) -> Manifiesto:
        run_id = str(uuid.uuid4())
        ruta = self.raiz / run_id
        (ruta / "out").mkdir(parents=True, exist_ok=False)
        (ruta / "stdout.txt").touch()
        (ruta / "stderr.txt").touch()
        m = Manifiesto(
            run_id=run_id, case_id=case_id, evidence_id=evidence_id, tool_id=tool_id,
            argv=list(argv), tool_version=tool_version,
            evidence_baseline_sha256=baseline_sha256, agent=agente,
        )
        self._escribir_manifiesto(m)
        return m

    def dir_run(self, run_id: str) -> Path:
        if not isinstance(run_id, str) or "/" in run_id or ".." in run_id:
            raise ValueError(f"run_id inválido: {run_id!r}")
        ruta = self.raiz / run_id
        if not (ruta / "manifest.json").is_file():
            raise KeyError(f"no existe el artefacto {run_id}")
        return ruta

    def ruta_stdout(self, run_id: str) -> Path:
        return self.raiz / run_id / "stdout.txt"

    def ruta_out(self, run_id: str) -> Path:
        return self.raiz / run_id / "out"

    def cerrar(self, m: Manifiesto, *, exit_code: int, timed_out: bool,
               stdout_texto: str | None, stderr_texto: str) -> Manifiesto:
        """Persiste stdout/stderr (si vinieron por texto), hashea todo y sella."""
        ruta = self.raiz / m.run_id
        if stdout_texto is not None:
            (ruta / "stdout.txt").write_text(stdout_texto, encoding="utf-8", errors="replace")
        (ruta / "stderr.txt").write_text(stderr_texto or "", encoding="utf-8", errors="replace")
        m.stdout_sha256, m.stdout_size = sha256_fichero(ruta / "stdout.txt")
        m.stderr_sha256, _ = sha256_fichero(ruta / "stderr.txt")
        m.stdout_lines = contar_lineas(ruta / "stdout.txt")
        m.output_files = self._ficheros_out(ruta / "out")
        m.exit_code = exit_code
        m.timed_out = timed_out
        m.finished_at = _ahora()
        m.status = "finished" if exit_code == 0 else "nonzero"
        self._escribir_manifiesto(m)
        return m

    def fallar(self, m: Manifiesto, tipo: str, mensaje: str) -> Manifiesto:
        m.status = "error"
        m.error_type = tipo
        m.error_message = mensaje
        m.finished_at = _ahora()
        self._escribir_manifiesto(m)
        return m

    def _escribir_manifiesto(self, m: Manifiesto) -> None:
        (self.raiz / m.run_id / "manifest.json").write_text(
            json.dumps(asdict(m), indent=2, sort_keys=True), encoding="utf-8"
        )

    def _ficheros_out(self, out: Path) -> list[dict[str, Any]]:
        salida = []
        if not out.is_dir():
            return salida
        for p in sorted(out.rglob("*")):
            if p.is_file():
                sha, tam = sha256_fichero(p)
                salida.append({
                    "relpath": str(p.relative_to(out)),
                    "size": tam,
                    "sha256": sha,
                })
        return salida

    # -- lectura ---------------------------------------------------------------------
    def manifiesto(self, run_id: str) -> dict[str, Any]:
        return json.loads((self.dir_run(run_id) / "manifest.json").read_text(encoding="utf-8"))

    def indice(self) -> list[dict[str, Any]]:
        """Referencias, no contenidos, en orden cronológico."""
        filas = []
        for hijo in self.raiz.iterdir():
            fichero = hijo / "manifest.json"
            if not fichero.is_file():
                continue
            try:
                m = json.loads(fichero.read_text(encoding="utf-8"))
            except ValueError:
                continue
            filas.append({
                "run_id": m.get("run_id"),
                "tool_id": m.get("tool_id"),
                "status": m.get("status"),
                "exit_code": m.get("exit_code"),
                "stdout_size": m.get("stdout_size"),
                "stdout_lines": m.get("stdout_lines"),
                "output_files": len(m.get("output_files") or []),
                "started_at": m.get("started_at"),
                "argv": m.get("argv"),
                "agent": m.get("agent"),
            })
        filas.sort(key=lambda f: f.get("started_at") or "")
        return filas

    def ficheros(self, run_id: str) -> list[dict[str, Any]]:
        m = self.manifiesto(run_id)
        base = [{"fichero": "stdout.txt", "size": m.get("stdout_size"), "lines": m.get("stdout_lines")},
                {"fichero": "stderr.txt", "size": None, "lines": None}]
        for f in m.get("output_files") or []:
            base.append({"fichero": "out/" + f["relpath"], "size": f["size"], "lines": None})
        return base

    def ruta_fichero(self, run_id: str, fichero: str | None) -> Path:
        """Resuelve `stdout.txt` | `stderr.txt` | `out/<relpath>` dentro del run (confinado)."""
        ruta_run = self.dir_run(run_id)
        nombre = fichero or "stdout.txt"
        if nombre in {"stdout", "stdout.txt"}:
            return ruta_run / "stdout.txt"
        if nombre in {"stderr", "stderr.txt"}:
            return ruta_run / "stderr.txt"
        if not nombre.startswith("out/"):
            nombre = "out/" + nombre
        objetivo = (ruta_run / nombre).resolve()
        try:
            objetivo.relative_to((ruta_run / "out").resolve())
        except ValueError as exc:
            raise ValueError(f"fichero fuera del artefacto {run_id}: {fichero!r}") from exc
        if not objetivo.is_file():
            raise KeyError(f"el artefacto {run_id} no tiene el fichero {nombre!r}")
        return objetivo

    def leer(self, run_id: str, desde: int = 1, n: int = 40, fichero: str | None = None,
             tope_chars: int = TOPE_CHARS_LECTURA) -> dict[str, Any]:
        """Un trozo: líneas [desde, desde+n) acotado en caracteres. Nunca el fichero entero."""
        ruta = self.ruta_fichero(run_id, fichero)
        desde = max(1, int(desde))
        n = max(1, min(int(n), TOPE_LINEAS_LECTURA))
        lineas: list[str] = []
        usados = 0
        total = 0
        truncado = False
        with ruta.open("r", encoding="utf-8", errors="replace") as fh:
            for numero, linea in enumerate(fh, start=1):
                total = numero
                if numero < desde or len(lineas) >= n:
                    continue
                linea = linea.rstrip("\n")
                if len(linea) > 200:
                    linea = linea[:200] + "…"
                if usados + len(linea) > tope_chars:
                    truncado = True
                    break
                lineas.append(f"{numero}: {linea}")
                usados += len(linea) + 1
        return {
            "run_id": run_id,
            "fichero": str(ruta.relative_to(self.raiz / run_id)),
            "desde": desde,
            "lineas": lineas,
            "total_lineas": total,
            "truncado": truncado or (desde + len(lineas) - 1) < total,
        }


def contar_lineas(ruta: Path) -> int:
    total = 0
    with Path(ruta).open("rb") as fh:
        while True:
            bloque = fh.read(1024 * 1024)
            if not bloque:
                break
            total += bloque.count(b"\n")
    return total
