"""Procedencia SINTÉTICA pero REAL para los tests de hallazgos.

Desde F03 un hallazgo afirmativo no se registra con un ``run_id`` inventado: el
servicio de dominio comprueba que la ejecución exista, sea de ese caso, haya
leído esa evidencia, la haya ejecutado esa herramienta, haya producido ese
artefacto y que sus bytes conserven el hash registrado. Los tests, por tanto, no
pueden seguir pasando un UUID cualquiera: tienen que MATERIALIZAR una ejecución.

Estos ayudantes la materializan de verdad (``ArtifactStore.start_run`` +
``finalize_run``, con su manifiesto y sus hashes) sobre el ``tmp_path`` del test.
No hay atajo ni doble: si estos ayudantes dejaran de producir una procedencia
válida, los tests fallarían, que es exactamente lo que se quiere de un gate.
"""

from __future__ import annotations

import uuid
from typing import Any

from agentopsy.artifacts.store import ArtifactStore
from agentopsy.audit.log import AuditLog
from agentopsy.evidence import EvidenceManager

#: Un baseline que NO es el de ninguna evidencia registrada. Existe para los
#: tests que necesitan justo eso: una ejecución que dice haber leído una
#: evidencia con un baseline distinto del que el caso tiene registrado, que desde
#: la reauditoría de 2026-09-08 bloquea la aprobación (RA02 b). No es el valor por
#: defecto: una fixture con hashes incoherentes deja de ser un gate.
BASELINE_SHA256 = "a" * 64
#: Salida por defecto: tres líneas, para poder citar un intervalo concreto.
STDOUT_POR_DEFECTO = "primera linea\nsegunda linea\ntercera linea\n"


def registrar_evidencia(cases: Any, case_id: str, *, nombre: str = "e.raw") -> Any:
    """Registra una evidencia REAL (copia + puerta de hash) y devuelve su handle.

    La procedencia exige que la evidencia que la ejecución dice haber leído
    EXISTA en el caso, así que un id inventado tampoco vale aquí. El fichero es
    minúsculo y sintético: lo que importa es que pase por ``EvidenceManager``.
    """
    origen = cases.root.parent / f"{case_id[:8]}-{nombre}"
    origen.parent.mkdir(parents=True, exist_ok=True)
    if not origen.exists():
        origen.write_bytes(b"Agentopsy-EVIDENCIA-SINTETICA")
    return EvidenceManager(cases).register(case_id, str(origen))


def crear_run(
    cases: Any,
    case_id: str,
    *,
    tool_id: str = "tsk_fls",
    argv: list[str] | None = None,
    stdout: str = STDOUT_POR_DEFECTO,
    stderr: str = "",
    exit_code: int = 0,
    evidence_id: str | None = None,
    baseline: str | None = None,
    tool_version: str = "sleuthkit 4.12.1",
    ficheros: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Materializa una ejecución REAL y devuelve su procedencia.

    El dict que devuelve trae ``run_id``, ``evidence_id``, ``tool_id`` y los
    hashes que el manifiesto registró, para que un test cite lo que de verdad
    hay ahí en lugar de un valor plausible.
    """
    store = ArtifactStore(cases)
    if evidence_id is None:
        evidence_id = registrar_evidencia(
            cases, case_id, nombre=f"{uuid.uuid4().hex[:8]}.raw"
        ).evidence_id
    if baseline is None:
        # El baseline REAL de la evidencia registrada. Un valor sintético dejaba
        # el manifiesto de la ejecución diciendo que había leído algo que el caso
        # no tiene, y esa incoherencia es hoy un bloqueo de aprobación.
        baseline = EvidenceManager(cases).get(case_id, evidence_id).sha256
    run_id, out_dir = store.start_run(
        case_id,
        tool_id,
        argv or [tool_id, "-r", "/evidence/disk.raw"],
        evidence_id=evidence_id,
        evidence_baseline_sha256=baseline,
        tool_version=tool_version,
    )
    store.set_run_argv(case_id, run_id, argv or [tool_id, "-r", "/evidence/disk.raw"])
    for relpath, contenido in (ficheros or {}).items():
        destino = out_dir / relpath
        destino.parent.mkdir(parents=True, exist_ok=True)
        destino.write_text(contenido, encoding="utf-8")
    run = store.finalize_run(
        case_id, run_id, exit_code=exit_code, stdout=stdout, stderr=stderr
    )
    # El ANCLA del manifiesto en la cadena, igual que hace el dispatcher al
    # cerrar una ejecución real. Sin ella el run sería moderno sin ancla, que es
    # un fallo de custodia (``lectura.AnclaAusenteError``) y no un caso de
    # prueba: la fixture tiene que producir procedencia VÁLIDA, o deja de ser un
    # gate y pasa a ser un adorno.
    audit = AuditLog(cases.case_dir(case_id) / "audit.jsonl")
    audit.append({
        "action": "tool_run_start",
        "case_id": case_id,
        "run_id": run_id,
        "tool_id": tool_id,
        "argv": argv or [tool_id, "-r", "/evidence/disk.raw"],
        "evidence_id": evidence_id,
        "baseline_sha256": baseline,
        "tool_version": tool_version,
    })
    audit.append({
        "action": "tool_run_finish",
        "case_id": case_id,
        "run_id": run_id,
        "status": run.status,
        "exit_code": exit_code,
        "stdout_sha256": run.stdout_sha256,
        "stderr_sha256": run.stderr_sha256,
        "output_files_count": len(run.output_files),
        "manifest_sha256": run.manifest_sha256,
    })
    return {
        "run_id": run_id,
        "evidence_id": evidence_id,
        "tool_id": tool_id,
        "stdout_sha256": run.stdout_sha256,
        "stderr_sha256": run.stderr_sha256,
        "output_files": {of.relpath: of.sha256 for of in run.output_files},
        "store": store,
        "run": run,
    }


def anclar_run(cases: Any, case_id: str, run: Any) -> None:
    """Deja en el audit del caso el ANCLA del manifiesto de un run ya cerrado.

    Es lo que hace el dispatcher al cerrar una ejecución real. Un test que llame
    a ``finalize_run`` o a ``fail_run`` por su cuenta y no ancle deja un run
    MODERNO (su manifiesto declara ``manifest_sha256``) sin ancla en la cadena,
    que desde la reauditoría de 2026-09-08 es un fallo de custodia y no un
    estado servible: la lectura verificada levanta ``AnclaAusenteError``.

    Anclar aquí no es acomodar el test a la comprobación: es que el estado que
    el test construía no se produce nunca en la aplicación.
    """
    AuditLog(cases.case_dir(case_id) / "audit.jsonl").append({
        "action": "tool_run_finish",
        "case_id": case_id,
        "run_id": run.run_id,
        "status": run.status,
        "exit_code": run.exit_code,
        "stdout_sha256": run.stdout_sha256,
        "stderr_sha256": run.stderr_sha256,
        "output_files_count": len(run.output_files),
        "manifest_sha256": run.manifest_sha256,
    })


def cerrar_run(
    store: Any,
    cases: Any,
    case_id: str,
    run_id: str,
    *,
    exit_code: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> Any:
    """``finalize_run`` + :func:`anclar_run`, que es como se cierra de verdad."""
    run = store.finalize_run(
        case_id, run_id, exit_code=exit_code, stdout=stdout, stderr=stderr
    )
    anclar_run(cases, case_id, run)
    return run


def procedencia(run: dict[str, Any], **extra: Any) -> dict[str, Any]:
    """Los campos de procedencia de un hallazgo que cita ``run`` (forma histórica).

    Es el atajo para el 90 % de los tests, que solo necesitan que el hallazgo
    tenga una fuente válida y no están probando el contrato de citas.
    """
    return {
        "run_id": run["run_id"],
        "evidence_id": run["evidence_id"],
        "tool_id": run["tool_id"],
        "artifact_sha256": run["stdout_sha256"],
        **extra,
    }


def referencia(
    run: dict[str, Any],
    *,
    artefacto: str = "stdout",
    relpath: str | None = None,
    desde: int = 1,
    hasta: int = 1,
    extracto: str | None = None,
) -> dict[str, Any]:
    """Una cita del contrato NUEVO: artefacto concreto y localizador de líneas."""
    sha = (
        run["stdout_sha256"]
        if artefacto == "stdout"
        else run["stderr_sha256"]
        if artefacto == "stderr"
        else run["output_files"][relpath]
    )
    ref: dict[str, Any] = {
        "run_id": run["run_id"],
        "evidence_id": run["evidence_id"],
        "tool_id": run["tool_id"],
        "artefacto": artefacto,
        "sha256": sha,
        "localizador": {"tipo": "lineas", "desde": desde, "hasta": hasta},
    }
    if relpath is not None:
        ref["relpath"] = relpath
    if extracto is not None:
        ref["extracto"] = extracto
    return ref


class EvidenciaFalsa:
    """Un ``EvidenceManager`` mínimo: la evidencia del run EXISTE en el caso.

    Solo implementa ``get``, que es lo único que el servicio de procedencia le
    pide, y falla como el real (``KeyError``) para un id que no registró.
    """

    def __init__(self, *ids: str) -> None:
        self._ids = set(ids)

    def add(self, evidence_id: str) -> None:
        self._ids.add(evidence_id)

    def get(self, case_id: str, evidence_id: str) -> Any:
        if evidence_id not in self._ids:
            raise KeyError(f"unknown evidence {evidence_id} in case {case_id}")
        return {"evidence_id": evidence_id, "case_id": case_id}


__all__ = [
    "BASELINE_SHA256",
    "anclar_run",
    "cerrar_run",
    "STDOUT_POR_DEFECTO",
    "EvidenciaFalsa",
    "crear_run",
    "procedencia",
    "referencia",
    "registrar_evidencia",
]
