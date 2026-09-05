"""«Trabajos realizados» — las ejecuciones reales, reensambladas del audit log.

Reconstruye cada corrida de herramienta del caso emparejando ``tool_run_start``
con su ``tool_run_finish`` en ``audit.jsonl`` y cruzando los hallazgos que citan
ese ``run_id``. Es la materia prima de la sección «Trabajos realizados» del
informe (``agentopsy.reports.indice`` §7) y del gate de comandos literales del
redactor (``agentopsy.reports.writer``).

Lo que el informe hace con esto NO es volcarlo: el apartado 7 resume el uso de
herramientas y detalla las ejecuciones FALLIDAS, y el detalle corrida a corrida
(argv, versiones, marcas temporales, hashes de las salidas) se queda donde ya
estaba íntegro, en el audit hash-encadenado. Este módulo lo entrega completo de
todas formas: es la fuente de la que salen ese resumen, las limitaciones del
apartado 9 y el corpus de argv auditados contra el que se valida cada bloque
``code`` del informe.

Dos reglas gobiernan este módulo, y las dos vienen de FORENSIC INVARIANT 4:

1. **El ``argv`` es el del audit, token a token.** Nunca se reconstruye desde
   los parámetros, ni se normaliza, ni se "arregla". ``argv_literal`` es
   simplemente ese array unido por espacios, para que el redactor pueda citarlo
   sin re-teclearlo — y para que el validador compare la cita contra el original.
2. **Lo que el audit no dice, no se dice.** Un run sin ``tool_version`` no
   inventa ``"unknown"`` (queda ``None``); un run sin ``tool_run_finish`` —el
   transporte se cayó, el api se reinició— aparece con ``status`` ``incompleto``
   y NO se descarta: una ejecución que consta iniciada y no consta terminada es
   información pericial, no ruido (RULE 2).

Lógica pura (RULE 3): lee el audit del caso y devuelve dicts; no imprime, no
toca la red.
"""

from __future__ import annotations

from typing import Any

from agentopsy.audit.log import AuditLog
from agentopsy.cases import CaseManager, case_manager
from agentopsy.findings.store import FindingStore, finding_store

#: Estado de una corrida en el informe. ``finished`` / ``error`` los declara el
#: propio ``tool_run_finish``; ``incompleto`` es la ausencia de finish.
STATUS_INCOMPLETO = "incompleto"

#: Campos de custodia que ``tool_run_start`` / ``tool_run_finish`` arrastran y
#: que el informe necesita (FORENSIC INVARIANT 4). Se copian si están; su
#: ausencia no se rellena.
_CUSTODY_KEYS = ("evidence_id", "baseline_sha256", "tool_version")

#: Campos que solo trae el ``finish``.
_FINISH_KEYS = (
    "exit_code",
    "error_type",
    "error_message",
    "stdout_sha256",
    "stderr_sha256",
    "output_files_count",
)


def tool_runs(
    case_id: str,
    *,
    cases: CaseManager = case_manager,
    findings: FindingStore = finding_store,
) -> list[dict[str, Any]]:
    """Las corridas de herramienta del caso, en orden de inicio.

    Una entrada por ``tool_run_start``, con lo que su ``tool_run_finish`` añada y
    los ``finding_ids`` que citan su ``run_id``. Lista vacía si el caso no tiene
    audit todavía. ``ValueError`` si el ``case_id`` está malformado y ``KeyError``
    si el caso no existe — igual que el resto de ``agentopsy.reports``.
    """
    case_dir = cases.case_dir(case_id)
    audit_path = case_dir / "audit.jsonl"
    if not audit_path.is_file():
        return []
    entries = AuditLog(audit_path).entries()

    # run_id → findings que lo citan. Un hallazgo sin run_id (un descarte) no
    # cuelga de ninguna corrida.
    findings_por_run: dict[str, list[str]] = {}
    for f in findings.list(case_id):
        if f.run_id:
            findings_por_run.setdefault(f.run_id, []).append(f.id)

    runs: dict[str, dict[str, Any]] = {}
    orden: list[str] = []
    for event in entries:
        action = event.get("action")
        run_id = event.get("run_id")
        if not isinstance(run_id, str) or not run_id:
            continue

        if action == "tool_run_start":
            argv = event.get("argv")
            argv_list = [str(a) for a in argv] if isinstance(argv, list) else []
            run: dict[str, Any] = {
                "run_id": run_id,
                "tool_id": event.get("tool_id"),
                # INVARIANT 4: el argv AUDITADO. `argv_literal` es ese array
                # unido, para citarlo sin re-teclearlo — no una reconstrucción.
                "argv": argv_list,
                "argv_literal": " ".join(argv_list),
                "started_at": event.get("ts_utc"),
                "status": STATUS_INCOMPLETO,
                "finished_at": None,
                "finding_ids": findings_por_run.get(run_id, []),
            }
            for key in _CUSTODY_KEYS:
                if event.get(key) is not None:
                    run[key] = event[key]
            derived = event.get("derived_inputs")
            if isinstance(derived, list) and derived:
                run["derived_inputs"] = derived
            if run_id not in runs:
                orden.append(run_id)
            runs[run_id] = run

        elif action == "tool_run_finish":
            run = runs.get(run_id)
            if run is None:
                # Un finish sin su start (audit truncado por delante): se
                # conserva como corrida sin argv en vez de perderse.
                run = {
                    "run_id": run_id,
                    "tool_id": event.get("tool_id"),
                    "argv": [],
                    "argv_literal": "",
                    "started_at": None,
                    "finding_ids": findings_por_run.get(run_id, []),
                }
                orden.append(run_id)
                runs[run_id] = run
            run["status"] = str(event.get("status") or STATUS_INCOMPLETO)
            run["finished_at"] = event.get("ts_utc")
            for key in _FINISH_KEYS:
                if event.get(key) is not None:
                    run[key] = event[key]
            for key in _CUSTODY_KEYS:
                if run.get(key) is None and event.get(key) is not None:
                    run[key] = event[key]

    return [runs[rid] for rid in orden]


def audited_argvs(runs: list[dict[str, Any]]) -> set[str]:
    """El conjunto de comandos literales auditados, normalizados por espacios.

    Es el corpus contra el que ``agentopsy.reports.writer`` valida cada bloque
    ``code`` del informe: un comando que el redactor no haya copiado de aquí no
    se publica (FORENSIC INVARIANT 4 — el informe cita el comando EJECUTADO, no
    el que el modelo cree que se ejecutó)."""
    return {" ".join(r["argv_literal"].split()) for r in runs if r.get("argv_literal")}


__all__ = ["STATUS_INCOMPLETO", "audited_argvs", "tool_runs"]
