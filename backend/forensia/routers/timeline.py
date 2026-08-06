"""Timeline HTTP surface. Thin adapter over ``forensia.timeline`` (CLAUDE.md RULE 3).

Two layers:

- ``GET /api/cases/{case_id}/timeline`` — the deterministic *investigation* timeline
  (audit tool runs + findings), always available, no tool executed.
- ``POST /api/cases/{case_id}/timeline/filesystem`` — start the on-demand *filesystem
  super-timeline* (``tsk_fls -m`` over the selected evidence) as a background job, then
  poll it at ``GET …/timeline/filesystem/jobs/{job_id}``. The completed result is
  materialized under the case (``timeline/<evidence_id>.json``) so it survives page
  reloads and api restarts (the job registry is in-memory only).
- ``GET /api/cases/{case_id}/timeline/filesystem?evidence_id=…`` — the last PERSISTED
  filesystem super-timeline for that evidence (``{result: … | null}``), used to rehydrate
  the view without re-running ``fls``.
- ``GET /api/cases/{case_id}/timeline/diagram?layer=…`` — el LAYOUT del dibujo de una
  capa (``forensia.timeline.diagram``), en unidades de dominio: lo pinta el navegador en
  SVG y, cuando la figura entre en el informe, el PDF con las mismas cifras.

RULE 2 — nothing is inferred: no ``evidence_id`` → 422; an unresolved ``os_profile``
(unknown / low confidence / conflict) → 409 the operator must anchor; ``fls`` failure →
the job carries the actionable error, never a partial timeline.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

from forensia.agent.jobs import job_registry
from forensia.cases.manager import (
    OsProfileUnresolved,
    case_manager,
    resolve_os_profile,
)
from forensia.evidence import evidence_manager
from forensia.evidence_context import EvidenceContext
from forensia.export_csv import export_basename
from forensia.security import require_token
from forensia.timeline import (
    TIMEZONE,
    build_filesystem_diagram,
    build_investigation_diagram,
    build_investigation_timeline,
    full_filesystem_events,
    load_filesystem_timeline,
    run_filesystem_timeline,
)
from forensia.timeline.export import timeline_to_csv

router = APIRouter()


@router.get(
    "/api/cases/{case_id}/timeline",
    dependencies=[Depends(require_token)],
)
def investigation_timeline(case_id: str) -> dict[str, Any]:
    """Chronological line of what happened in the case: every audited tool run and
    every recorded finding, ordered by their UTC timestamp. Deterministic and always
    available (it runs no new tool)."""
    try:
        events = build_investigation_timeline(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"case_id": case_id, "timezone": TIMEZONE, "events": events}


@router.get(
    "/api/cases/{case_id}/timeline/export.csv",
    dependencies=[Depends(require_token)],
)
def export_investigation_timeline_csv(case_id: str) -> Response:
    """Hoja de cálculo del timeline de investigación (ejecuciones de herramienta +
    hallazgos, en orden cronológico UTC, con su bloque de procedencia). Reusa el
    mismo builder determinista; un caso sin actividad devuelve la procedencia y la
    cabecera sin filas (0 filas, honesto)."""
    try:
        events = build_investigation_timeline(case_id)
        case = case_manager.load(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    body = timeline_to_csv(
        events, case_id=case_id, case_name=case.name, timezone=TIMEZONE
    )
    filename = f"{export_basename(case.name, 'timeline')}.csv"
    return Response(
        content=body,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


#: Las dos capas que se pueden DIBUJAR. La tercera (eventos relevantes) no es una
#: capa aparte en el dibujo: son las marcas sobre la banda de densidad.
_CAPAS_DIBUJABLES = ("investigation", "filesystem")


def _etiquetas_de_evidencia(case_id: str) -> dict[str, str]:
    """``evidence_id`` → etiqueta del carril del dibujo.

    El nombre del fichero copiado más los ocho primeros caracteres del
    identificador. Dos conjuntos EWF registrados en el mismo caso se copian los dos
    a ``original.E01``, así que el nombre a secas dejaría dos carriles
    indistinguibles en una figura que acaba en un anexo.
    """
    return {
        handle.evidence_id: f"{handle.original_path.name} · {handle.evidence_id[:8]}"
        for handle in evidence_manager.list(case_id)
    }


@router.get(
    "/api/cases/{case_id}/timeline/diagram",
    dependencies=[Depends(require_token)],
)
def timeline_diagram(
    case_id: str, layer: str | None = None, evidence_id: str | None = None
) -> dict[str, Any]:
    """El LAYOUT del dibujo de una capa del timeline, en unidades de dominio.

    ``layer=investigation`` dibuja la franja de trabajos (un carril por evidencia,
    una barra por ejecución con su duración auditada, una marca por hallazgo y la
    banda de fases de ATT&CK) y no necesita evidencia. ``layer=filesystem`` dibuja
    la banda de densidad MACB de UNA evidencia, y la exige.

    ``diagram`` es ``null`` con un ``message`` accionable cuando no hay nada que
    dibujar todavía (un caso sin actividad, una super-timeline sin generar): un eje
    vacío con leyenda sugeriría que se midió algo (RULE 2). ``layer`` es
    obligatorio: no se elige una capa por el operador.
    """
    if layer not in _CAPAS_DIBUJABLES:
        raise HTTPException(
            status_code=422,
            detail=(
                f"layer inválido: {layer!r}. Indica la capa que quieres dibujar, "
                f"una de {list(_CAPAS_DIBUJABLES)} (Agentopsy no elige una por ti, "
                "RULE 2)."
            ),
        )
    try:
        case = case_manager.load(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    respuesta: dict[str, Any] = {
        "case_id": case_id,
        "layer": layer,
        "timezone": TIMEZONE,
        "diagram": None,
        "message": None,
    }

    if layer == "investigation":
        events = build_investigation_timeline(case_id)
        diagram = build_investigation_diagram(
            events,
            case_id=case_id,
            case_name=case.name,
            evidence_labels=_etiquetas_de_evidencia(case_id),
        )
        respuesta["diagram"] = diagram
        if diagram is None:
            respuesta["message"] = (
                "El caso no tiene todavía ningún evento con marca temporal que "
                "situar en el eje. La franja de trabajos se dibuja con las "
                "ejecuciones del log de auditoría y los hallazgos registrados."
            )
        return respuesta

    if not evidence_id:
        raise HTTPException(
            status_code=422,
            detail="evidence_id is required: la banda de densidad se dibuja sobre "
                   "una evidencia concreta (Agentopsy no asume 'la única' ni 'la "
                   "última', RULE 2).",
        )
    try:
        handle = evidence_manager.get(case_id, evidence_id)
        material = full_filesystem_events(case_id, evidence_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if material is None:
        respuesta["message"] = (
            "La super-timeline de esta evidencia aún no está generada, así que no "
            "hay densidad que dibujar. Pulsa «Generar super-timeline» y vuelve al "
            "dibujo."
        )
        return respuesta
    events, relevant, _persisted = material
    respuesta["diagram"] = build_filesystem_diagram(
        events,
        relevant,
        case_id=case_id,
        case_name=case.name,
        evidence_id=evidence_id,
        evidence_label=f"{handle.original_path.name} · {handle.evidence_id[:8]}",
    )
    if respuesta["diagram"] is None:
        respuesta["message"] = (
            "La super-timeline de esta evidencia no tiene ningún evento con marca "
            "temporal legible."
        )
    return respuesta


class FilesystemTimelineRequest(BaseModel):
    # The evidence to build the filesystem super-timeline from. REQUIRED — Agentopsy
    # never assumes "the only" / "the most recent" evidence (RULE 2).
    evidence_id: str | None = None


@router.get(
    "/api/cases/{case_id}/timeline/filesystem",
    dependencies=[Depends(require_token)],
)
def get_persisted_filesystem_timeline(
    case_id: str, evidence_id: str | None = None
) -> dict[str, Any]:
    """Última super-timeline PERSISTIDA de una evidencia (``{result: … | null}``).

    Rehidrata la vista tras recargar la página o reiniciar el api sin re-ejecutar
    ``tsk_fls`` (el ``job_registry`` es solo en memoria; el resultado acotado se
    materializa en ``<case_dir>/timeline/<evidence_id>.json`` al generarlo).
    ``result`` es ``null`` si nunca se generó — el operador ve «Pulsa Generar».

    Sin ``evidence_id`` → 422 (RULE 2: no se asume 'la única' ni 'la última');
    evidencia inexistente → 404; id malformado → 422."""
    if not evidence_id:
        raise HTTPException(
            status_code=422,
            detail="evidence_id is required: indica la evidencia cuya super-timeline "
                   "quieres recuperar (Agentopsy no asume 'la única' ni 'la última', RULE 2).",
        )
    try:
        evidence_manager.get(case_id, evidence_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    try:
        result = load_filesystem_timeline(case_id, evidence_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"case_id": case_id, "timezone": TIMEZONE, "result": result}


@router.post(
    "/api/cases/{case_id}/timeline/filesystem",
    dependencies=[Depends(require_token)],
)
def start_filesystem_timeline(
    case_id: str, req: FilesystemTimelineRequest
) -> dict[str, Any]:
    """Start the ``tsk_fls -m`` super-timeline over the selected evidence as a background
    job and return its ``job_id`` immediately. Validation (evidence, os_profile) runs
    here, synchronously, so it fails fast before anything is enqueued; the disk-reading
    step runs decoupled from this request (a disconnect does not abort it)."""
    if not req.evidence_id:
        raise HTTPException(
            status_code=422,
            detail="evidence_id is required: selecciona una evidencia registrada en el "
                   "caso para construir la super-timeline (Agentopsy no asume 'la única' "
                   "ni 'la última', RULE 2).",
        )

    try:
        handle = evidence_manager.get(case_id, req.evidence_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    try:
        case = case_manager.load(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    try:
        os_profile = resolve_os_profile(case)
    except OsProfileUnresolved as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    evidence_context = EvidenceContext.from_handle(handle)

    # La super-timeline es un paso único (fls -m), no un loop iterativo: acepta la
    # firma nueva del job (emit, should_cancel) pero no hay punto de corte cooperativo.
    def _work(emit, _should_cancel) -> dict:  # noqa: ANN001 — Callables del job
        return run_filesystem_timeline(
            case_id, handle, evidence_context, os_profile, emit=emit
        )

    job = job_registry.submit(
        case_id,
        "fs_timeline",
        _work,
        meta={"evidence_id": req.evidence_id, "os_profile": os_profile},
    )
    return job.public()


@router.get(
    "/api/cases/{case_id}/timeline/filesystem/jobs/{job_id}",
    dependencies=[Depends(require_token)],
)
def get_filesystem_timeline_job(
    case_id: str, job_id: str, since: int = 0
) -> dict[str, Any]:
    """Poll a filesystem super-timeline job: running / done (``result.events``) / error.

    ``since`` returns only the progress events from that index onward, so the client can
    show the stage (``fls`` → ``mactime`` → ``done``) as it advances."""
    snap = job_registry.snapshot(job_id, since=max(0, since))
    if snap is None:
        raise HTTPException(status_code=404, detail=f"job {job_id} not found")
    if snap.get("case_id") != case_id:
        raise HTTPException(
            status_code=404,
            detail=f"job {job_id} does not belong to case {case_id}",
        )
    return snap
