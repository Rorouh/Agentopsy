"""Evidence inbox listing. Registration is per-case (``/api/cases/{case_id}/evidence``
in ``routers/cases.py``) — an evidence file cannot exist outside a case, so this
module only exposes the *inbox* the web UI presents instead of a native file
dialog. The old case-less ``/api/evidence/register`` predated cases: it no longer
matched ``EvidenceManager.register(case_id, source_path)`` and nothing consumed
it, so it is gone.
"""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from forensia.custody import build_custody_act
from forensia.evidence import evidence_manager, list_source_files
from forensia.security import require_token

router = APIRouter()


@router.get("/api/evidence/sources", dependencies=[Depends(require_token)])
def sources() -> dict:
    """Bandeja de entrada de evidencias (``FORENSIA_EVIDENCE_DIR`` — en el
    compose, ``./evidence`` del repo montado read-only en ``/evidence``). La UI
    web la presenta como selector; el operador elige el fichero explícitamente
    (RULE 2: nunca se registra "el único" ni "el más reciente"). Sin la
    variable definida → 503 accionable."""
    try:
        return {"sources": list_source_files()}
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get(
    "/api/cases/{case_id}/evidence/{evidence_id}/metadata",
    dependencies=[Depends(require_token)],
)
def evidence_metadata(case_id: str, evidence_id: str) -> dict[str, Any]:
    """Metadata de custodia de una evidencia: sha256 baseline, tamaño (bytes +
    legible), fecha de registro, nivel de solo-lectura con etiqueta HONESTA
    (``fs`` hoy — bloqueo a nivel de bloque es Fase 2, RULE 2), huella de triage
    y última verificación si existe. Caso/evidencia inexistente → 404; id
    malformado → 422 (nunca una respuesta vacía adivinada, RULE 2)."""
    try:
        return evidence_manager.metadata(case_id, evidence_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/api/cases/{case_id}/evidence/{evidence_id}/custody-act",
    dependencies=[Depends(require_token)],
)
def custody_act(case_id: str, evidence_id: str) -> dict[str, Any]:
    """Acta de adquisición estructurada (``forensia.custody.build_custody_act``):
    caso + examinador, evidencia (origen, sha256, tamaño, timestamps), cadena de
    custodia (``entry_hash`` del evento de registro en el log hash-encadenado +
    si la cadena verifica), nivel de solo-lectura y herramienta/versión. Caso o
    evidencia inexistente (o sin evento de registro en el audit) → 404; id
    malformado → 422."""
    try:
        return build_custody_act(case_id, evidence_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
