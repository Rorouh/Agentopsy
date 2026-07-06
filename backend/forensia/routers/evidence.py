"""Evidence inbox listing. Registration is per-case (``/api/cases/{case_id}/evidence``
in ``routers/cases.py``) — an evidence file cannot exist outside a case, so this
module only exposes the *inbox* the web UI presents instead of a native file
dialog. The old case-less ``/api/evidence/register`` predated cases: it no longer
matched ``EvidenceManager.register(case_id, source_path)`` and nothing consumed
it, so it is gone.
"""

from fastapi import APIRouter, Depends, HTTPException

from forensia.evidence import list_source_files
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
