"""Case + evidence HTTP surface.

Thin adapter over ``forensia.cases.manager.case_manager`` and
``forensia.evidence.evidence_manager`` (CLAUDE.md RULE 3). All routes are token-gated
and dataclass results are converted to JSON-friendly dicts here (Pydantic does not
serialize ``pathlib.Path`` natively).
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from forensia.cases.manager import case_manager
from forensia.evidence import evidence_manager
from forensia.evidence_jobs import register_job_registry
from forensia.security import require_token

router = APIRouter()


class CreateCaseRequest(BaseModel):
    name: str
    examiner: str
    # OPTIONAL manual anchor. Normally omitted: the OS is derived from the
    # evidence content by triage (auto-detección de SO). When present it is an
    # operator override for the ambiguous case (RULE 2 — never a silent default).
    os_profile: str | None = None
    notes: str = ""


class RegisterEvidenceRequest(BaseModel):
    source_path: str


class AnchorOsProfileRequest(BaseModel):
    os_profile: str


class DeleteCaseRequest(BaseModel):
    # El nombre del caso, tecleado por el operador para confirmar el borrado.
    # RULE 2: obligatorio y comparado EXACTO en el manager — sin él no se borra
    # nada, y no hay "borrar el caso activo" implícito.
    confirm_name: str


class UpdateCaseRequest(BaseModel):
    # All optional — the operator sends only the fields they're changing.
    # RULE 2: sending none is a caller bug, not a silent no-op; the manager
    # raises ValueError for that (→ 422 below).
    name: str | None = None
    examiner: str | None = None
    notes: str | None = None


def _case_dict(case: Any) -> dict[str, Any]:
    return asdict(case)


def _evidence_dict(handle: Any) -> dict[str, Any]:
    data = asdict(handle)
    # EvidenceHandle.original_path is a pathlib.Path — JSON cannot serialize it.
    if "original_path" in data and data["original_path"] is not None:
        data["original_path"] = str(data["original_path"])
    return data


# ---- cases ---------------------------------------------------------------


@router.post("/api/cases", dependencies=[Depends(require_token)])
def create_case(req: CreateCaseRequest) -> dict[str, Any]:
    try:
        case = case_manager.create(
            name=req.name,
            examiner=req.examiner,
            os_profile=req.os_profile,
            notes=req.notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _case_dict(case)


@router.get("/api/cases", dependencies=[Depends(require_token)])
def list_cases() -> list[dict[str, Any]]:
    return [_case_dict(c) for c in case_manager.list()]


@router.get("/api/cases/{case_id}", dependencies=[Depends(require_token)])
def get_case(case_id: str) -> dict[str, Any]:
    try:
        case = case_manager.load(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _case_dict(case)


@router.post("/api/cases/{case_id}/os-profile", dependencies=[Depends(require_token)])
def anchor_os_profile(case_id: str, req: AnchorOsProfileRequest) -> dict[str, Any]:
    """Operator's manual anchor of the case os_profile — the only time the
    operator sets it, used when triage is ambiguous or conflicting (the case
    routing returned 409). RULE 2 enmendada: on ambiguity the operator anchors,
    never a silent pick. The anchor is final and recorded in the audit log."""
    try:
        case = case_manager.anchor_os_profile(case_id, req.os_profile)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _case_dict(case)


@router.post("/api/cases/{case_id}/close", dependencies=[Depends(require_token)])
def close_case(case_id: str) -> dict[str, Any]:
    try:
        case = case_manager.close(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _case_dict(case)


@router.post("/api/cases/{case_id}/reopen", dependencies=[Depends(require_token)])
def reopen_case(case_id: str) -> dict[str, Any]:
    """Flip a closed case back to ``active`` — the only way to register more
    evidence or query the agent on it again. Symmetric to ``/close``."""
    try:
        case = case_manager.reopen(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _case_dict(case)


@router.post("/api/cases/{case_id}/update", dependencies=[Depends(require_token)])
def update_case(case_id: str, req: UpdateCaseRequest) -> dict[str, Any]:
    """Edit case metadata (name/examiner/notes). Every applied change is
    recorded in the case's audit log (FORENSIC INVARIANT 4)."""
    try:
        case = case_manager.update(
            case_id, name=req.name, examiner=req.examiner, notes=req.notes
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _case_dict(case)


@router.post("/api/cases/{case_id}/delete", dependencies=[Depends(require_token)])
def delete_case(case_id: str, req: DeleteCaseRequest) -> dict[str, Any]:
    """Borra el caso y TODO su directorio (evidencia, audit hash-encadenado,
    hallazgos, artefactos, chats, informes). Irreversible: el operador debe
    repetir el nombre del caso en ``confirm_name`` (RULE 2 — jamás se borra por
    id "a secas"). Caso inexistente → 404; confirmación que no cuadra (o id
    malformado, o directorio fuera de la raíz de casos) → 409 sin borrar nada."""
    try:
        case_manager.delete_case(case_id, req.confirm_name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"deleted": True, "case_id": case_id}


# ---- evidence ------------------------------------------------------------


@router.post("/api/cases/{case_id}/evidence", dependencies=[Depends(require_token)])
def register_evidence(case_id: str, req: RegisterEvidenceRequest) -> dict[str, Any]:
    try:
        handle = evidence_manager.register(case_id, req.source_path)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _evidence_dict(handle)


@router.post("/api/cases/{case_id}/evidence/async", dependencies=[Depends(require_token)])
def register_evidence_async(case_id: str, req: RegisterEvidenceRequest) -> dict[str, Any]:
    """Arranca el registro en SEGUNDO PLANO y devuelve el ``job_id`` al instante.

    Registrar una imagen grande recorre todos sus bytes tres veces (hash del
    origen → copia → re-hash): minutos. Hacerlo dentro de la petición HTTP la
    mata en el proxy (504) y corta la copia a mitad. Aquí el hash-gate corre
    desacoplado (``forensia.evidence_jobs``) y se sondea con
    ``GET …/evidence/jobs/{job_id}``; el registro síncrono sigue existiendo.

    Sólo se valida aquí lo que permite fallar rápido con el código HTTP correcto
    (caso inexistente → 404, ``source_path`` vacío → 422). El resto de guardas
    (caso cerrado, ruta fuera de la bandeja, symlink, set EWF incompleto) las
    aplica ``EvidenceManager.register`` y llegan como ``error`` accionable del
    job — nunca como un registro a medias (RULE 2)."""
    if not req.source_path or not req.source_path.strip():
        raise HTTPException(
            status_code=422,
            detail="source_path is required: elige la evidencia de la bandeja "
                   "(FORENSIA no asume 'la única' ni 'la más reciente' — RULE 2).",
        )
    try:
        case_manager.load(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    job = register_job_registry.submit(case_id, req.source_path, manager=evidence_manager)
    return job.public()


@router.get("/api/cases/{case_id}/evidence/jobs", dependencies=[Depends(require_token)])
def list_evidence_jobs(case_id: str) -> list[dict[str, Any]]:
    """Jobs de registro de este caso, más recientes primero. La web lo consulta al
    montar para RE-ENGANCHAR el sondeo de un registro que sigue vivo (cerrar la
    pestaña no lo aborta). El registro vive en memoria del api: un reinicio lo
    vacía (la evidencia ya registrada está en disco)."""
    return register_job_registry.list_for_case(case_id)


@router.get(
    "/api/cases/{case_id}/evidence/jobs/{job_id}",
    dependencies=[Depends(require_token)],
)
def get_evidence_job(case_id: str, job_id: str) -> dict[str, Any]:
    """Estado del job: pending / running (fase + bytes) / done (``evidence_id``) /
    error (mensaje accionable). Job inexistente — o de otro caso — → 404."""
    snap = register_job_registry.snapshot(job_id)
    if snap is None:
        raise HTTPException(status_code=404, detail=f"job {job_id} not found")
    if snap.get("case_id") != case_id:
        raise HTTPException(
            status_code=404,
            detail=f"job {job_id} does not belong to case {case_id}",
        )
    return snap


@router.get("/api/cases/{case_id}/evidence", dependencies=[Depends(require_token)])
def list_evidence(case_id: str) -> list[dict[str, Any]]:
    try:
        handles = evidence_manager.list(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return [_evidence_dict(h) for h in handles]


@router.post(
    "/api/cases/{case_id}/evidence/{evidence_id}/verify",
    dependencies=[Depends(require_token)],
)
def verify_evidence(case_id: str, evidence_id: str) -> dict[str, Any]:
    try:
        verified = evidence_manager.verify(case_id, evidence_id)
        # Re-read so the returned handle contains the freshly persisted
        # ``last_verification`` block (verify() wrote verification.json).
        handle = evidence_manager.get(case_id, evidence_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    payload = _evidence_dict(handle)
    payload["verified"] = bool(verified)
    return payload
