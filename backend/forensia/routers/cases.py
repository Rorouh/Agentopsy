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


class GrantConsentRequest(BaseModel):
    by: str


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


@router.post("/api/cases/{case_id}/consent", dependencies=[Depends(require_token)])
def grant_consent(case_id: str, req: GrantConsentRequest) -> dict[str, Any]:
    """Record per-case opt-in to cloud egress (F2 / THREAT_MODEL gate 9).

    Side-effecting + token-gated (the app-wide Host-header middleware covers the
    anti-rebinding check). Until this is called, ``/api/agent/query`` refuses the
    cloud path and no evidence-derived byte leaves the host.
    """
    try:
        case = case_manager.grant_cloud_consent(case_id, req.by)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _case_dict(case)


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
