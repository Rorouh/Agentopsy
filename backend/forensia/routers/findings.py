"""Per-case findings HTTP surface. Thin adapter over forensia.findings.store."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from forensia.findings.store import finding_store
from forensia.security import require_token

router = APIRouter()


class AppendFindingRequest(BaseModel):
    title: str
    summary: str
    severity: str
    evidence_id: str | None = None
    tool_id: str | None = None
    run_id: str | None = None


@router.get(
    "/api/cases/{case_id}/findings",
    dependencies=[Depends(require_token)],
)
def list_findings(case_id: str) -> list[dict[str, Any]]:
    try:
        return [asdict(f) for f in finding_store.list(case_id)]
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post(
    "/api/cases/{case_id}/findings",
    dependencies=[Depends(require_token)],
)
def append_finding(case_id: str, req: AppendFindingRequest) -> dict[str, Any]:
    try:
        finding = finding_store.append(case_id, req.model_dump())
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return asdict(finding)
