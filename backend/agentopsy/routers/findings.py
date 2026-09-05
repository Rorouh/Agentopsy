"""Per-case findings HTTP surface. Thin adapter over agentopsy.findings.store."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from agentopsy.i18n import traducir_excepcion
from agentopsy.findings.store import finding_store
from agentopsy.security import require_token
from agentopsy.toolkit.usage import tool_usage

router = APIRouter()


class AppendFindingRequest(BaseModel):
    title: str
    summary: str
    severity: str
    evidence_id: str | None = None
    tool_id: str | None = None
    run_id: str | None = None
    #: Técnicas ATT&CK que sostiene el hallazgo. Enum cerrada validada contra la
    #: semilla en agentopsy.findings.store — la ruta HTTP y la del agente comparten
    #: el mismo contrato, no pueden divergir.
    mitre_hints: list[str] = []


@router.get(
    "/api/cases/{case_id}/findings",
    dependencies=[Depends(require_token)],
)
def list_findings(case_id: str) -> list[dict[str, Any]]:
    try:
        return [asdict(f) for f in finding_store.list(case_id)]
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=traducir_excepcion(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc


@router.get(
    "/api/cases/{case_id}/tool-usage",
    dependencies=[Depends(require_token)],
)
def list_tool_usage(case_id: str) -> list[dict[str, Any]]:
    """Per-tool run counts for the case (Tools panel). Aggregated from audit.jsonl."""
    try:
        return tool_usage(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=traducir_excepcion(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc


@router.post(
    "/api/cases/{case_id}/findings",
    dependencies=[Depends(require_token)],
)
def append_finding(case_id: str, req: AppendFindingRequest) -> dict[str, Any]:
    try:
        finding = finding_store.append(case_id, req.model_dump())
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=traducir_excepcion(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc
    return asdict(finding)
