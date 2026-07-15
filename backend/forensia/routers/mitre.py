"""Superficie HTTP de MITRE ATT&CK. Adaptador fino sobre forensia.mitre (RULE 3)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from forensia.mitre import catalog
from forensia.mitre.coverage import coverage_store
from forensia.security import require_token

router = APIRouter()


class AdjudicateRequest(BaseModel):
    technique_id: str
    status: str  # "confirmada" | "sospechosa" | "descartada" | "none"
    rationale: str = ""
    related_finding_ids: list[str] = []


@router.get("/api/mitre/catalog", dependencies=[Depends(require_token)])
def get_catalog() -> dict[str, Any]:
    """El catálogo ATT&CK. Derivado de la semilla del orquestador — la enum cerrada.

    Si la semilla no está montada, devuelve `available: false` con un motivo
    accionable en vez de una lista por defecto (RULE 2).
    """
    return catalog.as_dict()


@router.get("/api/cases/{case_id}/mitre", dependencies=[Depends(require_token)])
def get_coverage(case_id: str) -> list[dict[str, Any]]:
    """Cobertura del caso: propuestas del agente + dictámenes del operador."""
    try:
        return coverage_store.coverage(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/api/cases/{case_id}/mitre", dependencies=[Depends(require_token)])
def adjudicate(case_id: str, req: AdjudicateRequest) -> dict[str, Any]:
    """Dictamen del perito sobre una técnica. Entra en el log hash-encadenado."""
    try:
        coverage_store.adjudicate(
            case_id,
            req.technique_id,
            req.status,
            req.rationale,
            req.related_finding_ids,
        )
        return {"coverage": coverage_store.coverage(case_id)}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
