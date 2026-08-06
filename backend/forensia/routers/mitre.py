"""Superficie HTTP de MITRE ATT&CK. Adaptador fino sobre forensia.mitre (RULE 3)."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

from forensia.cases.manager import case_manager
from forensia.export_csv import export_basename
from forensia.mitre import catalog
from forensia.mitre.coverage import coverage_store
from forensia.mitre.export import coverage_to_csv, coverage_to_navigator_layer
from forensia.security import require_token

router = APIRouter()


class AdjudicateRequest(BaseModel):
    technique_id: str
    status: str  # "confirmada" | "sospechosa" | "descartada" | "none"
    rationale: str = ""
    related_finding_ids: list[str] = []


@router.get("/api/mitre/catalog", dependencies=[Depends(require_token)])
def get_catalog() -> dict[str, Any]:
    """El catálogo ATT&CK Enterprise COMPLETO — lo que pinta la matriz y contra lo
    que dictamina el perito. La enum del agente (semilla curada) es un eje aparte:
    valida los `mitre_hints` que el agente propone, no lo que se muestra.

    Si el catálogo no está, devuelve `available: false` con un motivo accionable
    en vez de una lista por defecto (RULE 2).
    """
    return catalog.enterprise_as_dict()


@router.get("/api/cases/{case_id}/mitre", dependencies=[Depends(require_token)])
def get_coverage(case_id: str) -> list[dict[str, Any]]:
    """Cobertura del caso: propuestas del agente + dictámenes del operador."""
    try:
        return coverage_store.coverage(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/api/cases/{case_id}/mitre/export.csv",
    dependencies=[Depends(require_token)],
)
def export_coverage_csv(case_id: str) -> Response:
    """Hoja de cálculo de la cobertura ATT&CK del caso (una fila por técnica
    evaluada, con su bloque de procedencia). Un caso sin propuestas ni dictámenes
    devuelve la procedencia y la cabecera sin filas (0 filas, honesto)."""
    try:
        entries = coverage_store.coverage(case_id)
        case = case_manager.load(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    body = coverage_to_csv(entries, case_id=case_id, case_name=case.name)
    filename = f"{export_basename(case.name, 'mitre-attack')}.csv"
    return Response(
        content=body,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "/api/cases/{case_id}/mitre/navigator",
    dependencies=[Depends(require_token)],
)
def export_navigator_layer(case_id: str) -> Response:
    """Layer del MITRE ATT&CK Navigator (formato 4.5, dominio enterprise-attack) con
    las técnicas propuestas/adjudicadas coloreadas, para cargarlo en el Navigator
    oficial. Un caso sin técnicas evaluadas produce un layer válido sin celdas."""
    try:
        entries = coverage_store.coverage(case_id)
        case = case_manager.load(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    layer = coverage_to_navigator_layer(entries, case_id=case_id, case_name=case.name)
    filename = f"{export_basename(case.name, 'mitre-navigator')}.json"
    return Response(
        content=json.dumps(layer, ensure_ascii=False, indent=2),
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


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
