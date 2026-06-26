"""Artifact-run HTTP surface.

Thin adapter over ``forensia.artifacts.store.artifact_store`` (CLAUDE.md RULE 3).
Read-only — runs are produced by the dispatcher, never by the HTTP layer. All routes
are token-gated.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from forensia.artifacts.store import artifact_store
from forensia.security import require_token

router = APIRouter()


def _run_dict(run: Any) -> dict[str, Any]:
    return asdict(run)


@router.get("/api/cases/{case_id}/artifacts", dependencies=[Depends(require_token)])
def list_artifacts(case_id: str) -> list[dict[str, Any]]:
    try:
        runs = artifact_store.list_runs(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return [_run_dict(r) for r in runs]


@router.get(
    "/api/cases/{case_id}/artifacts/{run_id}",
    dependencies=[Depends(require_token)],
)
def get_artifact(case_id: str, run_id: str) -> dict[str, Any]:
    try:
        run = artifact_store.get_run(case_id, run_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _run_dict(run)
