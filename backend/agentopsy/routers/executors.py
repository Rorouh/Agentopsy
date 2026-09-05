"""Web-driven CLI login surface for the cloud executors (2026-07-15).

Thin adapter over ``agentopsy.executors.login`` (CLAUDE.md RULE 3). Every
side-effecting route is POST and token-gated (SECURITY INVARIANT 3 — the
app-wide CORS allowlist + Host-header middleware cover the anti-rebinding /
cross-origin part, exactly as the case routes rely on). The executor id
is confined to the closed cloud enum by ``agentopsy.executors.login`` (RULE 2):
an unknown / non-cloud id is a 422, never a silent default.

The one-time code and any token are never echoed to a log here (RULE 3 — the
logic module holds the same discipline); ``detail`` messages are the CLI's own
actionable text, with the code redacted upstream.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from agentopsy.i18n import traducir_excepcion
from agentopsy.executors.login import (
    LoginError,
    LoginRelayUnsupported,
    cancel_login,
    login_capabilities,
    login_status,
    start_login,
    submit_code,
)
from agentopsy.security import require_token

router = APIRouter()


class SubmitCodeRequest(BaseModel):
    code: str


@router.get("/api/executors/login-capabilities", dependencies=[Depends(require_token)])
def login_caps() -> dict[str, Any]:
    """Relay capability of every cloud executor, so the UI chooses UP FRONT
    between the "Conectar" flow and the manual-command degrade (Gemini)."""
    return {"executors": login_capabilities()}


@router.post("/api/executors/{executor_id}/login", dependencies=[Depends(require_token)])
def start(executor_id: str, force: bool = False) -> dict[str, Any]:
    # `force`: renovar una sesión que el sondeo da por buena. Lo pide el operador
    # explícitamente desde «Renovar sesión» porque el sondeo puede mentir (el CLI
    # de Claude reporta `loggedIn: true` con el token caducado). Ver `start_login`.
    try:
        return start_login(executor_id, force=force)
    except LoginRelayUnsupported as exc:
        raise HTTPException(
            status_code=409,
            detail=traducir_excepcion(exc),
            headers={"X-Agentopsy-Manual-Command": exc.manual_command},
        ) from exc
    except ValueError as exc:  # unknown / non-cloud id
        raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc
    except LoginError as exc:  # already logged in / unparseable output / launch failure
        raise HTTPException(status_code=409, detail=traducir_excepcion(exc)) from exc


@router.get("/api/executors/{executor_id}/login/status", dependencies=[Depends(require_token)])
def status(executor_id: str) -> dict[str, Any]:
    try:
        return login_status(executor_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc


@router.post("/api/executors/{executor_id}/login/code", dependencies=[Depends(require_token)])
def code(executor_id: str, req: SubmitCodeRequest) -> dict[str, Any]:
    try:
        return submit_code(executor_id, req.code)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc
    except LoginError as exc:
        raise HTTPException(status_code=409, detail=traducir_excepcion(exc)) from exc


@router.post("/api/executors/{executor_id}/login/cancel", dependencies=[Depends(require_token)])
def cancel(executor_id: str) -> dict[str, Any]:
    try:
        return cancel_login(executor_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc
