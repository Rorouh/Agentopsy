"""Chat-session HTTP surface.

Thin adapter over ``agentopsy.chats.store.chat_store`` (CLAUDE.md RULE 3). The timestamp
on appended messages is filled in here (UTC, ISO-8601 with ``Z`` suffix) so the renderer
never has to trust client clocks. All routes are token-gated.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from agentopsy.i18n import traducir_excepcion
from agentopsy.chats.store import ChatMessage, chat_store
from agentopsy.security import require_token

router = APIRouter()


class AppendMessageRequest(BaseModel):
    role: str
    content: str
    tool_calls: list[dict] | None = None
    activity: list[dict] | None = None  # traza de actividad para re-pintar al recargar


def _msg_dict(msg: Any) -> dict[str, Any]:
    return asdict(msg)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@router.get("/api/cases/{case_id}/chats", dependencies=[Depends(require_token)])
def list_chat_sessions(case_id: str) -> list[str]:
    try:
        return chat_store.list_sessions(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=traducir_excepcion(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc


@router.get(
    "/api/cases/{case_id}/chats/{session_id}",
    dependencies=[Depends(require_token)],
)
def read_chat_session(case_id: str, session_id: str) -> list[dict[str, Any]]:
    try:
        messages = chat_store.read(case_id, session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=traducir_excepcion(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc
    return [_msg_dict(m) for m in messages]


@router.post(
    "/api/cases/{case_id}/chats/{session_id}/messages",
    dependencies=[Depends(require_token)],
)
def append_chat_message(
    case_id: str, session_id: str, req: AppendMessageRequest
) -> dict[str, Any]:
    message = ChatMessage(
        role=req.role,
        content=req.content,
        ts=_utc_now_iso(),
        tool_calls=req.tool_calls,
        activity=req.activity,
    )
    try:
        chat_store.append(case_id, session_id, message)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=traducir_excepcion(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc
    return _msg_dict(message)
