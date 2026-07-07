"""Chat / agent-query HTTP surface.

Thin adapter (CLAUDE.md RULE 3): validates the operator's selections and hands
off to ``ForensicAgent.run`` through the executor the operator chose for the
request. RULE 2 — nothing is inferred:

- no ``case_id`` / ``evidence_id``  → 422 with the missing selection named,
- no ``executor`` in the request and no ``DEFAULT_EXECUTOR`` explicitly set by
  the user in Settings → 422 listing the valid executors,
- executor selected but unusable (binary missing, no session, Ollama
  unreachable) → 503 with the actionable reason — never a substitute,
- cloud-backed executor selected without recorded consent for this case →
  403 (SECURITY INVARIANT 7 / RGPD): the UI warns and records consent, and this
  gate makes an API client unable to bypass that warning.

The old keyword demo loop and the listing-skeleton fallback are gone: both were
silent degradations that RULE 2 forbids.
"""

from __future__ import annotations

import asyncio
import json
import threading
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from forensia.agent.agent import ForensicAgent
from forensia.agent.history import build_replay_messages
from forensia.agent.registry import agent_registry
from forensia.audit.log import AuditLog
from forensia.cases.manager import (
    OsProfileUnresolved,
    case_manager,
    resolve_os_profile,
)
from forensia.config import config
from forensia.consent import get_cloud_consent, record_cloud_consent
from forensia.evidence import evidence_manager
from forensia.executors import EXECUTOR_IDS, get_executor
from forensia.models.base import ExecutorBackend
from forensia.security import require_token

router = APIRouter()


class QueryRequest(BaseModel):
    # NOTE: there is NO ``os_profile`` here on purpose. The OS is DERIVED from
    # the evidence content by triage and resolved from the case in the backend
    # (``resolve_os_profile``) — the client never chooses or sends it (RULE 2:
    # no silent default, no host/context guess). A client that still sends the
    # key is simply ignored (Pydantic drops unknown fields).
    evidence_id: str | None = None
    case_id: str | None = None
    prompt: str
    # Executor selected by the OPERATOR for this request:
    # "claude-code" | "codex" | "gemini" | "ollama". When absent, the only
    # accepted source is DEFAULT_EXECUTOR — set EXPLICITLY by the user in
    # Settings (that is operator agency, not a code-invented default).
    executor: str | None = None
    # Chat session within the case. The backend reads ``ChatStore`` (case_dir
    # /chats/<session_id>.jsonl) to splice prior user/assistant turns + a
    # tool-runs ledger + a findings ledger into the agent's messages BEFORE
    # the in-flight user prompt. Without this, every turn is a fresh agent
    # with no memory — leading to repeated tool runs and lost intent.
    # Default "main" matches the frontend's CHAT_SESSION_ID.
    session_id: str = "main"


def _prepare_run(req: QueryRequest) -> tuple[ForensicAgent, str, list, str | None, dict]:
    """Validate the request and build the agent (shared by /query and /query/stream).

    Returns ``(agent, prompt, prior_messages, consent_ref, meta)``; raises
    ``HTTPException`` with the actionable reason on any RULE-2 / consent /
    availability failure — identical checks for both surfaces so the streaming
    path can't bypass them (SECURITY INVARIANT 7). ``consent_ref`` is the
    ``entry_hash`` of the recorded consent for a cloud executor (``None`` for a
    local one): ``ForensicAgent.run`` refuses a cloud run without it, so the
    ref MUST reach the ``agent.run`` call."""
    prompt = (req.prompt or "").strip()
    if not prompt:
        raise HTTPException(status_code=422, detail="prompt is empty")

    if not req.case_id:
        raise HTTPException(
            status_code=422,
            detail="case_id is required: selecciona un caso antes de consultar al "
                   "agente (FORENSIA no asume 'el único caso' — RULE 2).",
        )
    if not req.evidence_id:
        raise HTTPException(
            status_code=422,
            detail="evidence_id is required: selecciona una evidencia registrada en "
                   "el caso (FORENSIA no asume 'la última registrada' — RULE 2).",
        )

    executor_id = req.executor or config.get("DEFAULT_EXECUTOR")
    if not executor_id:
        raise HTTPException(
            status_code=422,
            detail="executor is required: selecciona un ejecutor "
                   f"({' | '.join(EXECUTOR_IDS)}) en la petición, o fija "
                   "DEFAULT_EXECUTOR explícitamente en Settings. FORENSIA no "
                   "elige uno por ti (RULE 2).",
        )
    try:
        executor = get_executor(str(executor_id))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    availability = executor.is_available()
    if not availability.available:
        raise HTTPException(status_code=503, detail=availability.reason)

    # Resolve the os_profile from the CASE (derived from evidence content by
    # triage, or operator-anchored) — never from the request, never a default
    # (RULE 2 enmendada). Ambiguity (unknown / low confidence / conflict / no
    # routable evidence) is a 409 the operator must resolve by anchoring.
    try:
        case = case_manager.load(req.case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    try:
        os_profile = resolve_os_profile(case)
    except OsProfileUnresolved as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    try:
        pkg = agent_registry.get_for_profile(os_profile)
    except KeyError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    try:
        audit = AuditLog(case_manager.case_dir(req.case_id) / "audit.jsonl")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    consent_ref: str | None = None
    if not executor.is_local:
        consent = get_cloud_consent(audit, req.case_id, executor.id)
        if consent is None:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"El ejecutor '{executor.id}' está respaldado por cloud: enviará "
                    "contenido derivado del caso (posibles datos personales) a su "
                    "proveedor bajo tu cuenta. Falta el consentimiento registrado para "
                    "este caso. Regístralo con POST /api/agent/cloud-consent "
                    f'{{"case_id": "{req.case_id}", "executor": "{executor.id}"}} '
                    "(la UI lo hace al confirmar el aviso de privacidad) antes de "
                    "consultar — SECURITY INVARIANT 7."
                ),
            )
        # The entry_hash anchors the run to the exact audit line that recorded
        # the consent; ForensicAgent.run refuses a cloud run without it.
        consent_ref = consent.get("entry_hash")

    run_context: dict = {
        "audit": audit,
        "case_id": req.case_id,
        "temperature": float(pkg.model.temperature),
    }
    if executor.id == "ollama":
        run_context["model"] = config.get("OLLAMA_MODEL") or pkg.model.name

    model = ExecutorBackend(executor, run_context=run_context)
    agent = ForensicAgent(package=pkg, model=model, evidence=evidence_manager, audit=audit)
    prior_messages = build_replay_messages(req.case_id, req.session_id)
    meta = {
        "evidence_id": req.evidence_id,
        "case_id": req.case_id,
        "os_profile": os_profile,
        "executor": {"id": executor.id, "name": executor.name, "local": executor.is_local},
        "agent": pkg.summary(),
    }
    return agent, prompt, prior_messages, consent_ref, meta


@router.post("/api/agent/query", dependencies=[Depends(require_token)])
def query(req: QueryRequest) -> dict:
    agent, prompt, prior_messages, consent_ref, meta = _prepare_run(req)
    try:
        result = agent.run(
            prompt=prompt,
            case_id=req.case_id,
            evidence_id=req.evidence_id,
            consent_ref=consent_ref,
            prior_messages=prior_messages,
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return {
        "status": "llm-loop",
        "reply": result.get("reply", ""),
        "iterations": result.get("iterations"),
        "tool_calls": result.get("tool_calls", []),
        **meta,
    }


@router.post("/api/agent/query/stream", dependencies=[Depends(require_token)])
async def query_stream(req: QueryRequest) -> StreamingResponse:
    """Same as /api/agent/query but streams the agent's progress as NDJSON: one JSON
    object per line for each reasoning step / tool_call / tool_result / finding, then a
    terminal ``{"type":"done", ...}`` carrying the final reply + metadata (so the UI can
    persist the turn exactly like the blocking endpoint). The agent runs in a worker
    thread; events cross to the event loop through a thread-safe queue."""
    agent, prompt, prior_messages, consent_ref, meta = _prepare_run(req)

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()
    _DONE = object()

    def push(event: dict[str, Any]) -> None:
        loop.call_soon_threadsafe(queue.put_nowait, event)

    def worker() -> None:
        try:
            result = agent.run(
                prompt=prompt,
                case_id=req.case_id,
                evidence_id=req.evidence_id,
                consent_ref=consent_ref,
                prior_messages=prior_messages,
                on_event=push,
            )
            push({
                "type": "done",
                "reply": result.get("reply", ""),
                "iterations": result.get("iterations"),
                "tool_calls": result.get("tool_calls", []),
                **meta,
            })
        except (KeyError, ValueError) as exc:
            push({"type": "error", "detail": str(exc)})
        except Exception as exc:  # noqa: BLE001 — surface, never hang the stream
            push({"type": "error", "detail": f"{type(exc).__name__}: {exc}"})
        finally:
            loop.call_soon_threadsafe(queue.put_nowait, _DONE)

    async def ndjson():
        threading.Thread(target=worker, name="agent-stream", daemon=True).start()
        while True:
            item = await queue.get()
            if item is _DONE:
                break
            yield json.dumps(item, ensure_ascii=False) + "\n"

    return StreamingResponse(
        ndjson(),
        media_type="application/x-ndjson",
        # Defeat proxy/response buffering so events reach the browser as they happen.
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
    )


@router.get("/api/agents", dependencies=[Depends(require_token)])
def list_agents() -> dict:
    return {
        "root": str(agent_registry.root),
        "agents": [pkg.summary() for pkg in agent_registry.list()],
    }


class CloudConsentRequest(BaseModel):
    case_id: str
    executor: str


@router.post("/api/agent/cloud-consent", dependencies=[Depends(require_token)])
def cloud_consent(req: CloudConsentRequest) -> dict:
    """Registra en el audit del caso que el operador aceptó que contenido
    derivado del caso salga al proveedor del ejecutor cloud elegido (SECURITY
    INVARIANT 7: la UI avisa, el audit lo registra — la evidencia puede
    contener datos personales reales → RGPD). La UI llama aquí cuando el
    operador confirma el aviso, ANTES del primer query con ese ejecutor."""
    if not req.case_id:
        raise HTTPException(status_code=422, detail="case_id is required")
    try:
        executor = get_executor(req.executor)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if executor.is_local:
        raise HTTPException(
            status_code=422,
            detail=f"{executor.id} es 100 % local: el contenido del caso no sale "
                   "de la máquina y no hay consentimiento que registrar.",
        )
    try:
        audit = AuditLog(case_manager.case_dir(req.case_id) / "audit.jsonl")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    entry = record_cloud_consent(audit, req.case_id, executor.id, executor.name)
    return {
        "recorded": True,
        "case_id": req.case_id,
        "executor": executor.id,
        "ts_utc": entry["ts_utc"],
    }
