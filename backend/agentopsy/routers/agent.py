"""Chat / agent-query HTTP surface.

Thin adapter (CLAUDE.md RULE 3): validates the operator's selections and hands
off to ``ForensicAgent.run`` through the executor the operator chose for the
request. RULE 2 — nothing is inferred:

- no ``case_id`` → 422 with the missing selection named; a case with no
  registered evidence → 422 (there is nothing to investigate),
- an ``evidence_id`` in the request → 422: the scope of an investigation is the
  WHOLE case (every registered evidence, none primary); focusing on one piece of
  evidence is something the examiner asks for in the prompt itself,
- no ``executor`` in the request and no ``DEFAULT_EXECUTOR`` explicitly set by
  the user in Settings → 422 listing the valid executors,
- executor selected but unusable (binary missing, no session, Ollama
  unreachable) → 503 with the actionable reason — never a substitute.

Selecting a cloud-backed executor sends case-derived content to that vendor under
the operator's own account (SECURITY INVARIANT 7 / RGPD); the UI warns about this
in the Guía page, but Agentopsy no longer requires or records a separate consent
step (removed 2026-07-16).

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

from agentopsy.i18n import t, traducir_excepcion
from agentopsy.agent.agent import ForensicAgent
from agentopsy.agent.history import build_replay_messages
from agentopsy.agent.jobs import job_registry
from agentopsy.agent.registry import agent_registry
from agentopsy.audit.log import AuditLog
from agentopsy.cases.manager import (
    OsProfileUnresolved,
    case_manager,
    resolve_os_profile,
)
from agentopsy.config import config
from agentopsy.evidence import evidence_manager
from agentopsy.executors import (
    EXECUTOR_IDS,
    MODEL_CONFIG_KEY,
    REASONING_CONFIG_KEY,
    get_executor,
)
from agentopsy.models.base import ExecutorBackend
from agentopsy.security import require_token

router = APIRouter()


class QueryRequest(BaseModel):
    # NOTE: there is NO ``os_profile`` here on purpose. The OS is DERIVED from
    # the evidence content by triage and resolved from the case in the backend
    # (``resolve_os_profile``) — the client never chooses or sends it (RULE 2:
    # no silent default, no host/context guess). A client that still sends the
    # key is simply ignored (Pydantic drops unknown fields).
    case_id: str | None = None
    # NOT a scope selector any more: the investigation covers EVERY evidence of the
    # case, with no primary one. The field survives only so that a client still
    # sending it (a stale SPA tab, a script) gets an actionable 422 instead of a run
    # whose scope silently differs from what it asked for (RULE 2).
    evidence_id: str | None = None
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
    ``HTTPException`` with the actionable reason on any RULE-2 / availability
    failure — identical checks for both surfaces so the streaming path can't
    bypass them. Cloud egress no longer requires a recorded consent (removed
    2026-07-16), so ``consent_ref`` is always ``None`` here; it stays in the
    tuple only as an optional audit label threaded into ``agent.run``."""
    prompt = (req.prompt or "").strip()
    if not prompt:
        raise HTTPException(status_code=422, detail=t("api.promptEmpty"))

    if not req.case_id:
        raise HTTPException(
            status_code=422,
            detail=t("api.caseRequired"),
        )
    if req.evidence_id is not None:
        raise HTTPException(
            status_code=422,
            detail=t("api.evidenceScopeIsCase"),
        )

    executor_id = req.executor or config.get("DEFAULT_EXECUTOR")
    if not executor_id:
        raise HTTPException(
            status_code=422,
            detail=t("api.executorRequired", ids=" | ".join(EXECUTOR_IDS)),
        )
    try:
        executor = get_executor(str(executor_id))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc

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
        raise HTTPException(status_code=404, detail=traducir_excepcion(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc
    # The scope is every registered evidence of the case. With none there is
    # nothing to investigate: say so before routing (a case without evidence has
    # no os_profile either, and "anchor the profile" would be the wrong advice).
    try:
        case_evidence = evidence_manager.list(req.case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=traducir_excepcion(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc
    if not case_evidence:
        raise HTTPException(status_code=422, detail=t("api.evidenceRequired"))
    try:
        os_profile = resolve_os_profile(case)
    except OsProfileUnresolved as exc:
        raise HTTPException(status_code=409, detail=traducir_excepcion(exc)) from exc

    try:
        pkg = agent_registry.get_for_profile(os_profile)
    except KeyError as exc:
        raise HTTPException(status_code=503, detail=traducir_excepcion(exc)) from exc

    try:
        audit = AuditLog(case_manager.case_dir(req.case_id) / "audit.jsonl")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=traducir_excepcion(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc

    # Cloud egress no longer requires a recorded consent (removed 2026-07-16):
    # a cloud executor proceeds without one. The executor stays explicitly
    # operator-selected (RULE 2) and the UI warns about egress in the Guía page.
    consent_ref: str | None = None

    run_context: dict = {
        "audit": audit,
        "case_id": req.case_id,
        "temperature": float(pkg.model.temperature),
    }
    # Operator-selected model, persisted per executor (RULE 2: never invented).
    configured_model = config.get(MODEL_CONFIG_KEY[executor.id])
    if executor.id == "ollama":
        # Ollama DEMANDS a model at call time; fall back to the package's declared
        # local model when the operator hasn't chosen one (still explicit — it is
        # the trained package's value, not a code guess).
        run_context["model"] = configured_model or pkg.model.name
    elif configured_model:
        # Cloud CLI: pass the chosen model as --model. Unset → the CLI's own
        # default (Agentopsy does not override it).
        run_context["model"] = configured_model
    # Nivel de razonamiento («potencia»), solo para los ejecutores que declaran
    # clave. Ausente → el que tenga configurado su CLI (RULE 2).
    reasoning_key = REASONING_CONFIG_KEY.get(executor.id)
    if reasoning_key:
        configured_effort = config.get(reasoning_key)
        if configured_effort:
            run_context["reasoning_effort"] = configured_effort

    model = ExecutorBackend(executor, run_context=run_context)
    agent = ForensicAgent(package=pkg, model=model, evidence=evidence_manager, audit=audit)
    prior_messages = build_replay_messages(req.case_id, req.session_id)
    meta = {
        "evidence_ids": [h.evidence_id for h in case_evidence],
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
            consent_ref=consent_ref,
            prior_messages=prior_messages,
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc

    return {
        "status": "llm-loop",
        "reply": result.get("reply", ""),
        "iterations": result.get("iterations"),
        "tool_calls": result.get("tool_calls", []),
        **meta,
    }


@router.post("/api/agent/analyze", dependencies=[Depends(require_token)])
def analyze(req: QueryRequest) -> dict:
    """Arranca el análisis del agente en SEGUNDO PLANO y devuelve un `job_id`.

    A diferencia de `/query` (síncrono) y `/query/stream` (atado a la conexión, se
    corta si el cliente se desconecta), aquí el análisis corre desacoplado de esta
    petición: el cliente puede cerrar la pestaña y volver luego a consultar el
    estado en `GET /api/agent/jobs/{job_id}`. Los hallazgos se persisten en
    caliente durante el run, así que el análisis termina y persiste aunque nadie
    consulte el job. La validación (ejecutor, evidencia, consentimiento, perfil)
    ocurre AQUÍ, síncrona, para fallar rápido antes de encolar."""
    agent, prompt, prior_messages, consent_ref, meta = _prepare_run(req)

    def _work(emit, should_cancel) -> dict:  # noqa: ANN001 — emit/should_cancel: Callables
        result = agent.run(
            prompt=prompt,
            case_id=req.case_id,
            consent_ref=consent_ref,
            prior_messages=prior_messages,
            on_event=emit,  # los eventos (tool_call/tool_result/finding) → al job
            should_cancel=should_cancel,  # botón «Parar»: corta entre iteraciones
        )
        return {
            "reply": result.get("reply", ""),
            "iterations": result.get("iterations"),
            "tool_calls": result.get("tool_calls", []),
        }

    job = job_registry.submit(
        req.case_id, "analyze", _work, prompt_chars=len(prompt), meta=meta
    )
    return job.public()


@router.get("/api/agent/jobs/{job_id}", dependencies=[Depends(require_token)])
def get_job(job_id: str, since: int = 0) -> dict:
    """Estado de un análisis en segundo plano: running / done (con result) / error.

    `since` devuelve sólo los eventos de progreso a partir de ese índice, para que
    el cliente sondee incrementalmente (el chat pinta el comando lanzado, el
    hallazgo registrado, etc. según van ocurriendo)."""
    snap = job_registry.snapshot(job_id, since=max(0, since))
    if snap is None:
        raise HTTPException(status_code=404, detail=t("api.jobNotFound", job_id=job_id))
    return snap


@router.post("/api/agent/jobs/{job_id}/cancel", dependencies=[Depends(require_token)])
def cancel_job(job_id: str) -> dict:
    """Pide PARAR un análisis en curso (botón «Parar»). Parada COOPERATIVA: el loop
    del agente la nota entre iteraciones y termina limpio, conservando lo persistido
    en caliente (findings, grafo, artefactos). Una herramienta ya en ejecución no se
    interrumpe a mitad, pero no se lanza la siguiente. Idempotente: si el job ya
    terminó, devuelve `cancelled=false` sin error."""
    signalled = job_registry.cancel(job_id)
    snap = job_registry.snapshot(job_id, since=0)
    if snap is None:
        raise HTTPException(status_code=404, detail=f"job {job_id} not found")
    return {"job_id": job_id, "cancel_requested": signalled, "status": snap["status"]}


@router.get("/api/cases/{case_id}/agent/jobs", dependencies=[Depends(require_token)])
def list_case_jobs(case_id: str) -> list[dict]:
    """Los análisis en segundo plano de un caso, más recientes primero."""
    return job_registry.list_for_case(case_id)


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
