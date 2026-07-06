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

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from forensia.agent.agent import ForensicAgent
from forensia.agent.history import build_replay_messages
from forensia.agent.registry import agent_registry
from forensia.audit.log import AuditLog
from forensia.cases.manager import case_manager
from forensia.config import config
from forensia.consent import has_cloud_consent, record_cloud_consent
from forensia.evidence import evidence_manager
from forensia.executors import EXECUTOR_IDS, get_executor
from forensia.models.base import ExecutorBackend
from forensia.security import require_token

router = APIRouter()

_VALID_OS_PROFILES = frozenset({"unix", "windows"})


class QueryRequest(BaseModel):
    os_profile: str = "unix"
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


@router.post("/api/agent/query", dependencies=[Depends(require_token)])
def query(req: QueryRequest) -> dict:
    prompt = (req.prompt or "").strip()
    if not prompt:
        raise HTTPException(status_code=422, detail="prompt is empty")

    if req.os_profile not in _VALID_OS_PROFILES:
        raise HTTPException(
            status_code=422,
            detail=f"os_profile must be one of {sorted(_VALID_OS_PROFILES)}, "
                   f"got {req.os_profile!r}",
        )

    # RULE 2: the operator anchors the query — FORENSIA never picks "the only
    # case" or "the most recent evidence".
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

    try:
        pkg = agent_registry.get_for_profile(req.os_profile)
    except KeyError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    try:
        audit = AuditLog(case_manager.case_dir(req.case_id) / "audit.jsonl")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        # case_id malformado (no UUID4) — petición inválida, no "caso no encontrado".
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    # SECURITY INVARIANT 7 / RGPD: a cloud-backed executor sends case-derived
    # content to its vendor under the operator's account. The UI warns and the
    # operator confirms (recorded via /api/agent/cloud-consent); enforce that
    # here so an API client cannot bypass the UI-only warning. Ollama is local
    # and never requires consent.
    if not executor.is_local and not has_cloud_consent(audit, req.case_id, executor.id):
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

    # Every executor run is audited with the literal argv / HTTP request; this
    # also records the operator's (possibly cloud-backed) choice per SECURITY
    # INVARIANT 7 — the UI shows the cloud warning based on `local` below.
    run_context: dict = {
        "audit": audit,
        "case_id": req.case_id,
        "temperature": float(pkg.model.temperature),
    }
    if executor.id == "ollama":
        # Resolution order (both operator-explicit, RULE 2-safe): OLLAMA_MODEL
        # from Settings wins; else the model the package recommends.
        run_context["model"] = config.get("OLLAMA_MODEL") or pkg.model.name

    model = ExecutorBackend(executor, run_context=run_context)
    agent = ForensicAgent(package=pkg, model=model, evidence=evidence_manager, audit=audit)

    # Replay prior chat history (tool ledger + findings + user/assistant text)
    # so the agent doesn't restart from scratch every turn.
    prior_messages = build_replay_messages(req.case_id, req.session_id)
    try:
        result = agent.run(
            prompt=prompt,
            case_id=req.case_id,
            evidence_id=req.evidence_id,
            prior_messages=prior_messages,
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return {
        "status": "llm-loop",
        "reply": result.get("reply", ""),
        "iterations": result.get("iterations"),
        "tool_calls": result.get("tool_calls", []),
        "evidence_id": req.evidence_id,
        "case_id": req.case_id,
        "os_profile": req.os_profile,
        "executor": {"id": executor.id, "name": executor.name, "local": executor.is_local},
        "agent": pkg.summary(),
    }


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
