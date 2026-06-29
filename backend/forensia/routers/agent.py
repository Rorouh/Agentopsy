"""Chat / agent-query HTTP surface.

Thin adapter (CLAUDE.md RULE 3) that picks the right execution path per request:

- If ``MODEL_BACKEND=cloud`` + a valid OpenAI key + ``MODEL_NAME`` are set, drives
  the real ``ForensicAgent.run`` loop (LLM-driven, with tool-calling over the
  package allowlist; see ``forensia.agent.agent``).
- Otherwise falls back to a deterministic keyword-matched demo loop so the
  dispatcher wiring still proves end-to-end against the registered evidence.
- If neither path can run (no case anchor, no keyword match, no model), returns
  the listing skeleton so the UI shows what WOULD be available.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from forensia.agent.agent import ForensicAgent
from forensia.agent.history import build_replay_messages
from forensia.agent.registry import agent_registry
from forensia.audit.log import AuditLog
from forensia.cases.manager import case_manager
from forensia.config import config
from forensia.evidence import evidence_manager
from forensia.models.base import get_backend
from forensia.security import require_token
from forensia.toolkit.dispatcher import ToolExecutionError, execute as dispatch_tool

router = APIRouter()

_VALID_OS_PROFILES = frozenset({"unix", "windows"})

_TOOLS_WITH_IMAGE_PATH = frozenset(
    {"tsk_mmls", "tsk_fls", "tsk_mactime", "ewf_info", "bulk_extractor"}
)
_TOOLS_WITH_DUMP_PATH = frozenset({"volatility3"})

_DEMO_ROUTES: tuple[tuple[tuple[str, ...], str, dict[str, Any]], ...] = (
    (("volcado", "memoria", "ram", "memory", "proceso", "pslist"),
     "volatility3", {"plugin": "linux.pslist.PsList"}),
    (("particion", "particiones", "tabla de particiones", "partitions", "mmls"),
     "tsk_mmls", {}),
    (("ficheros", "archivos", "lista", "fls"),
     "tsk_fls", {"recursive": False}),
    (("ewf", "metadatos", "info imagen", "case info"),
     "ewf_info", {}),
    (("carving", "bulk", "ioc", "iocs", "emails", "urls"),
     "bulk_extractor", {}),
)


class QueryRequest(BaseModel):
    os_profile: str = "unix"
    evidence_id: str | None = None
    case_id: str | None = None
    prompt: str
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

    try:
        pkg = agent_registry.get_for_profile(req.os_profile)
    except KeyError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    # Cloud LLM path — only when fully anchored (case + evidence) AND configured.
    if req.case_id and req.evidence_id and _cloud_ready():
        try:
            case = case_manager.load(req.case_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        # F2 / gate 9 — cloud egress needs recorded per-case consent. Without it we
        # return a structured `consent_required` (NOT a silent demo-loop fallback,
        # NOT any egress): zero evidence-derived bytes leave the host, and the
        # backend is never even constructed.
        consent = case.cloud_consent
        if consent is None or not consent.granted:
            return {
                "status": "consent_required",
                "reply": (
                    "Este caso usa un backend cloud, pero no tiene consentimiento de "
                    "egreso registrado. Los datos derivados de la evidencia saldrían a "
                    "un tercero (RGPD / cadena de custodia). Concede el consentimiento "
                    f"(POST /api/cases/{req.case_id}/consent) antes de consultar con cloud."
                ),
                "evidence_id": req.evidence_id,
                "case_id": req.case_id,
                "os_profile": req.os_profile,
                "agent": pkg.summary(),
            }

        audit = AuditLog(case_manager.case_dir(req.case_id) / "audit.jsonl")

        try:
            model = get_backend("cloud")
        except Exception as exc:  # noqa: BLE001 — surface config errors as 503
            raise HTTPException(status_code=503, detail=str(exc)) from exc

        agent = ForensicAgent(package=pkg, model=model, evidence=evidence_manager, audit=audit)
        # Replay prior chat history (tool ledger + findings + user/assistant
        # text) so the agent doesn't restart from scratch every turn.
        prior_messages = build_replay_messages(req.case_id, req.session_id)
        try:
            result = agent.run(
                prompt=prompt,
                case_id=req.case_id,
                evidence_id=req.evidence_id,
<<<<<<< HEAD
                consent_ref=consent.ref,
=======
                prior_messages=prior_messages,
>>>>>>> 17070672e0a907351fe0c9e82a2fe06c25b5d2d7
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
            "agent": pkg.summary(),
        }

    # Demo loop path — no cloud or no anchor.
    if req.case_id and req.evidence_id:
        choice = _choose_tool(prompt, req.os_profile)
        if choice is not None:
            tool_id, params = choice
            reply, status = _run_demo_tool(
                tool_id, params, req.case_id, req.evidence_id, pkg.name
            )
            return {
                "status": status,
                "reply": reply,
                "evidence_id": req.evidence_id,
                "case_id": req.case_id,
                "os_profile": req.os_profile,
                "agent": pkg.summary(),
            }

    # Last resort: listing skeleton.
    reply = _skeleton_reply(pkg.name, prompt, pkg.policy.allowed_tools)
    return {
        "status": "skeleton",
        "reply": reply,
        "evidence_id": req.evidence_id,
        "case_id": req.case_id,
        "os_profile": req.os_profile,
        "agent": pkg.summary(),
    }


@router.get("/api/agents", dependencies=[Depends(require_token)])
def list_agents() -> dict:
    return {
        "root": str(agent_registry.root),
        "agents": [pkg.summary() for pkg in agent_registry.list()],
    }


# ---- helpers ---------------------------------------------------------


def _cloud_ready() -> bool:
    return (
        config.get("MODEL_BACKEND") == "cloud"
        and bool(config.get("OPENAI_API_KEY"))
        and bool(config.get("MODEL_NAME"))
    )


def _choose_tool(prompt: str, os_profile: str) -> tuple[str, dict[str, Any]] | None:
    p = prompt.lower()
    for keywords, tool_id, base_params in _DEMO_ROUTES:
        if any(k in p for k in keywords):
            params = dict(base_params)
            if tool_id == "volatility3" and os_profile == "windows":
                params["plugin"] = "windows.pslist.PsList"
            return tool_id, params
    return None


def _run_demo_tool(
    tool_id: str,
    params: dict[str, Any],
    case_id: str,
    evidence_id: str,
    agent_name: str,
) -> tuple[str, str]:
    try:
        handle = evidence_manager.get(case_id, evidence_id)
    except KeyError as exc:
        return (
            f"**No encontré la evidencia** `{evidence_id}` en el caso `{case_id}`: {exc}",
            "demo-error",
        )

    evidence_path = str(handle.original_path)
    if tool_id in _TOOLS_WITH_IMAGE_PATH:
        params["image_path"] = evidence_path
    elif tool_id in _TOOLS_WITH_DUMP_PATH:
        params["dump_path"] = evidence_path

    try:
        result = dispatch_tool(tool_id, params, case_id=case_id)
    except ToolExecutionError as exc:
        return (
            f"**No se pudo invocar `{tool_id}`**: {exc}\n\n"
            "Probablemente el binario no está bundleado / en PATH todavía.",
            "demo-error",
        )
    except Exception as exc:  # noqa: BLE001
        return (
            f"**`{tool_id}` falló durante la ejecución**: "
            f"`{type(exc).__name__}: {exc}`",
            "demo-error",
        )

    return _format_demo_result(agent_name, tool_id, result), "demo-dispatch"


def _format_demo_result(agent_name: str, tool_id: str, result: dict[str, Any]) -> str:
    parsed = result.get("parsed") or {}
    exit_code = result.get("exit_code")
    run_id = result.get("run_id")
    argv = result.get("argv") or []

    lines: list[str] = [
        f"**{agent_name}** (demo loop, sin LLM — configura MODEL_BACKEND=cloud + "
        f"OPENAI_API_KEY + MODEL_NAME para activar el agente real) invocó "
        f"`{tool_id}` sobre la evidencia y persistió el resultado.\n",
        f"- **Exit code**: `{exit_code}`",
        f"- **Run ID**: `{run_id}`",
        f"- **Argv literal**:\n  ```\n  {' '.join(argv)}\n  ```",
    ]

    if isinstance(parsed, dict):
        if "partitions" in parsed:
            count = parsed.get("count", 0)
            lines.append(f"- **Particiones detectadas**: {count}")
            for p in parsed.get("partitions", [])[:5]:
                lines.append(
                    f"  - slot `{p.get('slot')}`: {p.get('description')} "
                    f"(start={p.get('start_sector')}, len={p.get('length_sectors')})"
                )
        elif "entries" in parsed:
            count = parsed.get("entries_count", 0)
            lines.append(f"- **Entradas listadas**: {count}")
        elif "fields" in parsed:
            lines.append(f"- **Campos extraídos**: {parsed.get('count', 0)}")
        elif "feature_counts" in parsed:
            total = parsed.get("total_features", 0)
            lines.append(f"- **Features encontrados**: {total}")
        elif "row_count" in parsed:
            lines.append(f"- **Filas (Volatility)**: {parsed.get('row_count', 0)}")

    stderr_sample = (result.get("stderr_sample") or "").strip()
    if exit_code != 0 and stderr_sample:
        lines.append(f"\n```\n{stderr_sample[:600]}\n```")

    artifact = result.get("artifact_run") or {}
    output_files = artifact.get("output_files") or []
    if output_files:
        lines.append(f"\n- **Artefactos generados**: {len(output_files)}")
        for f in output_files[:5]:
            lines.append(f"  - `{f.get('relpath')}` ({f.get('size')} bytes)")

    return "\n".join(lines)


def _skeleton_reply(agent_name: str, prompt: str, allowed_tools: tuple[str, ...]) -> str:
    tools_md = "\n".join(f"- `{t}`" for t in allowed_tools)
    return (
        f"**{agent_name}** está cargado y conectado. No detecté ningún caso/evidencia "
        "anclado a esta consulta o el prompt no matchea ninguna ruta del demo loop.\n\n"
        f"He recibido tu mensaje:\n\n> {prompt}\n\n"
        "Cuando configures cloud + API key + modelo en Settings, este agente podrá "
        "razonar y elegir herramientas por sí mismo. Mientras tanto, allowlist "
        "declarada en `policy/tools.yaml`:\n\n"
        f"{tools_md}"
    )
