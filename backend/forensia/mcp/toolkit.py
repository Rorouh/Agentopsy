"""MCP `mcp-toolkit` — the core server (S1).

Lo que hace:
- Publica las 4 Jira tools (``list_cases``, ``select_case``, ``list_evidence``,
  ``select_evidence``) que viven en ``jira_tools.py``.
- Publica las tools forenses del catálogo recortadas por la allowlist del
  ``AgentPackage`` del ``os_profile`` del caso seleccionado.
- Delega cada call_tool en ``forensia.toolkit.dispatcher.execute`` con el
  ``case_id`` que vive en el estado de sesión (``session.py``). Cero
  reimplementación: el dispatcher es el único que escribe en ``audit.jsonl``
  (L1) y resuelve binarios (L4: stdio puro).
- Aplica redaction del paquete activo a ``stdout_sample`` / ``stderr_sample``
  antes de devolver la respuesta MCP (L6).
- Devuelve ``output_files`` como ``resource_link`` MCP con URI
  ``artifact://<case>/<run>/<relpath>`` y registra un handler ``resources/read``
  que sirve los artefactos con límite de tamaño (D5').

Lo que NO hace:
- No abre sockets de red. Stdio puro (L4).
- No escribe en ``audit.jsonl``. Solo el dispatcher lo hace (L1).
- No acepta paths crudos a evidencia. Solo ``evidence_id`` UUID4 vía el
  estado de sesión (L2).
- No infiere "el único caso / la única evidencia" cuando nadie llamó
  ``select_case`` o ``select_evidence``: falla loud (RULE 2, no fallbacks).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from mcp import types
from mcp.server import Server

from forensia.audit.log import AuditLog
from forensia.cases.manager import case_manager
from forensia.mcp.jira_tools import (
    JIRA_TOOL_DEFINITIONS,
    JIRA_TOOL_NAMES,
    list_cases,
    list_evidence,
    select_case,
    select_evidence,
)
from forensia.mcp.redaction import get_redaction_mode
from forensia.mcp.resources import (
    build_resource_links_for_run,
    read_artifact,
)
from forensia.mcp.schemas import SCHEMA_BY_TOOL
from forensia.mcp.session import McpSession
from forensia.toolkit.catalog import BY_ID

logger = logging.getLogger("forensia.mcp")


@dataclass
class Lifecycle:
    """Callbacks invoked from __main__.py to bracket the MCP session in the
    audit log. The audit entries are written into the case selected at the
    time of the event — if no case is selected yet, the entries are buffered
    in memory and flushed on the next ``select_case``."""

    session: McpSession
    consent_ref: str
    _pending: list[dict[str, Any]]

    @classmethod
    def new(cls, session: McpSession, consent_ref: str) -> "Lifecycle":
        return cls(session=session, consent_ref=consent_ref, _pending=[])

    async def on_session_start(self) -> None:
        # The redaction mode is read here so a typo in the env var becomes a
        # startup failure rather than a silent mid-run wrong-output.
        try:
            mode = get_redaction_mode()
        except ValueError as exc:
            raise RuntimeError(f"refusing to open MCP session: {exc}") from exc
        entry = {
            "action": "mcp_session_open",
            "consent_ref": self.consent_ref,
            "client_kind": "external_stdio",
            "redaction_mode": mode,
        }
        self._buffer_or_emit(entry)

    async def on_session_end(self) -> None:
        entry = {
            "action": "mcp_session_close",
            "consent_ref": self.consent_ref,
        }
        self._buffer_or_emit(entry)

    def _buffer_or_emit(self, entry: dict[str, Any]) -> None:
        case_id = self.session.case_id
        if case_id is None:
            self._pending.append(entry)
            return
        case_dir = case_manager.case_dir(case_id)
        audit = AuditLog(case_dir / "audit.jsonl")
        audit.append(entry)

    def flush_pending_into(self, case_id: str) -> None:
        """Called from select_case once we know which case absorbs the early
        session events. Replays the buffer into that case's audit log."""
        if not self._pending:
            return
        case_dir = case_manager.case_dir(case_id)
        audit = AuditLog(case_dir / "audit.jsonl")
        while self._pending:
            audit.append(self._pending.pop(0))


def build_server(consent_ref: str) -> tuple[Server, Lifecycle]:
    """Construct the MCP server and its lifecycle hooks. Returned together so
    ``__main__.py`` can drive ``on_session_start``/``on_session_end`` around
    the actual ``server.run()`` call.
    """
    session = McpSession()
    lifecycle = Lifecycle.new(session, consent_ref=consent_ref)
    server: Server = Server("forensia-toolkit")

    # ----- tools/list -----------------------------------------------------

    @server.list_tools()  # type: ignore[no-untyped-call,misc]
    async def _list_tools() -> list[types.Tool]:
        tools: list[types.Tool] = []
        # The four Jira tools are always available, regardless of session state.
        # Their description tells the model what to call next when something's
        # missing (no case selected, no evidence selected, etc.).
        tools.extend(JIRA_TOOL_DEFINITIONS)

        # Forensic tools come ONLY once a case is selected, AND filtered by the
        # active agent package's allowlist for that case's os_profile.
        pkg = session.agent_package
        if pkg is None:
            return tools
        for tool_id in pkg.policy.allowed_tools:
            tool = BY_ID.get(tool_id)
            if tool is None:
                continue
            params_schema = SCHEMA_BY_TOOL.get(tool_id)
            if params_schema is None:
                logger.warning(
                    "tool %s lacks a schema in forensia.mcp.schemas.SCHEMA_BY_TOOL; "
                    "not publishing via MCP (RULE 2 — no fallback schema). Add a "
                    "BaseModel + register it to expose this tool.",
                    tool_id,
                )
                continue
            tools.append(
                types.Tool(
                    name=tool_id,
                    description=(params_schema.__doc__ or "").strip()
                    or f"FORENSIA forensic tool {tool_id!r} (see catalog.py)",
                    inputSchema=_pydantic_to_json_schema(params_schema),
                )
            )
        return tools

    # ----- tools/call -----------------------------------------------------

    @server.call_tool()  # type: ignore[no-untyped-call,misc]
    async def _call_tool(name: str, arguments: dict[str, Any]) -> list[Any]:
        # The four Jira tools are routed first; they manage their own validation.
        if name in JIRA_TOOL_NAMES:
            return await _dispatch_jira(name, arguments, session, server, lifecycle)

        # Forensic tools require an active case + (usually) evidence.
        return await _dispatch_forensic(name, arguments, session)

    # ----- resources/list + resources/read ---------------------------------

    @server.list_resources()  # type: ignore[no-untyped-call,misc]
    async def _list_resources() -> list[types.Resource]:
        # F3 of round-1 panel: declaring a list_resources handler is what
        # makes the SDK announce the ``resources`` capability in
        # ``initialize`` so spec-compliant clients enable resources/read.
        # The set of artifact URIs grows with every run; we don't enumerate
        # them all (that would be every tool ever executed across cases).
        # Return an empty list — the URIs surface via ``ResourceLink``
        # content blocks in tool responses (D5').
        return []

    @server.read_resource()  # type: ignore[no-untyped-call,misc]
    async def _read_resource(uri: str) -> list[Any]:
        # D5' — serve ``artifact://`` URIs that the tool responses pointed at.
        # The parser + path-traversal guard live in forensia.mcp.resources.
        try:
            return read_artifact(str(uri))
        except (ValueError, KeyError, FileNotFoundError) as exc:
            # RULE 2 — fail loud with an actionable error, no fallback.
            raise RuntimeError(f"cannot read artifact {uri!r}: {exc}") from exc

    return server, lifecycle


# ---- internal dispatch helpers --------------------------------------------


async def _dispatch_jira(
    name: str,
    arguments: dict[str, Any],
    session: McpSession,
    server: Server,
    lifecycle: Lifecycle,
) -> list[types.TextContent]:
    if name == "list_cases":
        return _text(list_cases())
    if name == "select_case":
        result = select_case(session, arguments)
        # If select_case succeeded, flush any buffered lifecycle entries +
        # write the select_case audit entry into the newly selected case.
        if session.case_id is not None and not result.get("isError"):
            lifecycle.flush_pending_into(session.case_id)
            case_dir = case_manager.case_dir(session.case_id)
            AuditLog(case_dir / "audit.jsonl").append(
                {
                    "action": "mcp_session_select_case",
                    "case_id": session.case_id,
                    "consent_ref": lifecycle.consent_ref,
                    "agent_package": (
                        session.agent_package.id if session.agent_package else None
                    ),
                }
            )
        # The set of available tools changes when a case is selected (allowlist
        # of the agent package for that os_profile). Tell the client.
        try:
            await server.request_context.session.send_tool_list_changed()  # type: ignore[attr-defined]
        except (AttributeError, RuntimeError):
            # Some clients / SDK versions ignore the notification; not fatal.
            pass
        return _text(result)
    if name == "list_evidence":
        return _text(list_evidence(session))
    if name == "select_evidence":
        return _text(select_evidence(session, arguments))
    raise RuntimeError(f"unreachable: unknown jira tool {name!r}")


async def _dispatch_forensic(
    name: str,
    arguments: dict[str, Any],
    session: McpSession,
) -> list[types.TextContent]:
    # Local import to avoid a circular dep that only matters at call time.
    from forensia.toolkit.dispatcher import ToolExecutionError, execute as dispatch_tool

    tool = BY_ID.get(name)
    if tool is None:
        # RULE 2: do not fall back to a "closest match" tool. Fail loud.
        return _error(f"unknown tool: {name!r} (not in forensia.toolkit.catalog)")

    case_id = session.case_id
    if case_id is None:
        return _error(
            "no case selected — call `select_case` first. RULE 2 (no fallbacks): "
            "the server does not auto-pick a case even if there is only one."
        )

    if session.agent_package is None or name not in session.agent_package.policy.allowed_tools:
        return _error(
            f"tool {name!r} is not in the allowlist of the active agent package "
            f"({session.agent_package.id if session.agent_package else '<none>'}). "
            f"Pick a different tool from `tools/list`."
        )

    # Validate arguments through the tool's params_schema. This enforces L2:
    # the schema rejects raw paths to evidence — only the session-injected
    # path is acceptable, and the dispatcher resolves it via EvidenceManager.
    params_schema = SCHEMA_BY_TOOL.get(name)
    if params_schema is None:
        return _error(
            f"tool {name!r} has no Pydantic schema registered in "
            f"forensia.mcp.schemas.SCHEMA_BY_TOOL; refusing to invoke with raw "
            f"arguments. Register the BaseModel and restart the server."
        )
    try:
        validated = params_schema(**arguments).model_dump(exclude_none=True)
    except Exception as exc:  # noqa: BLE001 — validation error → INVALID_PARAMS
        return _error(f"invalid params for tool {name!r}: {exc}")

    # Inject the evidence path from the session — the schema does NOT carry
    # paths; the dispatcher reads the handle from EvidenceManager and adds it.
    evidence_id = session.evidence_id
    if evidence_id is None:
        return _error(
            "no evidence selected — call `select_evidence` first. RULE 2 (no fallbacks): "
            "the server does not auto-pick evidence even if the case has only one."
        )
    # The actual evidence path injection happens in dispatcher via _EVIDENCE_INJECTION
    # of ForensicAgent — but the MCP server is a different caller. Read the handle
    # ourselves and stuff the path into the appropriate param key.
    from forensia.evidence import evidence_manager

    handle = evidence_manager.get(case_id, evidence_id)
    validated = _inject_evidence_path(name, validated, str(handle.original_path))

    try:
        # os_profile of the active package routes the tool to its maletín (§B): the same
        # profile that gated the allowlist above, so no cross-maletín fallback (RULE 2).
        result = dispatch_tool(
            name, validated, case_id=case_id, os_profile=session.agent_package.os_profile
        )
    except ToolExecutionError as exc:
        return _error(f"tool {name!r} failed to execute: {exc}")

    # L6 — apply redaction from the active agent package before responding.
    from forensia.mcp.redaction import apply_redaction

    result = apply_redaction(result, session.agent_package)

    # D5' — emit ResourceLink content blocks for every artefact of the run
    # (stdout.txt, stderr.txt, and any out/<file>) so the client can navigate
    # the run via resources/read. The bulky payload (stdout_sample, parsed,
    # exit_code, etc.) is the first TextContent block.
    content: list[Any] = _text(result)
    run_id = result.get("run_id")
    artifact_run = result.get("artifact_run") or {}
    if run_id:
        content.extend(build_resource_links_for_run(case_id, run_id, artifact_run))
    return content


def _inject_evidence_path(tool_id: str, params: dict[str, Any], path: str) -> dict[str, Any]:
    """Mirror of ``ForensicAgent._EVIDENCE_INJECTION`` — the dispatcher expects
    the path under a specific key per tool. We don't have access to that map
    from the agent module (would create a circular import), so we keep a copy
    here. Tools that don't take an evidence path (e.g. ``jq``) are absent.
    """
    injection_map = {
        "file_info": "image_path",
        "xxd_head": "image_path",
        "strings_head": "image_path",
        "tsk_mmls": "image_path",
        "tsk_fls": "image_path",
        "tsk_mactime": "bodyfile_path",
        "tsk_icat": "image_path",
        "ewf_info": "image_path",
        "bulk_extractor": "image_path",
        "yara": "target_path",
        "volatility3": "dump_path",
        "hayabusa": "evtx_dir",
        "chainsaw": "target_dir",
        "regripper": "hive_path",
        "evtxecmd": "evtx_path",
        "mftecmd": "mft_path",
    }
    key = injection_map.get(tool_id)
    if key is not None and params.get(key) in (None, ""):
        params[key] = path
    return params


# ---- response helpers -----------------------------------------------------


def _text(payload: Any) -> list[types.TextContent]:
    """Serialise a Python dict/list/str into a single MCP TextContent block."""
    if isinstance(payload, str):
        body = payload
    else:
        body = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    return [types.TextContent(type="text", text=body[:64_000])]


def _error(message: str) -> list[types.TextContent]:
    """Tool execution that fails business-logic-wise returns an isError content
    block per the MCP spec — NOT a JSON-RPC error (that would mean the protocol
    itself errored, which isn't the case)."""
    return [
        types.TextContent(
            type="text",
            text=json.dumps({"isError": True, "error": message}, ensure_ascii=False),
        )
    ]


# ---- JSON Schema serialization --------------------------------------------


def _pydantic_to_json_schema(model_cls: type) -> dict[str, Any]:
    """Return a flat (no-$ref) JSON Schema for an MCP ``inputSchema``.

    Some MCP clients refuse internal ``$ref`` resolution. We use jsonref to
    inline all references so the published schema is a single self-contained
    object. The mode="serialization" path mirrors what model_dump produces.
    """
    import jsonref  # local import: optional dep [mcp] (RULE 1 — don't pull on import)

    raw = model_cls.model_json_schema(mode="serialization")
    flat = jsonref.replace_refs(raw, proxies=False, lazy_load=False)
    # jsonref leaves a "$defs" block that's now redundant; strip it.
    if isinstance(flat, dict):
        flat.pop("$defs", None)
        flat.pop("definitions", None)
    return flat  # type: ignore[return-value]


__all__ = ["build_server", "Lifecycle"]
