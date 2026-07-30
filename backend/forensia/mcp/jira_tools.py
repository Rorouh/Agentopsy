"""The four Jira-pattern tools: list_cases, select_case, list_evidence,
select_evidence.

The shape is deliberate: every operation that requires server state to make
sense (everything that needs a case or an evidence) is gated through these
four calls. The model (LLM) calls them in natural conversation, just like the
Atlassian/Jira MCP server's ``getProjects`` → ``selectProject`` flow.

Schema choices:
- ``list_*`` take no arguments — they read the filesystem state of Agentopsy.
- ``select_*`` take a single ``id`` argument (UUID). RULE 2: no defaults, no
  "the only one", no "the most recent". If the id is missing or invalid the
  tool returns ``INVALID_PARAMS`` semantics via ``isError: true``.
"""

from __future__ import annotations

from typing import Any

from mcp import types

from forensia.agent.registry import agent_registry
from forensia.cases.manager import OsProfileUnresolved, case_manager, resolve_os_profile
from forensia.evidence import evidence_manager
from forensia.mcp.session import McpSession

JIRA_TOOL_NAMES: frozenset[str] = frozenset(
    {"list_cases", "select_case", "list_evidence", "select_evidence"}
)

# ---- tool definitions (published via tools/list) --------------------------

JIRA_TOOL_DEFINITIONS: list[types.Tool] = [
    types.Tool(
        name="list_cases",
        description=(
            "List forensic cases registered in Agentopsy. Each case has an id "
            "(UUID), a human name (e.g. 'Windows IR 2026-001'), the examiner, "
            "and an os_profile that is DERIVED from the evidence content by "
            "triage ('unix' | 'windows' | null when undetermined/ambiguous). "
            "Call this first when starting a session; pick one with `select_case`."
        ),
        inputSchema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="select_case",
        description=(
            "Select a case as the active context for subsequent forensic tool "
            "calls. The server will load the agent package for the case's "
            "os_profile and emit `tools/list_changed` so the client refreshes "
            "the available tools. RULE 2: no fallback, passing an invalid id "
            "or a profile with no agent package loaded fails loud."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "case_id": {
                    "type": "string",
                    "description": "UUID4 of the case (from `list_cases`).",
                    "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                }
            },
            "required": ["case_id"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="list_evidence",
        description=(
            "List the evidences registered in the currently selected case. "
            "Requires a prior `select_case`. Returns evidence_id (UUID), "
            "original basename, size, sha256, registered_at, and the "
            "deterministic triage fingerprint (detected_os, detected_kind)."
        ),
        inputSchema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="select_evidence",
        description=(
            "Select an evidence within the active case for subsequent forensic "
            "tool calls. The server injects the read-only evidence path into "
            "the tool arguments, clients never see raw paths. RULE 2: no "
            "fallback to 'the only evidence', no fallback to 'the most "
            "recently registered'."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "evidence_id": {
                    "type": "string",
                    "description": "UUID4 of the evidence (from `list_evidence`).",
                    "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                }
            },
            "required": ["evidence_id"],
            "additionalProperties": False,
        },
    ),
]


# ---- implementations ------------------------------------------------------


def list_cases() -> dict[str, Any]:
    cases = case_manager.list()
    return {
        "cases": [
            {
                "id": c.id,
                "name": c.name,
                "examiner": c.examiner,
                "os_profile": c.os_profile,
                "status": c.status,
                "created_at": c.created_at,
                "notes": c.notes,
            }
            for c in cases
        ],
        "count": len(cases),
    }


def select_case(session: McpSession, arguments: dict[str, Any]) -> dict[str, Any]:
    case_id = arguments.get("case_id")
    if not isinstance(case_id, str) or not case_id:
        return _err("select_case requires `case_id` (UUID4 from list_cases).")
    try:
        case = case_manager.load(case_id)
    except KeyError:
        return _err(f"unknown case_id {case_id!r}, call `list_cases` to see valid ids.")
    # Resolve the os_profile from the case (derived from evidence content by
    # triage, or operator-anchored) — never guessed. Ambiguity escalates.
    try:
        os_profile = resolve_os_profile(case)
    except OsProfileUnresolved as exc:
        return _err(str(exc))
    try:
        pkg = agent_registry.get_for_profile(os_profile)
    except KeyError:
        return _err(
            f"no agent package loaded for os_profile {os_profile!r}. "
            f"Drop one under agentes/ and restart the MCP server. RULE 2, "
            f"the server will not fall back to a different package."
        )
    session.set_case(case_id, pkg)
    return {
        "selected_case": {
            "id": case.id,
            "name": case.name,
            "os_profile": os_profile,
            "agent_package": {
                "id": pkg.id,
                "name": pkg.name,
                "allowed_tools_count": len(pkg.policy.allowed_tools),
            },
        },
        "next": (
            "Call `list_evidence` to see what's available in this case, then "
            "`select_evidence` to pick one. After that, the forensic tools "
            "specific to this os_profile become available in `tools/list`."
        ),
    }


def list_evidence(session: McpSession) -> dict[str, Any]:
    if session.case_id is None:
        return _err("no case selected, call `select_case` first.")
    handles = evidence_manager.list(session.case_id)
    return {
        "evidence": [
            {
                "evidence_id": h.evidence_id,
                "original_basename": h.original_path.name,
                "size_bytes": h.size,
                "sha256": h.sha256,
                "registered_at": h.registered_at,
                "detected_os": h.detected_os,
                "detected_kind": h.detected_kind,
                "verified": h.last_verification is not None
                and h.last_verification.verified,
            }
            for h in handles
        ],
        "count": len(handles),
        "case_id": session.case_id,
    }


def select_evidence(session: McpSession, arguments: dict[str, Any]) -> dict[str, Any]:
    if session.case_id is None:
        return _err("no case selected, call `select_case` first.")
    evidence_id = arguments.get("evidence_id")
    if not isinstance(evidence_id, str) or not evidence_id:
        return _err("select_evidence requires `evidence_id` (UUID4 from list_evidence).")
    try:
        handle = evidence_manager.get(session.case_id, evidence_id)
    except KeyError:
        return _err(
            f"unknown evidence_id {evidence_id!r} in case {session.case_id!r}, "
            f"call `list_evidence` to see valid ids."
        )
    session.set_evidence(evidence_id)
    return {
        "selected_evidence": {
            "evidence_id": handle.evidence_id,
            "original_basename": handle.original_path.name,
            "sha256": handle.sha256,
            "detected_os": handle.detected_os,
            "detected_kind": handle.detected_kind,
        },
        "next": (
            "Forensic tools in `tools/list` now operate on this evidence. The "
            "server injects the read-only path automatically, never pass raw "
            "paths in tool arguments."
        ),
    }


def _err(message: str) -> dict[str, Any]:
    return {"isError": True, "error": message}


__all__ = [
    "JIRA_TOOL_DEFINITIONS",
    "JIRA_TOOL_NAMES",
    "list_cases",
    "select_case",
    "list_evidence",
    "select_evidence",
]
