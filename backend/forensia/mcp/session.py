"""In-memory session state for the MCP server.

A single ``McpSession`` instance lives per server process — i.e. per
connected client. Claude Desktop spawns one ``python -m forensia.mcp`` per
configured server, so each client gets its own state by construction; we do
not need a sessions table keyed by JSON-RPC client id.

State follows the Jira pattern:
- ``case_id``: the case the operator (or LLM via ``select_case``) chose.
- ``evidence_id``: the evidence within that case.
- ``agent_package``: loaded once on ``select_case`` from
  ``forensia.agent.registry.agent_registry``. Its ``policy/tools.yaml``
  allowlist is the authoritative filter for ``tools/list``.

RULE 2 — no fallbacks. If a property is ``None`` we never substitute a
"reasonable" value; we make callers fail loud.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from forensia.agent.package import AgentPackage
from forensia.agent.registry import agent_registry
from forensia.cases.manager import OsProfileUnresolved, case_manager, resolve_os_profile


@dataclass
class McpSession:
    """Mutable session state. Public attributes accessed by toolkit.py."""

    case_id: Optional[str] = None
    evidence_id: Optional[str] = None
    agent_package: Optional[AgentPackage] = None

    def __post_init__(self) -> None:
        """Honour FORENSIA_CASE_ID as a *test-only* preselection.

        The env var exists so CI can run the MCP server end-to-end without an
        interactive Jira flow. It is NOT a production fallback (RULE 2): it
        only kicks in when the test harness sets it explicitly. If the value
        does not resolve to a real case, we fail loud at construction.
        """
        preset = os.environ.get("FORENSIA_CASE_ID", "").strip()
        if not preset:
            return
        case = case_manager.load(preset)  # raises KeyError if missing — that's fine
        self.case_id = case.id
        try:
            profile = resolve_os_profile(case)
            self.agent_package = agent_registry.get_for_profile(profile)
        except (OsProfileUnresolved, KeyError):
            # The session is constructible — but tools/list will be empty until
            # the os_profile resolves (routable evidence or an operator anchor)
            # and its package is present. We don't paper over it (RULE 2).
            self.agent_package = None

    def set_case(self, case_id: str, agent_package: AgentPackage) -> None:
        # Switching case clears the evidence selection — a different case can
        # have different evidences. RULE 2: do not auto-select the first.
        self.case_id = case_id
        self.agent_package = agent_package
        self.evidence_id = None

    def set_evidence(self, evidence_id: str) -> None:
        if self.case_id is None:
            raise RuntimeError(
                "set_evidence called with no case selected, internal error: callers "
                "must guard with `case_id is None` before this point."
            )
        self.evidence_id = evidence_id


__all__ = ["McpSession"]
