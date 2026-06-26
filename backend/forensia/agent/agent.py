"""The forensic agent loop.

ONE agent parametrized by an ``AgentPackage`` loaded from ``agentes/<id>/``: the
reasoning loop is identical; what changes per profile is the package (prompts,
model backend, allowlist of tools, redaction policy). This avoids maintaining
two divergent agents.

Safety (THREAT_MODEL gates 5-7): the model proposes a ``tool_id`` from the
package's allowlist (which is itself a subset of the catalog for the package's
``os_profile``) plus typed params; this class resolves the real argv from the
allowlist, runs it shell-free, and records the literal command in the audit
log. The model never sees a raw command string and evidence content is never
treated as an instruction.

State of the implementation: skeleton. The constructor + ``available_tools``
are fully wired (so ``/api/agent/query`` can prove the package is loaded and
report the active toolset to the UI). The ``run`` loop itself is still
intentionally not implemented — see CLAUDE.md "Status".
"""

from __future__ import annotations

from forensia.agent.package import AgentPackage
from forensia.audit import AuditLog
from forensia.evidence import EvidenceManager
from forensia.models.base import ModelBackend
from forensia.toolkit.catalog import BY_ID as TOOL_BY_ID
from forensia.toolkit.tool import Tool


class ForensicAgent:
    def __init__(
        self,
        package: AgentPackage,
        model: ModelBackend,
        evidence: EvidenceManager,
        audit: AuditLog,
    ) -> None:
        self.package = package
        self.os_profile = package.os_profile
        self.model = model
        self.evidence = evidence
        self.audit = audit

    def available_tools(self) -> tuple[Tool, ...]:
        """Tools the agent is ACTUALLY allowed to invoke (allowlist ∩ catalog).

        The loader has already validated that every id in the allowlist exists
        in the catalog and matches the package's ``os_profile``; this lookup
        cannot miss.
        """
        return tuple(TOOL_BY_ID[tool_id] for tool_id in self.package.policy.allowed_tools)

    def run(self, prompt: str, evidence_id: str) -> dict:
        raise NotImplementedError("agent loop not implemented yet (skeleton)")
