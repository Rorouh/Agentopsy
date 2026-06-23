"""The forensic agent loop.

ONE agent parametrized by `os_profile` ("unix" | "windows"): the reasoning loop is
identical; only the available toolkit and the OS-artifact knowledge differ. This avoids
maintaining two divergent agents.

Safety (THREAT_MODEL gates 5-7): the model proposes a Tool.id from the profile's catalog
plus typed params; this class resolves the real argv from the allowlist, runs it shell-free,
and records the literal command in the audit log. The model never sees a raw command string
and evidence content is never treated as an instruction.
"""

from __future__ import annotations

from forensia.audit import AuditLog
from forensia.evidence import EvidenceManager
from forensia.models.base import ModelBackend
from forensia.toolkit.catalog import for_profile
from forensia.toolkit.tool import Tool


class ForensicAgent:
    def __init__(
        self,
        os_profile: str,
        model: ModelBackend,
        evidence: EvidenceManager,
        audit: AuditLog,
    ) -> None:
        if os_profile not in ("unix", "windows"):
            raise ValueError(f"os_profile must be 'unix' or 'windows', got {os_profile!r}")
        self.os_profile = os_profile
        self.model = model
        self.evidence = evidence
        self.audit = audit

    def available_tools(self) -> tuple[Tool, ...]:
        return for_profile(self.os_profile)

    def run(self, prompt: str, evidence_id: str) -> dict:
        raise NotImplementedError("agent loop not implemented yet (skeleton)")
