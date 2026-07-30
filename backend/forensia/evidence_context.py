"""Verified evidence context threaded from ``EvidenceManager`` to every tool run.

A minimal, immutable, typed carrier for the two facts a tool run must bind to the
evidence it acts on (FORENSIC INVARIANT 4): the ``evidence_id`` and the evidence's
``baseline_sha256`` (the hash the ``EvidenceManager`` computed at the ingest hash gate).

It is built ONLY from an ``EvidenceHandle`` obtained via ``EvidenceManager`` (see
``EvidenceContext.from_handle``) — never from an LLM value, an arbitrary path, or
caller-supplied params. The dispatcher records it in ``tool_run_start`` /
``tool_run_finish`` but NEVER re-derives it (no opportunistic ``baseline.json`` read):
the surfaces (API / MCP / ForensicAgent) thread it in explicitly, so a missing or
invalid context fails loud before the runner (RULE 2).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# A SHA-256 hex digest: exactly 64 hex chars. An empty string, ``None`` or a
# placeholder is rejected — the baseline hash always exists before evidence is
# exposed (FORENSIC INVARIANTS 1-2), so a run can always carry a real one.
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class EvidenceContext:
    """Immutable ``(evidence_id, baseline_sha256)`` a tool run is anchored to."""

    evidence_id: str
    baseline_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_id, str) or not self.evidence_id.strip():
            raise ValueError("EvidenceContext.evidence_id must be a non-empty string")
        if not isinstance(self.baseline_sha256, str) or not _SHA256_RE.match(
            self.baseline_sha256
        ):
            raise ValueError(
                "EvidenceContext.baseline_sha256 must be a 64-hex SHA-256 digest "
                f"(got {self.baseline_sha256!r}), no empty/None/placeholder allowed"
            )

    @classmethod
    def from_handle(cls, handle: Any) -> EvidenceContext:
        """Build from a hash-verified ``EvidenceHandle`` (``EvidenceManager.get``).

        The handle's ``sha256`` is the baseline the ingest hash gate recorded, so the
        context is trustworthy by construction. This is the ONLY sanctioned factory:
        callers must not assemble a context from LLM/path/param values.
        """
        return cls(evidence_id=handle.evidence_id, baseline_sha256=handle.sha256)

    def matches_handle(self, handle: Any) -> bool:
        """True when this context corresponds to ``handle`` (same id + baseline hash).

        Lets a surface assert the context it threads was built from the very handle it
        resolved the evidence path from — a forged/mismatched context is detectable.
        """
        return self.evidence_id == handle.evidence_id and self.baseline_sha256.casefold() == str(
            handle.sha256
        ).casefold()

    def audit_fields(self) -> dict[str, str]:
        """The uniform fields recorded in ``tool_run_start`` / ``tool_run_finish``."""
        return {
            "evidence_id": self.evidence_id,
            "baseline_sha256": self.baseline_sha256,
        }


__all__ = ["EvidenceContext"]
