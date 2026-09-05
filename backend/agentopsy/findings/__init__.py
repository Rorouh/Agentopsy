"""Per-case structured findings — populated by the agent during the loop.

The agent records a finding via the internal ``record_finding`` tool (see
``agentopsy.agent.tool_schemas``) every time it reaches a meaningful
conclusion. The UI reads them from ``GET /api/cases/{id}/findings`` to fill
the "Hallazgos del caso" panel.
"""

from agentopsy.findings.store import Finding, FindingStore, finding_store

__all__ = ["Finding", "FindingStore", "finding_store"]
