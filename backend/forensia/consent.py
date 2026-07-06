"""Cloud-executor consent — recorded AND enforced on the HTTP agent-query path.

SECURITY INVARIANT 7 / RGPD: selecting a cloud-backed executor (Claude Code,
Codex CLI, Gemini CLI) sends case-derived content — which may contain real
personal data — to that vendor under the operator's own account. The UI warns
and the operator confirms; that confirmation is recorded in the case's
hash-chained audit log. This module is the single owner of both sides of that
fact so the constant and the matching rule cannot drift:

- ``record_cloud_consent`` — append the consent entry (the
  ``/api/agent/cloud-consent`` endpoint calls it when the operator confirms).
- ``has_cloud_consent`` — has the operator consented for THIS case + THIS
  executor? ``/api/agent/query`` refuses a cloud executor without it (403), so
  an API client cannot bypass the UI-only warning (the E2E verification of
  2026-07-02 found the gate lived only in the SPA).

Ollama is 100% local — it never sends case content anywhere, so it never
requires (and never records) consent; callers gate on ``executor.is_local``.
"""

from __future__ import annotations

from typing import Any

from forensia.audit.log import AuditLog

# The single action string both sides key on. Do not inline it elsewhere.
CLOUD_CONSENT_ACTION = "cloud_executor_consent"


def record_cloud_consent(
    audit: AuditLog,
    case_id: str,
    executor_id: str,
    executor_name: str,
    *,
    source: str = "web-ui",
) -> dict[str, Any]:
    """Append the operator's consent for ``executor_id`` on ``case_id`` to the
    case audit log (hash-chained). Returns the written entry."""
    return audit.append(
        {
            "action": CLOUD_CONSENT_ACTION,
            "case_id": case_id,
            "executor": executor_id,
            "executor_name": executor_name,
            "source": source,
        }
    )


def has_cloud_consent(audit: AuditLog, case_id: str, executor_id: str) -> bool:
    """True iff a ``cloud_executor_consent`` entry for exactly this ``case_id``
    and ``executor_id`` exists in the case audit log."""
    for entry in audit.entries():
        if (
            entry.get("action") == CLOUD_CONSENT_ACTION
            and entry.get("case_id") == case_id
            and entry.get("executor") == executor_id
        ):
            return True
    return False
