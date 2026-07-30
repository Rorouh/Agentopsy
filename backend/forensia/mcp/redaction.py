"""Apply the active agent package's redaction policy to tool outputs (L6).

The agent package's ``policy/redaction.yaml`` declares regex patterns + a
replacement string. When the MCP server is reached by a cloud client (Claude
Desktop), tool outputs flow back to a third-party LLM in the next turn —
RULE 7 / gate 7 of the threat model demands that PII/IP/hashes are scrubbed
before crossing the boundary.

We apply the patterns to ``stdout_sample`` and ``stderr_sample`` strings of
the dispatcher result. The literal argv, exit_code, run_id, sha256s, etc.
are NOT redacted — they're metadata, not evidence content.

Modes (``FORENSIA_REDACTION_MODE``):
- ``strict`` (default): apply every pattern that lists ``"strict"`` in its
  ``apply_in`` field — by default that's all of them. Right answer with a
  cloud client like Claude Desktop. Caveat from DFIR panel: redacts
  forensically meaningful values (e.g. IPs from NetScan), which is the point.
- ``relaxed``: only apply patterns whose ``apply_in`` includes ``"relaxed"``.
  For panels and local sessions where the operator wants the forensic
  payload (IPs, MACs, hostnames) but still wants credentials/keys/JWTs
  scrubbed. The default per-package policy keeps ``aws_access_key``, ``jwt``,
  and ``private_key_block`` in relaxed; everything else falls out.
- ``off``: no patterns applied. Only ever appropriate for in-process tests
  and CI where the output never crosses a trust boundary. The mode is
  recorded in the audit (``mcp_session_open.redaction_mode``) so the
  boundary is auditable.

The mode is read at server startup (env var) and travels with the
``mcp_session_open`` audit entry; the operator can prove which mode was
active for any given run.
"""

from __future__ import annotations

import os
import re
from typing import Any, Literal

from forensia.agent.package import AgentPackage

RedactionMode = Literal["strict", "relaxed", "off"]
_VALID_MODES = ("strict", "relaxed", "off")


def get_redaction_mode() -> RedactionMode:
    """Read FORENSIA_REDACTION_MODE from the env. Default ``strict``.

    Unknown values fail LOUD (RULE 2 — no fallback to "closest valid"). The
    server startup is the canonical place to surface a typo.
    """
    raw = os.environ.get("FORENSIA_REDACTION_MODE", "strict").strip().lower()
    if raw not in _VALID_MODES:
        raise ValueError(
            f"invalid FORENSIA_REDACTION_MODE={raw!r}; "
            f"expected one of {_VALID_MODES}. RULE 2, no fallback."
        )
    return raw  # type: ignore[return-value]


def apply_redaction(
    result: dict[str, Any],
    agent_package: AgentPackage | None,
    mode: RedactionMode | None = None,
) -> dict[str, Any]:
    """Mutate ``result`` in place applying the package's redaction patterns to
    ``stdout_sample`` / ``stderr_sample``. Returns the same dict for chaining.

    ``mode`` (default: read from env) controls aggressiveness — see module
    docstring. ``off`` skips all patterns and marks the response.

    If the agent package is ``None`` (shouldn't happen in production: the
    server refuses tool calls without a selected case → an agent package), we
    do NOT silently bypass redaction in strict mode — we replace the samples
    with a stub indicating no policy was applied (visible failure, RULE 2).
    """
    if not isinstance(result, dict):
        return result

    if mode is None:
        mode = get_redaction_mode()

    if mode == "off":
        result["redaction"] = {"applied": False, "reason": "FORENSIA_REDACTION_MODE=off"}
        return result

    if agent_package is None:
        result["stdout_sample"] = "[NO REDACTION APPLIED, no agent package]"
        result["stderr_sample"] = "[NO REDACTION APPLIED, no agent package]"
        result["redaction"] = {"applied": False, "reason": "no agent package"}
        return result

    patterns = agent_package.policy.redaction_patterns
    if not patterns:
        result["redaction"] = {"applied": False, "reason": "empty policy"}
        return result

    # Filter patterns by the active mode. Each pattern declares apply_in;
    # we keep only those whose set includes our current mode. RULE 2: do
    # NOT silently apply patterns that opted out — relaxed mode would be a
    # no-op alias of strict (that was the round-2 panel finding).
    applicable = [p for p in patterns if mode in p.apply_in]

    compiled: list[tuple[re.Pattern[str], str, str]] = []
    for p in applicable:
        try:
            compiled.append((re.compile(p.regex), p.replacement, p.name))
        except re.error:
            result.setdefault("redaction_warnings", []).append(
                f"invalid pattern in policy/redaction.yaml: {p.name!r}"
            )

    for key in ("stdout_sample", "stderr_sample"):
        sample = result.get(key)
        if isinstance(sample, str):
            for pattern, replacement, _name in compiled:
                sample = pattern.sub(replacement, sample)
            result[key] = sample

    result["redaction"] = {
        "applied": True,
        "mode": mode,
        "pattern_count": len(compiled),
        "patterns_in_mode": [n for _, _, n in compiled],
        "agent_package": agent_package.id,
    }
    return result


__all__ = ["RedactionMode", "apply_redaction", "get_redaction_mode"]
