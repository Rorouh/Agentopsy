"""Egress redaction — minimize personal data before it crosses to a cloud model.

Pure functions: no I/O, no network, no mutation of the input. The agent loop
applies these at the SINGLE cloud-egress boundary (``ForensicAgent.run``), so the
declared per-package ``policy/redaction.yaml`` is actually enforced — see
THREAT_MODEL gate 9 and FORENSIC_SOUNDNESS §5.

With a local backend (the privacy default) the evidence-derived content never
leaves the host, so redaction is NOT applied: the caller passes the raw messages
straight through.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from forensia.agent.package import RedactionPattern


def apply_redaction(text: str, patterns: Sequence[RedactionPattern]) -> str:
    """Run every pattern's ``regex`` → ``replacement`` over ``text``, in order.

    Patterns are applied sequentially, so a later pattern sees the output of the
    earlier ones. Returns ``text`` unchanged when ``patterns`` is empty.
    """
    if not isinstance(text, str):
        raise TypeError(f"apply_redaction expects str, got {type(text).__name__}")
    redacted = text
    for pattern in patterns:
        redacted = re.sub(pattern.regex, pattern.replacement, redacted)
    return redacted


def redact_messages(
    messages: Sequence[dict[str, Any]],
    patterns: Sequence[RedactionPattern],
) -> list[dict[str, Any]]:
    """Return a COPY of an OpenAI-shape message list with every string ``content``
    field passed through :func:`apply_redaction`.

    The input list and its dicts are never mutated: the canonical conversation
    held by the loop stays faithful (raw) for replay/debugging, while only the
    wire payload handed to the cloud backend is minimized. Covers the system
    prompt (which carries the injected evidence filename), the user prompt, and
    every tool-result message (which carries tool stdout/stderr/parsed output).
    """
    out: list[dict[str, Any]] = []
    for msg in messages:
        copy = dict(msg)
        content = copy.get("content")
        if isinstance(content, str):
            copy["content"] = apply_redaction(content, patterns)
        out.append(copy)
    return out


__all__ = ["apply_redaction", "redact_messages"]
