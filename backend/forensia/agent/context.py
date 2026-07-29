"""Provider-agnostic context-window management for the agent loop (Bug 008).

The executor is stateless: Agentopsy re-sends the whole conversation on every
iteration, so an append-only transcript grows O(N) and the total wire cost of a
run grows O(N^2). Prompt caching can't be relied on uniformly across the four
executors (Claude Code / Codex / Gemini / Ollama), so the only uniform lever is
to **send less**. This module projects the canonical ``messages`` list to a
bounded OUTBOUND copy.

Contract (mirrors ``redaction.redact_messages``): pure function, no I/O, never
mutates the input. The loop keeps the canonical ``messages`` raw for
replay/audit/custody; only the copy that crosses the wire is trimmed here.

The trim is conservative: the system prompt, the task, the assistant reasoning
turns and the most recent K tool results survive verbatim; older tool results —
the heavy artifacts — collapse to a one-line stub that still names the run, so
the model can fetch the detail from the artifact with ``jq`` if it needs it.
"""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from typing import Any

# The playbook (the largest static block in the system prompt — ~22 KB on
# windows) is re-sent verbatim on EVERY iteration. Only ONE of its two primary
# branches applies to a given piece of evidence, yet both travel every turn
# (Bug 008). Split at level-2 headers and drop the branch that doesn't match the
# triage `detected_kind`. Common sections (routing, cost discipline, best
# practices, per-tool annex) and the intro always stay.

# Per-tool annex sub-headings (### …) worth branch-trimming. The annex ships in
# EVERY iteration as a "common" ## section, but ~6 KB of it are disk-only tool
# docs that are dead weight on a memory dump (Bug 008 §2 Nivel 1). Keyword sets are
# CONSERVATIVE: a sub-heading that matches neither stays (fails safe — RULE 2:
# never hide guidance we're unsure about).


def session_context_budget_chars() -> int:
    """Safety ceiling (chars) for sending the transcript UNCUT under session
    transport (Fase 3). With a resumable session each message crosses the wire
    exactly once and is then read at cache rate, so windowing stops saving and
    starts costing: the measured run spent 12 of 21 turns re-reading artifacts
    its own stubs had elided (``docs/diseno/tokens-2026-07/fase-turnos.md`` §3).
    The ceiling only exists so a pathological run cannot overflow the model's
    context window: the measured turn-22 transcript was ~111 K chars, so the
    default 400 000 gives ~4× headroom while staying inside a 200 K-token
    window. Crossing it re-enables ``window_messages`` AND is audited
    (``context_window_trimmed``) — never a silent cut (RULE 2). Override with
    ``FORENSIA_SESSION_CONTEXT_MAX_CHARS``; an invalid value fails loud."""
    raw = os.environ.get("FORENSIA_SESSION_CONTEXT_MAX_CHARS")
    if raw is None:
        return 400_000
    try:
        value = int(raw)
    except ValueError:
        value = 0
    if value <= 0:
        raise RuntimeError(
            f"FORENSIA_SESSION_CONTEXT_MAX_CHARS={raw!r} no es válido: debe ser "
            "un entero de caracteres > 0 — Agentopsy no lo sustituye por el "
            "default (RULE 2)."
        )
    return value


def transcript_chars(messages: Sequence[dict[str, Any]]) -> int:
    """Total content chars of a message list — the datum the session budget and
    its audit event are measured in."""
    return sum(len(str(m.get("content") or "")) for m in messages)


def keep_last_tool_results_default() -> int:
    """How many of the most recent tool-result messages stay verbatim on the wire.

    Older ones are stubbed. Default 4; per-deployment override via
    ``FORENSIA_CONTEXT_KEEP_TOOL_RESULTS``. Minimum 1 (the model always sees at
    least the latest result in full)."""
    try:
        return max(1, int(os.environ.get("FORENSIA_CONTEXT_KEEP_TOOL_RESULTS", "4")))
    except ValueError:
        return 4


def _embedded_json(text: str) -> Any:
    """Best-effort: parse the outermost ``{...}`` object embedded in ``text`` (a tool
    result wrapped in NO-trust spotlighting delimiters). ``None`` if none parses."""
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except (ValueError, json.JSONDecodeError):
        return None


def _stub_for(content: Any) -> str:
    """One-line replacement for an elided tool-result body. Best-effort extracts
    ``tool_id`` / ``exit_code`` / ``run_id`` from the JSON so the stub still points
    the model at the run artifact."""
    tool_id: Any = None
    exit_code: Any = None
    run_id: Any = None
    if isinstance(content, str):
        try:
            body = json.loads(content)
        except (ValueError, json.JSONDecodeError):
            # A real tool result is wrapped in NO-trust spotlighting delimiters
            # (agent._UNTRUSTED_OPEN/CLOSE around the JSON). Recover the embedded
            # object so the stub can still name tool_id/exit_code/run_id.
            body = _embedded_json(content)
        if isinstance(body, dict):
            tool_id = body.get("tool_id")
            exit_code = body.get("exit_code")
            run_id = body.get("run_id")
            if not run_id and isinstance(body.get("artifact_run"), dict):
                run_id = body["artifact_run"].get("run_id")
    meta = ", ".join(
        part
        for part in (
            f"tool={tool_id}" if tool_id else "",
            f"exit={exit_code}" if exit_code is not None else "",
            # Full run_id, never a prefix — it is the agent's recovery key for the run's
            # artifacts ({run_id, relpath}); a truncated id is rejected by the ArtifactStore.
            f"run={run_id}" if run_id else "",
        )
        if part
    )
    return (
        "[resultado de tool elidido para acotar el contexto"
        + (f" ({meta})" if meta else "")
        + "; el detalle sigue en el artefacto del run — recupéralo con `jq` si lo necesitas]"
    )


def window_messages(
    messages: Sequence[dict[str, Any]],
    keep_last_tool_results: int | None = None,
) -> list[dict[str, Any]]:
    """Return a COPY of ``messages`` with all but the most recent
    ``keep_last_tool_results`` tool-result messages collapsed to a stub.

    Only ``role == "tool"`` messages are ever touched; system / user / assistant
    turns pass through verbatim so the reasoning chain stays coherent. The input
    list and its dicts are never mutated.
    """
    keep = (
        keep_last_tool_results
        if keep_last_tool_results is not None
        else keep_last_tool_results_default()
    )
    tool_indices = [i for i, m in enumerate(messages) if m.get("role") == "tool"]
    if len(tool_indices) <= keep:
        return [dict(m) for m in messages]

    stub_targets = set(tool_indices[:-keep])
    out: list[dict[str, Any]] = []
    for i, msg in enumerate(messages):
        copy = dict(msg)
        if i in stub_targets:
            copy["content"] = _stub_for(copy.get("content"))
        out.append(copy)
    return out


__all__ = [
    "window_messages",
    "keep_last_tool_results_default",
    "session_context_budget_chars",
    "transcript_chars",
]
