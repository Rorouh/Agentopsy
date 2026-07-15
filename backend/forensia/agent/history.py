"""Server-side replay of a chat session for the next agent turn.

Without this module, each call to ``/api/agent/query`` arrived at
``ForensicAgent.run()`` as a fresh agent with no memory of prior turns —
which meant the model re-executed ``tsk_mmls`` and ``volatility3 windows.info``
in every turn, and "hazlo" had no referent for the operator's earlier "do
pslist/netscan/malfind in the next iteration" instruction.

What we replay, in order, into the OpenAI ``messages`` list (between system
and the in-flight user prompt):

1. The user/assistant text from prior turns (read from ``ChatStore``, which
   the renderer persists as the conversation progresses). The LAST user turn
   in the store is skipped — that's the in-flight one the router just received.
2. One synthetic system message titled "## Tool runs so far" listing the
   ``tool_calls`` persisted on prior assistant turns (tool_id + exit code +
   short run id). This is the cheap stand-in for full OpenAI tool-message
   replay — we can't safely replay raw ``tool_calls`` / ``tool`` messages
   because their ``tool_call_id`` chain isn't persisted and an id mismatch
   crashes the OpenAI call. The ledger is enough to stop the model from
   repeating runs it already did.
3. One synthetic system message titled "## Findings so far" listing
   structured ``Finding[]`` from ``finding_store.list(case_id)`` (title +
   severity + tool_id). This frames "what's still open" so the model resumes
   on the *next* play instead of re-doing the initial play.

Token budget: cap at the last ``MAX_REPLAY_TURNS`` user/assistant pairs OR
``MAX_REPLAY_CHARS`` total content chars, whichever hits first. No LLM-based
summarization in v1 — accept the cap.

Source of truth is ``ChatStore``, not the renderer's in-memory ``msgs`` —
RULE 2 says don't trust unverified inputs (the renderer is hardened, but
evidence is hostile and we don't want a path where a compromised renderer
could inject fabricated history into the agent's context). The renderer
sends only the ``session_id``; the backend reads the file.
"""

from __future__ import annotations

import logging
from typing import Any

from forensia.chats.store import ChatMessage, chat_store
from forensia.findings.store import Finding, finding_store

logger = logging.getLogger(__name__)

# Caps. These are *per turn* (each call to build_replay_messages), not lifetime.
MAX_REPLAY_TURNS = 6                # user/assistant pairs (12 messages)
MAX_REPLAY_CHARS = 8_000            # total content chars across replayed text
MAX_LEDGER_ENTRIES = 30             # tool-run ledger cap (~one screen)
MAX_FINDINGS_ENTRIES = 10           # findings ledger cap


def build_replay_messages(case_id: str, session_id: str) -> list[dict[str, Any]]:
    """Return a list of OpenAI-shaped messages to splice between system and user.

    Order: [tool-runs ledger] + [findings ledger] + [prior user/assistant text].

    Returns ``[]`` (not None) when there is no prior history — callers can
    splice unconditionally.
    """
    try:
        messages = chat_store.read(case_id, session_id)
    except KeyError:
        # No session file yet — fresh chat for this case. Nothing to replay.
        return []

    # Drop the LAST user message — that's the in-flight prompt the router is
    # about to add itself. Without this we'd duplicate it.
    trimmed = _drop_trailing_user(messages)

    replay: list[dict[str, Any]] = []

    ledger_block = _tool_runs_ledger(trimmed)
    if ledger_block:
        replay.append({"role": "system", "content": ledger_block})

    findings_block = _findings_ledger(case_id)
    if findings_block:
        replay.append({"role": "system", "content": findings_block})

    # Tail-cap the user/assistant transcript by turns + chars.
    transcript = _cap_transcript(trimmed, MAX_REPLAY_TURNS, MAX_REPLAY_CHARS)
    for m in transcript:
        if m.role in ("user", "assistant"):
            replay.append({"role": m.role, "content": m.content})

    return replay


# ---- internals ------------------------------------------------------------


def _drop_trailing_user(messages: list[ChatMessage]) -> list[ChatMessage]:
    """The renderer appends the user message BEFORE calling /api/agent/query.
    Strip the trailing user (and any system/tool gap after) so we don't echo
    the live prompt back into history. If the trailing message is already an
    assistant turn (e.g. retry on a successful previous answer), leave it.
    """
    if not messages:
        return messages
    out = list(messages)
    while out and out[-1].role in ("system", "tool"):
        out.pop()
    if out and out[-1].role == "user":
        out.pop()
    return out


def _cap_transcript(
    messages: list[ChatMessage], max_turns: int, max_chars: int
) -> list[ChatMessage]:
    """Keep the last ``max_turns`` user/assistant turns, then enforce a
    cumulative ``max_chars`` budget walking back from the end.
    """
    pairs: list[ChatMessage] = [m for m in messages if m.role in ("user", "assistant")]
    if len(pairs) > max_turns * 2:
        pairs = pairs[-max_turns * 2:]

    used = 0
    kept_reversed: list[ChatMessage] = []
    for m in reversed(pairs):
        cost = len(m.content)
        if used + cost > max_chars and kept_reversed:
            # If even ONE message alone is over budget, keep it (truncating
            # would lose more than we gain in budget realism).
            break
        kept_reversed.append(m)
        used += cost
    return list(reversed(kept_reversed))


def _tool_runs_ledger(messages: list[ChatMessage]) -> str:
    """Build a markdown summary of tool runs persisted on prior assistant
    turns. Entries look like ``- T{n} {tool_id} exit={code} run={run_id[:8]}``.
    Returns ``""`` if no prior turn carries tool_calls.
    """
    rows: list[str] = []
    turn_no = 0
    for m in messages:
        if m.role != "assistant" or not m.tool_calls:
            continue
        turn_no += 1
        for call in m.tool_calls:
            if not isinstance(call, dict):
                continue
            tool_id = call.get("tool_id", "?")
            run_id = call.get("run_id") or "-"
            exit_code = call.get("exit_code")
            refused = call.get("refused")
            error = call.get("error")
            if refused:
                rows.append(
                    f"- T{turn_no} {tool_id} REFUSED ({call.get('reason','?')})"
                )
            elif error:
                err_short = (error[:120] + "…") if len(error) > 120 else error
                rows.append(f"- T{turn_no} {tool_id} ERROR: {err_short}")
            else:
                tag = f"exit={exit_code}" if exit_code is not None else "exit=?"
                rows.append(f"- T{turn_no} {tool_id} {tag} run={run_id[:8]}")
            if len(rows) >= MAX_LEDGER_ENTRIES:
                rows.append(f"- (older entries omitted — kept last {MAX_LEDGER_ENTRIES})")
                break
        if len(rows) >= MAX_LEDGER_ENTRIES:
            break

    if not rows:
        return ""

    return (
        "## Tool runs so far (this chat session)\n"
        "Cada línea es una invocación que YA HICISTE — no repitas exactamente "
        "los mismos `{tool_id, params}`. Las entradas con `exit=0` produjeron "
        "artefactos que ya están en disco; las que fallaron (`exit!=0` o "
        "`ERROR`) ya descartaste el camino — no las reintentes a ciegas.\n\n"
        + "\n".join(rows)
    )


def _findings_ledger(case_id: str) -> str:
    """Build a markdown list of structured findings persisted via record_finding."""
    try:
        findings: list[Finding] = finding_store.list(case_id)
    except (KeyError, OSError):
        return ""
    if not findings:
        return ""

    # Most recent first; cap.
    findings = list(findings)[-MAX_FINDINGS_ENTRIES:]
    rows = [
        f"- `{f.id}` [{f.severity}] {f.title}"
        + (f" (tool={f.tool_id})" if f.tool_id else "")
        for f in findings
    ]
    return (
        "## Findings so far (este caso)\n"
        "Estos hallazgos YA están registrados por turnos previos tuyos. Tómalos "
        "como base — no los re-deduzcas. Construye sobre ellos.\n"
        "El id entre backticks es el `finding_id` REAL: úsalo tal cual en "
        "`annotate_mitre(finding_id, …)` para anclar técnicas ATT&CK a un hallazgo "
        "existente. NUNCA inventes un finding_id — si no está en esta lista, no "
        "existe.\n\n"
        + "\n".join(rows)
    )


__all__ = ["build_replay_messages"]
