"""Content-integrity guard for a REUSED CLI session (``claude -p --resume``).

Why this module exists
----------------------
Sending only the DELTA into a reused session is what makes an Agentopsy analysis
cost what a terminal session costs (``docs/diseno/tokens-2026-07/plan.md`` Fase 1,
−72 % measured). It is also the single most dangerous change in that plan: a
delta that lands in a session whose history is NOT Agentopsy's canonical message
list makes the model reason over evidence **it believes it saw and did not see**.
In a forensic tool that is strictly worse than spending tokens.

So the delta is not sent on trust. It is sent only when Agentopsy can ACCOUNT for
the session, and "account for" is three deterministic checks against facts the
CLI actually exposes — never an assumption:

1. **The CLI added no turns of its own.** ``num_turns`` in the JSON envelope is
   the number of turns that ONE call put into the session. Agentopsy authors
   exactly one. Measured 2026-07-29 (``claude`` 2.1.220): with a tool enabled a
   single call reported ``num_turns=3`` and the session gained
   ``assistant:tool_use`` / ``user:tool_result`` rows Agentopsy never wrote.
2. **The session was not compacted.** Claude Code compacts long sessions by
   REPLACING history with a model-generated summary; real sessions on disk carry
   ``{"type":"system","subtype":"compact_boundary"}`` with
   ``compactMetadata.cumulativeDroppedTokens`` in the millions. That is exactly
   the lossy summarisation the plan discarded by design (a summary can drop a
   ``run_id`` or a SHA-256, and then a ``Finding`` cannot anchor its provenance)
   — the difference is that the CLI can impose it unilaterally, so it must be
   DETECTED rather than merely avoided.
3. **The transcript holds what Agentopsy wrote, and only that.** The on-disk
   session file is parsed and its authored prompts counted against the number
   Agentopsy actually sent.

Any check that fails — or that cannot be RUN — returns ``can_send_delta=False``.
The caller then reopens with FULL context and audits the reason. That is a
fallback of *content* (send more, never less) and it is recorded, never silent
(RULE 2). There is deliberately no "assume it went well" branch: an
unverifiable session is treated exactly like a diverged one.

Pure logic, no printing and no process spawning (RULE 3): the caller supplies the
envelope facts and owns the audit write.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Where Claude Code persists session transcripts. Under the compose the api
#: container's HOME *is* the ``forensia-cli-auth`` volume, so this resolves
#: inside the stack exactly as it does on a developer host.
SESSION_ROOT = Path.home() / ".claude" / "projects"

#: Row marker Claude Code writes when it compacts a conversation (verified
#: 2026-07-29 across real session files: ``subtype`` on a ``type: "system"`` row,
#: alongside ``isCompactSummary`` on the injected summary message).
_COMPACT_SUBTYPE = "compact_boundary"
_COMPACT_SUMMARY_KEY = "isCompactSummary"


@dataclass(frozen=True)
class SessionVerdict:
    """Whether a delta may be sent into ``session_id``, and the evidence for it.

    ``checks`` is a flat, JSON-serialisable record of what was actually verified.
    It goes into the audit event so a reviewer can see WHY a turn ran as a delta
    or as full context — this guard adds traceability, it never removes any
    (FORENSIC INVARIANT 4).
    """

    can_send_delta: bool
    #: Actionable Spanish sentence when ``can_send_delta`` is False. None otherwise.
    reason: str | None = None
    checks: dict[str, Any] = field(default_factory=dict)


def find_transcript(session_id: str, root: Path | None = None) -> Path | None:
    """The on-disk transcript for ``session_id``, or ``None`` if not found.

    Located by GLOB on the session id rather than by recomputing Claude Code's
    per-cwd directory slug. The id is a UUID and therefore unique across
    projects, so the glob is exact — and it stays correct if the CLI ever changes
    how it derives that directory name (it lowercases and folds ``_`` and ``/``
    alike, an internal detail we deliberately do not depend on).
    """
    base = root or SESSION_ROOT
    if not base.is_dir():
        return None
    for candidate in base.glob(f"*/{session_id}.jsonl"):
        if candidate.is_file():
            return candidate
    return None


def _read_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _block_types(row: dict[str, Any]) -> list[str]:
    message = row.get("message")
    if not isinstance(message, dict):
        return []
    content = message.get("content")
    if isinstance(content, str):
        return ["text"]
    if isinstance(content, list):
        return [b.get("type", "?") for b in content if isinstance(b, dict)]
    return []


def inspect_transcript(path: Path) -> dict[str, Any]:
    """Facts about a session transcript, as counts — never an interpretation.

    ``authored_prompts`` counts the USER turns a caller actually wrote: rows of
    type ``user`` carrying text, excluding tool results (which the CLI writes when
    it runs its own tools), excluding compaction summaries, and excluding meta
    rows. ``cli_tool_calls`` counts ``tool_use`` blocks — with Agentopsy's own
    tools disallowed this must be 0, because Agentopsy executes forensic tools
    itself and only ever asks the model for a JSON decision.
    """
    rows = _read_rows(path)
    authored = 0
    tool_calls = 0
    tool_results = 0
    compacted = False
    for row in rows:
        if row.get("type") == "system" and row.get("subtype") == _COMPACT_SUBTYPE:
            compacted = True
            continue
        if row.get(_COMPACT_SUMMARY_KEY):
            compacted = True
            continue
        if row.get("isMeta") or row.get("isSidechain"):
            continue
        blocks = _block_types(row)
        if row.get("type") == "user":
            if "tool_result" in blocks:
                tool_results += 1
            elif blocks:
                authored += 1
        elif row.get("type") == "assistant":
            tool_calls += sum(1 for b in blocks if b == "tool_use")
    return {
        "rows": len(rows),
        "authored_prompts": authored,
        "cli_tool_calls": tool_calls,
        "cli_tool_results": tool_results,
        "compacted": compacted,
    }


def verify_session(
    session_id: str | None,
    *,
    expected_prompts: int,
    num_turns: int | None,
    root: Path | None = None,
) -> SessionVerdict:
    """Decide whether a delta may be sent into ``session_id``.

    ``expected_prompts`` is how many prompts Agentopsy has itself sent into this
    session so far (including the one just answered). ``num_turns`` is the value
    the last envelope reported.

    Returns ``can_send_delta=False`` — with an actionable reason — whenever the
    session is diverged OR simply cannot be verified. Both cases are handled the
    same way on purpose: an unverifiable session is not a safe session.
    """
    checks: dict[str, Any] = {
        "session_id": session_id,
        "expected_prompts": expected_prompts,
        "num_turns": num_turns,
    }

    if not session_id:
        return SessionVerdict(
            False,
            "El ejecutor no devolvió un session_id, así que no hay sesión que "
            "reanudar. Se envía el contexto completo.",
            checks,
        )

    # 1) The CLI must not have appended turns Agentopsy did not author.
    if num_turns is None:
        return SessionVerdict(
            False,
            "El ejecutor no informó num_turns, así que Agentopsy no puede "
            "descartar que el CLI añadiera turnos propios a la sesión. Se envía "
            "el contexto completo.",
            checks,
        )
    if num_turns != 1:
        return SessionVerdict(
            False,
            f"El CLI registró {num_turns} turnos en la sesión para una sola "
            "llamada de Agentopsy: la sesión contiene turnos que Agentopsy no ha "
            "escrito y su historial ya no coincide con la lista canónica. Se "
            "reabre con el contexto completo.",
            checks,
        )

    # 2) + 3) The transcript on disk must exist and hold exactly what we wrote.
    path = find_transcript(session_id, root)
    checks["transcript_found"] = path is not None
    if path is None:
        return SessionVerdict(
            False,
            "No se encuentra el fichero de sesión del CLI, así que Agentopsy no "
            "puede verificar su contenido. Se envía el contexto completo.",
            checks,
        )
    checks["transcript_path"] = str(path)

    try:
        facts = inspect_transcript(path)
    except OSError as exc:
        checks["transcript_error"] = str(exc)
        return SessionVerdict(
            False,
            f"No se pudo leer el fichero de sesión del CLI ({exc}). Se envía el "
            "contexto completo.",
            checks,
        )
    checks.update(facts)

    if facts["compacted"]:
        return SessionVerdict(
            False,
            "El CLI ha COMPACTADO la sesión: ha sustituido parte del historial "
            "por un resumen generado por el modelo, que puede haber perdido un "
            "run_id o un SHA-256 y romper la procedencia de un hallazgo. Se "
            "reabre la sesión con el contexto completo.",
            checks,
        )

    if facts["cli_tool_calls"]:
        return SessionVerdict(
            False,
            f"La sesión contiene {facts['cli_tool_calls']} llamadas a "
            "herramientas propias del CLI, que Agentopsy no ha ejecutado ni "
            "auditado. Se reabre con el contexto completo.",
            checks,
        )

    if facts["authored_prompts"] != expected_prompts:
        return SessionVerdict(
            False,
            f"La sesión contiene {facts['authored_prompts']} prompts y Agentopsy "
            f"ha enviado {expected_prompts}: el historial no coincide con la "
            "lista canónica. Se reabre con el contexto completo.",
            checks,
        )

    return SessionVerdict(True, None, checks)
