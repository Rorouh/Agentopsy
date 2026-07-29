"""Permanent regression guard on prompt-cache reuse.

The whole saving of ``docs/diseno/tokens-2026-07/plan.md`` Fase 1 rests on
something Agentopsy does not control: where Claude Code places its cache
breakpoints, an internal detail of the CLI. A version bump can silently move
them, and the symptom — the analysis still works, it just costs 3-4× more —
is invisible from the outside until it reaches the bill. So the system watches
its own cache behaviour and says so when it degrades.

The signal is measured, not assumed. Verified 2026-07-29 on ``claude`` 2.1.220,
three consecutive resumed turns:

    turn 1   cache_creation 6068   cache_read  5033
    turn 2   cache_creation   69   cache_read 11101   ( = 5033 + 6068 )
    turn 3   cache_creation  301   cache_read 11170   ( = 11101 + 69  )

A healthy reused session therefore shows ``cache_read`` GROWING every turn while
``cache_creation`` collapses to the size of the delta. Flat ``cache_read`` across
several turns means the prefix is being rewritten instead of reused — which is
precisely the pathology the diagnostic measured before the fix (``cache_read``
pinned at 9051 for 22 turns while ~28k tokens were rewritten each turn).

**This is a COST signal, not a correctness signal.** A cold cache costs money; it
does not corrupt the analysis. Content integrity is a different question with a
different mechanism and different consequences — see
``forensia.executors.session_guard``. The two are kept apart on purpose: a
degraded cache must never be mistaken for a diverged session, nor the reverse.

Pure logic, no I/O (RULE 3): ``observe`` returns the warning text and the caller
owns logging and the audit write.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from forensia.executors.base import Usage

#: Consecutive non-growing turns tolerated before warning. One flat turn is
#: ordinary (a turn whose delta was tiny can round to no new cached prefix); a
#: sustained run of them is a regression.
DEFAULT_STALL_THRESHOLD = 3


@dataclass
class CacheHealthMonitor:
    """Tracks ``cache_read`` growth across the turns of ONE analysis run.

    Stateful by design (it compares against the previous turn) and scoped to a
    single run, so nothing leaks between cases.
    """

    stall_threshold: int = DEFAULT_STALL_THRESHOLD
    _previous_read: int | None = None
    _previous_creation: int | None = None
    _stalled_turns: int = 0
    _warned: bool = False
    #: Per-turn record, for the run summary. Never contains case content.
    history: list[dict[str, Any]] = field(default_factory=list)

    def observe(
        self,
        usage: Usage | None,
        *,
        session_active: bool,
        turn: int,
    ) -> str | None:
        """Record one turn; return an actionable warning the first time the
        cache looks broken, else ``None``.

        Only meaningful while a session is being reused: without a session every
        turn is a cold start by construction and a flat ``cache_read`` is the
        expected behaviour, not a regression — warning there would be noise.
        """
        if usage is None or not session_active:
            self._previous_read = None
            self._previous_creation = None
            self._stalled_turns = 0
            return None

        read = usage.cache_read_input_tokens
        creation = usage.cache_creation_input_tokens
        if read is None:
            # The executor does not report cache accounting: there is nothing to
            # watch. Silence beats a warning we cannot substantiate (RULE 2).
            return None

        previous_read = self._previous_read
        grew = previous_read is None or read > previous_read
        self.history.append(
            {
                "turn": turn,
                "cache_read": read,
                "cache_creation": creation,
                "grew": grew,
            }
        )

        if grew:
            self._stalled_turns = 0
        else:
            self._stalled_turns += 1

        self._previous_read = read
        self._previous_creation = creation

        if self._stalled_turns >= self.stall_threshold and not self._warned:
            self._warned = True
            return (
                f"La caché de prompt no está creciendo: cache_read lleva "
                f"{self._stalled_turns} turnos consecutivos sin aumentar "
                f"(sigue en {read} tokens) pese a haber sesión reutilizada. "
                "El prefijo se está reescribiendo en cada turno en vez de "
                "reutilizarse, lo que multiplica el coste de entrada sin "
                "cambiar el resultado del análisis. Causa más probable: una "
                "actualización del CLI ha movido sus puntos de corte de caché. "
                "Comprueba la versión del ejecutor y revisa "
                "docs/diseno/tokens-2026-07/diagnostico.md antes de lanzar "
                "análisis largos."
            )
        return None

    def summary(self) -> dict[str, Any]:
        """Flat, JSON-serialisable state for the run's audit event."""
        return {
            "turns_observed": len(self.history),
            "cache_stalled_turns": self._stalled_turns,
            "cache_regression_warned": self._warned,
        }
