"""Per-case executor cost/token stats, aggregated from the append-only audit log.

Read-only view (Bug 008 / §2 «Coste de tokens», Nivel 0): how many prompts each
executor ran in a case and how many tokens / how much cost they billed. Source of
truth is ``case_dir/audit.jsonl`` — the ``executor_run_finish`` events carry
``executor``, ``prompt_chars``/``response_chars`` and, when the executor's envelope
reported them, ``input_tokens`` / ``output_tokens`` / ``cost_usd``
(FORENSIC INVARIANT 4). Cumulative across every chat session of the case.

Since 2026-07-29 those events also carry the prompt-cache split
(``cache_creation_input_tokens`` / ``cache_read_input_tokens`` /
``total_input_tokens``). **``total_tokens`` is built on ``total_input_tokens``, not
on ``input_tokens``**: on a cache-aware executor the latter is only the uncached
remainder, and reading it as the prompt size understated Agentopsy's real input by
~15× (``docs/diseno/tokens-2026-07/diagnostico.md`` §1.1) — which is what made the
pre-flight estimate wrong. Events appended before that date carry no cache keys and
fall back to ``input_tokens``, so historical rows keep exactly the meaning they had
when they were written (the log is append-only; nothing is rewritten).

This is also the experimental datum for the TFM: token/cost per case and executor
is a direct, comparable metric across the four executors.

An executor that does not report a datum contributes ``None`` for it — the
aggregate distinguishes "not reported" from a real zero via ``runs_with_tokens``.
"""

from __future__ import annotations

import json
from typing import Any

from forensia.cases.manager import case_manager


def executor_cost(case_id: str) -> list[dict[str, Any]]:
    """Return ``[{executor, runs, runs_with_tokens, input_tokens, output_tokens,
    total_tokens, cost_usd, response_chars}]`` sorted by most-used first.

    Raises ``ValueError`` for a malformed ``case_id`` (422 at the router); a case
    with no audit log yet returns an empty list.
    """
    case_dir = case_manager.case_dir(case_id)
    audit = case_dir / "audit.jsonl"
    if not audit.is_file():
        return []

    stats: dict[str, dict[str, Any]] = {}
    for raw in audit.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if event.get("action") != "executor_run_finish":
            continue
        executor = event.get("executor")
        if not isinstance(executor, str) or not executor:
            continue
        # Only successful runs (those with a response) count toward totals; error
        # finishes carry no usage.
        if "response_chars" not in event:
            continue

        entry = stats.setdefault(executor, {
            "executor": executor,
            "runs": 0,
            "runs_with_tokens": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0,
            "total_input_tokens": 0,
            "total_tokens": 0,
            "cost_usd": 0.0,
            "response_chars": 0,
        })
        entry["runs"] += 1
        entry["response_chars"] += _int(event.get("response_chars"))

        input_tok = event.get("input_tokens")
        output_tok = event.get("output_tokens")
        if input_tok is not None or output_tok is not None:
            entry["runs_with_tokens"] += 1
            entry["input_tokens"] += _int(input_tok)
            entry["output_tokens"] += _int(output_tok)
            entry["cache_creation_input_tokens"] += _int(
                event.get("cache_creation_input_tokens")
            )
            entry["cache_read_input_tokens"] += _int(event.get("cache_read_input_tokens"))
            # The REAL prompt size. `input_tokens` alone is the uncached remainder
            # on a cache-aware executor, which understated Agentopsy's own input by
            # ~15× (docs/diseno/tokens-2026-07/diagnostico.md §1.1) and is what made
            # the pre-flight estimate wrong. Events written before 2026-07-29 carry
            # no `total_input_tokens`, so they fall back to `input_tokens` and keep
            # exactly their previous meaning — the aggregate stays readable across
            # the append-only history (FORENSIC INVARIANT 4: nothing is rewritten).
            total_in = event.get("total_input_tokens")
            total_in = _int(total_in) if total_in is not None else _int(input_tok)
            entry["total_input_tokens"] += total_in
            entry["total_tokens"] += total_in + _int(output_tok)
        cost = event.get("cost_usd")
        if cost is not None:
            entry["cost_usd"] += _float(cost)

    out = sorted(stats.values(), key=lambda s: (-s["runs"], s["executor"]))
    # Round cost so a sum of floats doesn't surface 0.30000000000000004.
    for entry in out:
        entry["cost_usd"] = round(entry["cost_usd"], 6)
    return out


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _float(value: Any) -> float:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0.0
