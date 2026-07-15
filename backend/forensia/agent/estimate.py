"""Pre-flight estimate of an analysis run: iterations, tokens, cost and time.

Today an analysis is launched blind. A real disk analysis takes minutes and a
cloud-backed executor bills the operator's own account, so the operator deserves
an HONEST heads-up BEFORE pressing go. This module produces exactly that: a
**range with declared assumptions**, never a fake number with false precision
(CLAUDE.md RULE 2). Pure logic, no I/O side effects — the router is a thin
adapter over ``estimate_analysis`` (RULE 3).

How the estimate is grounded (the ``basis`` axis, per quantity):

- **Tokens / cost** — if the case already has history for this executor
  (``forensia.executors.cost.executor_cost``: real tokens billed per successful
  run, from the audit log), the per-iteration figure is anchored on that real
  average. Otherwise it falls back to a documented heuristic (``HEUR_*``). The
  chosen basis travels in the payload so the UI can say which it used.
- **Time** — anchored on the observed average ``duration_ms`` of this executor's
  runs in the case audit when present, else a documented heuristic.
- **Cost tariff** — tokens × the executor's published rate. For a LOCAL executor
  (Ollama) the monetary cost is exactly ``0`` ("local, sin coste monetario").
  For a cloud executor we only apply a rate we can cite (``TARIFFS``); when no
  published rate is wired for that executor the cost is reported
  ``available: false`` with an actionable note — we never invent a tariff
  (RULE 2). The rate is the provider's public *API* price: under a CLI
  subscription the marginal cost may well be 0, which the disclaimer states.

A missing/invalid ``executor_id`` fails loud (``ValueError`` → 422 at the
router): FORENSIA never guesses "the local one" (RULE 2).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from forensia.cases.manager import case_manager
from forensia.evidence import evidence_manager, human_readable_size
from forensia.executors import get_executor
from forensia.executors.cost import executor_cost

# ── Heuristic constants (the fallback when the case has no history) ───────────
# These are DECLARED ASSUMPTIONS, not measurements. They are deliberately coarse
# and surfaced verbatim in the payload so a reviewer can judge them.

#: Iterations of the agent tool-use loop for a typical analysis. The loop's hard
#: safety cap is the package's ``max_iterations`` (commonly 8; see
#: ``forensia.agent.agent.run``); the trained playbooks pin fixed pipelines that
#: run a handful of tools. We express the uncertainty as a range.
ITER_MIN = 4
ITER_MAX = 10

#: Tokens (input + output combined) the executor bills PER loop iteration when we
#: have no history to anchor on. ~4k of prompt/context replayed each turn + ~1k
#: of model output is the working assumption.
HEUR_TOKENS_PER_ITER = 5000

#: Wall-clock seconds PER iteration when we have no history. Dominated by the
#: forensic tool runtime inside the maletín, NOT the model latency — a full disk
#: analysis can exceed 7 minutes, so the per-iteration figure is generous and the
#: iteration range widens it further.
HEUR_SECONDS_PER_ITER = 25.0

#: When we must split a combined token count into input/output for costing and
#: history didn't report the split, assume this fraction is input (context replay
#: dominates, so most tokens are input).
INPUT_FRACTION_DEFAULT = 0.8


@dataclass(frozen=True)
class TariffRate:
    """A published per-token price for a cloud executor. ``source`` is the
    citation — no rate ships without one (RULE 2: honesty over a guessed number)."""

    assumed_model: str
    input_usd_per_mtok: float
    output_usd_per_mtok: float
    source: str


#: Published API tariffs we are willing to CITE, keyed by executor id. A cloud
#: executor absent from this table reports cost ``available: false`` — we do not
#: fabricate OpenAI/Google pricing we can't cite. Ollama is local (cost 0) and is
#: intentionally NOT here. Extend this table (with a citable ``source``) to wire a
#: new executor's tariff.
TARIFFS: dict[str, TariffRate] = {
    # Claude Code drives a Claude model; its default is a Sonnet-class model.
    # Anthropic's public API price for Claude Sonnet is $3 / $15 per 1M tokens
    # (input / output). This is the "if billed at API rates" basis; under a Claude
    # Code subscription the marginal per-token cost to the operator may be 0 — the
    # disclaimer says so.
    "claude-code": TariffRate(
        assumed_model="Claude (Sonnet-class, el modelo por defecto de Claude Code)",
        input_usd_per_mtok=3.0,
        output_usd_per_mtok=15.0,
        source="Tarifa pública de la API de Anthropic para Claude Sonnet: "
        "3 USD / 15 USD por millón de tokens (entrada / salida).",
    ),
}

DISCLAIMER = (
    "Estimación ORIENTATIVA con supuestos declarados, no un presupuesto. Los "
    "rangos salen del histórico real del caso cuando existe (media por ejecución "
    "en el audit) y, si no, de una heurística documentada. El coste monetario "
    "asume la tarifa PÚBLICA de API del proveedor; bajo una suscripción de la CLI "
    "el coste marginal puede ser 0. Un análisis de disco real puede superar los "
    "7 minutos según el tamaño de la evidencia."
)


def estimate_analysis(
    case_id: str,
    executor_id: str,
    evidence_id: str | None = None,
) -> dict[str, Any]:
    """Return an honest pre-flight estimate for one analysis run.

    Ranges for iterations, tokens, monetary cost and time, each tagged with the
    ``basis`` it rests on. ``executor_id`` is REQUIRED and validated against the
    closed enum — an unknown id raises ``ValueError`` (FORENSIA never substitutes
    a default, RULE 2). Unknown ``case_id`` / ``evidence_id`` raise ``KeyError``;
    a malformed one raises ``ValueError`` (the router maps these to 404 / 422).
    """
    # RULE 2: no silent default — validate the operator's choice, fail loud.
    executor = get_executor(executor_id)  # ValueError on unknown id

    # Optional evidence enrichment (size drives real tool runtime). If provided it
    # must be valid — fail loud rather than silently ignore a bad id (RULE 2).
    evidence_size_bytes: int | None = None
    evidence_size_human: str | None = None
    if evidence_id:
        meta = evidence_manager.metadata(case_id, evidence_id)  # KeyError/ValueError
        evidence_size_bytes = int(meta["size_bytes"])
        evidence_size_human = human_readable_size(evidence_size_bytes)

    # History for THIS executor in THIS case (real tokens billed per run).
    history = _history_for(case_id, executor_id)  # KeyError/ValueError on bad case

    iterations = {"min": ITER_MIN, "max": ITER_MAX}
    tokens = _estimate_tokens(history)
    time_seconds = _estimate_time(case_id, executor_id)
    cost = _estimate_cost(executor_id, executor.is_local, tokens, history)

    basis = _basis_summary(tokens["basis"], time_seconds["basis"], cost)

    return {
        "case_id": case_id,
        "executor": {
            "id": executor.id,
            "name": executor.name,
            "local": executor.is_local,
        },
        "evidence_id": evidence_id,
        "evidence_size_bytes": evidence_size_bytes,
        "evidence_size_human": evidence_size_human,
        "iterations": iterations,
        "tokens": tokens,
        "cost_usd": cost,
        "time_seconds": time_seconds,
        "basis": basis,
        "disclaimer": DISCLAIMER,
    }


# ── internals ────────────────────────────────────────────────────────────────


def _history_for(case_id: str, executor_id: str) -> dict[str, Any] | None:
    """The ``executor_cost`` aggregate row for this executor, or ``None`` if the
    case has no counted runs for it. Propagates KeyError/ValueError for a bad
    case_id (the sanctioned aggregator owns that validation)."""
    for row in executor_cost(case_id):
        if row.get("executor") == executor_id:
            return row
    return None


def _estimate_tokens(history: dict[str, Any] | None) -> dict[str, Any]:
    """Per-iteration token estimate × the iteration range.

    Anchored on the case's real average tokens-per-run for this executor when the
    history reported any (``runs_with_tokens`` > 0); otherwise the documented
    heuristic. The range is driven purely by the iteration uncertainty — we do
    NOT invent a second spread factor on top (that would fake precision)."""
    if history and history.get("runs_with_tokens", 0) > 0:
        per_iter = round(history["total_tokens"] / history["runs_with_tokens"])
        basis = "history"
    else:
        per_iter = HEUR_TOKENS_PER_ITER
        basis = "heuristic"
    return {
        "min": ITER_MIN * per_iter,
        "max": ITER_MAX * per_iter,
        "per_iteration": per_iter,
        "basis": basis,
    }


def _estimate_time(case_id: str, executor_id: str) -> dict[str, Any]:
    """Per-iteration seconds × the iteration range, anchored on observed
    ``duration_ms`` of this executor's runs when the audit has any."""
    avg_ms = _avg_duration_ms(case_id, executor_id)
    if avg_ms is not None:
        per_iter = round(avg_ms / 1000.0, 1)
        basis = "history"
    else:
        per_iter = HEUR_SECONDS_PER_ITER
        basis = "heuristic"
    return {
        "min": round(ITER_MIN * per_iter),
        "max": round(ITER_MAX * per_iter),
        "per_iteration": per_iter,
        "basis": basis,
    }


def _avg_duration_ms(case_id: str, executor_id: str) -> float | None:
    """Mean ``duration_ms`` over this executor's successful ``executor_run_finish``
    events in the case audit, or ``None`` if there are none. Reads the audit
    directly because ``executor_cost`` doesn't surface duration."""
    case_dir = case_manager.case_dir(case_id)  # KeyError/ValueError on bad case
    audit = case_dir / "audit.jsonl"
    if not audit.is_file():
        return None
    total = 0.0
    count = 0
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
        if event.get("executor") != executor_id:
            continue
        # Only successful runs carry a response; error finishes are not
        # representative of an iteration's cost.
        if "response_chars" not in event:
            continue
        dur = event.get("duration_ms")
        if isinstance(dur, (int, float)) and not isinstance(dur, bool) and dur >= 0:
            total += float(dur)
            count += 1
    return (total / count) if count else None


def _estimate_cost(
    executor_id: str,
    is_local: bool,
    tokens: dict[str, Any],
    history: dict[str, Any] | None,
) -> dict[str, Any]:
    """Monetary cost range from the token range × the executor's tariff.

    - Local executor (Ollama) → exactly 0, labelled honestly.
    - Cloud executor with a wired, citable tariff → tokens × rate.
    - Cloud executor without a tariff → ``available: false`` + actionable note
      (RULE 2: never a fabricated price)."""
    if is_local:
        return {
            "available": True,
            "min": 0.0,
            "max": 0.0,
            "currency": "USD",
            "label": "local, sin coste monetario",
            "tariff": None,
            "note": None,
        }

    rate = TARIFFS.get(executor_id)
    if rate is None:
        return {
            "available": False,
            "min": None,
            "max": None,
            "currency": "USD",
            "label": None,
            "tariff": None,
            "note": (
                f"No hay tarifa pública configurada para el ejecutor '{executor_id}'. "
                "El coste depende del plan/tarifa del proveedor; FORENSIA no inventa "
                "un precio (RULE 2)."
            ),
        }

    # Split each token bound into input/output. Prefer the case's real split when
    # history reported both; else the documented default fraction.
    input_fraction = INPUT_FRACTION_DEFAULT
    if history and history.get("input_tokens", 0) + history.get("output_tokens", 0) > 0:
        input_fraction = history["input_tokens"] / (
            history["input_tokens"] + history["output_tokens"]
        )

    def _cost(total_tokens: int) -> float:
        input_tok = total_tokens * input_fraction
        output_tok = total_tokens * (1.0 - input_fraction)
        usd = (
            input_tok / 1_000_000 * rate.input_usd_per_mtok
            + output_tok / 1_000_000 * rate.output_usd_per_mtok
        )
        return round(usd, 4)

    return {
        "available": True,
        "min": _cost(tokens["min"]),
        "max": _cost(tokens["max"]),
        "currency": "USD",
        "label": None,
        "tariff": {
            "assumed_model": rate.assumed_model,
            "input_usd_per_mtok": rate.input_usd_per_mtok,
            "output_usd_per_mtok": rate.output_usd_per_mtok,
            "source": rate.source,
        },
        "note": None,
    }


def _basis_summary(tokens_basis: str, time_basis: str, cost: dict[str, Any]) -> str:
    """One-line, human summary of what the estimate rests on."""
    def _word(b: str) -> str:
        return "histórico del caso" if b == "history" else "heurística por defecto"

    parts = [
        f"tokens: {_word(tokens_basis)}",
        f"tiempo: {_word(time_basis)}",
    ]
    if not cost["available"]:
        parts.append("coste: tarifa no disponible")
    elif cost["tariff"] is None:
        parts.append("coste: local (0)")
    else:
        parts.append("coste: tarifa pública de API")
    return "; ".join(parts) + "."
