"""Estimación pre-vuelo del análisis (hallazgo E).

Los gates que importan:
- Con histórico del caso, tokens/tiempo se anclan en la media REAL por ejecución
  del ejecutor (mucho mejor que un número inventado); `basis == "history"`.
- Sin histórico, cae a la heurística documentada; `basis == "heuristic"`.
- Ollama (local) → coste monetario exactamente 0, etiquetado con honestidad.
- Un ejecutor cloud sin tarifa cableada → coste `available: false` (RULE 2: no
  se inventa un precio), nunca un número fabricado.
- Un ejecutor inexistente → error accionable (RULE 2: no se elige "el local").
"""

from __future__ import annotations

from forensia.agent import estimate as estimate_mod
from forensia.agent.estimate import (
    HEUR_TOKENS_PER_ITER,
    ITER_MAX,
    ITER_MIN,
    estimate_analysis,
)
from forensia.audit.log import AuditLog
from forensia.executors import cost as cost_mod


def _patch_cases(monkeypatch, tmp_path):
    """Apunta el CaseManager de cost y estimate al mismo root temporal."""
    from forensia.cases import CaseManager

    cases = CaseManager(root=tmp_path / "cases")
    monkeypatch.setattr(cost_mod, "case_manager", cases)
    monkeypatch.setattr(estimate_mod, "case_manager", cases)
    return cases


def _finish(executor: str, **extra) -> dict:
    ev = {
        "action": "executor_run_finish",
        "executor": executor,
        "case_id": "c",
        "exit_code": None,
        "duration_ms": 20,
        "response_sha256": "x",
        "response_chars": 100,
    }
    ev.update(extra)
    return ev


# ── ejecutor inexistente ─────────────────────────────────────────────────────


def test_unknown_executor_fails_loud(tmp_path, monkeypatch) -> None:
    _patch_cases(monkeypatch, tmp_path)
    try:
        estimate_analysis(case_id="whatever", executor_id="not-an-executor")
        raise AssertionError("debería fallar por ejecutor desconocido")
    except ValueError as exc:
        assert "not-an-executor" in str(exc)


# ── sin histórico → heurística ───────────────────────────────────────────────


def test_no_history_uses_documented_heuristic(tmp_path, monkeypatch) -> None:
    cases = _patch_cases(monkeypatch, tmp_path)
    case = cases.create(name="c", examiner="e", os_profile="windows")

    est = estimate_analysis(case_id=case.id, executor_id="claude-code")

    assert est["tokens"]["basis"] == "heuristic"
    assert est["tokens"]["per_iteration"] == HEUR_TOKENS_PER_ITER
    assert est["tokens"]["min"] == ITER_MIN * HEUR_TOKENS_PER_ITER
    assert est["tokens"]["max"] == ITER_MAX * HEUR_TOKENS_PER_ITER
    assert est["time_seconds"]["basis"] == "heuristic"
    assert est["iterations"] == {"min": ITER_MIN, "max": ITER_MAX}
    # claude-code SÍ tiene tarifa cableada → coste disponible aún sin histórico.
    assert est["cost_usd"]["available"] is True
    assert est["cost_usd"]["max"] > est["cost_usd"]["min"] > 0
    assert est["disclaimer"]


# ── con histórico → anclado en la media real ─────────────────────────────────


def test_history_anchors_tokens_time_and_cost(tmp_path, monkeypatch) -> None:
    cases = _patch_cases(monkeypatch, tmp_path)
    case = cases.create(name="c", examiner="e", os_profile="windows")
    audit = AuditLog(cases.case_dir(case.id) / "audit.jsonl")
    # Dos ejecuciones con tokens y duración: media 1500 tokens/exec, 30 ms/exec.
    audit.append(_finish("claude-code", input_tokens=1000, output_tokens=200, duration_ms=20))
    audit.append(_finish("claude-code", input_tokens=1500, output_tokens=300, duration_ms=40))

    est = estimate_analysis(case_id=case.id, executor_id="claude-code")

    # total_tokens=3000 en 2 runs → 1500 por iteración (real, no inventado).
    assert est["tokens"]["basis"] == "history"
    assert est["tokens"]["per_iteration"] == 1500
    assert est["tokens"]["min"] == ITER_MIN * 1500
    # tiempo: media (20+40)/2 = 30 ms → 0.03 s por iteración.
    assert est["time_seconds"]["basis"] == "history"
    assert est["time_seconds"]["per_iteration"] == 0.0  # round(0.03,1) == 0.0
    # coste con la tarifa pública cableada de claude-code.
    assert est["cost_usd"]["available"] is True
    assert est["cost_usd"]["tariff"]["input_usd_per_mtok"] == 3.0
    assert est["cost_usd"]["tariff"]["source"]
    assert "histórico del caso" in est["basis"]


# ── Ollama: local, coste 0 ───────────────────────────────────────────────────


def test_ollama_local_cost_is_zero(tmp_path, monkeypatch) -> None:
    cases = _patch_cases(monkeypatch, tmp_path)
    case = cases.create(name="c", examiner="e", os_profile="unix")

    est = estimate_analysis(case_id=case.id, executor_id="ollama")

    assert est["executor"]["local"] is True
    assert est["cost_usd"]["available"] is True
    assert est["cost_usd"]["min"] == 0.0
    assert est["cost_usd"]["max"] == 0.0
    assert "local" in est["cost_usd"]["label"]
    assert est["cost_usd"]["tariff"] is None


# ── ejecutor cloud sin tarifa → coste no disponible (no se inventa) ──────────


def test_cloud_without_tariff_reports_unavailable(tmp_path, monkeypatch) -> None:
    cases = _patch_cases(monkeypatch, tmp_path)
    case = cases.create(name="c", examiner="e", os_profile="unix")

    est = estimate_analysis(case_id=case.id, executor_id="gemini")

    assert est["executor"]["local"] is False
    assert est["cost_usd"]["available"] is False
    assert est["cost_usd"]["min"] is None
    assert "no inventa" in est["cost_usd"]["note"]
    assert "no disponible" in est["basis"]


# ── enriquecimiento por evidencia (tamaño) ───────────────────────────────────


def test_evidence_size_is_included_when_evidence_given(tmp_path, monkeypatch) -> None:
    cases = _patch_cases(monkeypatch, tmp_path)
    case = cases.create(name="c", examiner="e", os_profile="windows")

    def fake_metadata(case_id: str, evidence_id: str) -> dict:
        assert case_id == case.id and evidence_id == "ev1"
        return {"size_bytes": 2_147_483_648}  # 2 GiB

    monkeypatch.setattr(estimate_mod.evidence_manager, "metadata", fake_metadata)

    est = estimate_analysis(case_id=case.id, executor_id="ollama", evidence_id="ev1")
    assert est["evidence_id"] == "ev1"
    assert est["evidence_size_bytes"] == 2_147_483_648
    assert est["evidence_size_human"]
