"""Telemetría de coste por ejecutor — Bug 008 §2 Nivel 0.

Los gates que importan:
- Cada ejecutor parsea el usage de SU envelope (los datos que hoy se tiraban).
- Un envelope con forma distinta / sin el dato degrada a None, nunca a un número
  inventado (RULE 2). El texto extraído NUNCA se ve afectado.
- El evento `executor_run_finish` persiste los tokens/coste cuando existen.
- La agregación por caso/ejecutor distingue "no reportado" de un cero real.
"""

from __future__ import annotations

import json

from forensia.audit.log import AuditLog
from forensia.executors.base import Usage
from forensia.executors.claude_code import ClaudeCodeExecutor
from forensia.executors.cost import executor_cost
from forensia.executors.gemini import GeminiExecutor
from forensia.executors.ollama import OllamaExecutor


# ── parseo por ejecutor ──────────────────────────────────────────────────────


def test_claude_code_parses_usage_and_cost() -> None:
    env = json.dumps({
        "result": "hola",
        "usage": {"input_tokens": 1200, "output_tokens": 340},
        "total_cost_usd": 0.021,
    })
    u = ClaudeCodeExecutor()._extract_usage(env)
    assert u == Usage(1200, 340, 0.021, "claude_code.usage")


def test_ollama_parses_eval_counts_and_has_no_cost() -> None:
    env = json.dumps({"response": "x", "prompt_eval_count": 900, "eval_count": 210})
    u = OllamaExecutor()._extract_usage(env)
    assert u.input_tokens == 900
    assert u.output_tokens == 210
    assert u.cost_usd is None  # local → sin coste


def test_gemini_finds_canonical_token_keys_nested_in_stats() -> None:
    env = json.dumps({
        "response": "x",
        "stats": {"models": {"gemini-2": {"tokens": {
            "promptTokenCount": 800, "candidatesTokenCount": 150,
        }}}},
    })
    u = GeminiExecutor()._extract_usage(env)
    assert u.input_tokens == 800
    assert u.output_tokens == 150


def test_codex_parses_token_counts_from_jsonl_stream() -> None:
    from forensia.executors.codex import CodexExecutor
    stream = "\n".join([
        '{"type":"item.started"}',
        '{"type":"turn.completed","usage":{"input_tokens":2200,"output_tokens":450}}',
    ])
    u = CodexExecutor()._extract_usage(stream)
    assert u.input_tokens == 2200
    assert u.output_tokens == 450
    assert u.source == "codex.json"


def test_codex_last_token_event_wins() -> None:
    from forensia.executors.codex import CodexExecutor
    stream = "\n".join([
        '{"usage":{"input_tokens":100,"output_tokens":10}}',
        '{"usage":{"input_tokens":300,"output_tokens":80}}',
    ])
    u = CodexExecutor()._extract_usage(stream)
    assert u.input_tokens == 300 and u.output_tokens == 80


def test_codex_argv_uses_json_but_text_still_from_file() -> None:
    from forensia.executors.codex import CodexExecutor
    ex = CodexExecutor()
    ex._last_message_path = "/tmp/x.md"
    argv = ex._build_argv("hola", None)
    assert "--json" in argv
    assert "--output-last-message" in argv  # el texto sigue viniendo del fichero


def test_codex_no_token_events_degrades_to_none() -> None:
    from forensia.executors.codex import CodexExecutor
    assert CodexExecutor()._extract_usage('{"type":"item.started"}') is None


def test_unparseable_or_reshaped_envelope_degrades_to_none() -> None:
    """RULE 2: forma inesperada → 'no reportado', jamás un número fabricado."""
    assert ClaudeCodeExecutor()._extract_usage("not json") is None
    assert ClaudeCodeExecutor()._extract_usage(json.dumps({"result": "x"})) is None
    assert OllamaExecutor()._extract_usage(json.dumps({"response": "x"})) is None
    assert GeminiExecutor()._extract_usage(json.dumps({"response": "x", "stats": {}})) is None


def test_negative_or_bool_token_values_are_rejected() -> None:
    env = json.dumps({"result": "x", "usage": {"input_tokens": -5, "output_tokens": True}})
    assert ClaudeCodeExecutor()._extract_usage(env) is None


def test_as_audit_fields_only_emits_present_data() -> None:
    assert Usage(input_tokens=10, source="s").as_audit_fields() == {
        "input_tokens": 10, "usage_source": "s",
    }
    assert Usage().as_audit_fields() == {}


# ── agregación desde el audit log ────────────────────────────────────────────


def _finish(executor: str, **extra) -> dict:
    ev = {
        "action": "executor_run_finish",
        "executor": executor,
        "case_id": "c",
        "exit_code": None,
        "duration_ms": 5,
        "response_sha256": "x",
        "response_chars": 100,
    }
    ev.update(extra)
    return ev


def test_executor_cost_aggregates_tokens_and_cost(tmp_path, monkeypatch) -> None:
    from forensia.cases import CaseManager
    from forensia.executors import cost as cost_mod
    cases = CaseManager(root=tmp_path / "cases")
    monkeypatch.setattr(cost_mod, "case_manager", cases)
    case = cases.create(name="c", examiner="e", os_profile="windows")
    audit = AuditLog(cases.case_dir(case.id) / "audit.jsonl")
    audit.append(_finish("claude-code", input_tokens=1000, output_tokens=200, cost_usd=0.01))
    audit.append(_finish("claude-code", input_tokens=1500, output_tokens=300, cost_usd=0.02))
    audit.append(_finish("ollama", input_tokens=800, output_tokens=100))  # sin coste

    by_exec = {e["executor"]: e for e in executor_cost(case.id)}

    cc = by_exec["claude-code"]
    assert cc["runs"] == 2
    assert cc["runs_with_tokens"] == 2
    assert cc["total_tokens"] == 3000
    assert cc["cost_usd"] == 0.03

    ol = by_exec["ollama"]
    assert ol["total_tokens"] == 900
    assert ol["cost_usd"] == 0.0


def test_run_without_reported_tokens_counts_but_does_not_fake_zero(tmp_path, monkeypatch) -> None:
    """Un run cuyo ejecutor no reportó tokens (p. ej. Codex) cuenta como run
    pero NO infla los totales de tokens con un cero falso."""
    from forensia.cases import CaseManager
    from forensia.executors import cost as cost_mod
    cases = CaseManager(root=tmp_path / "cases")
    monkeypatch.setattr(cost_mod, "case_manager", cases)
    case = cases.create(name="c", examiner="e", os_profile="windows")
    audit = AuditLog(cases.case_dir(case.id) / "audit.jsonl")
    audit.append(_finish("codex"))  # sin tokens
    audit.append(_finish("codex", input_tokens=500, output_tokens=90))

    entry = executor_cost(case.id)[0]
    assert entry["runs"] == 2
    assert entry["runs_with_tokens"] == 1  # solo uno reportó
    assert entry["total_tokens"] == 590


def test_error_finishes_are_not_counted(tmp_path, monkeypatch) -> None:
    from forensia.cases import CaseManager
    from forensia.executors import cost as cost_mod
    cases = CaseManager(root=tmp_path / "cases")
    monkeypatch.setattr(cost_mod, "case_manager", cases)
    case = cases.create(name="c", examiner="e", os_profile="windows")
    audit = AuditLog(cases.case_dir(case.id) / "audit.jsonl")
    audit.append({
        "action": "executor_run_finish", "executor": "gemini",
        "case_id": "c", "exit_code": 1, "duration_ms": 5, "error": "boom",
    })
    assert executor_cost(case.id) == []


def test_no_audit_log_yet_returns_empty(tmp_path, monkeypatch) -> None:
    from forensia.cases import CaseManager
    from forensia.executors import cost as cost_mod
    cases = CaseManager(root=tmp_path / "cases")
    monkeypatch.setattr(cost_mod, "case_manager", cases)
    case = cases.create(name="c", examiner="e", os_profile="windows")
    assert executor_cost(case.id) == []
