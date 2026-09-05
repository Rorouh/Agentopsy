"""El usage que cada ejecutor reporta, y que acaba en el log de auditoría.

La telemetría de coste que se PINTABA se retiró (2026-08-12): el conteo no era
fiable y el panel de Investigación daba cifras que no se sostenían. Lo que NO se
retiró es esto: el usage sigue parseándose y sigue viajando al log encadenado,
porque es procedencia de la corrida, no una métrica de producto.

Los gates que importan:
- Cada ejecutor parsea el usage de SU envelope.
- Un envelope con forma distinta / sin el dato degrada a None, nunca a un número
  inventado (RULE 2). El texto extraído NUNCA se ve afectado.
- El evento `executor_run_finish` persiste los tokens/coste cuando existen.
"""

from __future__ import annotations

import json

from agentopsy.executors.base import Usage
from agentopsy.executors.claude_code import ClaudeCodeExecutor
from agentopsy.executors.gemini import GeminiExecutor
from agentopsy.executors.ollama import OllamaExecutor


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
    from agentopsy.executors.codex import CodexExecutor
    stream = "\n".join([
        '{"type":"item.started"}',
        '{"type":"turn.completed","usage":{"input_tokens":2200,"output_tokens":450}}',
    ])
    u = CodexExecutor()._extract_usage(stream)
    assert u.input_tokens == 2200
    assert u.output_tokens == 450
    assert u.source == "codex.json"


def test_codex_last_token_event_wins() -> None:
    from agentopsy.executors.codex import CodexExecutor
    stream = "\n".join([
        '{"usage":{"input_tokens":100,"output_tokens":10}}',
        '{"usage":{"input_tokens":300,"output_tokens":80}}',
    ])
    u = CodexExecutor()._extract_usage(stream)
    assert u.input_tokens == 300 and u.output_tokens == 80


def test_codex_argv_uses_json_but_text_still_from_file() -> None:
    from agentopsy.executors.codex import CodexExecutor
    ex = CodexExecutor()
    ex._last_message_path = "/tmp/x.md"
    argv = ex._build_argv("hola", None)
    assert "--json" in argv
    assert "--output-last-message" in argv  # el texto sigue viniendo del fichero


def test_codex_no_token_events_degrades_to_none() -> None:
    from agentopsy.executors.codex import CodexExecutor
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
    # `total_input_tokens` joined the event on 2026-07-29: on a cache-aware
    # executor `input_tokens` is only the UNCACHED remainder, so the real prompt
    # size has to be audited explicitly. With no cache datum reported it equals
    # `input_tokens`, which is the correct total for that executor.
    assert Usage(input_tokens=10, source="s").as_audit_fields() == {
        "input_tokens": 10, "total_input_tokens": 10, "usage_source": "s",
    }
    # Nothing reported → nothing emitted: a real zero stays distinguishable from
    # "the executor did not report it" (RULE 2).
    assert Usage().as_audit_fields() == {}
