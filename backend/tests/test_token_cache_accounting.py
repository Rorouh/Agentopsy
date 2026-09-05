"""Prompt-cache accounting, session integrity and the cost-estimate correction.

The gates that matter:

- ``Usage`` parses the cache split per executor, and reports ``None`` — never a
  fabricated number — for an executor that does not report it (RULE 2).
- ``total_input_tokens`` is the REAL prompt size. Reading ``input_tokens`` as the
  prompt (it is only the uncached remainder) understated Agentopsy's input ~15×
  and is the bug behind the wrong pre-flight estimate.
- The audit event GAINS the cache fields, ``session_id``, ``resume`` and
  ``num_turns`` and keeps the literal argv (FORENSIC INVARIANT 4: this change is
  purely additive).
- The session guard refuses a delta whenever the session cannot be positively
  accounted for — diverged, compacted, unverifiable or unknown all take the same
  full-context path, and the reason is actionable.
- The cache watchdog fires only on a sustained stall, and only while a session is
  actually being reused.
- The reordered prompt keeps the response contract LAST (it is what holds the
  strict parser together).
"""

from __future__ import annotations

import json

from agentopsy.i18n import t
from agentopsy.executors.base import Usage
from agentopsy.executors.cache_health import CacheHealthMonitor
from agentopsy.executors.claude_code import ClaudeCodeExecutor
from agentopsy.executors.codex import CodexExecutor
from agentopsy.executors.gemini import GeminiExecutor
from agentopsy.executors.session_guard import (
    inspect_transcript,
    verify_session,
)
from agentopsy.models.base import ExecutorBackend

def _bloque(clave: str) -> str:
    """El encabezado de un bloque del prompt, EN EL IDIOMA EN CURSO.

    Los bloques se rotulan desde el catálogo (`agentContract.*`), así que un test
    que fija el ORDEN del prompt tiene que nombrarlos por su clave y no por su
    texto castellano: lo que se protege es la posición, no la palabra.
    """
    return t(clave).strip().splitlines()[0].strip()


# Shape verified against `claude` 2.1.220 on 2026-07-29.
_ENVELOPE = {
    "type": "result",
    "result": '{"action": "final", "text": "listo"}',
    "session_id": "32b4168c-31a5-47cf-918d-32c0f1cf8fde",
    "num_turns": 1,
    "total_cost_usd": 0.0014881,
    "usage": {
        "input_tokens": 10,
        "output_tokens": 46,
        "cache_creation_input_tokens": 69,
        "cache_read_input_tokens": 11101,
    },
}


# ── Usage: the cache split and the real prompt size ───────────────────────────


def test_claude_code_parses_cache_split():
    usage = ClaudeCodeExecutor()._extract_usage(json.dumps(_ENVELOPE))
    assert usage is not None
    assert usage.input_tokens == 10
    assert usage.cache_creation_input_tokens == 69
    assert usage.cache_read_input_tokens == 11101
    # The real prompt is the SUM, not `input_tokens`: 10 + 69 + 11101.
    assert usage.total_input_tokens == 11180


def test_input_tokens_alone_would_understate_the_prompt():
    """The regression this whole change exists to prevent."""
    usage = ClaudeCodeExecutor()._extract_usage(json.dumps(_ENVELOPE))
    assert usage.total_input_tokens / usage.input_tokens > 100


def test_executors_without_cache_accounting_report_none():
    """Codex/Gemini report a prompt TOTAL in `input_tokens` (cached tokens are a
    subset there, unlike Anthropic's API). Mapping anything onto the cache fields
    would double-count, so they stay None and `total_input_tokens` == input."""
    codex = CodexExecutor()._extract_usage(
        json.dumps({"type": "token_count", "input_tokens": 900, "output_tokens": 100})
    )
    assert codex.cache_creation_input_tokens is None
    assert codex.cache_read_input_tokens is None
    assert codex.total_input_tokens == 900

    gemini = GeminiExecutor()._extract_usage(
        json.dumps({"stats": {"promptTokenCount": 900, "candidatesTokenCount": 100}})
    )
    assert gemini.cache_read_input_tokens is None
    assert gemini.total_input_tokens == 900


def test_total_input_tokens_is_none_when_nothing_reported():
    """A real zero must stay distinguishable from 'not reported' (RULE 2)."""
    assert Usage().total_input_tokens is None
    assert Usage(output_tokens=5).total_input_tokens is None
    assert Usage(input_tokens=0).total_input_tokens == 0


def test_audit_fields_are_additive():
    """FORENSIC INVARIANT 4: the change adds keys, never removes them."""
    fields = Usage(
        input_tokens=10,
        output_tokens=46,
        cache_creation_input_tokens=69,
        cache_read_input_tokens=11101,
        cost_usd=0.0015,
        source="claude_code.usage",
    ).as_audit_fields()
    for key in ("input_tokens", "output_tokens", "cost_usd", "usage_source"):
        assert key in fields
    assert fields["cache_creation_input_tokens"] == 69
    assert fields["cache_read_input_tokens"] == 11101
    assert fields["total_input_tokens"] == 11180


def test_session_and_turn_count_parsed():
    executor = ClaudeCodeExecutor()
    raw = json.dumps(_ENVELOPE)
    assert executor._extract_session_id(raw) == _ENVELOPE["session_id"]
    assert executor._extract_turn_count(raw) == 1
    # Unparseable envelope → no session to reuse, never an exception.
    assert executor._extract_session_id("not json") is None
    assert executor._extract_turn_count("not json") is None


# ── Session guard: a delta may never reach an unaccountable session ───────────


def _write_session(tmp_path, session_id, rows):
    directory = tmp_path / "-some-project"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{session_id}.jsonl"
    path.write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
    )
    return path


def _turn(role, blocks):
    return {"type": role, "message": {"role": role, "content": blocks}}


def _clean_rows(prompts):
    rows = []
    for i in range(prompts):
        rows.append(_turn("user", [{"type": "text", "text": f"prompt {i}"}]))
        rows.append(_turn("assistant", [{"type": "text", "text": "{}"}]))
    return rows


def test_guard_allows_delta_on_a_clean_session(tmp_path):
    sid = "11111111-1111-4111-8111-111111111111"
    _write_session(tmp_path, sid, _clean_rows(2))
    verdict = verify_session(sid, expected_prompts=2, num_turns=1, root=tmp_path)
    assert verdict.can_send_delta
    assert verdict.checks["authored_prompts"] == 2


def test_guard_refuses_when_cli_added_turns(tmp_path):
    """Measured 2026-07-29: one call with a tool enabled reported num_turns=3 and
    left tool_use/tool_result rows Agentopsy never wrote."""
    sid = "22222222-2222-4222-8222-222222222222"
    _write_session(tmp_path, sid, _clean_rows(1))
    verdict = verify_session(sid, expected_prompts=1, num_turns=3, root=tmp_path)
    assert not verdict.can_send_delta
    assert "no ha escrito" in verdict.reason


def test_guard_refuses_a_compacted_session(tmp_path):
    """Compaction replaces history with a model-generated summary, which can drop
    a run_id or a SHA-256 and break a Finding's provenance."""
    sid = "33333333-3333-4333-8333-333333333333"
    rows = _clean_rows(1) + [
        {"type": "system", "subtype": "compact_boundary", "content": "Conversation compacted"}
    ]
    _write_session(tmp_path, sid, rows)
    verdict = verify_session(sid, expected_prompts=1, num_turns=1, root=tmp_path)
    assert not verdict.can_send_delta
    assert "COMPACTADO" in verdict.reason


def test_guard_refuses_when_transcript_missing(tmp_path):
    """Unverifiable is treated exactly like diverged — there is no 'assume it
    went well' branch."""
    verdict = verify_session(
        "44444444-4444-4444-8444-444444444444",
        expected_prompts=1,
        num_turns=1,
        root=tmp_path,
    )
    assert not verdict.can_send_delta
    assert "no puede verificar" in verdict.reason


def test_guard_refuses_on_prompt_count_mismatch(tmp_path):
    sid = "55555555-5555-4555-8555-555555555555"
    _write_session(tmp_path, sid, _clean_rows(5))
    verdict = verify_session(sid, expected_prompts=2, num_turns=1, root=tmp_path)
    assert not verdict.can_send_delta
    assert "no coincide" in verdict.reason


def test_guard_refuses_without_session_or_turn_count(tmp_path):
    assert not verify_session(None, expected_prompts=0, num_turns=1, root=tmp_path).can_send_delta
    sid = "66666666-6666-4666-8666-666666666666"
    _write_session(tmp_path, sid, _clean_rows(1))
    assert not verify_session(
        sid, expected_prompts=1, num_turns=None, root=tmp_path
    ).can_send_delta


def test_inspect_transcript_counts_cli_tool_calls(tmp_path):
    sid = "77777777-7777-4777-8777-777777777777"
    rows = [
        _turn("user", [{"type": "text", "text": "hola"}]),
        _turn("assistant", [{"type": "tool_use", "name": "Bash"}]),
        _turn("user", [{"type": "tool_result", "content": "UNO"}]),
        _turn("assistant", [{"type": "text", "text": "ok"}]),
    ]
    path = _write_session(tmp_path, sid, rows)
    facts = inspect_transcript(path)
    assert facts["authored_prompts"] == 1
    assert facts["cli_tool_calls"] == 1
    assert facts["cli_tool_results"] == 1
    assert facts["compacted"] is False


# ── Cache watchdog ───────────────────────────────────────────────────────────


def _usage(read, creation=0):
    return Usage(cache_read_input_tokens=read, cache_creation_input_tokens=creation)


def test_watchdog_silent_while_cache_grows():
    monitor = CacheHealthMonitor()
    for turn, read in enumerate([5033, 11101, 11170, 12000, 13000], start=1):
        assert monitor.observe(_usage(read), session_active=True, turn=turn) is None


def test_watchdog_warns_after_sustained_stall():
    monitor = CacheHealthMonitor()
    assert monitor.observe(_usage(9051), session_active=True, turn=1) is None
    warnings = [
        monitor.observe(_usage(9051), session_active=True, turn=t) for t in (2, 3, 4)
    ]
    assert warnings[0] is None and warnings[1] is None
    assert warnings[2] is not None
    assert "9051" in warnings[2]
    # Warns once, not every turn afterwards.
    assert monitor.observe(_usage(9051), session_active=True, turn=5) is None
    assert monitor.summary()["cache_regression_warned"] is True


def test_watchdog_silent_without_a_session():
    """Without session reuse every turn is a cold start by construction: a flat
    cache_read is expected there, and warning would be noise."""
    monitor = CacheHealthMonitor()
    for turn in range(1, 6):
        assert monitor.observe(_usage(9051), session_active=False, turn=turn) is None


def test_watchdog_silent_when_executor_reports_no_cache():
    monitor = CacheHealthMonitor()
    for turn in range(1, 6):
        assert monitor.observe(
            Usage(input_tokens=900), session_active=True, turn=turn
        ) is None


# ── Prompt ordering (Fase 2) ─────────────────────────────────────────────────


def _messages():
    return [
        {"role": "system", "content": "CONDUCTA"},
        {"role": "user", "content": "analiza"},
        {"role": "assistant", "content": "{}"},
        {"role": "tool", "tool_call_id": "c1", "content": "salida"},
    ]


def test_stable_blocks_precede_the_transcript():
    prompt = ExecutorBackend._render_prompt(_messages(), [{"name": "tsk_fls"}])
    assert prompt.index("## SISTEMA") < prompt.index(_bloque("agentContract.toolsHeader"))
    assert prompt.index(_bloque("agentContract.toolsHeader")) < prompt.index("## USUARIO")


def test_response_contract_stays_last():
    """It is what holds `_parse_action`'s strict envelope together; a parse
    failure costs a whole retry turn."""
    prompt = ExecutorBackend._render_prompt(_messages(), [{"name": "tsk_fls"}])
    # El contrato cierra el prompt, sea cual sea el idioma: se compara con su
    # última línea del catálogo, no con una frase castellana.
    assert prompt.rstrip().endswith(t("agentContract.format").rstrip().splitlines()[-1])
    assert prompt.index(_bloque("agentContract.format")) > prompt.index("## RESULTADO DE TOOL")


def test_reordering_preserves_content():
    """Same blocks, different order — nothing is dropped from what the model sees."""
    prompt = ExecutorBackend._render_prompt(_messages(), [{"name": "tsk_fls"}])
    for fragment in ("CONDUCTA", "analiza", "salida", "tsk_fls", _bloque("agentContract.format")):
        assert fragment in prompt


def test_delta_omits_the_static_blocks_but_keeps_the_contract():
    delta = ExecutorBackend._render_delta(
        [{"role": "tool", "tool_call_id": "c9", "content": "nueva salida"}]
    )
    assert "nueva salida" in delta
    assert _bloque("agentContract.toolsHeader") not in delta
    assert "## SISTEMA" not in delta
    assert delta.rstrip().endswith(t("agentContract.format").rstrip().splitlines()[-1])
