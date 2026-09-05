"""Fase 3 — con transporte por sesión el tránscrito viaja ÍNTEGRO.

El windowing (Bug 008) ahorra cuando el ejecutor es stateless y re-envía todo
cada turno; con una sesión reanudable INVIERTE la economía: el stub plantado en
la sesión hace que el modelo queme turnos releyendo lo que el propio stub
elidió (medido: 12 de 21 turnos, ~42 % de la entrada). Los gates que importan:

- Con backend capaz de sesión, ningún resultado de tool se elide y
  ``messages_full`` es la MISMA lista que cruzó el punto único de egreso.
- Sin sesión, el windowing sigue intacto (comportamiento pre-2026-07-30).
- El presupuesto de seguridad: superarlo re-activa el windowing y lo AUDITA
  (``context_window_trimmed``) — nunca un recorte silencioso (RULE 2).
- El envío de contexto completo del ``ExecutorBackend`` (apertura o reapertura)
  se renderiza SIEMPRE desde la lista canónica cuando existe: un stub jamás
  siembra una sesión — la contabilidad de ``_absorb`` (mensajes entregados)
  debe corresponder a lo que la sesión de verdad contiene.
- Un ejecutor que declara reanudación y no devuelve ``session_id`` avisa UNA
  vez (coste visible, nunca fatal).
"""

from __future__ import annotations

from typing import Any

import pytest
from _agent_pkg import make_package
from test_agent_loop import _FakeEvidence

from agentopsy.agent.agent import ForensicAgent
from agentopsy.agent.context import session_context_budget_chars, transcript_chars
from agentopsy.models.base import (
    ExecutorBackend,
    FinalAnswer,
    ModelBackend,
    ModelCapabilities,
    ToolCall,
)

_STUB_MARK = "[resultado de tool elidido"


# ── helpers ───────────────────────────────────────────────────────────────────


class _CaptureBackend(ModelBackend):
    """Pide ``iterations`` veces la misma tool y captura cada estado de egreso."""

    name = "fake-capture"

    def __init__(self, tool_id: str, iterations: int, *, session: bool) -> None:
        self.tool_id = tool_id
        self.iterations = iterations
        self.supports_session_transport = session
        self.captured: list[dict[str, Any]] = []
        self._n = 0

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            supports_native_tools=False, json_mode=True, max_context=0, is_local=True
        )

    def next_action(self, state: dict[str, Any], tools: list[dict[str, Any]]):
        self.captured.append(
            {"messages": state["messages"], "messages_full": state.get("messages_full")}
        )
        self._n += 1
        if self._n > self.iterations:
            return FinalAnswer(text="fin")
        return ToolCall(
            tool_id=self.tool_id,
            params={},
            call_id=f"c{self._n}",
            assistant_message={"role": "assistant", "content": "{}"},
        )


class _ListAudit(list):
    def append(self, event: dict[str, Any]) -> None:  # type: ignore[override]
        super().append(dict(event))


@pytest.fixture
def ok_dispatcher(monkeypatch: pytest.MonkeyPatch):
    """Dispatcher falso: cada corrida sale bien y produce un run_id distinto."""
    counter = {"n": 0}

    def fake_execute(
        tool_id, params, *, case_id=None, os_profile=None, timeout=None,
        evidence_context=None,
    ):
        counter["n"] += 1
        return {
            "tool_id": tool_id,
            "argv": ["mmls", "/cases/x/original.raw"],
            "exit_code": 0,
            "stdout_sample": f"SALIDA_SINTETICA {counter['n']} " + "x" * 200,
            "stderr_sample": "",
            "parsed": None,
            "run_id": f"run{counter['n']:03d}",
        }

    monkeypatch.setattr("agentopsy.toolkit.dispatcher.execute", fake_execute)


def _contents(messages: list[dict[str, Any]]) -> list[str]:
    return [str(m.get("content") or "") for m in messages]


# ── el loop: windowing por capacidad de sesión ────────────────────────────────


def test_session_backend_sends_uncut_transcript(ok_dispatcher) -> None:
    backend = _CaptureBackend("tsk_mmls", 6, session=True)
    agent = ForensicAgent(make_package("unix"), backend, _FakeEvidence())

    agent.run("lista la raíz", case_id="c", evidence_id="e")

    last = backend.captured[-1]
    # Con 6 resultados de tool (> keep=4), el backend de sesión NO ve stubs…
    assert not any(_STUB_MARK in c for c in _contents(last["messages"]))
    assert sum("SALIDA_SINTETICA" in c for c in _contents(last["messages"])) == 6
    # …y `messages_full` ES la misma lista que cruzó el punto único de egreso
    # (idéntico payload auditado; el delta parte de la misma contabilidad).
    assert last["messages_full"] is last["messages"]


def test_stateless_backend_keeps_the_windowing(ok_dispatcher) -> None:
    backend = _CaptureBackend("tsk_mmls", 6, session=False)
    agent = ForensicAgent(make_package("unix"), backend, _FakeEvidence())

    agent.run("lista la raíz", case_id="c", evidence_id="e")

    last = backend.captured[-1]
    assert any(_STUB_MARK in c for c in _contents(last["messages"]))
    assert last["messages_full"] is None


def test_over_budget_trim_is_windowed_and_audited(
    ok_dispatcher, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTOPSY_SESSION_CONTEXT_MAX_CHARS", "50")
    audit = _ListAudit()
    backend = _CaptureBackend("tsk_mmls", 6, session=True)
    agent = ForensicAgent(make_package("unix"), backend, _FakeEvidence(), audit=audit)

    agent.run("lista la raíz", case_id="c", evidence_id="e")

    last = backend.captured[-1]
    assert any(_STUB_MARK in c for c in _contents(last["messages"]))
    trims = [e for e in audit if e.get("event") == "context_window_trimmed"]
    assert trims, "el recorte con sesión activa debe quedar en el audit (RULE 2)"
    assert trims[0]["budget_chars"] == 50
    assert trims[0]["transcript_chars"] > 50


# ── el presupuesto ────────────────────────────────────────────────────────────


def test_budget_default_and_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENTOPSY_SESSION_CONTEXT_MAX_CHARS", raising=False)
    assert session_context_budget_chars() == 400_000
    monkeypatch.setenv("AGENTOPSY_SESSION_CONTEXT_MAX_CHARS", "1234")
    assert session_context_budget_chars() == 1234


@pytest.mark.parametrize("raw", ["0", "-5", "abc"])
def test_budget_invalid_fails_loud(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv("AGENTOPSY_SESSION_CONTEXT_MAX_CHARS", raw)
    with pytest.raises(RuntimeError, match="AGENTOPSY_SESSION_CONTEXT_MAX_CHARS"):
        session_context_budget_chars()


def test_transcript_chars_counts_content() -> None:
    msgs = [
        {"role": "user", "content": "abc"},
        {"role": "tool", "content": "de"},
        {"role": "assistant", "content": None},
    ]
    assert transcript_chars(msgs) == 5


# ── ExecutorBackend: el contexto completo se renderiza del canónico ───────────


class _ResumableExecutor:
    id = "fake-resume"
    name = "Fake Resume"
    is_local = True
    supports_session_resume = True

    def __init__(self) -> None:
        self.prompts: list[str] = []

    def run(self, prompt: str, context: dict[str, Any] | None = None):
        raise AssertionError("estos tests no llegan a ejecutar")


def _windowed_and_canonical() -> tuple[list[dict], list[dict]]:
    canonical = [
        {"role": "system", "content": "CONDUCTA"},
        {"role": "user", "content": "analiza"},
        {"role": "tool", "tool_call_id": "c1", "content": "SALIDA REAL COMPLETA"},
    ]
    windowed = [dict(m) for m in canonical]
    windowed[2]["content"] = _STUB_MARK + " (tool=x, run=r)]"
    return windowed, canonical


def test_session_seeding_prompt_renders_from_canonical() -> None:
    backend = ExecutorBackend(_ResumableExecutor())
    windowed, canonical = _windowed_and_canonical()

    prompt, resumed, reason = backend._plan_transport(windowed, [], canonical)

    assert resumed is False and reason is None
    assert "SALIDA REAL COMPLETA" in prompt
    assert _STUB_MARK not in prompt  # un stub jamás siembra una sesión


def test_reopen_prompt_renders_from_canonical(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = ExecutorBackend(_ResumableExecutor())
    backend._session_id = "s1"
    backend._prompts_sent = 1
    backend._last_num_turns = 1
    monkeypatch.setattr(
        "agentopsy.models.base.verify_session",
        lambda *a, **k: type(
            "V", (), {"can_send_delta": False, "reason": "sesión divergida"}
        )(),
    )
    windowed, canonical = _windowed_and_canonical()

    prompt, resumed, reason = backend._plan_transport(windowed, [], canonical)

    assert resumed is False
    assert reason == "sesión divergida"
    assert "SALIDA REAL COMPLETA" in prompt
    assert _STUB_MARK not in prompt


def test_missing_session_id_warns_once() -> None:
    backend = ExecutorBackend(_ResumableExecutor())

    class _NoSession:
        session_id = None
        num_turns = 1
        usage = None

    backend._absorb(_NoSession(), resumed=False, delivered=0)
    backend._absorb(_NoSession(), resumed=False, delivered=0)

    warnings = [n for n in backend.notices if "session_id" in n]
    assert len(warnings) == 1  # una vez por corrida, no por turno
