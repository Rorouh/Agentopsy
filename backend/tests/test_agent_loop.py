"""Guardrail anti-bucle del loop del agente (Bug 001).

Una tool que falla no debe reintentarse indefinidamente: tras `max_attempts` fallos del
mismo `tool_id` en una sesión, el loop la bloquea y empuja al modelo a cambiar de
herramienta o cerrar. Aquí se pin­ea con un modelo falso que insiste en la misma tool y un
dispatcher falso que siempre devuelve exit≠0 — sin docker, sin maletines, sin binarios.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from forensia.i18n import t
from forensia.agent.agent import ForensicAgent, _max_tool_attempts
from _agent_pkg import make_package
from forensia.models.base import ModelBackend, ModelCapabilities, ToolCall

def _marca(clave: str) -> str:
    """El marcador distintivo de un bloque del prompt, EN EL IDIOMA EN CURSO.

    Los bloques del prompt se rotulan desde el catálogo, así que un test los
    nombra por su CLAVE y no por su texto castellano: lo que fija es que el
    marcador está, no con qué palabra se escribe. Para los que abren con una
    etiqueta entre corchetes (`[Presupuesto]`, `[Reminder]`) devuelve esa
    etiqueta; para el resto, el primer trozo de la primera línea.
    """
    texto = t(clave).strip()
    if texto.startswith("["):
        return texto[: texto.index("]") + 1]
    return texto.split("\n")[0].split(",")[0].strip()


REPO_ROOT = Path(__file__).resolve().parents[2]
AGENTES_DIR = REPO_ROOT / "agentes"


def test_max_tool_attempts_defaults_to_3_when_env_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FORENSIA_MAX_TOOL_ATTEMPTS", raising=False)
    assert _max_tool_attempts() == 3


@pytest.mark.parametrize("raw", ["0", "-1", "abc"])
def test_max_tool_attempts_fails_loud_on_invalid_env(
    monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    monkeypatch.setenv("FORENSIA_MAX_TOOL_ATTEMPTS", raw)
    with pytest.raises(RuntimeError, match="FORENSIA_MAX_TOOL_ATTEMPTS"):
        _max_tool_attempts()


class _AlwaysSameTool(ModelBackend):
    """Modelo que SIEMPRE pide la misma tool — simula el bucle del Bug 001."""

    name = "fake"

    def __init__(self, tool_id: str, params: dict[str, Any] | None = None) -> None:
        self.tool_id = tool_id
        self.params = params or {}

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(supports_native_tools=False, json_mode=True, max_context=0, is_local=True)

    def next_action(self, state: dict[str, Any], tools: list[dict[str, Any]]) -> ToolCall:
        return ToolCall(
            tool_id=self.tool_id,
            params=dict(self.params),
            call_id="x",
            assistant_message={"role": "assistant", "content": "{}"},
        )


class _FakeEvidence:
    def get(self, case_id: str, evidence_id: str) -> SimpleNamespace:
        return SimpleNamespace(
            evidence_id=evidence_id,
            original_path=Path("/cases/x/original.raw"),
            detected_os="unix",
            detected_kind="disk",
            # The merged agent loop anchors each run in the audit chain with the
            # evidence hash (agent_run_start → evidence_sha256; and the verified
            # EvidenceContext threaded to the dispatcher); a real EvidenceHandle
            # always carries both id and hash, so the fake must too.
            sha256="0" * 64,
        )


def test_agent_rejects_model_chosen_evidence_path_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"n": 0}

    def forbidden_execute(*args, **kwargs):
        del args, kwargs
        calls["n"] += 1
        raise AssertionError("dispatcher must not be reached")

    monkeypatch.setattr("forensia.toolkit.dispatcher.execute", forbidden_execute)
    pkg = make_package("unix")
    agent = ForensicAgent(
        pkg,
        _AlwaysSameTool(
            "yara",
            {"target_path": "/etc/passwd", "rules_path": "rules.yar"},
        ),
        _FakeEvidence(),
    )

    result = agent.run("analiza", case_id="c", evidence_id="e")

    assert calls["n"] == 0
    assert any(
        "may not choose an EVIDENCE_INPUT" in call.get("error", "")
        for call in result["tool_calls"]
    )


def test_failing_tool_blocked_after_max_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORENSIA_MAX_TOOL_ATTEMPTS", "3")

    calls = {"n": 0}

    def fake_execute(
        tool_id, params, *, case_id=None, os_profile=None, timeout=None, evidence_context=None
    ):
        calls["n"] += 1
        return {
            "tool_id": tool_id,
            "argv": ["mmls", "/cases/x/original.raw"],
            "exit_code": 1,  # siempre falla (imagen sin tabla de particiones)
            "stdout_sample": "",
            "stderr_sample": "Cannot determine partition type",
            "parsed": None,
            "run_id": "r",
        }

    monkeypatch.setattr("forensia.toolkit.dispatcher.execute", fake_execute)

    pkg = make_package("unix")
    # `tsk_mmls` está en la allowlist del paquete unix y es una tool real del catálogo.
    agent = ForensicAgent(pkg, _AlwaysSameTool("tsk_mmls"), _FakeEvidence())

    result = agent.run("lista la raíz", case_id="c", evidence_id="e")

    # El dispatcher se ejecutó EXACTAMENTE max_attempts veces (3), no una por iteración.
    assert calls["n"] == 3
    # El resto de iteraciones se bloquearon (el modelo insistió, el loop lo cortó).
    blocked = [c for c in result["tool_calls"] if c.get("blocked")]
    assert len(blocked) >= 1
    assert all(c["reason"] == "max_failed_attempts" for c in blocked)
    # Los 3 intentos reales quedaron con su exit_code de fallo.
    ran = [c for c in result["tool_calls"] if "exit_code" in c and not c.get("blocked")]
    assert len(ran) == 3
    assert all(c["exit_code"] == 1 for c in ran)


def test_successful_tool_is_not_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Una tool que va bien puede llamarse muchas veces (p. ej. tsk_icat por inodo): el
    guardrail cuenta FALLOS, no usos."""
    monkeypatch.setenv("FORENSIA_MAX_TOOL_ATTEMPTS", "3")

    calls = {"n": 0}

    def fake_execute(
        tool_id, params, *, case_id=None, os_profile=None, timeout=None, evidence_context=None
    ):
        calls["n"] += 1
        return {
            "tool_id": tool_id,
            "argv": ["fls", "/cases/x/original.raw"],
            "exit_code": 0,  # siempre OK
            "stdout_sample": "d/d 13:\tbin",
            "stderr_sample": "",
            "parsed": {"format": "list", "entries_count": 1, "entries": []},
            "run_id": "r",
        }

    monkeypatch.setattr("forensia.toolkit.dispatcher.execute", fake_execute)

    pkg = make_package("unix")
    agent = ForensicAgent(pkg, _AlwaysSameTool("tsk_fls"), _FakeEvidence())
    result = agent.run("lista la raíz", case_id="c", evidence_id="e")

    # Nunca se bloquea; corre una vez por iteración hasta agotar max_iter.
    assert calls["n"] == result["iterations"]
    assert not any(c.get("blocked") for c in result["tool_calls"])


def test_records_nudge_injected_after_tools_without_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refuerzo estructural: si el agente encadena herramientas del catálogo sin
    registrar hallazgos, el loop le inyecta un recordatorio de `record_finding`."""
    monkeypatch.setenv("FORENSIA_MAX_TOOL_ATTEMPTS", "10")  # sin tope de fallos

    def fake_execute(
        tool_id, params, *, case_id=None, os_profile=None, timeout=None, evidence_context=None
    ):
        return {
            "tool_id": tool_id, "argv": ["fls", "/cases/x/original.raw"], "exit_code": 0,
            "stdout_sample": "d/d 13:\tbin", "stderr_sample": "",
            "parsed": {"format": "list", "entries_count": 1, "entries": []}, "run_id": "r",
        }

    monkeypatch.setattr("forensia.toolkit.dispatcher.execute", fake_execute)

    seen: list[int] = []

    class _Capturing(_AlwaysSameTool):
        def next_action(self, state, tools):  # noqa: ANN001
            msgs = state.get("messages", [])
            if any(
                isinstance(m, dict) and _marca("agentLoop.findingReminder") in str(m.get("content", ""))
                for m in msgs
            ):
                seen.append(len(msgs))
            return super().next_action(state, tools)

    pkg = make_package("unix")
    agent = ForensicAgent(pkg, _Capturing("tsk_fls"), _FakeEvidence())
    agent.run("lista la raíz", case_id="c", evidence_id="e")

    assert seen, "tras 3 herramientas sin registrar hallazgo debe inyectarse el recordatorio"


def test_budget_nudges_demand_a_final_before_exhaustion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fase de turnos §6.4 — la corrida medida agotó 21 iteraciones sin emitir un
    solo `final` (12,97 USD sin respuesta al operador). El agente no conoce su
    presupuesto salvo que se le diga: a 2 iteraciones del límite se le avisa de
    que cierre, y en la última se le exige el `final`. Nunca antes."""
    monkeypatch.setenv("FORENSIA_MAX_TOOL_ATTEMPTS", "10")

    def fake_execute(
        tool_id, params, *, case_id=None, os_profile=None, timeout=None, evidence_context=None
    ):
        return {
            "tool_id": tool_id, "argv": ["mmls", "/cases/x/original.raw"], "exit_code": 0,
            "stdout_sample": "ok", "stderr_sample": "", "parsed": None, "run_id": "r",
        }

    monkeypatch.setattr("forensia.toolkit.dispatcher.execute", fake_execute)

    class _CapturingStates(_AlwaysSameTool):
        def __init__(self, tool_id: str) -> None:
            super().__init__(tool_id)
            self.states: list[list[str]] = []

        def next_action(self, state, tools):  # noqa: ANN001
            self.states.append(
                [str(m.get("content") or "") for m in state.get("messages", [])]
            )
            return super().next_action(state, tools)

    backend = _CapturingStates("tsk_mmls")
    agent = ForensicAgent(
        make_package("unix", max_iterations=4), backend, _FakeEvidence()
    )
    agent.run("lista la raíz", case_id="c", evidence_id="e")

    assert len(backend.states) == 4
    # Las dos primeras iteraciones trabajan sin presión de presupuesto…
    assert not any(_marca("agentLoop.budgetTwoLeft") in c for c in backend.states[0])
    assert not any(_marca("agentLoop.budgetTwoLeft") in c for c in backend.states[1])
    # …a 2 del límite se le pide cerrar, y en la última se le exige el `final`.
    assert any(t("agentLoop.budgetTwoLeft") in c for c in backend.states[2])
    assert any(t("agentLoop.budgetLast") in c for c in backend.states[3])


def test_budget_nudge_skips_single_iteration_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FORENSIA_MAX_TOOL_ATTEMPTS", "10")

    def fake_execute(
        tool_id, params, *, case_id=None, os_profile=None, timeout=None, evidence_context=None
    ):
        return {
            "tool_id": tool_id, "argv": ["mmls", "/cases/x/original.raw"], "exit_code": 0,
            "stdout_sample": "ok", "stderr_sample": "", "parsed": None, "run_id": "r",
        }

    monkeypatch.setattr("forensia.toolkit.dispatcher.execute", fake_execute)

    seen: list[str] = []

    class _Capturing(_AlwaysSameTool):
        def next_action(self, state, tools):  # noqa: ANN001
            seen.extend(str(m.get("content") or "") for m in state.get("messages", []))
            return super().next_action(state, tools)

    agent = ForensicAgent(
        make_package("unix", max_iterations=1), _Capturing("tsk_mmls"), _FakeEvidence()
    )
    agent.run("lista la raíz", case_id="c", evidence_id="e")

    assert not any(_marca("agentLoop.budgetTwoLeft") in c for c in seen)
