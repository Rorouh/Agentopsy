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

from forensia.agent.agent import ForensicAgent
from forensia.agent.loader import load_package
from forensia.models.base import ModelBackend, ModelCapabilities, ToolCall

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENTES_DIR = REPO_ROOT / "agentes"


class _AlwaysSameTool(ModelBackend):
    """Modelo que SIEMPRE pide la misma tool — simula el bucle del Bug 001."""

    name = "fake"

    def __init__(self, tool_id: str) -> None:
        self.tool_id = tool_id

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(supports_native_tools=False, json_mode=True, max_context=0, is_local=True)

    def next_action(self, state: dict[str, Any], tools: list[dict[str, Any]]) -> ToolCall:
        return ToolCall(
            tool_id=self.tool_id,
            params={},
            call_id="x",
            assistant_message={"role": "assistant", "content": "{}"},
        )


class _FakeEvidence:
    def get(self, case_id: str, evidence_id: str) -> SimpleNamespace:
        return SimpleNamespace(
            original_path=Path("/cases/x/original.raw"),
            detected_os="unix",
            detected_kind="disk",
            # The merged agent loop anchors each run in the audit chain with the
            # evidence hash (agent_run_start → evidence_sha256); a real
            # EvidenceHandle always carries it, so the fake must too.
            sha256="0" * 64,
        )


def test_failing_tool_blocked_after_max_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORENSIA_MAX_TOOL_ATTEMPTS", "3")

    calls = {"n": 0}

    def fake_execute(tool_id, params, *, case_id=None, os_profile=None, timeout=None):
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

    pkg = load_package(AGENTES_DIR / "forensia-unix")
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

    def fake_execute(tool_id, params, *, case_id=None, os_profile=None, timeout=None):
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

    pkg = load_package(AGENTES_DIR / "forensia-unix")
    agent = ForensicAgent(pkg, _AlwaysSameTool("tsk_fls"), _FakeEvidence())
    result = agent.run("lista la raíz", case_id="c", evidence_id="e")

    # Nunca se bloquea; corre una vez por iteración hasta agotar max_iter.
    assert calls["n"] == result["iterations"]
    assert not any(c.get("blocked") for c in result["tool_calls"])
