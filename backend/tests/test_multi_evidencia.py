"""El agente ve y usa TODAS las evidencias del caso (RAM + disco), no solo una.

El bug (2026-07-28): la investigación mandaba una única `evidence_id` (la primera),
así que en un caso con memoria + disco el agente quedaba encajonado en el disco y
repetía `tsk_fls`/`tsk_mmls` sin tocar nunca la RAM — no llegaba a los TTP/credenciales
que viven en memoria. Ahora el agente:

- ve las dos evidencias en el system prompt (con su `kind`);
- puede APUNTAR cada herramienta a una evidencia con el param `evidence_id`;
- el path y el EvidenceContext se resuelven de ESA evidencia (custodia por handle).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from _agent_pkg import make_package

from forensia.i18n import t
from forensia.agent.agent import ForensicAgent
from forensia.models.base import FinalAnswer, ModelBackend, ModelCapabilities, ToolCall

RAM_ID = "11111111-1111-4111-8111-111111111111"
DISK_ID = "22222222-2222-4222-8222-222222222222"


def _handle(eid: str, name: str, kind: str) -> SimpleNamespace:
    return SimpleNamespace(
        evidence_id=eid,
        original_path=Path(f"/cases/x/{name}"),
        detected_os="windows",
        detected_kind=kind,
        sha256="0" * 64,
    )


class _MultiEvidence:
    """Doble con DOS evidencias: memoria y disco."""

    def __init__(self) -> None:
        self._h = {
            RAM_ID: _handle(RAM_ID, "original.raw", "memory"),
            DISK_ID: _handle(DISK_ID, "original.vmdk", "container_disk"),
        }

    def get(self, case_id: str, evidence_id: str) -> SimpleNamespace:
        return self._h[evidence_id]

    def list(self, case_id: str) -> list[SimpleNamespace]:
        return list(self._h.values())


class _ScriptedModel(ModelBackend):
    name = "fake"

    def __init__(self, actions: list[Any]) -> None:
        self._actions = list(actions)
        self.offered_specs: list[dict[str, Any]] = []
        self.seen_system = ""

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            supports_native_tools=False, json_mode=True, max_context=0, is_local=True
        )

    def next_action(self, state, tools):
        self.offered_specs = tools
        for m in state.get("messages", []):
            if m.get("role") == "system":
                self.seen_system = m["content"]
                break
        return self._actions.pop(0) if self._actions else FinalAnswer(text="fin")


def test_system_prompt_lists_both_evidences() -> None:
    pkg = make_package("windows")
    agent = ForensicAgent(pkg, _ScriptedModel([]), _MultiEvidence())
    text = agent._system_prompt(
        "c", "original.raw", ("tsk_fls", "volatility3"), "windows", "memory",
        evidence_choices=[
            (RAM_ID, "original.raw · memory"),
            (DISK_ID, "original.vmdk · container_disk"),
        ],
    )
    # El bloque de varias evidencias viaja entero, en el idioma del agente.
    assert t("agentCtx.multiEvidence").strip().splitlines()[0] in text
    assert RAM_ID in text and DISK_ID in text
    assert "memory" in text and "container_disk" in text


def test_tool_targets_the_chosen_evidence(monkeypatch) -> None:
    """`evidence_id` en la tool call resuelve el path de ESA evidencia, no la primaria."""
    seen: dict[str, Any] = {}

    def fake_execute(tool_id, params, **kwargs):
        seen["tool_id"] = tool_id
        seen["ctx_evidence_id"] = kwargs["evidence_context"].evidence_id
        # el path inyectado del volcado de RAM, no del vmdk primario
        seen["image_path"] = params.get("dump_path") or params.get("image_path")
        return {"tool_id": tool_id, "argv": [tool_id], "exit_code": 0,
                "stdout_sample": "ok", "stderr_sample": "", "parsed": None, "run_id": "r1"}

    monkeypatch.setattr("forensia.toolkit.dispatcher.execute", fake_execute)
    pkg = make_package("windows")
    # Primaria = disco; el modelo apunta volatility3 a la RAM explícitamente.
    model = _ScriptedModel([
        ToolCall(tool_id="volatility3", params={"evidence_id": RAM_ID, "plugin": "windows.info"}, call_id="x"),
    ])
    ForensicAgent(pkg, model, _MultiEvidence()).run(
        "perfila la memoria", case_id="c", evidence_id=DISK_ID
    )
    assert seen["ctx_evidence_id"] == RAM_ID  # el audit se ata a la RAM, no al disco
    assert "original.raw" in str(seen["image_path"])  # corrió sobre el volcado de RAM


def test_tool_schema_exposes_evidence_selector_only_when_multiple() -> None:
    from forensia.agent.tool_schemas import tool_spec

    choices = [(RAM_ID, "original.raw · memory"), (DISK_ID, "original.vmdk · container_disk")]
    with_sel = tool_spec("tsk_fls", choices)["function"]["parameters"]["properties"]
    assert "evidence_id" in with_sel
    assert set(with_sel["evidence_id"]["enum"]) == {RAM_ID, DISK_ID}
    # Con una sola evidencia NO se añade el selector (Agentopsy inyecta esa).
    one = tool_spec("tsk_fls", [(RAM_ID, "original.raw · memory")])["function"]["parameters"]["properties"]
    assert "evidence_id" not in one
    # Sin choices tampoco.
    assert "evidence_id" not in tool_spec("tsk_fls")["function"]["parameters"]["properties"]


def test_unknown_evidence_id_is_rejected(monkeypatch) -> None:
    def fake_execute(tool_id, params, **kwargs):  # pragma: no cover — no debe llamarse
        raise AssertionError("no debería ejecutar con una evidencia inválida")

    monkeypatch.setattr("forensia.toolkit.dispatcher.execute", fake_execute)
    pkg = make_package("windows")
    model = _ScriptedModel([
        ToolCall(tool_id="tsk_fls", params={"evidence_id": "99999999-9999-4999-8999-999999999999"}, call_id="x"),
    ])
    result = ForensicAgent(pkg, model, _MultiEvidence()).run(
        "x", case_id="c", evidence_id=DISK_ID
    )
    # El run no crashea: el error se le devuelve al modelo como resultado de tool.
    errs = [t for t in result["tool_calls"] if t.get("error")]
    assert any("no es una evidencia de este caso" in (t.get("error") or "") for t in errs)
