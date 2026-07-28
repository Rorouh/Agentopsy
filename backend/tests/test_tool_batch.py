"""CP2 — Varias herramientas en un solo turno del modelo.

Por qué: el coste de una corrida es `contexto × turnos` — el ejecutor es stateless
y Agentopsy le reenvía el transcript entero en cada iteración. Con una herramienta
por turno, el barrido de ~25 ejecuciones que resolvió el Caso Murciélago en
`prueba-agentes` no cabe ni en presupuesto ni en el tope de iteraciones.

Gates:
- El parser acepta `tool_batch` y valida su forma (fail-loud, RULE 2).
- El loop ejecuta TODAS las llamadas del lote en la MISMA iteración, en orden.
- El lote no relaja ninguna garantía: cada call deja su entrada en el log y su
  mensaje de resultado; el guardrail anti-bucle sigue contando fallos.
- Un `tool_call` suelto sigue funcionando igual (no hay regresión de contrato).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from forensia.agent.agent import ForensicAgent
from forensia.agent.loader import load_package
from forensia.models.base import (
    ExecutorBackend,
    FinalAnswer,
    ModelBackend,
    ModelCapabilities,
    ToolBatch,
    ToolCall,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENTES_DIR = REPO_ROOT / "agentes"


# ── el parser del contrato ──────────────────────────────────────────────────


def _parse(text: str):
    return ExecutorBackend._parse_action(text)


def test_parsea_un_lote() -> None:
    action = _parse(
        '{"action":"tool_batch","calls":['
        '{"tool_id":"tsk_mmls","params":{}},'
        '{"tool_id":"tsk_fls","params":{"recursive":true}}]}'
    )
    assert isinstance(action, ToolBatch)
    assert [c.tool_id for c in action.calls] == ["tsk_mmls", "tsk_fls"]
    assert action.calls[1].params == {"recursive": True}
    # Cada call lleva su propio id para anclar su resultado.
    assert len({c.call_id for c in action.calls}) == 2


def test_un_tool_call_suelto_sigue_funcionando() -> None:
    action = _parse('{"action":"tool_call","tool_id":"file_info","params":{}}')
    assert isinstance(action, ToolCall)
    assert action.tool_id == "file_info"


def test_final_sigue_funcionando() -> None:
    assert isinstance(_parse('{"action":"final","text":"listo"}'), FinalAnswer)


@pytest.mark.parametrize(
    "bad",
    [
        '{"action":"tool_batch"}',
        '{"action":"tool_batch","calls":[]}',
        '{"action":"tool_batch","calls":"tsk_fls"}',
        '{"action":"tool_batch","calls":[{"params":{}}]}',
        '{"action":"tool_batch","calls":[{"tool_id":"x","params":"no"}]}',
        '{"action":"tool_batch","calls":["tsk_fls"]}',
    ],
)
def test_un_lote_mal_formado_falla_fuerte(bad) -> None:
    with pytest.raises(ValueError):
        _parse(bad)


def test_el_contrato_le_explica_al_modelo_cuando_usar_el_lote() -> None:
    prompt = ExecutorBackend._render_prompt(
        [{"role": "user", "content": "x"}], [{"function": {"name": "f"}}]
    )
    assert "tool_batch" in prompt
    assert "cuestan mucho menos" in prompt or "menos que" in prompt


# ── el loop ejecuta el lote entero en una iteración ─────────────────────────


class _OneBatchThenFinal(ModelBackend):
    name = "fake"

    def __init__(self, calls: list[ToolCall]) -> None:
        self._batch = ToolBatch(
            calls=tuple(calls),
            assistant_message={"role": "assistant", "content": "voy a lanzar el lote"},
        )
        self.turns = 0

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            supports_native_tools=False, json_mode=True, max_context=0, is_local=True
        )

    def next_action(self, state, tools):
        self.turns += 1
        return self._batch if self.turns == 1 else FinalAnswer(text="fin")


class _FakeEvidence:
    def get(self, case_id: str, evidence_id: str) -> SimpleNamespace:
        return SimpleNamespace(
            evidence_id=evidence_id,
            original_path=Path("/cases/x/original.raw"),
            detected_os="unix",
            detected_kind="disk",
            sha256="0" * 64,
        )


def _call(tool_id: str, **params: Any) -> ToolCall:
    return ToolCall(tool_id=tool_id, params=params, call_id=tool_id)


def test_tres_herramientas_en_un_solo_turno_del_modelo(monkeypatch) -> None:
    ejecutadas: list[str] = []

    def fake_execute(tool_id, params, **kwargs):
        ejecutadas.append(tool_id)
        return {
            "tool_id": tool_id,
            "argv": [tool_id],
            "exit_code": 0,
            "stdout_sample": "",
            "stderr_sample": "",
            "parsed": None,
            "run_id": "r",
        }

    monkeypatch.setattr("forensia.toolkit.dispatcher.execute", fake_execute)
    pkg = load_package(AGENTES_DIR / "forensia-unix")
    model = _OneBatchThenFinal(
        [_call("tsk_mmls"), _call("file_info"), _call("strings_head")]
    )
    agent = ForensicAgent(pkg, model, _FakeEvidence())

    result = agent.run("barre", case_id="c", evidence_id="e")

    # Las tres se ejecutaron, EN ORDEN…
    assert ejecutadas == ["tsk_mmls", "file_info", "strings_head"]
    # …y el modelo solo habló DOS veces (el lote + el cierre).
    assert model.turns == 2
    assert result["iterations"] == 2
    # Cada una dejó su entrada en el log, como si fueran calls sueltas.
    ids = [c["tool_id"] for c in result["tool_calls"]]
    assert ids == ["tsk_mmls", "file_info", "strings_head"]


def test_un_fallo_en_medio_no_aborta_el_resto_del_lote(monkeypatch) -> None:
    """Política del FLUJO destilado: «emitir lo legible + listar las saltadas». Un
    plugin no soportado no debe tumbar el barrido entero (heurística h5)."""
    ejecutadas: list[str] = []

    def fake_execute(tool_id, params, **kwargs):
        ejecutadas.append(tool_id)
        return {
            "tool_id": tool_id,
            "argv": [tool_id],
            "exit_code": 1 if tool_id == "file_info" else 0,
            "stdout_sample": "",
            "stderr_sample": "no soportado" if tool_id == "file_info" else "",
            "parsed": None,
            "run_id": "r",
        }

    monkeypatch.setattr("forensia.toolkit.dispatcher.execute", fake_execute)
    pkg = load_package(AGENTES_DIR / "forensia-unix")
    model = _OneBatchThenFinal(
        [_call("tsk_mmls"), _call("file_info"), _call("strings_head")]
    )
    result = ForensicAgent(pkg, model, _FakeEvidence()).run(
        "barre", case_id="c", evidence_id="e"
    )

    assert ejecutadas == ["tsk_mmls", "file_info", "strings_head"]
    codes = {c["tool_id"]: c.get("exit_code") for c in result["tool_calls"]}
    assert codes["file_info"] == 1
    assert codes["strings_head"] == 0


def test_una_tool_fuera_de_la_allowlist_dentro_del_lote_se_rechaza_sin_parar(
    monkeypatch,
) -> None:
    ejecutadas: list[str] = []

    def fake_execute(tool_id, params, **kwargs):
        ejecutadas.append(tool_id)
        return {
            "tool_id": tool_id, "argv": [tool_id], "exit_code": 0,
            "stdout_sample": "", "stderr_sample": "", "parsed": None, "run_id": "r",
        }

    monkeypatch.setattr("forensia.toolkit.dispatcher.execute", fake_execute)
    pkg = load_package(AGENTES_DIR / "forensia-unix")
    # `regripper` es del paquete windows: fuera de la allowlist unix.
    model = _OneBatchThenFinal([_call("tsk_mmls"), _call("regripper"), _call("jq")])
    result = ForensicAgent(pkg, model, _FakeEvidence()).run(
        "barre", case_id="c", evidence_id="e"
    )

    assert "regripper" not in ejecutadas  # nunca llegó al dispatcher
    assert ejecutadas == ["tsk_mmls", "jq"]  # el resto del lote sí corrió
    rechazo = next(c for c in result["tool_calls"] if c["tool_id"] == "regripper")
    assert rechazo["refused"] is True
    assert rechazo["reason"] == "not_in_allowlist"
