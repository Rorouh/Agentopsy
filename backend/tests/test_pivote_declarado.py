"""CP4 — El agente puede cambiar de vía, pero declarándolo.

La jugada que resolvió el Caso Murciélago en `prueba-agentes` fue un pivote: el
disco no abría (`nbd`/libguestfs no van en el host, convertir no cabía en disco)
→ volcar los hives desde la RAM con `hivelist --dump` y responder huso horario,
USB, cuentas y documentos recientes sin tocar el disco.

El agente no tenía forma de expresarlo, así que cuando una vía se cerraba seguía
empujando la misma puerta hasta agotar iteraciones.

RULE 2 prohíbe el fallback SILENCIOSO —«si esta tool falla pruebo la otra a ver»—,
no el pivote razonado. La diferencia está en estos gates:

- Exige `via_cerrada`, `motivo` (con su sostén) y `via_alternativa`. Sin los tres,
  se rechaza: un descarte sin prueba podría estar tapando un fallo puntual.
- Queda en la cadena de custodia hash-encadenada (`agent_pivot`), así que el
  perito VE que se descartó algo, con qué prueba y qué se hizo en su lugar.
- No ejecuta nada por su cuenta ni desbloquea ninguna herramienta.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agentopsy.i18n import t as traducir
from agentopsy.agent.agent import ForensicAgent
from _agent_pkg import make_package
from agentopsy.agent.tool_schemas import internal_tool_specs
from agentopsy.audit import AuditLog
from agentopsy.cases import CaseManager
from agentopsy.models.base import FinalAnswer, ModelBackend, ModelCapabilities, ToolCall

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENTES_DIR = REPO_ROOT / "agentes"


class _Scripted(ModelBackend):
    name = "fake"

    def __init__(self, actions: list[Any]) -> None:
        self._actions = list(actions)

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            supports_native_tools=False, json_mode=True, max_context=0, is_local=True
        )

    def next_action(self, state, tools):
        self.offered = [t["function"]["name"] for t in tools]
        return self._actions.pop(0) if self._actions else FinalAnswer(text="fin")


class _FakeEvidence:
    def get(self, case_id: str, evidence_id: str) -> SimpleNamespace:
        return SimpleNamespace(
            evidence_id=evidence_id,
            original_path=Path("/cases/x/original.raw"),
            detected_os="windows",
            detected_kind="disk",
            sha256="0" * 64,
        )


def _pivote(**params: Any) -> ToolCall:
    return ToolCall(tool_id="declarar_pivote", params=params, call_id="x")


@pytest.fixture
def wired(tmp_path):
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Caso", examiner="ramos", os_profile="windows")
    pkg = make_package("windows")

    def build(actions):
        model = _Scripted(actions)
        audit = AuditLog(cases.case_dir(case.id) / "audit.jsonl")
        return ForensicAgent(pkg, model, _FakeEvidence(), audit=audit), model

    return build, cases, case.id


def _audit_events(cases, case_id, action: str) -> list[dict]:
    path = cases.case_dir(case_id) / "audit.jsonl"
    if not path.is_file():
        return []
    return [
        e
        for e in (
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
        if (e.get("event") or e.get("action")) == action
    ]


# ── el pivote válido queda registrado ───────────────────────────────────────


def test_un_pivote_completo_se_registra_en_la_cadena_de_custodia(wired) -> None:
    build, cases, case_id = wired
    agent, _ = build([
        _pivote(
            via_cerrada="tsk_fls sobre el disco para fechar los documentos",
            motivo="exit 1, stderr 'Cannot determine file system type' (run 4ba06311)",
            via_alternativa=(
                "volcar los hives desde la RAM con volatility3 hivelist y pasarlos "
                "por regripper: da huso, cuentas y documentos recientes"
            ),
        )
    ])
    result = agent.run("analiza", case_id=case_id, evidence_id="e")

    call = result["tool_calls"][0]
    assert call["tool_id"] == "declarar_pivote"
    assert call.get("error") is None

    eventos = _audit_events(cases, case_id, "agent_pivot")
    assert len(eventos) == 1
    assert "tsk_fls" in eventos[0]["via_cerrada"]
    assert "run 4ba06311" in eventos[0]["motivo"]
    assert "regripper" in eventos[0]["via_alternativa"]


def test_el_perito_puede_ver_el_pivote_en_la_actividad(wired) -> None:
    build, _cases, case_id = wired
    eventos: list[dict] = []
    agent, _ = build([
        _pivote(via_cerrada="el disco", motivo="exit 1", via_alternativa="la RAM")
    ])
    agent.run("x", case_id=case_id, evidence_id="e", on_event=eventos.append)
    assert any(e.get("type") == "pivot" for e in eventos)


# ── un descarte sin sostén NO es un pivote ──────────────────────────────────


@pytest.mark.parametrize(
    "params",
    [
        {"via_cerrada": "el disco", "motivo": "", "via_alternativa": "la RAM"},
        {"via_cerrada": "", "motivo": "exit 1", "via_alternativa": "la RAM"},
        {"via_cerrada": "el disco", "motivo": "exit 1", "via_alternativa": ""},
        {},
    ],
)
def test_sin_los_tres_campos_se_rechaza(wired, params) -> None:
    build, cases, case_id = wired
    agent, _ = build([_pivote(**params)])
    result = agent.run("x", case_id=case_id, evidence_id="e")

    assert "obligatorios" in (result["tool_calls"][0].get("error") or "")
    # Y NO ensucia la cadena de custodia con un descarte sin prueba.
    assert _audit_events(cases, case_id, "agent_pivot") == []


def test_un_pivote_rechazado_no_tumba_el_run(wired) -> None:
    build, _cases, case_id = wired
    agent, _ = build([
        _pivote(via_cerrada="x", motivo="", via_alternativa=""),
        _pivote(via_cerrada="el disco", motivo="exit 1", via_alternativa="la RAM"),
    ])
    result = agent.run("x", case_id=case_id, evidence_id="e")
    assert result["tool_calls"][0].get("error")
    assert result["tool_calls"][1].get("error") is None


# ── no desbloquea nada ──────────────────────────────────────────────────────


def test_el_pivote_no_ejecuta_ninguna_herramienta(wired, monkeypatch) -> None:
    """Declarar no es actuar: el pivote solo deja constancia. Si además ejecutase
    algo, sería el fallback automático que RULE 2 prohíbe."""
    build, _cases, case_id = wired

    def forbidden(*a, **k):
        raise AssertionError("el pivote no debe llegar al dispatcher")

    monkeypatch.setattr("agentopsy.toolkit.dispatcher.execute", forbidden)
    agent, _ = build([
        _pivote(via_cerrada="el disco", motivo="exit 1", via_alternativa="la RAM")
    ])
    agent.run("x", case_id=case_id, evidence_id="e")


def test_la_tool_se_ofrece_y_exige_los_tres_campos() -> None:
    specs = {s["function"]["name"]: s["function"] for s in internal_tool_specs()}
    assert "declarar_pivote" in specs
    params = specs["declarar_pivote"]["parameters"]
    assert set(params["required"]) == {"via_cerrada", "motivo", "via_alternativa"}
    assert params["additionalProperties"] is False
    # La descripción tiene que dejar claro que exige el sostén.
    desc = specs["declarar_pivote"]["description"]
    # La descripción exige el SOSTÉN y prohíbe cambiar de vía en silencio. Se
    # comprueba en los DOS idiomas: es la garantía de la tool, no una frase.
    assert desc == traducir("schema.pivotDesc")
    assert "run_id" in traducir("schema.pivotDesc", "es")
    assert "silencio" in traducir("schema.pivotDesc", "es")
    assert "run_id" in traducir("schema.pivotDesc", "en")
    assert "silently" in traducir("schema.pivotDesc", "en")
