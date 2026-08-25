"""CP3 — Las dos tools del grafo, cableadas en el loop.

Gates:
- `anotar_conocimiento` PERSISTE y queda en la cadena de audit (metadatos + hash,
  nunca el contenido).
- Un `doc_id` inválido NO tumba el run: vuelve como error de tool para que el
  modelo se corrija (misma política que el resto del canal lateral).
- **Control C4 (canal de blanqueo)**: lo que vuelve de un nodo del CASO viaja
  marcado NO CONFIABLE; lo que vuelve de un doc ESTÁTICO del paquete no. Es la
  frontera que impide que bytes derivados de evidencia hostil entren como notas
  del agente y salgan como contexto de confianza.
- El error de id desconocido nombra LOS DOS ámbitos (paquete y caso).
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from forensia.i18n import t
from forensia.agent.agent import ForensicAgent
from _agent_pkg import make_package
from forensia.agent.tool_schemas import internal_tool_specs
from forensia.audit import AuditLog
from forensia.cases import CaseManager
from forensia.knowledge import DOC_ID_PATTERN, KnowledgeStore
from forensia.models.base import FinalAnswer, ModelBackend, ModelCapabilities, ToolCall

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


class _ScriptedModel(ModelBackend):
    """Emite una lista fija de acciones y GUARDA los mensajes que ve en cada turno.

    Guardar el estado es lo que permite comprobar el envoltorio de no-confianza:
    es exactamente lo que el modelo real leería.
    """

    name = "fake"

    def __init__(self, actions: list[Any]) -> None:
        self._actions = list(actions)
        self.seen_messages: list[list[dict[str, Any]]] = []

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            supports_native_tools=False, json_mode=True, max_context=0, is_local=True
        )

    def next_action(self, state: dict[str, Any], tools: list[dict[str, Any]]) -> Any:
        self.seen_messages.append(list(state.get("messages") or []))
        self.offered_tools = [t["function"]["name"] for t in tools]
        if self._actions:
            return self._actions.pop(0)
        return FinalAnswer(text="fin")


def _call(tool_id: str, **params: Any) -> ToolCall:
    return ToolCall(
        tool_id=tool_id,
        params=params,
        call_id="x",
        assistant_message={"role": "assistant", "content": "{}"},
    )


class _FakeEvidence:
    def get(self, case_id: str, evidence_id: str) -> SimpleNamespace:
        return SimpleNamespace(
            evidence_id=evidence_id,
            original_path=Path("/cases/x/original.raw"),
            detected_os="windows",
            detected_kind="disk",
            sha256="0" * 64,
        )


@pytest.fixture
def wired(tmp_path, monkeypatch):
    """Agente real con el store apuntando a un root temporal."""
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Caso grafo", examiner="ramos", os_profile="windows")
    store = KnowledgeStore(cases)
    monkeypatch.setattr("forensia.agent.agent.knowledge_store", store)
    pkg = make_package("windows")

    def build(actions):
        model = _ScriptedModel(actions)
        # El audit es opcional en el constructor; aquí se ancla al caso temporal
        # porque parte del contrato es QUÉ queda en la cadena (y qué no).
        audit = AuditLog(cases.case_dir(case.id) / "audit.jsonl")
        return ForensicAgent(pkg, model, _FakeEvidence(), audit=audit), model

    return build, store, case.id, cases


# ── escritura ───────────────────────────────────────────────────────────────


def test_anotar_persiste_y_devuelve_ok(wired) -> None:
    build, store, case_id, _ = wired
    agent, _model = build([
        _call(
            "anotar_conocimiento",
            doc_id="perfil-sistema",
            section="zona-horaria",
            content="Pacific (UTC-7), del hive SYSTEM. run 4ba06311-...",
        )
    ])

    result = agent.run("anota", case_id=case_id, evidence_id="e")

    logged = [c for c in result["tool_calls"] if c["tool_id"] == "anotar_conocimiento"]
    assert logged and logged[0].get("error") is None
    node = store.read(case_id, "perfil-sistema")
    assert node is not None
    assert "Pacific (UTC-7)" in node.markdown


def test_anotar_queda_en_el_audit_sin_el_contenido(wired) -> None:
    build, _store, case_id, cases = wired
    agent, _ = build([
        _call(
            "anotar_conocimiento",
            doc_id="cuentas",
            section="testuser",
            content="SECRETO-QUE-NO-DEBE-ESTAR-EN-EL-AUDIT",
        )
    ])
    agent.run("anota", case_id=case_id, evidence_id="e")

    audit_path = cases.case_dir(case_id) / "audit.jsonl"
    entries = [
        json.loads(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    # El canal lateral del agente escribe bajo la clave `event` (el EvidenceManager
    # usa `action`); se aceptan las dos para no acoplar el test a esa asimetría.
    written = [
        e
        for e in entries
        if (e.get("event") or e.get("action")) == "knowledge_written"
    ]
    assert len(written) == 1
    assert written[0]["doc_id"] == "cuentas"
    assert written[0]["section"] == "testuser"
    assert len(written[0]["content_sha256"]) == 64
    # Metadatos y hash, JAMÁS el contenido (F3).
    assert "SECRETO-QUE-NO-DEBE-ESTAR-EN-EL-AUDIT" not in audit_path.read_text("utf-8")


def test_doc_id_invalido_no_tumba_el_run_y_vuelve_como_error(wired) -> None:
    build, store, case_id, _ = wired
    agent, _ = build([
        _call("anotar_conocimiento", doc_id="../../fuera", section="s", content="c"),
        _call("anotar_conocimiento", doc_id="recuperado", section="s", content="c"),
    ])

    result = agent.run("anota", case_id=case_id, evidence_id="e")

    calls = [c for c in result["tool_calls"] if c["tool_id"] == "anotar_conocimiento"]
    assert "doc_id" in (calls[0].get("error") or "")
    # El loop siguió y el segundo intento sí escribió: el modelo puede corregirse.
    assert calls[1].get("error") is None
    assert store.read(case_id, "recuperado") is not None


def test_contenido_gigante_se_rechaza_con_error_accionable(wired) -> None:
    build, _store, case_id, _ = wired
    agent, _ = build([
        _call("anotar_conocimiento", doc_id="n", section="s", content="x" * 99_999)
    ])
    result = agent.run("anota", case_id=case_id, evidence_id="e")
    err = result["tool_calls"][0].get("error") or ""
    assert "tope" in err and "run_id" in err


# ── lectura y control C4 (blanqueo) ─────────────────────────────────────────


def _tool_messages(messages: list[dict[str, Any]]) -> str:
    return "\n".join(
        str(m.get("content") or "") for m in messages if m.get("role") == "tool"
    )


def test_un_nodo_del_caso_vuelve_marcado_no_confiable(wired) -> None:
    build, store, case_id, _ = wired
    store.append(case_id, "leads", "key-exe", "Ejecutable sospechoso en el Desktop")

    agent, model = build([_call("consultar_conocimiento", doc_id="leads")])
    agent.run("consulta", case_id=case_id, evidence_id="e")

    # El ÚLTIMO estado que vio el modelo lleva el resultado de la tool.
    served = _tool_messages(model.seen_messages[-1])
    assert "Ejecutable sospechoso en el Desktop" in served
    # C4: las notas del agente citan cadenas derivadas de evidencia hostil →
    # vuelven como DATO, nunca como instrucción.
    assert _marca("agentLoop.untrustedOpen") in served


def test_un_doc_estatico_del_paquete_sigue_siendo_de_confianza(wired) -> None:
    build, _store, case_id, _ = wired
    agent, model = build([
        _call("consultar_conocimiento", doc_id="artefactos-windows")
    ])
    agent.run("consulta", case_id=case_id, evidence_id="e")

    served = _tool_messages(model.seen_messages[-1])
    assert served, "el doc del paquete debería haberse servido"
    # Lo escribió el equipo, no la evidencia: sin spotlighting.
    assert _marca("agentLoop.untrustedOpen") not in served


def test_el_nodo_del_caso_gana_al_doc_del_paquete_con_el_mismo_id(wired) -> None:
    """Ámbito del caso primero: si el agente creó un nodo con el id de un doc del
    paquete, lo que quiere leer es SU nota, no el catálogo genérico."""
    build, store, case_id, _ = wired
    store.append(case_id, "artefactos-windows", "mi-nota", "LO-MIO-DEL-CASO")

    agent, model = build([_call("consultar_conocimiento", doc_id="artefactos-windows")])
    agent.run("consulta", case_id=case_id, evidence_id="e")

    served = _tool_messages(model.seen_messages[-1])
    assert "LO-MIO-DEL-CASO" in served
    assert _marca("agentLoop.untrustedOpen") in served


def test_id_desconocido_nombra_los_dos_ambitos(wired) -> None:
    build, store, case_id, _ = wired
    store.append(case_id, "cronologia", "s", "c")

    agent, _ = build([_call("consultar_conocimiento", doc_id="no-existe")])
    result = agent.run("consulta", case_id=case_id, evidence_id="e")

    err = result["tool_calls"][0].get("error") or ""
    # El paquete ya no trae docs estáticos (contrato de archivo único): la
    # referencia de paquete es vacía y solo hay nodos del CASO.
    # El error nombra los DOS ámbitos: el del paquete y el del caso.
    assert err == t(
        "agentLoop.unknownDocId",
        None,
        doc_id=repr("no-existe"),
        valid=[],
        nodes=["cronologia"],
    )
    assert "cronologia" in err  # ámbito caso
    assert "anotar_conocimiento" in err  # y cómo crearlo


# ── contrato expuesto al modelo ─────────────────────────────────────────────


def test_anotar_esta_en_las_specs_internas_con_el_charset_cerrado() -> None:
    specs = {s["function"]["name"]: s["function"] for s in internal_tool_specs()}
    assert "anotar_conocimiento" in specs
    params = specs["anotar_conocimiento"]["parameters"]
    assert params["required"] == ["doc_id", "section", "content"]
    assert params["additionalProperties"] is False
    # El patrón que ve el modelo es EL MISMO que impone el store.
    assert params["properties"]["doc_id"]["pattern"] == DOC_ID_PATTERN


def test_anotar_se_ofrece_siempre_consultar_cuando_hay_algo(wired) -> None:
    """El paquete ya no trae docs estáticos: `anotar_conocimiento` se ofrece
    siempre (el grafo puede empezar vacío), pero `consultar_conocimiento` solo
    cuando hay ALGO que servir — un nodo escrito en este caso (RULE 2: sin índice
    no hay tool que prometa algo inexistente)."""
    build, store, case_id, _ = wired

    # Caso vacío: solo anotar.
    agent, model = build([])
    agent.run("hola", case_id=case_id, evidence_id="e")
    assert "anotar_conocimiento" in model.offered_tools
    assert "consultar_conocimiento" not in model.offered_tools

    # Tras escribir un nodo, consultar aparece.
    store.append(case_id, "cronologia", "s", "c")
    agent2, model2 = build([])
    agent2.run("hola", case_id=case_id, evidence_id="e")
    assert "anotar_conocimiento" in model2.offered_tools
    assert "consultar_conocimiento" in model2.offered_tools
