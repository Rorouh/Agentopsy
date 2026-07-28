"""CP4 — El índice del grafo viaja en el system prompt; el contenido NO.

Es el gate económico de todo el diseño: el gasto es `contexto × turnos`, así que
persistir a disco no ahorra nada si el contenido sigue viajando cada iteración.
Lo que viaja es el PUNTERO.

Gates:
- Con nodos escritos, el prompt lleva sus ids y sus SECCIONES.
- El CONTENIDO de un nodo nunca aparece en el prompt.
- El núcleo declarado se lista aunque esté vacío (para saber dónde escribir).
- Sin núcleo y sin nodos, la sección no existe (RULE 2: no prometer lo que no hay).
- Un caso sin encargo declarado es válido (decisión D4): nada revienta.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from forensia.agent.agent import ForensicAgent
from forensia.agent.loader import load_package
from forensia.agent.package import CaseKnowledgeNode
from forensia.cases import CaseManager
from forensia.knowledge import KnowledgeStore
from forensia.models.base import ModelCapabilities, ModelBackend

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENTES_DIR = REPO_ROOT / "agentes"


class _Noop(ModelBackend):
    name = "fake"

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            supports_native_tools=False, json_mode=True, max_context=0, is_local=True
        )

    def next_action(self, state, tools):  # pragma: no cover - no se invoca aquí
        raise AssertionError("no se usa")


@pytest.fixture
def prompt_for(tmp_path, monkeypatch):
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Caso grafo", examiner="ramos", os_profile="windows")
    store = KnowledgeStore(cases)
    monkeypatch.setattr("forensia.agent.agent.knowledge_store", store)

    def build(package=None):
        pkg = package or load_package(AGENTES_DIR / "forensia-windows")
        agent = ForensicAgent(pkg, _Noop(), SimpleNamespace())
        return agent._system_prompt(
            case.id, "original.raw", ("tsk_fls",), "windows", "disk"
        )

    return build, store, case.id


def test_el_nucleo_vacio_se_lista_para_saber_donde_escribir(prompt_for) -> None:
    build, _store, _case_id = prompt_for
    prompt = build()
    assert "## Conocimiento de este caso" in prompt
    assert "`perfil-sistema`" in prompt
    assert "(vacío)" in prompt


def test_un_nodo_escrito_aporta_sus_secciones_pero_no_su_contenido(prompt_for) -> None:
    build, store, case_id = prompt_for
    store.append(
        case_id,
        "perfil-sistema",
        "zona-horaria",
        "CONTENIDO-LARGO-QUE-NO-DEBE-VIAJAR Pacific UTC-7",
    )
    prompt = build()

    assert "`perfil-sistema`" in prompt
    assert "`zona-horaria`" in prompt  # el puntero sí
    assert "CONTENIDO-LARGO-QUE-NO-DEBE-VIAJAR" not in prompt  # el contenido no


def test_un_nodo_fuera_del_nucleo_tambien_aparece(prompt_for) -> None:
    build, store, case_id = prompt_for
    store.append(case_id, "hipotesis-exfiltracion", "canal", "sshd")
    prompt = build()
    assert "`hipotesis-exfiltracion`" in prompt
    assert "`canal`" in prompt


def test_sin_nucleo_y_sin_nodos_la_seccion_no_existe(prompt_for) -> None:
    build, _store, _case_id = prompt_for
    pkg = load_package(AGENTES_DIR / "forensia-windows")
    desnudo = type(pkg)(
        **{
            **{f.name: getattr(pkg, f.name) for f in pkg.__dataclass_fields__.values()},
            "case_knowledge": (),
        }
    )
    prompt = build(desnudo)
    assert "## Conocimiento de este caso" not in prompt


def test_el_indice_explica_como_escribir_y_leer(prompt_for) -> None:
    build, _store, _case_id = prompt_for
    prompt = build()
    assert "anotar_conocimiento(doc_id, section, content)" in prompt
    assert "consultar_conocimiento(doc_id)" in prompt
    assert "en caliente" in prompt.lower()


def test_caso_desconocido_no_revienta_el_prompt(tmp_path, monkeypatch) -> None:
    """Un caso sin encargo, o directamente inexistente, es un estado válido (D4):
    el prompt se construye igual, solo con el núcleo."""
    cases = CaseManager(root=tmp_path / "cases")
    monkeypatch.setattr("forensia.agent.agent.knowledge_store", KnowledgeStore(cases))
    pkg = load_package(AGENTES_DIR / "forensia-unix")
    agent = ForensicAgent(pkg, _Noop(), SimpleNamespace())

    prompt = agent._system_prompt(
        "11111111-1111-4111-8111-111111111111", "x.raw", ("tsk_fls",), "unix", "disk"
    )
    assert "## Conocimiento de este caso" in prompt
    assert "`preguntas-abiertas`" in prompt


def test_el_nucleo_incluye_preguntas_abiertas_que_se_llena_incrementalmente(
    prompt_for,
) -> None:
    """Decisión D4: el encargo no se pide por adelantado; el nodo se llena según
    llegan las peticiones."""
    build, _store, _case_id = prompt_for
    prompt = build()
    assert "`preguntas-abiertas`" in prompt
    assert "PETICIÓN A PETICIÓN" in prompt or "petición" in prompt.lower()


def test_case_knowledge_node_es_solo_id_y_descripcion() -> None:
    node = CaseKnowledgeNode(id="x", description="y")
    assert set(node.__dataclass_fields__) == {"id", "description"}
