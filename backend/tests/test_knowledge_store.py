"""CP1 — Store del grafo de conocimiento por caso.

Gates que cierra este fichero:

- **C1 · el modelo emite un id, nunca una ruta**: el charset cerrado hace que el
  traversal no sea expresable, y cualquier intento se rechaza fuerte.
- **C2 · confinamiento**: nada se escribe fuera del `knowledge/` del caso.
- **C3 · append-only con vista consolidada**: el registro nunca pierde una
  versión; la vista muestra la última de cada sección, en orden estable.
- **C6 · caps**: bloque, secciones por nodo y nodos por caso fallan fuerte
  (RULE 2: error accionable, jamás truncado silencioso).
- **C7 · un nodo no es un hallazgo**: el store no toca `findings.jsonl`.
"""

from __future__ import annotations

import json

import pytest

from agentopsy.cases import CaseManager
from agentopsy.knowledge import (
    MAX_BLOCK_CHARS,
    MAX_NODES_PER_CASE,
    MAX_SECTIONS_PER_NODE,
    KnowledgeStore,
)


@pytest.fixture
def store_case(tmp_path) -> tuple[KnowledgeStore, str, CaseManager]:
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Caso grafo", examiner="ramos", os_profile="windows")
    return KnowledgeStore(cases), case.id, cases


# ── C1 · el doc_id es un id, no una ruta ────────────────────────────────────


@pytest.mark.parametrize(
    "bad",
    [
        "../../etc/passwd",
        "/etc/passwd",
        "..",
        "a/b",
        "a.b",
        "Perfil-Sistema",  # mayúsculas fuera del charset
        "-empieza-con-guion",
        "",
        "   ",
        "x" * 65,
        "nodo con espacios",
        "nodo\nsalto",
    ],
)
def test_doc_id_fuera_del_charset_se_rechaza(store_case, bad) -> None:
    store, case_id, _ = store_case
    with pytest.raises(ValueError, match="doc_id"):
        store.append(case_id, bad, "seccion", "contenido")


def test_doc_id_valido_se_acepta(store_case) -> None:
    store, case_id, _ = store_case
    for good in ("perfil-sistema", "a", "nodo123", "9-vidas"):
        block = store.append(case_id, good, "s", "c")
        assert block.doc_id == good


def test_traversal_no_escribe_nada_fuera(store_case, tmp_path) -> None:
    store, case_id, cases = store_case
    with pytest.raises(ValueError):
        store.append(case_id, "../../fuera", "s", "c")
    # Nada se creó fuera del caso.
    assert not (tmp_path / "fuera.md").exists()
    assert not (cases.root / "fuera.md").exists()


# ── C2 · confinamiento ──────────────────────────────────────────────────────


def test_todo_se_escribe_bajo_knowledge_del_caso(store_case) -> None:
    store, case_id, cases = store_case
    store.append(case_id, "perfil-sistema", "SO", "Win7 SP1 x64")
    kdir = cases.case_dir(case_id) / "knowledge"
    assert (kdir / "perfil-sistema.md").is_file()
    assert (kdir / ".historial" / "perfil-sistema.jsonl").is_file()
    # No se tocó ni la evidencia ni los artefactos.
    assert list((cases.case_dir(case_id) / "evidence").glob("*")) == []


def test_caso_desconocido_falla(store_case) -> None:
    store, _, _ = store_case
    with pytest.raises(KeyError):
        store.append("11111111-1111-4111-8111-111111111111", "n", "s", "c")


# ── C3 · append-only con vista consolidada ──────────────────────────────────


def test_reescribir_una_seccion_supersede_la_vista_pero_conserva_el_registro(
    store_case,
) -> None:
    store, case_id, cases = store_case
    store.append(case_id, "perfil-sistema", "zona-horaria", "UTC (provisional)")
    store.append(case_id, "perfil-sistema", "zona-horaria", "Pacific (UTC-7)")

    node = store.read(case_id, "perfil-sistema")
    assert node is not None
    # La VISTA solo enseña la última.
    assert "Pacific (UTC-7)" in node.markdown
    assert "UTC (provisional)" not in node.markdown
    # El REGISTRO conserva las dos: nada se borra jamás.
    history = store.history(case_id, "perfil-sistema")
    assert [b.content for b in history] == ["UTC (provisional)", "Pacific (UTC-7)"]
    assert node.block_count == 2

    # Y en disco, el jsonl tiene dos líneas íntegras.
    raw = (cases.case_dir(case_id) / "knowledge" / ".historial" / "perfil-sistema.jsonl")
    lines = [json.loads(x) for x in raw.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert len(lines) == 2
    assert lines[0]["content"] == "UTC (provisional)"


def test_el_orden_de_secciones_es_el_de_primera_aparicion(store_case) -> None:
    store, case_id, _ = store_case
    store.append(case_id, "cronologia", "inicio", "17:15 login")
    store.append(case_id, "cronologia", "final", "19:24 volcado")
    # Corregir la PRIMERA no debe saltarla al final.
    store.append(case_id, "cronologia", "inicio", "17:15:22 login de IEUser")

    node = store.read(case_id, "cronologia")
    assert node is not None
    assert node.sections == ("inicio", "final")
    assert node.markdown.index("inicio") < node.markdown.index("final")


def test_varias_secciones_conviven(store_case) -> None:
    store, case_id, _ = store_case
    store.append(case_id, "perfil-sistema", "SO", "Win7 SP1 x64")
    store.append(case_id, "perfil-sistema", "hora-del-volcado", "2021-03-23 19:24:35 UTC")
    node = store.read(case_id, "perfil-sistema")
    assert node is not None
    assert "Win7 SP1 x64" in node.markdown
    assert "2021-03-23 19:24:35 UTC" in node.markdown
    assert node.sections == ("SO", "hora-del-volcado")


def test_el_bloque_lleva_hash_y_marca_de_tiempo(store_case) -> None:
    store, case_id, _ = store_case
    block = store.append(case_id, "cuentas", "testuser", "creada 19:07:38", iteration=3)
    assert len(block.sha256) == 64
    assert block.created_at.endswith("Z")
    assert block.iteration == 3


# ── lectura e índice ────────────────────────────────────────────────────────


def test_nodo_inexistente_devuelve_none_y_historial_vacio(store_case) -> None:
    store, case_id, _ = store_case
    assert store.read(case_id, "no-existe") is None
    assert store.history(case_id, "no-existe") == []


def test_indice_vacio_en_caso_nuevo(store_case) -> None:
    store, case_id, _ = store_case
    assert store.index(case_id) == []


def test_el_indice_lleva_secciones_pero_no_contenido(store_case) -> None:
    store, case_id, _ = store_case
    store.append(case_id, "perfil-sistema", "SO", "Win7 SP1 x64 build 7601")
    store.append(case_id, "cuentas", "testuser", "admin creada 19:07:38")

    index = store.index(case_id)
    assert {n.doc_id for n in index} == {"perfil-sistema", "cuentas"}
    perfil = next(n for n in index if n.doc_id == "perfil-sistema")
    assert perfil.sections == ("SO",)
    assert perfil.block_count == 1
    # El índice NO arrastra contenido: es lo que lo hace barato en contexto.
    assert not any("7601" in str(n) for n in index)


# ── C6 · topes: fallan fuerte, nunca truncan ────────────────────────────────


def test_bloque_demasiado_grande_falla_con_error_accionable(store_case) -> None:
    store, case_id, _ = store_case
    with pytest.raises(ValueError, match="tope"):
        store.append(case_id, "n", "s", "x" * (MAX_BLOCK_CHARS + 1))


def test_contenido_vacio_se_rechaza(store_case) -> None:
    store, case_id, _ = store_case
    with pytest.raises(ValueError, match="content"):
        store.append(case_id, "n", "s", "   ")


def test_seccion_invalida_se_rechaza(store_case) -> None:
    store, case_id, _ = store_case
    with pytest.raises(ValueError, match="section"):
        store.append(case_id, "n", "", "c")
    with pytest.raises(ValueError, match="section"):
        store.append(case_id, "n", "x" * 121, "c")


def test_tope_de_nodos_por_caso(store_case) -> None:
    store, case_id, _ = store_case
    for i in range(MAX_NODES_PER_CASE):
        store.append(case_id, f"nodo-{i}", "s", "c")
    with pytest.raises(ValueError, match="tope"):
        store.append(case_id, "uno-de-mas", "s", "c")
    # Pero añadir a un nodo EXISTENTE sigue funcionando.
    store.append(case_id, "nodo-0", "otra-seccion", "c")


def test_tope_de_secciones_por_nodo(store_case) -> None:
    store, case_id, _ = store_case
    for i in range(MAX_SECTIONS_PER_NODE):
        store.append(case_id, "grande", f"sec-{i}", "c")
    with pytest.raises(ValueError, match="secciones"):
        store.append(case_id, "grande", "una-de-mas", "c")
    # Reescribir una sección YA existente no cuenta contra el tope.
    store.append(case_id, "grande", "sec-0", "corregido")


# ── robustez ────────────────────────────────────────────────────────────────


def test_una_linea_corrupta_no_invalida_el_registro(store_case, caplog) -> None:
    store, case_id, cases = store_case
    store.append(case_id, "n", "s1", "bueno")
    raw = cases.case_dir(case_id) / "knowledge" / ".historial" / "n.jsonl"
    with raw.open("a", encoding="utf-8") as fh:
        fh.write("{esto no es json\n")
    store.append(case_id, "n", "s2", "tambien bueno")

    history = store.history(case_id, "n")
    assert [b.content for b in history] == ["bueno", "tambien bueno"]


def test_la_vista_se_reescribe_atomicamente_sin_dejar_tmp(store_case) -> None:
    store, case_id, cases = store_case
    store.append(case_id, "n", "s", "c")
    store.append(case_id, "n", "s", "c2")
    kdir = cases.case_dir(case_id) / "knowledge"
    assert [p.name for p in kdir.glob(".*.tmp")] == []
