"""CP2 — El núcleo del grafo por caso se declara en el paquete (decisión D2).

Híbrido: el manifiesto fija un núcleo estable de nodos para que el índice del
prompt tenga forma conocida, y el agente puede crear otros dentro del charset.

Gates:
- `case_knowledge` es OPCIONAL: un paquete sin él sigue cargando (grafo libre).
- Los ids se validan contra el MISMO charset que impone el store en runtime, de
  modo que un núcleo mal declarado revienta al ARRANCAR el api, no en mitad de un
  análisis (RULE 2 — fallar en la frontera correcta).
- Los dos paquetes reales lo declaran y sus ids son válidos.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from forensia.agent.loader import AgentPackageError, load_package
from forensia.cases import CaseManager
from forensia.knowledge import DOC_ID_PATTERN, MAX_NODES_PER_CASE, KnowledgeStore


def _repo_agentes() -> Path:
    return Path(__file__).resolve().parents[2] / "agentes"


def _write_pkg(tmp_path, case_knowledge) -> "object":
    """Paquete mínimo válido con el `case_knowledge` que se quiera probar."""
    d = tmp_path / "pkg"
    (d / "prompts").mkdir(parents=True)
    (d / "policy").mkdir(parents=True)
    for name in ("system", "identity", "playbook"):
        (d / "prompts" / f"{name}.md").write_text(f"# {name}\n", encoding="utf-8")
    (d / "policy" / "tools.yaml").write_text(
        yaml.safe_dump({"allowed": ["file_info"]}), encoding="utf-8"
    )
    (d / "policy" / "redaction.yaml").write_text(
        yaml.safe_dump({"patterns": []}), encoding="utf-8"
    )
    manifest = {
        "id": "pkg-prueba",
        "name": "Paquete de prueba",
        "version": "0.1.0",
        "os_profile": "unix",
        "model": {"name": "m", "temperature": 0.1, "max_iterations": 4},
        "prompts": {
            "system": "prompts/system.md",
            "identity": "prompts/identity.md",
            "playbook": "prompts/playbook.md",
        },
        "policy": {"tools": "policy/tools.yaml", "redaction": "policy/redaction.yaml"},
    }
    if case_knowledge is not None:
        manifest["case_knowledge"] = case_knowledge
    (d / "agent.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    return d


def test_case_knowledge_es_opcional(tmp_path) -> None:
    pkg = load_package(_write_pkg(tmp_path, None))
    assert pkg.case_knowledge == ()


def test_nucleo_valido_se_carga(tmp_path) -> None:
    pkg = load_package(
        _write_pkg(
            tmp_path,
            [
                {"id": "perfil-sistema", "description": "SO, build y huso."},
                {"id": "cuentas", "description": "Usuarios del sistema."},
            ],
        )
    )
    assert [n.id for n in pkg.case_knowledge] == ["perfil-sistema", "cuentas"]
    assert pkg.case_knowledge[0].description.startswith("SO")


@pytest.mark.parametrize(
    "bad_id", ["Perfil-Sistema", "../fuera", "a/b", "a.b", "-guion", "con espacio"]
)
def test_id_fuera_del_charset_falla_al_cargar(tmp_path, bad_id) -> None:
    with pytest.raises(AgentPackageError, match="case_knowledge"):
        load_package(_write_pkg(tmp_path, [{"id": bad_id, "description": "x"}]))


def test_id_duplicado_falla(tmp_path) -> None:
    with pytest.raises(AgentPackageError, match="duplicate"):
        load_package(
            _write_pkg(
                tmp_path,
                [{"id": "a", "description": "x"}, {"id": "a", "description": "y"}],
            )
        )


def test_descripcion_obligatoria(tmp_path) -> None:
    with pytest.raises(AgentPackageError, match="description"):
        load_package(_write_pkg(tmp_path, [{"id": "a"}]))


def test_no_es_una_lista_falla(tmp_path) -> None:
    with pytest.raises(AgentPackageError, match="case_knowledge"):
        load_package(_write_pkg(tmp_path, {"id": "a"}))


def test_el_nucleo_no_puede_agotar_el_tope_del_store(tmp_path) -> None:
    demasiados = [
        {"id": f"nodo-{i}", "description": "x"} for i in range(MAX_NODES_PER_CASE + 1)
    ]
    with pytest.raises(AgentPackageError, match="tope|admite"):
        load_package(_write_pkg(tmp_path, demasiados))


# ── los paquetes REALES del repo ────────────────────────────────────────────


@pytest.mark.parametrize("pkg_id", ["forensia-unix", "forensia-windows"])
def test_los_paquetes_reales_declaran_un_nucleo_usable(pkg_id, tmp_path) -> None:
    pkg = load_package(_repo_agentes() / pkg_id)
    assert pkg.case_knowledge, f"{pkg_id} debería declarar case_knowledge"

    ids = [n.id for n in pkg.case_knowledge]
    # El núcleo acordado en la decisión D2.
    assert {"perfil-sistema", "cuentas", "cronologia", "preguntas-abiertas"} <= set(ids)

    # Y cada id declarado es ACEPTABLE por el store en runtime: si el manifiesto
    # pudiera declarar un id que el store rechaza, el agente fallaría al anotarlo.
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="c", examiner="e", os_profile=pkg.os_profile)
    store = KnowledgeStore(cases)
    for node_id in ids:
        assert re.match(DOC_ID_PATTERN, node_id)
        store.append(case.id, node_id, "prueba", "contenido")


@pytest.mark.parametrize("pkg_id", ["forensia-unix", "forensia-windows"])
def test_el_summary_expone_el_nucleo(pkg_id) -> None:
    pkg = load_package(_repo_agentes() / pkg_id)
    summary = pkg.summary()
    assert "case_knowledge" in summary
    assert {"id", "description"} == set(summary["case_knowledge"][0])
