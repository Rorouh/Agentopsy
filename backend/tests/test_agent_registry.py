"""Tests del cargador + registry del agente (contrato de archivo único).

Desde 2026-07-28 el agente se configura con un solo ``agentes/agent.md``. Cubre:

- ``read_instructions`` lee ``agent.md``; ausente o vacío falla en seco (RULE 2).
- ``build_package`` deriva la allowlist del catálogo por perfil (nada escrito a mano).
- ``load_packages`` construye un agente por perfil compartiendo el mismo texto.
- La registry sobre el repo carga ``agentopsy-unix`` y ``agentopsy-windows``; un
  perfil desconocido lanza ``KeyError``; sin ``agent.md`` arranca vacía (degrada).
- Superficie HTTP: ``/api/agents`` lista lo cargado; ``/api/agent/query`` sin caso
  responde 422 accionable.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentopsy.agent.loader import (
    AgentPackageError,
    build_package,
    default_allowed_tools,
    load_packages,
    read_instructions,
)
from agentopsy.agent.registry import AgentRegistry
from agentopsy.i18n import set_current_lang
from agentopsy.server import create_app

PORT = 50999

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENTES_DIR = REPO_ROOT / "agentes"


# ---- read_instructions -----------------------------------------------------


@pytest.fixture
def _castellano():
    """Fija el castellano para el bloque: el fichero de comportamiento es POR
    IDIOMA (`agent.md` / `agent.en.md`) y el de partida del producto es inglés."""
    token = set_current_lang("es")
    yield
    from agentopsy.i18n import _LANG_ACTUAL

    _LANG_ACTUAL.reset(token)


def test_reads_the_single_agent_md(_castellano) -> None:
    text = read_instructions(AGENTES_DIR)
    assert text.startswith("# agent.md")
    assert "perito forense" in text.lower()


def test_the_english_twin_is_the_one_read_in_english() -> None:
    """El agente tiene un fichero POR IDIOMA y se elige por el de la petición.

    No es una traducción automática del castellano: es el mismo método escrito
    dos veces, porque el `title` y el `summary` que el agente escribe viajan tal
    cual al informe pericial.
    """
    token = set_current_lang("en")
    try:
        text = read_instructions(AGENTES_DIR)
        assert text.startswith("# agent.en.md")
        assert "forensics examiner" in text.lower()
    finally:
        from agentopsy.i18n import _LANG_ACTUAL

        _LANG_ACTUAL.reset(token)


def test_the_missing_file_of_a_language_never_falls_back_to_the_other(
    tmp_path: Path,
) -> None:
    """RULE 2: con el fichero inglés ausente NO se carga el castellano.

    Caer al otro idioma dejaría al perito con un agente que escribe en un idioma
    que no eligió, y ese texto acaba en el informe pericial.
    """
    (tmp_path / "agent.md").write_text("# agent.md\ncontenido", encoding="utf-8")
    token = set_current_lang("en")
    try:
        with pytest.raises(AgentPackageError, match="agent.en.md"):
            read_instructions(tmp_path)
    finally:
        from agentopsy.i18n import _LANG_ACTUAL

        _LANG_ACTUAL.reset(token)


def test_missing_agent_md_fails_loud(tmp_path: Path, _castellano) -> None:
    with pytest.raises(AgentPackageError, match="no existe"):
        read_instructions(tmp_path)


def test_empty_agent_md_fails_loud(tmp_path: Path, _castellano) -> None:
    (tmp_path / "agent.md").write_text("   \n", encoding="utf-8")
    with pytest.raises(AgentPackageError, match="vacío"):
        read_instructions(tmp_path)


# ---- allowlist derivada del catálogo ---------------------------------------


def test_allowlist_comes_from_catalog_by_profile() -> None:
    unix = set(default_allowed_tools("unix"))
    windows = set(default_allowed_tools("windows"))
    assert "regripper" in windows and "regripper" not in unix
    assert "hayabusa" in windows and "hayabusa" not in unix
    # `qemu_nbd` es hoy la ÚNICA del catálogo exclusiva de unix (y no se expone al
    # agente). `foremost` lo fue por error hasta el 2026-09-03: talla por firmas, así
    # que sirve a los dos perfiles; ver `test_cross_tools_declare_both_os_profiles`.
    assert "qemu_nbd" in unix and "qemu_nbd" not in windows
    assert "foremost" in unix and "foremost" in windows
    assert "volatility3" in unix and "volatility3" in windows


def test_invalid_profile_rejected() -> None:
    with pytest.raises(AgentPackageError, match="os_profile inválido"):
        default_allowed_tools("macos")


# ---- build_package ---------------------------------------------------------


def test_build_package_shape(_castellano) -> None:
    pkg = build_package("windows", read_instructions(AGENTES_DIR))
    assert pkg.id == "agentopsy-windows"
    assert pkg.os_profile == "windows"
    assert "regripper" in pkg.policy.allowed_tools
    assert pkg.prompts.system.startswith("# agent.md")
    assert pkg.prompts.identity == "" and pkg.prompts.playbook == ""
    assert pkg.knowledge == () and pkg.case_knowledge == () and pkg.objetivos == ()
    assert pkg.policy.redaction_patterns
    assert all("strict" in p.apply_in for p in pkg.policy.redaction_patterns)


def test_build_package_empty_instructions_rejected() -> None:
    with pytest.raises(AgentPackageError, match="vacías"):
        build_package("unix", "   ")


def test_build_package_allowlist_override() -> None:
    pkg = build_package("unix", "x", allowed_tools=("file_info",))
    assert pkg.policy.allowed_tools == ("file_info",)


def test_load_packages_returns_both_profiles() -> None:
    pkgs = load_packages(AGENTES_DIR)
    assert set(pkgs) == {"unix", "windows"}
    assert pkgs["unix"].prompts.system == pkgs["windows"].prompts.system


# ---- registry --------------------------------------------------------------


def test_registry_loads_both_real_profiles() -> None:
    reg = AgentRegistry(AGENTES_DIR)
    assert reg.has_profile("unix")
    assert reg.has_profile("windows")
    assert reg.get_for_profile("unix").id == "agentopsy-unix"
    assert reg.get_for_profile("windows").id == "agentopsy-windows"
    assert [pkg.id for pkg in reg.list()] == ["agentopsy-unix", "agentopsy-windows"]


def test_registry_unknown_profile_raises() -> None:
    reg = AgentRegistry(AGENTES_DIR)
    with pytest.raises(KeyError):
        reg.get_for_profile("macos")


def test_registry_empty_when_no_dir(tmp_path: Path) -> None:
    reg = AgentRegistry(tmp_path / "does-not-exist")
    assert reg.list() == []
    with pytest.raises(KeyError):
        reg.get_for_profile("unix")


def test_registry_empty_when_dir_has_no_agent_md(tmp_path: Path) -> None:
    (tmp_path / "algo.txt").write_text("no soy agent.md", encoding="utf-8")
    reg = AgentRegistry(tmp_path)
    assert reg.list() == []


# ---- HTTP surface ----------------------------------------------------------


@pytest.fixture
def client() -> TestClient:
    app = create_app(PORT)
    return TestClient(app, base_url=f"http://127.0.0.1:{PORT}")


def test_list_agents_endpoint(client: TestClient) -> None:
    token = client.app.state.token
    r = client.get("/api/agents", headers={"X-Agentopsy-Token": token})
    assert r.status_code == 200
    ids = {a["id"] for a in r.json()["agents"]}
    assert "agentopsy-unix" in ids
    assert "agentopsy-windows" in ids


def test_query_without_case_is_actionable_422(client: TestClient) -> None:
    token = client.app.state.token
    r = client.post(
        "/api/agent/query",
        headers={"X-Agentopsy-Token": token},
        json={"prompt": "hola", "os_profile": "unix"},
    )
    assert r.status_code == 422
    assert "case_id" in r.json()["detail"]


def test_query_empty_prompt(client: TestClient) -> None:
    token = client.app.state.token
    r = client.post(
        "/api/agent/query",
        headers={"X-Agentopsy-Token": token},
        json={"prompt": "   "},
    )
    assert r.status_code == 422


# ---- los dos ficheros de comportamiento no pueden divergir ------------------


def test_the_two_behaviour_files_keep_the_same_sections() -> None:
    """`agent.md` y `agent.en.md` son el MISMO método escrito dos veces.

    Si uno gana una sección y el otro no, Agentopsy se comporta distinto según
    el idioma de la interfaz, que es exactamente lo que una herramienta forense
    no puede hacer: el método no depende de la lengua del perito. Se comparan
    los ENCABEZADOS numerados, que son el esqueleto; la prosa de cada apartado
    es de cada lengua y no se compara.
    """
    import re

    def numeros(texto: str) -> list[str]:
        return [m.group(1) for m in re.finditer(r"^## (\d+)\.", texto, re.M)]

    es = (AGENTES_DIR / "agent.md").read_text(encoding="utf-8")
    en = (AGENTES_DIR / "agent.en.md").read_text(encoding="utf-8")

    assert numeros(es) == numeros(en), (
        "los dos agent.md han divergido en su esqueleto de apartados"
    )
    assert numeros(es), "el esqueleto de apartados no se está detectando"


def test_the_english_twin_says_it_writes_in_english() -> None:
    """La línea que decide el idioma de lo que el agente ESCRIBE.

    El `title` y el `summary` de cada hallazgo viajan tal cual al informe, así
    que si el fichero inglés no lo dice, el modelo puede responder en la lengua
    del último texto que haya visto.
    """
    en = (AGENTES_DIR / "agent.en.md").read_text(encoding="utf-8")
    es = (AGENTES_DIR / "agent.md").read_text(encoding="utf-8")
    assert "in English" in en
    assert "en español" in es
