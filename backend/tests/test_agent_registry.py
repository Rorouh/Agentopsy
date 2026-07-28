"""Tests del cargador + registry del agente (contrato de archivo único).

Desde 2026-07-28 el agente se configura con un solo ``agentes/agent.md``. Cubre:

- ``read_instructions`` lee ``agent.md``; ausente o vacío falla en seco (RULE 2).
- ``build_package`` deriva la allowlist del catálogo por perfil (nada escrito a mano).
- ``load_packages`` construye un agente por perfil compartiendo el mismo texto.
- La registry sobre el repo carga ``forensia-unix`` y ``forensia-windows``; un
  perfil desconocido lanza ``KeyError``; sin ``agent.md`` arranca vacía (degrada).
- Superficie HTTP: ``/api/agents`` lista lo cargado; ``/api/agent/query`` sin caso
  responde 422 accionable.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from forensia.agent.loader import (
    AgentPackageError,
    build_package,
    default_allowed_tools,
    load_packages,
    read_instructions,
)
from forensia.agent.registry import AgentRegistry
from forensia.server import create_app

PORT = 50999

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENTES_DIR = REPO_ROOT / "agentes"


# ---- read_instructions -----------------------------------------------------


def test_reads_the_single_agent_md() -> None:
    text = read_instructions(AGENTES_DIR)
    assert text.startswith("# agent.md")
    assert "perito forense" in text.lower()


def test_missing_agent_md_fails_loud(tmp_path: Path) -> None:
    with pytest.raises(AgentPackageError, match="no existe"):
        read_instructions(tmp_path)


def test_empty_agent_md_fails_loud(tmp_path: Path) -> None:
    (tmp_path / "agent.md").write_text("   \n", encoding="utf-8")
    with pytest.raises(AgentPackageError, match="vacío"):
        read_instructions(tmp_path)


# ---- allowlist derivada del catálogo ---------------------------------------


def test_allowlist_comes_from_catalog_by_profile() -> None:
    unix = set(default_allowed_tools("unix"))
    windows = set(default_allowed_tools("windows"))
    assert "regripper" in windows and "regripper" not in unix
    assert "hayabusa" in windows and "hayabusa" not in unix
    assert "foremost" in unix and "foremost" not in windows
    assert "volatility3" in unix and "volatility3" in windows


def test_invalid_profile_rejected() -> None:
    with pytest.raises(AgentPackageError, match="os_profile inválido"):
        default_allowed_tools("macos")


# ---- build_package ---------------------------------------------------------


def test_build_package_shape() -> None:
    pkg = build_package("windows", read_instructions(AGENTES_DIR))
    assert pkg.id == "forensia-windows"
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
    assert reg.get_for_profile("unix").id == "forensia-unix"
    assert reg.get_for_profile("windows").id == "forensia-windows"
    assert [pkg.id for pkg in reg.list()] == ["forensia-unix", "forensia-windows"]


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
    r = client.get("/api/agents", headers={"X-Forensia-Token": token})
    assert r.status_code == 200
    ids = {a["id"] for a in r.json()["agents"]}
    assert "forensia-unix" in ids
    assert "forensia-windows" in ids


def test_query_without_case_is_actionable_422(client: TestClient) -> None:
    token = client.app.state.token
    r = client.post(
        "/api/agent/query",
        headers={"X-Forensia-Token": token},
        json={"prompt": "hola", "os_profile": "unix", "evidence_id": ""},
    )
    assert r.status_code == 422
    assert "case_id" in r.json()["detail"]


def test_query_empty_prompt(client: TestClient) -> None:
    token = client.app.state.token
    r = client.post(
        "/api/agent/query",
        headers={"X-Forensia-Token": token},
        json={"prompt": "   "},
    )
    assert r.status_code == 422
