"""Tests for the agent package loader + registry.

Covers:
- Valid manifest loads end to end (the two real packages shipped in agentes/).
- Schema violations fail loud with actionable messages (RULE 2).
- Path-escape attempts (`../`, absolute) are rejected.
- Allowlist must reference catalog tool ids that match the os_profile.
- Registry refuses two agents declaring the same os_profile.
- HTTP surface: /api/agents lists what was loaded; /api/agent/query returns 503
  when no agent is loaded for the requested profile.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from forensia.agent.loader import AgentPackageError, load_package
from forensia.agent.registry import AgentRegistry, AgentRegistryError
from forensia.server import create_app

PORT = 50999

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENTES_DIR = REPO_ROOT / "agentes"


# ---- valid real packages ---------------------------------------------------


def test_forensia_unix_package_loads() -> None:
    pkg = load_package(AGENTES_DIR / "forensia-unix")
    assert pkg.id == "forensia-unix"
    assert pkg.os_profile == "unix"
    assert pkg.model.name == "llama3.1:8b"
    assert pkg.model.max_iterations == 18
    assert "tsk_mmls" in pkg.policy.allowed_tools
    assert "volatility3" in pkg.policy.allowed_tools
    # Prompts loaded as text from disk.
    assert "FORENSIA-UNIX" in pkg.prompts.identity


def test_forensia_windows_package_loads() -> None:
    pkg = load_package(AGENTES_DIR / "forensia-windows")
    assert pkg.id == "forensia-windows"
    assert pkg.os_profile == "windows"
    assert "regripper" in pkg.policy.allowed_tools
    # The Windows agent uses the Windows-only tools.
    assert "hayabusa" in pkg.policy.allowed_tools


# ---- schema violations -----------------------------------------------------


def _write_manifest(dirpath: Path, manifest: dict) -> Path:
    (dirpath / "prompts").mkdir(parents=True, exist_ok=True)
    (dirpath / "policy").mkdir(parents=True, exist_ok=True)
    for name in ("system.md", "identity.md", "playbook.md"):
        (dirpath / "prompts" / name).write_text(f"# {name}\n", encoding="utf-8")
    (dirpath / "policy" / "tools.yaml").write_text(
        yaml.safe_dump({"allowed": ["tsk_mmls"]}), encoding="utf-8"
    )
    (dirpath / "policy" / "redaction.yaml").write_text("patterns: []\n", encoding="utf-8")
    path = dirpath / "agent.yaml"
    path.write_text(yaml.safe_dump(manifest), encoding="utf-8")
    return path


def _valid_manifest() -> dict:
    return {
        "id": "test-unix",
        "name": "Test Unix",
        "version": "0.1.0",
        "os_profile": "unix",
        "authors": ["Test"],
        "model": {
            "name": "llama3.1:8b",
            "temperature": 0.2,
            "max_iterations": 8,
        },
        "prompts": {
            "system": "prompts/system.md",
            "identity": "prompts/identity.md",
            "playbook": "prompts/playbook.md",
        },
        "policy": {
            "tools": "policy/tools.yaml",
            "redaction": "policy/redaction.yaml",
        },
    }


def test_invalid_os_profile_fails(tmp_path: Path) -> None:
    m = _valid_manifest()
    m["os_profile"] = "macos"
    _write_manifest(tmp_path, m)
    with pytest.raises(AgentPackageError, match="os_profile"):
        load_package(tmp_path)


def test_invalid_id_fails(tmp_path: Path) -> None:
    m = _valid_manifest()
    m["id"] = "Not Kebab Case"
    _write_manifest(tmp_path, m)
    with pytest.raises(AgentPackageError, match="kebab-case"):
        load_package(tmp_path)


def test_model_backend_key_rejected(tmp_path: Path) -> None:
    # 'model.backend' fue eliminado en el contrato v1.2: el ejecutor lo elige
    # el operador en runtime. Declararlo debe fallar con mensaje accionable.
    m = _valid_manifest()
    m["model"]["backend"] = "local"
    _write_manifest(tmp_path, m)
    with pytest.raises(AgentPackageError, match="model.backend.*eliminado"):
        load_package(tmp_path)


def test_prompt_path_escape_rejected(tmp_path: Path) -> None:
    m = _valid_manifest()
    m["prompts"]["system"] = "../escape.md"
    _write_manifest(tmp_path, m)
    with pytest.raises(AgentPackageError, match="outside the agent directory"):
        load_package(tmp_path)


def test_absolute_prompt_path_rejected(tmp_path: Path) -> None:
    m = _valid_manifest()
    # tmp_path is guaranteed absolute on every OS (Path.is_absolute() == True),
    # so this exercises the "RELATIVE" rejection branch uniformly on Win/Mac/Linux.
    # A bare "/etc/passwd" would be relative on Windows (no drive letter) and would
    # hit a different validation error.
    m["prompts"]["system"] = str(tmp_path / "outside.md")
    _write_manifest(tmp_path, m)
    with pytest.raises(AgentPackageError, match="RELATIVE"):
        load_package(tmp_path)


def test_tool_outside_catalog_rejected(tmp_path: Path) -> None:
    _write_manifest(tmp_path, _valid_manifest())
    (tmp_path / "policy" / "tools.yaml").write_text(
        yaml.safe_dump({"allowed": ["nuke_disk"]}), encoding="utf-8"
    )
    with pytest.raises(AgentPackageError, match="not in forensia.toolkit.catalog"):
        load_package(tmp_path)


def test_tool_wrong_os_profile_rejected(tmp_path: Path) -> None:
    # The unix sample declares an os_profile=unix. RegRipper is windows-only.
    m = _valid_manifest()
    _write_manifest(tmp_path, m)
    (tmp_path / "policy" / "tools.yaml").write_text(
        yaml.safe_dump({"allowed": ["regripper"]}), encoding="utf-8"
    )
    with pytest.raises(AgentPackageError, match="does not declare os_profile"):
        load_package(tmp_path)


def test_empty_allowlist_rejected(tmp_path: Path) -> None:
    _write_manifest(tmp_path, _valid_manifest())
    (tmp_path / "policy" / "tools.yaml").write_text(
        yaml.safe_dump({"allowed": []}), encoding="utf-8"
    )
    with pytest.raises(AgentPackageError, match="empty"):
        load_package(tmp_path)


# ---- registry --------------------------------------------------------------


def test_registry_loads_both_real_profiles() -> None:
    reg = AgentRegistry(AGENTES_DIR)
    assert reg.has_profile("unix")
    assert reg.has_profile("windows")
    assert reg.get_for_profile("unix").id == "forensia-unix"
    assert reg.get_for_profile("windows").id == "forensia-windows"
    # Exactly the two investigation packages load. The synthesis pack
    # `_orchestrator/` is ignored on purpose (leading `_`): it never shows up
    # as an agent and never claims an os_profile.
    assert [pkg.id for pkg in reg.list()] == ["forensia-unix", "forensia-windows"]


def test_registry_refuses_duplicate_profile(tmp_path: Path) -> None:
    # Two packages with the same os_profile in the same agentes/ root.
    for sub in ("alpha", "beta"):
        d = tmp_path / sub
        m = _valid_manifest()
        m["id"] = sub + "-unix"
        _write_manifest(d, m)
    with pytest.raises(AgentRegistryError, match="two agents declare os_profile"):
        AgentRegistry(tmp_path)


def test_registry_empty_when_no_dir(tmp_path: Path) -> None:
    reg = AgentRegistry(tmp_path / "does-not-exist")
    assert reg.list() == []
    with pytest.raises(KeyError):
        reg.get_for_profile("unix")


# ---- HTTP surface ----------------------------------------------------------


@pytest.fixture
def client() -> TestClient:
    app = create_app(PORT)
    return TestClient(app, base_url=f"http://127.0.0.1:{PORT}")


def test_list_agents_endpoint(client: TestClient) -> None:
    token = client.app.state.token
    r = client.get("/api/agents", headers={"X-Forensia-Token": token})
    assert r.status_code == 200
    body = r.json()
    ids = {a["id"] for a in body["agents"]}
    assert "forensia-unix" in ids
    assert "forensia-windows" in ids
    # The ignored synthesis pack is not an agent.
    assert "_orchestrator" not in ids


def test_query_without_case_is_actionable_422(client: TestClient) -> None:
    # RULE 2: sin caso anclado no hay skeleton ni demo loop — error accionable.
    token = client.app.state.token
    r = client.post(
        "/api/agent/query",
        headers={"X-Forensia-Token": token},
        json={"prompt": "hola", "os_profile": "unix", "evidence_id": ""},
    )
    assert r.status_code == 422
    assert "case_id" in r.json()["detail"]


def test_query_invalid_os_profile(client: TestClient) -> None:
    token = client.app.state.token
    r = client.post(
        "/api/agent/query",
        headers={"X-Forensia-Token": token},
        json={"prompt": "hola", "os_profile": "macos"},
    )
    assert r.status_code == 422


def test_query_empty_prompt(client: TestClient) -> None:
    token = client.app.state.token
    r = client.post(
        "/api/agent/query",
        headers={"X-Forensia-Token": token},
        json={"prompt": "   ", "os_profile": "unix"},
    )
    assert r.status_code == 422
