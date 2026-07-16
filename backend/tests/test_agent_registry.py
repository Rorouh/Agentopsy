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
    assert pkg.model.max_iterations == 12  # Bug 008: lowered 18 → 12 (runaway cap)
    assert "tsk_mmls" in pkg.policy.allowed_tools
    assert "volatility3" in pkg.policy.allowed_tools
    # Prompts loaded as text from disk.
    assert "FORENSIA-UNIX" in pkg.prompts.identity


def test_forensia_windows_package_loads() -> None:
    pkg = load_package(AGENTES_DIR / "forensia-windows")
    assert pkg.id == "forensia-windows"
    assert pkg.os_profile == "windows"
    assert "regripper" in pkg.policy.allowed_tools


def test_real_packages_ship_knowledge_docs() -> None:
    """El mapa de memoria: ambos paquetes traen su catálogo de artefactos, cargado
    y por debajo del cap de contexto (8000) para que quepa en un resultado de tool."""
    for prof, doc_id in (("unix", "artefactos-unix"), ("windows", "artefactos-windows")):
        pkg = load_package(AGENTES_DIR / f"forensia-{prof}")
        ids = [d.id for d in pkg.knowledge]
        assert doc_id in ids, f"{prof}: falta el doc {doc_id}"
        doc = next(d for d in pkg.knowledge if d.id == doc_id)
        assert doc.content.strip() and len(doc.content) < 8000
        assert doc.description  # viaja en el índice del system prompt
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


def _manifest_with_knowledge(knowledge: object) -> dict:
    m = _valid_manifest()
    m["knowledge"] = knowledge
    return m


def test_knowledge_docs_parsed(tmp_path: Path) -> None:
    _write_manifest(
        tmp_path,
        _manifest_with_knowledge(
            [
                {
                    "id": "artefactos-unix",
                    "title": "Artefactos",
                    "description": "Dónde mirar",
                    "path": "knowledge/artefactos-unix.md",
                }
            ]
        ),
    )
    (tmp_path / "knowledge").mkdir()
    (tmp_path / "knowledge" / "artefactos-unix.md").write_text(
        "# Artefactos\ncontenido de referencia", encoding="utf-8"
    )
    pkg = load_package(tmp_path)
    assert [d.id for d in pkg.knowledge] == ["artefactos-unix"]
    assert "contenido de referencia" in pkg.knowledge[0].content
    assert pkg.summary()["knowledge"][0]["description"] == "Dónde mirar"


def test_knowledge_absent_is_empty(tmp_path: Path) -> None:
    _write_manifest(tmp_path, _valid_manifest())  # no knowledge key
    assert load_package(tmp_path).knowledge == ()


def test_knowledge_duplicate_id_rejected(tmp_path: Path) -> None:
    entry = {"id": "dup", "title": "t", "description": "d", "path": "knowledge/a.md"}
    _write_manifest(tmp_path, _manifest_with_knowledge([entry, dict(entry)]))
    (tmp_path / "knowledge").mkdir()
    (tmp_path / "knowledge" / "a.md").write_text("x", encoding="utf-8")
    with pytest.raises(AgentPackageError, match="duplicate knowledge id"):
        load_package(tmp_path)


def test_knowledge_bad_id_rejected(tmp_path: Path) -> None:
    _write_manifest(
        tmp_path,
        _manifest_with_knowledge(
            [{"id": "Not Kebab", "title": "t", "description": "d", "path": "knowledge/a.md"}]
        ),
    )
    with pytest.raises(AgentPackageError, match="kebab-case"):
        load_package(tmp_path)


def test_knowledge_path_escape_rejected(tmp_path: Path) -> None:
    _write_manifest(
        tmp_path,
        _manifest_with_knowledge(
            [{"id": "esc", "title": "t", "description": "d", "path": "../escape.md"}]
        ),
    )
    with pytest.raises(AgentPackageError, match="outside the agent directory"):
        load_package(tmp_path)


def test_knowledge_not_a_list_rejected(tmp_path: Path) -> None:
    _write_manifest(tmp_path, _manifest_with_knowledge({"id": "x"}))
    with pytest.raises(AgentPackageError, match="'knowledge' must be a list"):
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


def test_query_empty_prompt(client: TestClient) -> None:
    # ``os_profile`` is no longer a request field — it is derived from the case
    # in the backend. An empty prompt still fails fast (422) before any routing.
    token = client.app.state.token
    r = client.post(
        "/api/agent/query",
        headers={"X-Forensia-Token": token},
        json={"prompt": "   "},
    )
    assert r.status_code == 422
