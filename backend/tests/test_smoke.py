from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentopsy.audit import AuditLog
from agentopsy.server import create_app

PORT = 50999


@pytest.fixture
def client() -> TestClient:
    app = create_app(PORT)
    return TestClient(app, base_url=f"http://127.0.0.1:{PORT}")


def test_health_is_public(client: TestClient) -> None:
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_capabilities_reports_container_runtime(client: TestClient) -> None:
    token = client.app.state.token
    r = client.get("/api/capabilities", headers={"X-Agentopsy-Token": token})
    assert r.status_code == 200
    body = r.json()
    # No docker-branded key: the runtime is reported generically because Podman /
    # nerdctl are equally valid (CLAUDE.md RULE 1).
    assert "docker" not in body
    assert "container_runtime" in body
    assert isinstance(body["container_runtime"], bool)

    # Maletines (CLAUDE.md RULE 1): capabilities reporta el estado de cada uno.
    toolkits = body["toolkits"]
    assert set(toolkits) == {"toolkit-unix", "toolkit-windows"}
    for svc in toolkits.values():
        assert svc["running"] in (True, False, None)  # None = api no puede consultarlo
        assert svc["running"] or isinstance(svc["reason"], str)

    # Cada tool se reporta con disponibilidad + maletín(es) + razón accionable cuando
    # no está (los maletines nunca están arriba en tests → shape, no valores).
    tools = body["tools"]
    assert tools, "expected a non-empty tools map"
    for tid, status in tools.items():
        assert isinstance(status["available"], bool), tid
        assert isinstance(status["toolkits"], list), tid
        assert status["available"] or isinstance(status["reason"], str), tid

    # Los cuatro ejecutores del pivote 2026-07-02, cada uno con disponibilidad
    # y razón accionable cuando no lo está (nunca un sustituto — RULE 2).
    executors = body["executors"]
    assert set(executors) == {"claude-code", "codex", "gemini", "ollama"}
    for status in executors.values():
        assert isinstance(status["available"], bool)
        assert status["available"] or isinstance(status["reason"], str)
    assert executors["ollama"]["local"] is True
    assert executors["claude-code"]["local"] is False


def test_audit_log_is_hash_chained(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append({"action": "register", "evidence_id": "abc"})
    log.append({"action": "run_tool", "tool_id": "tsk_fls"})
    assert log.verify() is True

    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    tampered = lines[0].replace('"register"', '"DELETED"')
    (tmp_path / "audit.jsonl").write_text(tampered + "\n" + lines[1] + "\n")
    assert log.verify() is False
