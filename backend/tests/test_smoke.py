from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from forensia.audit import AuditLog
from forensia.server import create_app

PORT = 50999


@pytest.fixture
def client() -> TestClient:
    app = create_app(PORT)
    return TestClient(app, base_url=f"http://127.0.0.1:{PORT}")


def test_health_is_public(client: TestClient) -> None:
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_capabilities_reports_no_docker_key(client: TestClient) -> None:
    token = client.app.state.token
    r = client.get("/api/capabilities", headers={"X-Forensia-Token": token})
    assert r.status_code == 200
    body = r.json()
    assert "docker" not in body
    assert body["models"]["local_default"] is True
    assert "tools" in body


def test_audit_log_is_hash_chained(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append({"action": "register", "evidence_id": "abc"})
    log.append({"action": "run_tool", "tool_id": "tsk_fls"})
    assert log.verify() is True

    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    tampered = lines[0].replace('"register"', '"DELETED"')
    (tmp_path / "audit.jsonl").write_text(tampered + "\n" + lines[1] + "\n")
    assert log.verify() is False
