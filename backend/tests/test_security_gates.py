"""Behavioural + static security gates (THREAT_MODEL). Cheap now, expensive to retrofit."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from forensia.server import create_app

PORT = 50998
SRC = Path(__file__).resolve().parents[1] / "forensia"


@pytest.fixture
def client() -> TestClient:
    app = create_app(PORT)
    return TestClient(app, base_url=f"http://127.0.0.1:{PORT}")


def test_gate1_binds_loopback_only() -> None:
    server_src = (SRC / "server.py").read_text()
    assert '"127.0.0.1"' in server_src
    assert '"0.0.0.0"' not in server_src


def test_gate2_foreign_host_header_rejected(client: TestClient) -> None:
    r = client.get("/api/health", headers={"host": "evil.example.com"})
    assert r.status_code == 403


def test_gate3_capabilities_requires_token(client: TestClient) -> None:
    assert client.get("/api/capabilities").status_code == 401
    bad = client.get("/api/capabilities", headers={"X-Forensia-Token": "nope"})
    assert bad.status_code == 401


def test_gate5_no_shell_execution_anywhere() -> None:
    forbidden = ("shell=True", "os.system(", "os.popen(", "subprocess.getoutput")
    for py in SRC.rglob("*.py"):
        text = py.read_text()
        for needle in forbidden:
            assert needle not in text, f"{needle} found in {py}"
