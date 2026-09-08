"""La superficie HTTP: token, host check, ingesta, jobs y estado del agente."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from tests.conftest import MaletinFalso, ModeloGuion


@pytest.fixture
def cliente(entorno, monkeypatch):
    monkeypatch.setenv("LOCALFIT_ALLOWED_HOSTS", "testserver")
    import importlib

    import api as mod_api
    import herramientas.ejecutor as mod_ejecutor

    importlib.reload(mod_api)
    guion = [
        {"accion": "escribir_tareas", "args": {"tareas": ["identificar"]}},
        {"accion": "file_info", "args": {}},
        {"accion": "informar", "args": {"texto": "listo"}},
        {"veredicto": "aprobar", "respuesta": "respuesta final"},
    ]
    monkeypatch.setattr(mod_api, "Modeloseguro", lambda: ModeloGuion(guion))
    monkeypatch.setattr(mod_ejecutor, "Maletin", lambda *a, **k: MaletinFalso())
    c = TestClient(mod_api.app)
    token = c.get("/api-local/session").json()["token"]
    c.headers.update({"X-Agentopsy-Token": token})
    return c


def test_salud_y_token(entorno, monkeypatch):
    monkeypatch.setenv("LOCALFIT_ALLOWED_HOSTS", "testserver")
    import importlib

    import api as mod_api

    importlib.reload(mod_api)
    c = TestClient(mod_api.app)
    assert c.get("/api-local/health").json()["engine"] == "local-fit-llm"
    assert c.get("/api-local/cases").status_code == 401
    assert c.get("/api-local/health", headers={"host": "evil:1"}).status_code == 403


def test_ingesta_y_estado(cliente, entorno):
    caso = cliente.post("/api-local/cases", json={"name": "por api", "examiner": "perito"}).json()
    r = cliente.post(f"/api-local/cases/{caso['id']}/evidence/ingest",
                     json={"source": "mini.mem", "kind": "memory", "os_profile": "windows"})
    assert r.status_code == 200 and len(r.json()["sha256"]) == 64
    assert cliente.get(f"/api-local/cases/{caso['id']}/evidence").json()[0]["kind"] == "memory"
    assert cliente.get(f"/api-local/cases/{caso['id']}/audit/verify").json()["ok"] is True
    r = cliente.post(f"/api-local/cases/{caso['id']}/evidence/ingest", json={"source": "../x", "kind": "memory"})
    assert r.status_code == 422
    assert cliente.get("/api-local/cases/00000000-0000-4000-8000-000000000000").status_code == 404


def test_job_en_segundo_plano(cliente, entorno):
    caso = entorno["caso"]["id"]
    ev = entorno["evidencia"].evidence_id
    r = cliente.post("/api-local/agent/analyze", json={"prompt": "analiza", "case_id": caso, "evidence_id": ev})
    assert r.status_code == 200, r.text
    job_id = r.json()["job_id"]
    for _ in range(100):
        snap = cliente.get(f"/api-local/agent/jobs/{job_id}?since=0").json()
        if snap["status"] != "running":
            break
        time.sleep(0.05)
    assert snap["status"] == "done", snap
    assert snap["result"]["reply"] == "respuesta final"
    tipos = [e["type"] for e in snap["events"]]
    assert "tool_call" in tipos and "revision" in tipos and "tareas" in tipos
    assert cliente.get(f"/api-local/cases/{caso}/agent/jobs").json()[0]["job_id"] == job_id
    estado = cliente.get(f"/api-local/cases/{caso}/agent/state/main").json()
    assert estado["tareas"][0]["texto"] == "identificar"
    # La web persiste el chat: el motor no lo duplica por HTTP.
    assert cliente.get(f"/api-local/cases/{caso}/chats").json() == []
    arte = cliente.get(f"/api-local/cases/{caso}/artifacts")
    assert arte.status_code == 200, arte.text
    assert arte.json()[0]["tool_id"] == "file_info"


def test_validaciones_de_query(cliente, entorno):
    assert cliente.post("/api-local/agent/query", json={"prompt": "", "case_id": "x", "evidence_id": "y"}).status_code == 422
    assert cliente.post("/api-local/agent/query", json={"prompt": "hola"}).status_code == 422
    r = cliente.post("/api-local/agent/query", json={"prompt": "hola", "case_id": entorno["caso"]["id"], "evidence_id": "nope"})
    assert r.status_code == 404
