"""CP5 — Superficie HTTP del grafo de conocimiento por caso.

Gates:
- Token obligatorio en las tres rutas (SECURITY INVARIANT 3).
- Índice sin contenido / nodo con la vista consolidada / historial íntegro.
- **Solo lectura**: no hay verbo de escritura. El grafo lo escribe el agente
  dentro del loop, donde cada bloque queda anclado en la cadena de audit; una
  segunda vía HTTP rompería esa trazabilidad.
- Un `doc_id` fuera del charset devuelve 422, no 500 ni un fichero de fuera.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from forensia.cases.manager import CaseManager
from forensia.knowledge import KnowledgeStore
from forensia.server import create_app

PORT = 51100


@pytest.fixture
def wired(tmp_path, monkeypatch):
    cases = CaseManager(root=tmp_path / "cases")
    store = KnowledgeStore(cases)

    import forensia.routers.cases as cases_router
    import forensia.routers.knowledge as knowledge_router

    monkeypatch.setattr(knowledge_router, "knowledge_store", store)
    monkeypatch.setattr(cases_router, "case_manager", cases)

    case = cases.create(name="Caso grafo", examiner="ramos", os_profile="windows")
    app = create_app(PORT)
    client = TestClient(app, base_url=f"http://127.0.0.1:{PORT}")
    auth = {"X-Forensia-Token": app.state.token}
    return client, auth, store, case.id


# ── gate de token ───────────────────────────────────────────────────────────


def test_sin_token_401(wired) -> None:
    client, _auth, _store, case_id = wired
    assert client.get(f"/api/cases/{case_id}/knowledge").status_code == 401
    assert client.get(f"/api/cases/{case_id}/knowledge/x").status_code == 401
    assert client.get(f"/api/cases/{case_id}/knowledge/x/historial").status_code == 401


# ── índice ──────────────────────────────────────────────────────────────────


def test_indice_vacio(wired) -> None:
    client, auth, _store, case_id = wired
    r = client.get(f"/api/cases/{case_id}/knowledge", headers=auth)
    assert r.status_code == 200
    assert r.json() == []


def test_indice_lleva_secciones_pero_no_contenido(wired) -> None:
    client, auth, store, case_id = wired
    store.append(case_id, "perfil-sistema", "zona-horaria", "NO-DEBE-SALIR Pacific")
    r = client.get(f"/api/cases/{case_id}/knowledge", headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert body[0]["doc_id"] == "perfil-sistema"
    assert body[0]["sections"] == ["zona-horaria"]
    assert "NO-DEBE-SALIR" not in r.text


# ── nodo ────────────────────────────────────────────────────────────────────


def test_leer_nodo_devuelve_la_vista_consolidada(wired) -> None:
    client, auth, store, case_id = wired
    store.append(case_id, "cuentas", "testuser", "primera version")
    store.append(case_id, "cuentas", "testuser", "version corregida")

    r = client.get(f"/api/cases/{case_id}/knowledge/cuentas", headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert "version corregida" in body["markdown"]
    assert "primera version" not in body["markdown"]
    assert body["block_count"] == 2


def test_nodo_inexistente_404(wired) -> None:
    client, auth, _store, case_id = wired
    r = client.get(f"/api/cases/{case_id}/knowledge/no-existe", headers=auth)
    assert r.status_code == 404


def test_doc_id_fuera_del_charset_es_422(wired) -> None:
    client, auth, _store, case_id = wired
    r = client.get(f"/api/cases/{case_id}/knowledge/MAYUS", headers=auth)
    assert r.status_code == 422
    assert "doc_id" in r.json()["detail"]


def test_caso_inexistente_404(wired) -> None:
    client, auth, _store, _case_id = wired
    otro = "11111111-1111-4111-8111-111111111111"
    assert client.get(f"/api/cases/{otro}/knowledge", headers=auth).status_code == 404


# ── historial ───────────────────────────────────────────────────────────────


def test_el_historial_conserva_todas_las_versiones(wired) -> None:
    client, auth, store, case_id = wired
    store.append(case_id, "cronologia", "inicio", "17:15 login")
    store.append(case_id, "cronologia", "inicio", "17:15:22 login de IEUser")

    r = client.get(f"/api/cases/{case_id}/knowledge/cronologia/historial", headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert [b["content"] for b in body] == ["17:15 login", "17:15:22 login de IEUser"]
    assert all(len(b["sha256"]) == 64 for b in body)


# ── solo lectura ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("verb", ["POST", "PUT", "PATCH", "DELETE"])
def test_no_hay_escritura_por_http(wired, verb) -> None:
    client, auth, _store, case_id = wired
    # `request()` en vez de los atajos: TestClient.delete() no acepta cuerpo.
    r = client.request(
        verb, f"/api/cases/{case_id}/knowledge", headers=auth, json={"doc_id": "x"}
    )
    assert r.status_code in (404, 405)
