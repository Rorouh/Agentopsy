"""Superficie HTTP para la SPA (migración del frontend al servicio `web`).

Covers:
- ``/api/session`` entrega el token SOLO tras pasar el Host-check: es el
  bootstrap del cliente web (mismo-origen vía el proxy nginx) y un Host
  desconocido → 403 (anti DNS-rebinding, SECURITY INVARIANT 2).
- ``create_app(ui_origins=...)`` añade los hosts de la UI a la allowlist del
  Host-check (el nginx del servicio web reenvía el Host original del navegador).
- ``/api/evidence/sources``: sin ``FORENSIA_EVIDENCE_DIR`` → 503 accionable
  (RULE 2 — jamás se adivina una bandeja); con la bandeja montada lista solo
  ficheros regulares no ocultos.
- ``/api/evidence/upload`` (subida del perito): deposita el fichero en la
  bandeja; rechaza formato no soportado (422), traversal en el nombre (422) y
  sobrescritura de evidencia existente (409); exige token.
- ``/api/agent/query``: un ejecutor cloud disponible ya NO exige consentimiento
  (el consent de egress cloud se eliminó 2026-07-16) — pasa la validación de
  ejecutor; un ``os_profile`` sin resolver → 409 accionable (RULE 2 enmendada,
  el operador ancla).
- Cadena de custodia (forensic invariant 4): registrar evidencia y verificarla
  escriben ``evidence_register`` / ``evidence_verify`` en el audit del caso.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from _symlink_support import requires_symlinks
from fastapi.testclient import TestClient

from forensia.cases.manager import CaseManager
from forensia.executors import ClaudeCodeExecutor, ExecutorAvailability, OllamaExecutor
from forensia.server import create_app

PORT = 51007


@pytest.fixture
def isolated_cases(tmp_path, monkeypatch):
    cases = CaseManager(root=tmp_path / "cases")

    import forensia.routers.agent as agent_router
    import forensia.routers.cases as cases_router
    from forensia.evidence import EvidenceManager

    monkeypatch.setattr(cases_router, "case_manager", cases)
    monkeypatch.setattr(agent_router, "case_manager", cases)
    # El singleton evidence_manager guarda su propia referencia al CaseManager
    # real; para que register/verify operen sobre el árbol de casos aislado hay
    # que darle uno atado a la misma raíz.
    monkeypatch.setattr(cases_router, "evidence_manager", EvidenceManager(cases))
    return cases


@pytest.fixture
def client(isolated_cases) -> TestClient:
    app = create_app(PORT)
    return TestClient(app, base_url=f"http://127.0.0.1:{PORT}")


@pytest.fixture
def auth(client) -> dict[str, str]:
    return {"X-Forensia-Token": client.app.state.token}


# ---- /api/session -------------------------------------------------------------


def test_session_returns_the_in_memory_token(client: TestClient) -> None:
    r = client.get("/api/session")
    assert r.status_code == 200
    assert r.json() == {"token": client.app.state.token}


def test_session_rejected_on_foreign_host(client: TestClient) -> None:
    # DNS-rebinding: el atacante hace resolver evil.example → 127.0.0.1 y el
    # navegador manda Host: evil.example. El Host-check corta ANTES de que el
    # token pueda salir.
    r = client.get("/api/session", headers={"Host": "evil.example:5173"})
    assert r.status_code == 403


def test_ui_origins_extend_the_host_allowlist(isolated_cases) -> None:
    # Sin ui_origins el host de la UI no pasa; con ellos (compose:
    # FORENSIA_UI_ORIGINS) el Host que nginx reenvía sí. Allowlist EXACTA.
    bare = TestClient(create_app(PORT), base_url=f"http://127.0.0.1:{PORT}")
    assert (
        bare.get("/api/session", headers={"Host": "127.0.0.1:5173"}).status_code == 403
    )

    app = create_app(PORT, ui_origins=("http://127.0.0.1:5173", "http://localhost:5173"))
    ui = TestClient(app, base_url=f"http://127.0.0.1:{PORT}")
    r = ui.get("/api/session", headers={"Host": "127.0.0.1:5173"})
    assert r.status_code == 200
    assert r.json()["token"] == app.state.token
    assert ui.get("/api/session", headers={"Host": "localhost:5173"}).status_code == 200
    assert ui.get("/api/session", headers={"Host": "evil.example:5173"}).status_code == 403


# ---- /api/evidence/sources -----------------------------------------------------


def test_sources_without_env_is_actionable_503(
    client: TestClient, auth: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FORENSIA_EVIDENCE_DIR", raising=False)
    r = client.get("/api/evidence/sources", headers=auth)
    assert r.status_code == 503
    assert "FORENSIA_EVIDENCE_DIR" in r.json()["detail"]


@requires_symlinks
def test_sources_lists_only_regular_visible_files(
    client: TestClient, auth: dict, monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    inbox = tmp_path / "inbox"
    (inbox / "sub").mkdir(parents=True)
    (inbox / "disco.raw").write_bytes(b"A" * 10)
    (inbox / "sub" / "mem.vmem").write_bytes(b"B" * 20)
    (inbox / ".oculto").write_bytes(b"C")
    (inbox / "enlace.raw").symlink_to(inbox / "disco.raw")
    monkeypatch.setenv("FORENSIA_EVIDENCE_DIR", str(inbox))

    r = client.get("/api/evidence/sources", headers=auth)
    assert r.status_code == 200
    sources = r.json()["sources"]
    names = [s["name"] for s in sources]
    assert names == ["disco.raw", str(Path("sub") / "mem.vmem")]
    assert {s["size"] for s in sources} == {10, 20}
    # Toda ruta devuelta vive dentro de la bandeja — es la que registerEvidence recibirá.
    assert all(s["path"].startswith(str(inbox)) for s in sources)


def test_sources_requires_token(client: TestClient) -> None:
    assert client.get("/api/evidence/sources").status_code == 401


# ---- /api/evidence/upload ------------------------------------------------------


def test_upload_deposits_file_in_inbox(
    client: TestClient, auth: dict, monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.setenv("FORENSIA_EVIDENCE_DIR", str(inbox))

    r = client.post(
        "/api/evidence/upload",
        headers=auth,
        files={"file": ("disco.raw", b"D" * 32, "application/octet-stream")},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "disco.raw"
    assert body["size"] == 32
    # El fichero quedó en la bandeja y ahora lo lista /sources.
    assert (inbox / "disco.raw").read_bytes() == b"D" * 32
    listed = client.get("/api/evidence/sources", headers=auth).json()["sources"]
    assert "disco.raw" in [s["name"] for s in listed]
    # Ningún temporal de subida oculto sobrevive.
    assert not list(inbox.glob(".subiendo-*"))


def test_upload_rejects_unsupported_format(
    client: TestClient, auth: dict, monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.setenv("FORENSIA_EVIDENCE_DIR", str(inbox))

    r = client.post(
        "/api/evidence/upload",
        headers=auth,
        files={"file": ("notas.txt", b"nope", "text/plain")},
    )
    assert r.status_code == 422
    assert not list(inbox.iterdir())


def test_upload_rejects_path_traversal(
    client: TestClient, auth: dict, monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.setenv("FORENSIA_EVIDENCE_DIR", str(inbox))

    r = client.post(
        "/api/evidence/upload",
        headers=auth,
        files={"file": ("../escape.raw", b"x", "application/octet-stream")},
    )
    assert r.status_code == 422
    assert not (tmp_path / "escape.raw").exists()


def test_upload_never_overwrites_existing_evidence(
    client: TestClient, auth: dict, monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "disco.raw").write_bytes(b"original")
    monkeypatch.setenv("FORENSIA_EVIDENCE_DIR", str(inbox))

    r = client.post(
        "/api/evidence/upload",
        headers=auth,
        files={"file": ("disco.raw", b"nuevo", "application/octet-stream")},
    )
    assert r.status_code == 409
    # El original intacto — nunca se sobrescribe evidencia.
    assert (inbox / "disco.raw").read_bytes() == b"original"


def test_upload_requires_token(client: TestClient) -> None:
    r = client.post(
        "/api/evidence/upload",
        files={"file": ("disco.raw", b"x", "application/octet-stream")},
    )
    assert r.status_code == 401


def _create_case(client: TestClient, auth: dict) -> str:
    r = client.post(
        "/api/cases",
        headers=auth,
        json={"name": "Caso RGPD", "examiner": "E. Marques", "os_profile": "unix"},
    )
    assert r.status_code == 200, r.text
    return r.json()["id"]


# ---- /api/agent/query: validación de ejecutor / os_profile (backend) -----------


def _query(client: TestClient, auth: dict, case_id: str, executor: str) -> object:
    return client.post(
        "/api/agent/query",
        headers=auth,
        json={
            "prompt": "analiza",
            "os_profile": "unix",
            "case_id": case_id,
            "evidence_id": "e1",  # inválido a propósito: la puerta de consent va ANTES
            "executor": executor,
        },
    )


def test_query_unresolved_os_profile_is_409(
    client: TestClient, auth: dict, isolated_cases: CaseManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A case whose os_profile triage could not determine (here: no evidence yet)
    # must NOT route silently — /api/agent/query answers 409 with an actionable
    # "anchor the profile" message (RULE 2 enmendada). A local executor is used
    # so the consent gate is not what stops the request.
    monkeypatch.setattr(
        OllamaExecutor, "is_available", lambda self: ExecutorAvailability(available=True)
    )
    case = isolated_cases.create(name="Ambiguo", examiner="alice")  # no anchor, no evidence
    r = client.post(
        "/api/agent/query",
        headers=auth,
        json={"prompt": "analiza", "case_id": case.id, "evidence_id": "e1", "executor": "ollama"},
    )
    assert r.status_code == 409
    assert "os-profile" in r.json()["detail"]


def test_anchor_os_profile_endpoint_sets_and_persists(
    client: TestClient, auth: dict, isolated_cases: CaseManager
) -> None:
    # The operator's manual anchor (the ambiguous case) round-trips through the
    # HTTP surface and persists as an operator-sourced profile.
    case = isolated_cases.create(name="Ambiguo", examiner="alice")
    r = client.post(
        f"/api/cases/{case.id}/os-profile",
        headers=auth,
        json={"os_profile": "windows"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["os_profile"] == "windows"
    assert body["os_profile_source"] == "operator"
    assert isolated_cases.load(case.id).os_profile == "windows"


def test_anchor_os_profile_rejects_invalid(
    client: TestClient, auth: dict, isolated_cases: CaseManager
) -> None:
    case = isolated_cases.create(name="Ambiguo", examiner="alice")
    r = client.post(
        f"/api/cases/{case.id}/os-profile",
        headers=auth,
        json={"os_profile": "macos"},
    )
    assert r.status_code == 422


def test_cloud_query_no_longer_requires_consent(
    client: TestClient, auth: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    # El consentimiento de egress cloud se eliminó (2026-07-16): un ejecutor cloud
    # disponible ya NO exige consentimiento registrado. La petición pasa la
    # validación de ejecutor y falla más adelante por el evidence_id inválido
    # (422), NUNCA 403 — no queda ninguna puerta de consent que atravesar.
    monkeypatch.setattr(
        ClaudeCodeExecutor, "is_available", lambda self: ExecutorAvailability(available=True)
    )
    case_id = _create_case(client, auth)
    r = _query(client, auth, case_id, "claude-code")
    assert r.status_code != 403
    assert r.status_code == 422


def test_local_executor_query_reaches_evidence_validation(
    client: TestClient, auth: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ollama es 100 % local: la petición pasa la validación de ejecutor y falla
    # luego por el evidence_id inválido → 422, jamás 403.
    monkeypatch.setattr(
        OllamaExecutor, "is_available", lambda self: ExecutorAvailability(available=True)
    )
    case_id = _create_case(client, auth)
    r = _query(client, auth, case_id, "ollama")
    assert r.status_code != 403
    assert r.status_code == 422


# ---- cadena de custodia: register + verify auditados (forensic invariant 4) ----


def _audit_actions(cases: CaseManager, case_id: str) -> list[dict]:
    audit_path = cases.case_dir(case_id) / "audit.jsonl"
    return [json.loads(line) for line in audit_path.read_text().splitlines() if line.strip()]


def test_register_evidence_writes_baseline_to_audit(
    client: TestClient, auth: dict, isolated_cases: CaseManager, tmp_path
) -> None:
    case_id = _create_case(client, auth)
    source = tmp_path / "disco.raw"
    source.write_bytes(b"EVIDENCIA-DE-PRUEBA" * 64)

    r = client.post(
        f"/api/cases/{case_id}/evidence",
        headers=auth,
        json={"source_path": str(source)},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    evidence_id = body["evidence_id"]

    entries = _audit_actions(isolated_cases, case_id)
    reg = [e for e in entries if e.get("action") == "evidence_register"]
    assert len(reg) == 1, "register() debe escribir exactamente una entrada en el audit"
    entry = reg[0]
    assert entry["evidence_id"] == evidence_id
    assert entry["sha256"] == body["sha256"]           # hash baseline
    assert entry["size"] == body["size"]               # tamaño
    assert entry["source_path"] == str(source)         # ruta origen
    assert "registered_at" in entry                    # timestamp
    # El audit sigue siendo una cadena hash íntegra tras el append de register.
    from forensia.audit.log import AuditLog

    assert AuditLog(isolated_cases.case_dir(case_id) / "audit.jsonl").verify() is True


def test_verify_endpoint_audits_result(
    client: TestClient, auth: dict, isolated_cases: CaseManager, tmp_path
) -> None:
    case_id = _create_case(client, auth)
    source = tmp_path / "mem.raw"
    source.write_bytes(b"RAMDUMP" * 100)
    reg = client.post(
        f"/api/cases/{case_id}/evidence", headers=auth, json={"source_path": str(source)}
    )
    assert reg.status_code == 200, reg.text
    evidence_id = reg.json()["evidence_id"]

    r = client.post(
        f"/api/cases/{case_id}/evidence/{evidence_id}/verify", headers=auth
    )
    assert r.status_code == 200, r.text
    assert r.json()["verified"] is True

    entries = _audit_actions(isolated_cases, case_id)
    ver = [e for e in entries if e.get("action") == "evidence_verify"]
    assert len(ver) == 1
    assert ver[0]["evidence_id"] == evidence_id
    assert ver[0]["verified"] is True
    assert ver[0]["baseline_sha256"] == reg.json()["sha256"]


# ---- /api/cases/{id}/executor-cost (Bug 008 Nivel 0) --------------------------


def test_executor_cost_endpoint_returns_aggregated_usage(
    client: TestClient, auth, isolated_cases, monkeypatch
) -> None:
    """El endpoint fino agrega el usage de los eventos executor_run_finish."""
    from forensia.audit.log import AuditLog
    from forensia.executors import cost as cost_mod

    monkeypatch.setattr(cost_mod, "case_manager", isolated_cases)
    case = isolated_cases.create(name="c", examiner="e", os_profile="windows")
    audit = AuditLog(isolated_cases.case_dir(case.id) / "audit.jsonl")
    audit.append({
        "action": "executor_run_finish", "executor": "claude-code", "case_id": case.id,
        "exit_code": None, "duration_ms": 5, "response_sha256": "x", "response_chars": 80,
        "input_tokens": 1000, "output_tokens": 200, "cost_usd": 0.01,
        "usage_source": "claude_code.usage",
    })

    resp = client.get(f"/api/cases/{case.id}/executor-cost", headers=auth)
    assert resp.status_code == 200
    body = resp.json()
    assert body[0]["executor"] == "claude-code"
    assert body[0]["total_tokens"] == 1200
    assert body[0]["cost_usd"] == 0.01


def test_executor_cost_endpoint_requires_token(client: TestClient) -> None:
    resp = client.get("/api/cases/whatever/executor-cost")
    assert resp.status_code == 401
