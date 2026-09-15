"""Superficie HTTP para la SPA (migración del frontend al servicio `web`).

Covers:
- ``/api/session`` entrega el token SOLO tras pasar el Host-check: es el
  bootstrap del cliente web (mismo-origen vía el proxy nginx) y un Host
  desconocido → 403 (anti DNS-rebinding, SECURITY INVARIANT 2).
- ``create_app(ui_origins=...)`` añade los hosts de la UI a la allowlist del
  Host-check (el nginx del servicio web reenvía el Host original del navegador).
- ``/api/evidence/sources``: sin ``AGENTOPSY_EVIDENCE_DIR`` → 503 accionable
  (RULE 2 — jamás se adivina una bandeja); con la bandeja montada lista solo
  ficheros regulares no ocultos.
- ``/api/evidence/upload`` (subida del perito): deposita el fichero en la
  bandeja; acepta también los segmentos de continuación de un EWF partido
  (``.E02`` … — sin ellos no se puede subir el CONJUNTO desde el navegador, y
  sin el conjunto ``ewfmount`` no reensambla la imagen); rechaza formato no
  soportado (422), traversal en el nombre (422) y sobrescritura de evidencia
  existente (409); exige token.
- ``/api/cases/{id}/delete``: borra el caso ENTERO solo si ``confirm_name``
  coincide EXACTO con el nombre (RULE 2) — 409 si no, 404 si no existe, 401 sin
  token.
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

from agentopsy.cases.manager import CaseManager
from agentopsy.executors import ClaudeCodeExecutor, ExecutorAvailability, OllamaExecutor
from agentopsy.i18n import t
from agentopsy.server import create_app

PORT = 51007


@pytest.fixture
def isolated_cases(tmp_path, monkeypatch):
    cases = CaseManager(root=tmp_path / "cases")

    import agentopsy.routers.agent as agent_router
    import agentopsy.routers.cases as cases_router
    from agentopsy.evidence import EvidenceManager

    monkeypatch.setattr(cases_router, "case_manager", cases)
    monkeypatch.setattr(agent_router, "case_manager", cases)
    # El singleton evidence_manager guarda su propia referencia al CaseManager
    # real; para que register/verify operen sobre el árbol de casos aislado hay
    # que darle uno atado a la misma raíz.
    evidence = EvidenceManager(cases)
    monkeypatch.setattr(cases_router, "evidence_manager", evidence)
    # La investigación abarca TODAS las evidencias del caso: el router del agente
    # las lee del mismo árbol aislado.
    monkeypatch.setattr(agent_router, "evidence_manager", evidence)
    return cases


@pytest.fixture
def client(isolated_cases) -> TestClient:
    app = create_app(PORT)
    return TestClient(app, base_url=f"http://127.0.0.1:{PORT}")


@pytest.fixture
def auth(client) -> dict[str, str]:
    return {"X-Agentopsy-Token": client.app.state.token}


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
    # AGENTOPSY_UI_ORIGINS) el Host que nginx reenvía sí. Allowlist EXACTA.
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
    monkeypatch.delenv("AGENTOPSY_EVIDENCE_DIR", raising=False)
    r = client.get("/api/evidence/sources", headers=auth)
    assert r.status_code == 503
    assert "AGENTOPSY_EVIDENCE_DIR" in r.json()["detail"]


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
    monkeypatch.setenv("AGENTOPSY_EVIDENCE_DIR", str(inbox))

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
    monkeypatch.setenv("AGENTOPSY_EVIDENCE_DIR", str(inbox))

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


def test_upload_accepts_supplied_material(
    client: TestClient, auth: dict, monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    # Un documento es evidencia: entra por la bandeja como una imagen de disco.
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.setenv("AGENTOPSY_EVIDENCE_DIR", str(inbox))

    r = client.post(
        "/api/evidence/upload",
        headers=auth,
        files={"file": ("contrato.pdf", b"%PDF-1.7\n", "application/pdf")},
    )
    assert r.status_code == 200
    assert (inbox / "contrato.pdf").read_bytes() == b"%PDF-1.7\n"


def test_upload_rejects_an_unrecognised_extension(
    client: TestClient, auth: dict, monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.setenv("AGENTOPSY_EVIDENCE_DIR", str(inbox))

    r = client.post(
        "/api/evidence/upload",
        headers=auth,
        files={"file": ("captura.qqq", b"nope", "application/octet-stream")},
    )
    assert r.status_code == 422
    assert "./evidence" in r.json()["detail"]
    assert not list(inbox.iterdir())


def test_upload_rejects_path_traversal(
    client: TestClient, auth: dict, monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.setenv("AGENTOPSY_EVIDENCE_DIR", str(inbox))

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
    monkeypatch.setenv("AGENTOPSY_EVIDENCE_DIR", str(inbox))

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


@pytest.mark.parametrize("segment", ["caso.E02", "caso.E09", "caso.Ex02"])
def test_upload_accepts_ewf_continuation_segments(
    client: TestClient, auth: dict, monkeypatch: pytest.MonkeyPatch, tmp_path, segment
) -> None:
    # Un EWF partido son N ficheros y la bandeja los necesita TODOS (ewfmount
    # reensambla desde el .E01 a sus hermanos co-localizados): las
    # continuaciones se suben aunque no sean puntos de entrada registrables.
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.setenv("AGENTOPSY_EVIDENCE_DIR", str(inbox))

    r = client.post(
        "/api/evidence/upload",
        headers=auth,
        files={"file": (segment, b"S" * 16, "application/octet-stream")},
    )
    assert r.status_code == 200, r.text
    assert (inbox / segment).read_bytes() == b"S" * 16


def test_upload_whole_ewf_set_then_register_ingests_it_as_one_evidence(
    client: TestClient, auth: dict, isolated_cases: CaseManager,
    monkeypatch: pytest.MonkeyPatch, tmp_path,
) -> None:
    # Camino completo del perito por la web: subir los 3 segmentos y registrar
    # el .E01 (el único registrable) → UNA evidencia con el set entero.
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.setenv("AGENTOPSY_EVIDENCE_DIR", str(inbox))
    case_id = _create_case(client, auth)

    for i in (1, 2, 3):
        r = client.post(
            "/api/evidence/upload",
            headers=auth,
            files={"file": (f"LoneWolf.E{i:02d}", f"seg-{i}".encode(), "application/octet-stream")},
        )
        assert r.status_code == 200, r.text

    reg = client.post(
        f"/api/cases/{case_id}/evidence",
        headers=auth,
        json={"source_path": str(inbox / "LoneWolf.E01")},
    )
    assert reg.status_code == 200, reg.text
    assert [s["name"] for s in reg.json()["segments"]] == [
        "original.E01",
        "original.E02",
        "original.E03",
    ]


def test_upload_of_a_continuation_that_is_already_there_is_409(
    client: TestClient, auth: dict, monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    # La UI trata este 409 como informativo (re-soltar un set del que ya había
    # parte es normal), pero el backend sigue sin sobrescribir evidencia jamás.
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "caso.E02").write_bytes(b"original")
    monkeypatch.setenv("AGENTOPSY_EVIDENCE_DIR", str(inbox))

    r = client.post(
        "/api/evidence/upload",
        headers=auth,
        files={"file": ("caso.E02", b"nuevo", "application/octet-stream")},
    )
    assert r.status_code == 409
    assert (inbox / "caso.E02").read_bytes() == b"original"


def _create_case(client: TestClient, auth: dict) -> str:
    r = client.post(
        "/api/cases",
        headers=auth,
        json={"name": "Caso RGPD", "examiner": "E. Marques", "os_profile": "unix"},
    )
    assert r.status_code == 200, r.text
    return r.json()["id"]


# ---- /api/cases/{id}/delete ----------------------------------------------------


def test_delete_case_removes_it_when_the_name_matches(
    client: TestClient, auth: dict, isolated_cases: CaseManager, tmp_path
) -> None:
    case_id = _create_case(client, auth)
    source = tmp_path / "disco.raw"
    source.write_bytes(b"EVIDENCIA" * 32)
    reg = client.post(
        f"/api/cases/{case_id}/evidence", headers=auth, json={"source_path": str(source)}
    )
    assert reg.status_code == 200, reg.text

    r = client.post(
        f"/api/cases/{case_id}/delete", headers=auth, json={"confirm_name": "Caso RGPD"}
    )
    assert r.status_code == 200, r.text
    assert r.json() == {"deleted": True, "case_id": case_id}
    # El directorio entero (evidencia + audit incluidos) ya no existe.
    assert not (isolated_cases.root / case_id).exists()
    assert client.get(f"/api/cases/{case_id}", headers=auth).status_code == 404


def test_delete_case_with_wrong_name_is_409_and_keeps_the_case(
    client: TestClient, auth: dict, isolated_cases: CaseManager
) -> None:
    case_id = _create_case(client, auth)
    r = client.post(
        f"/api/cases/{case_id}/delete", headers=auth, json={"confirm_name": "caso rgpd"}
    )
    assert r.status_code == 409
    assert "confirm_name" in r.json()["detail"]
    assert (isolated_cases.root / case_id).is_dir()
    assert client.get(f"/api/cases/{case_id}", headers=auth).status_code == 200


def test_delete_unknown_case_is_404(client: TestClient, auth: dict) -> None:
    r = client.post(
        "/api/cases/11111111-1111-4111-8111-111111111111/delete",
        headers=auth,
        json={"confirm_name": "lo que sea"},
    )
    assert r.status_code == 404


def test_delete_without_confirm_name_is_422(client: TestClient, auth: dict) -> None:
    # RULE 2: la confirmación es obligatoria — sin ella el body ni siquiera valida.
    case_id = _create_case(client, auth)
    r = client.post(f"/api/cases/{case_id}/delete", headers=auth, json={})
    assert r.status_code == 422


def test_delete_requires_token(client: TestClient, auth: dict) -> None:
    case_id = _create_case(client, auth)
    r = client.post(f"/api/cases/{case_id}/delete", json={"confirm_name": "Caso RGPD"})
    assert r.status_code == 401


# ---- /api/agent/query: validación de ejecutor / os_profile (backend) -----------


def _query(client: TestClient, auth: dict, case_id: str, executor: str) -> object:
    return client.post(
        "/api/agent/query",
        headers=auth,
        json={
            "prompt": "analiza",
            "os_profile": "unix",
            "case_id": case_id,
            "executor": executor,
        },
    )


def test_query_unresolved_os_profile_is_409(
    client: TestClient,
    auth: dict,
    isolated_cases: CaseManager,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # A case whose os_profile triage could not determine (here: its only evidence
    # is a supplied file, which never fixes the profile) must NOT route silently:
    # /api/agent/query answers 409 with an actionable "anchor the profile" message
    # (RULE 2 enmendada). A local executor is used so the consent gate is not what
    # stops the request.
    from agentopsy.evidence import EvidenceManager

    monkeypatch.setattr(
        OllamaExecutor, "is_available", lambda self: ExecutorAvailability(available=True)
    )
    case = isolated_cases.create(name="Ambiguo", examiner="alice")  # no anchor
    nota = tmp_path / "nota.txt"
    nota.write_text("texto sin marcadores de sistema\n", encoding="utf-8")
    EvidenceManager(isolated_cases).register(case.id, str(nota))
    r = client.post(
        "/api/agent/query",
        headers=auth,
        json={"prompt": "analiza", "case_id": case.id, "executor": "ollama"},
    )
    assert r.status_code == 409
    assert "os-profile" in r.json()["detail"]


def test_query_of_a_case_without_evidence_is_422(
    client: TestClient, auth: dict, isolated_cases: CaseManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The scope of an investigation is every evidence of the case: with none there
    # is nothing to investigate, and the answer says so (not "anchor the profile").
    monkeypatch.setattr(
        OllamaExecutor, "is_available", lambda self: ExecutorAvailability(available=True)
    )
    case = isolated_cases.create(name="Vacío", examiner="alice")
    r = client.post(
        "/api/agent/query",
        headers=auth,
        json={"prompt": "analiza", "case_id": case.id, "executor": "ollama"},
    )
    assert r.status_code == 422
    assert r.json()["detail"] == t("api.evidenceRequired", "en")


@pytest.mark.parametrize("endpoint", ["/api/agent/query", "/api/agent/analyze"])
def test_query_rejects_an_evidence_id_because_the_scope_is_the_case(
    client: TestClient,
    auth: dict,
    isolated_cases: CaseManager,
    monkeypatch: pytest.MonkeyPatch,
    endpoint: str,
) -> None:
    # There is no primary evidence any more: a client that still sends one (a
    # stale SPA tab, a script) gets an actionable 422 instead of a run whose scope
    # silently differs from the one it asked for (RULE 2).
    monkeypatch.setattr(
        OllamaExecutor, "is_available", lambda self: ExecutorAvailability(available=True)
    )
    case = isolated_cases.create(name="Dos evidencias", examiner="alice")
    r = client.post(
        endpoint,
        headers=auth,
        json={
            "prompt": "analiza",
            "case_id": case.id,
            "evidence_id": "11111111-1111-4111-8111-111111111111",
            "executor": "ollama",
        },
    )
    assert r.status_code == 422
    assert r.json()["detail"] == t("api.evidenceScopeIsCase", "en")


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
    from agentopsy.audit.log import AuditLog

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
