"""HTTP surface for cases / evidence / artifacts / chats — token gate + roundtrips."""

from __future__ import annotations

import hashlib

import pytest
from fastapi.testclient import TestClient

from forensia.artifacts.store import ArtifactStore
from forensia.cases.manager import CaseManager
from forensia.chats.store import ChatStore
from forensia.evidence import EvidenceManager
from forensia.server import create_app

PORT = 51000


@pytest.fixture
def isolated_storage(tmp_path, monkeypatch):
    """Build fresh storage singletons rooted at tmp_path and patch every reference."""
    cases = CaseManager(root=tmp_path / "cases")
    evidence = EvidenceManager(cases)
    artifacts = ArtifactStore(cases)
    chats = ChatStore(cases)

    # Patch the module-level names every router imports from.
    import forensia.routers.cases as cases_router
    import forensia.routers.artifacts as artifacts_router
    import forensia.routers.chats as chats_router

    monkeypatch.setattr(cases_router, "case_manager", cases)
    monkeypatch.setattr(cases_router, "evidence_manager", evidence)
    monkeypatch.setattr(artifacts_router, "artifact_store", artifacts)
    monkeypatch.setattr(chats_router, "chat_store", chats)

    # Also patch the dispatcher singletons in case any other test triggers it.
    import forensia.toolkit.dispatcher as dispatcher_mod

    monkeypatch.setattr(dispatcher_mod, "case_manager", cases)
    monkeypatch.setattr(dispatcher_mod, "artifact_store", artifacts)
    return {"cases": cases, "evidence": evidence, "artifacts": artifacts, "chats": chats}


@pytest.fixture
def client(isolated_storage):
    app = create_app(PORT)
    return TestClient(app, base_url=f"http://127.0.0.1:{PORT}")


@pytest.fixture
def token(client):
    return client.app.state.token


@pytest.fixture
def auth(token):
    return {"X-Forensia-Token": token}


# --------------------------------------------------------------------------- #
# /api/cases
# --------------------------------------------------------------------------- #
class TestCasesRoutes:
    def test_create_without_token_returns_401(self, client):
        r = client.post(
            "/api/cases",
            json={"name": "op", "examiner": "alice", "os_profile": "unix"},
        )
        assert r.status_code == 401

    def test_create_with_invalid_os_profile_returns_422(self, client, auth):
        r = client.post(
            "/api/cases",
            json={"name": "op", "examiner": "alice", "os_profile": "btrfs"},
            headers=auth,
        )
        assert r.status_code == 422

    def test_create_missing_required_field_returns_422(self, client, auth):
        # Pydantic itself returns 422 on schema mismatch. ``os_profile`` is now
        # optional (derived), so we omit a still-required field (``examiner``).
        r = client.post(
            "/api/cases",
            json={"name": "op"},
            headers=auth,
        )
        assert r.status_code == 422

    def test_create_without_os_profile_succeeds(self, client, auth):
        # Auto-detección de SO: omitting os_profile is the normal path — it is
        # derived from the evidence content later, not chosen at creation.
        r = client.post(
            "/api/cases",
            json={"name": "op", "examiner": "alice"},
            headers=auth,
        )
        assert r.status_code == 200, r.text
        assert r.json()["os_profile"] is None

    def test_full_roundtrip_create_get_list_close(self, client, auth):
        r = client.post(
            "/api/cases",
            json={
                "name": "Op Roundtrip",
                "examiner": "alice",
                "os_profile": "unix",
                "notes": "hi",
            },
            headers=auth,
        )
        assert r.status_code == 200
        case = r.json()
        assert case["status"] == "active"

        got = client.get(f"/api/cases/{case['id']}", headers=auth)
        assert got.status_code == 200
        assert got.json() == case

        listed = client.get("/api/cases", headers=auth)
        assert listed.status_code == 200
        assert any(c["id"] == case["id"] for c in listed.json())

        closed = client.post(f"/api/cases/{case['id']}/close", headers=auth)
        assert closed.status_code == 200
        assert closed.json()["status"] == "closed"

    def test_get_unknown_case_returns_404(self, client, auth):
        r = client.get(
            "/api/cases/11111111-1111-4111-8111-111111111111", headers=auth
        )
        assert r.status_code == 404

    def test_get_malformed_case_id_returns_422(self, client, auth):
        r = client.get("/api/cases/not-a-uuid", headers=auth)
        assert r.status_code == 422

    def test_update_edits_fields(self, client, auth):
        created = client.post(
            "/api/cases",
            json={"name": "op", "examiner": "alice"},
            headers=auth,
        ).json()
        r = client.post(
            f"/api/cases/{created['id']}/update",
            json={"name": "op renamed", "notes": "updated notes"},
            headers=auth,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["name"] == "op renamed"
        assert body["notes"] == "updated notes"
        assert body["examiner"] == "alice"

    def test_update_with_no_fields_returns_422(self, client, auth):
        created = client.post(
            "/api/cases", json={"name": "op", "examiner": "alice"}, headers=auth
        ).json()
        r = client.post(f"/api/cases/{created['id']}/update", json={}, headers=auth)
        assert r.status_code == 422

    def test_update_unknown_case_returns_404(self, client, auth):
        r = client.post(
            "/api/cases/11111111-1111-4111-8111-111111111111/update",
            json={"name": "x"},
            headers=auth,
        )
        assert r.status_code == 404

    def test_close_then_reopen_roundtrip(self, client, auth):
        created = client.post(
            "/api/cases", json={"name": "op", "examiner": "alice"}, headers=auth
        ).json()
        closed = client.post(f"/api/cases/{created['id']}/close", headers=auth)
        assert closed.json()["status"] == "closed"
        reopened = client.post(f"/api/cases/{created['id']}/reopen", headers=auth)
        assert reopened.status_code == 200
        assert reopened.json()["status"] == "active"

    def test_reopen_unknown_case_returns_404(self, client, auth):
        r = client.post(
            "/api/cases/11111111-1111-4111-8111-111111111111/reopen", headers=auth
        )
        assert r.status_code == 404


# --------------------------------------------------------------------------- #
# /api/cases/{case_id}/evidence
# --------------------------------------------------------------------------- #
class TestEvidenceRoutes:
    def _new_case(self, client, auth):
        r = client.post(
            "/api/cases",
            json={"name": "op", "examiner": "alice", "os_profile": "unix"},
            headers=auth,
        )
        return r.json()["id"]

    def test_register_without_token_returns_401(self, client):
        r = client.post(
            "/api/cases/11111111-1111-4111-8111-111111111111/evidence",
            json={"source_path": "/tmp/x"},
        )
        assert r.status_code == 401

    def test_register_missing_field_returns_422(self, client, auth):
        case_id = self._new_case(client, auth)
        r = client.post(
            f"/api/cases/{case_id}/evidence", json={}, headers=auth
        )
        assert r.status_code == 422

    def test_register_full_roundtrip(self, client, auth, tmp_path):
        case_id = self._new_case(client, auth)
        src = tmp_path / "img.raw"
        payload = b"raw-evidence-bytes"
        src.write_bytes(payload)
        r = client.post(
            f"/api/cases/{case_id}/evidence",
            json={"source_path": str(src)},
            headers=auth,
        )
        assert r.status_code == 200, r.text
        handle = r.json()
        assert handle["sha256"] == hashlib.sha256(payload).hexdigest()
        # original_path must serialise as a string (not a {"as_posix": …} dict).
        assert isinstance(handle["original_path"], str)
        assert handle["original_path"].endswith("original.raw")

        listed = client.get(
            f"/api/cases/{case_id}/evidence", headers=auth
        )
        assert listed.status_code == 200
        assert handle["evidence_id"] in [h["evidence_id"] for h in listed.json()]

        verified = client.post(
            f"/api/cases/{case_id}/evidence/{handle['evidence_id']}/verify",
            headers=auth,
        )
        assert verified.status_code == 200
        assert verified.json()["verified"] is True

    def test_register_unknown_case_returns_404(self, client, auth, tmp_path):
        src = tmp_path / "img.raw"
        src.write_bytes(b"x")
        r = client.post(
            "/api/cases/11111111-1111-4111-8111-111111111111/evidence",
            json={"source_path": str(src)},
            headers=auth,
        )
        assert r.status_code == 404

    def test_register_on_closed_case_returns_422(self, client, auth, tmp_path):
        case_id = self._new_case(client, auth)
        client.post(f"/api/cases/{case_id}/close", headers=auth)
        src = tmp_path / "img.raw"
        src.write_bytes(b"x")
        r = client.post(
            f"/api/cases/{case_id}/evidence",
            json={"source_path": str(src)},
            headers=auth,
        )
        assert r.status_code == 422


# --------------------------------------------------------------------------- #
# /api/cases/{case_id}/artifacts
# --------------------------------------------------------------------------- #
class TestArtifactsRoutes:
    def _new_case(self, client, auth):
        r = client.post(
            "/api/cases",
            json={"name": "op", "examiner": "alice", "os_profile": "unix"},
            headers=auth,
        )
        return r.json()["id"]

    def test_list_without_token_returns_401(self, client):
        r = client.get(
            "/api/cases/11111111-1111-4111-8111-111111111111/artifacts"
        )
        assert r.status_code == 401

    def test_list_empty_returns_empty_list(self, client, auth):
        case_id = self._new_case(client, auth)
        r = client.get(f"/api/cases/{case_id}/artifacts", headers=auth)
        assert r.status_code == 200
        assert r.json() == []

    def test_get_unknown_run_returns_404(self, client, auth):
        case_id = self._new_case(client, auth)
        r = client.get(
            f"/api/cases/{case_id}/artifacts/11111111-1111-4111-8111-111111111111",
            headers=auth,
        )
        assert r.status_code == 404

    def test_list_unknown_case_returns_404(self, client, auth):
        r = client.get(
            "/api/cases/11111111-1111-4111-8111-111111111111/artifacts",
            headers=auth,
        )
        assert r.status_code == 404

    def test_list_after_storing_a_run(self, client, auth, isolated_storage):
        case_id = self._new_case(client, auth)
        # Drop in a finalized run via the store directly — the HTTP layer is read-only.
        run_id, out_dir = isolated_storage["artifacts"].start_run(
            case_id, "tool_x", argv=["x"]
        )
        (out_dir / "a.csv").write_bytes(b"x")
        isolated_storage["artifacts"].finalize_run(
            case_id, run_id, exit_code=0, stdout="", stderr=""
        )
        r = client.get(f"/api/cases/{case_id}/artifacts", headers=auth)
        assert r.status_code == 200
        body = r.json()
        assert len(body) == 1
        assert body[0]["run_id"] == run_id

        r2 = client.get(
            f"/api/cases/{case_id}/artifacts/{run_id}", headers=auth
        )
        assert r2.status_code == 200
        assert r2.json()["exit_code"] == 0

    def test_http_exposes_finished_and_error_run_states(
        self, client, auth, isolated_storage
    ):
        case_id = self._new_case(client, auth)
        artifacts = isolated_storage["artifacts"]

        finished_id, _ = artifacts.start_run(case_id, "tool_ok", argv=["ok"])
        artifacts.finalize_run(
            case_id,
            finished_id,
            exit_code=17,
            stdout="normal stdout",
            stderr="normal stderr",
        )

        error_id, _ = artifacts.start_run(case_id, "tool_error", argv=["error"])
        artifacts.fail_run(
            case_id,
            error_id,
            error_type="MaletinExecError",
            error_message="exec-agent connection refused",
            stdout="partial stdout",
            stderr="partial stderr",
        )

        listed = client.get(f"/api/cases/{case_id}/artifacts", headers=auth)
        assert listed.status_code == 200
        by_id = {run["run_id"]: run for run in listed.json()}
        assert by_id[finished_id]["status"] == "finished"
        assert by_id[finished_id]["exit_code"] == 17
        assert by_id[finished_id]["error_type"] is None
        assert by_id[finished_id]["error_message"] is None
        assert by_id[error_id]["status"] == "error"
        assert by_id[error_id]["exit_code"] is None
        assert by_id[error_id]["error_type"] == "MaletinExecError"
        assert by_id[error_id]["error_message"] == "exec-agent connection refused"

        finished = client.get(
            f"/api/cases/{case_id}/artifacts/{finished_id}", headers=auth
        )
        assert finished.status_code == 200
        assert finished.json()["status"] == "finished"
        assert finished.json()["exit_code"] == 17

        failed = client.get(
            f"/api/cases/{case_id}/artifacts/{error_id}", headers=auth
        )
        assert failed.status_code == 200
        assert failed.json()["status"] == "error"
        assert failed.json()["exit_code"] is None
        assert failed.json()["error_type"] == "MaletinExecError"
        assert failed.json()["error_message"] == "exec-agent connection refused"


# --------------------------------------------------------------------------- #
# /api/cases/{case_id}/chats
# --------------------------------------------------------------------------- #
class TestChatsRoutes:
    def _new_case(self, client, auth):
        r = client.post(
            "/api/cases",
            json={"name": "op", "examiner": "alice", "os_profile": "unix"},
            headers=auth,
        )
        return r.json()["id"]

    def test_list_sessions_without_token_returns_401(self, client):
        r = client.get(
            "/api/cases/11111111-1111-4111-8111-111111111111/chats"
        )
        assert r.status_code == 401

    def test_append_invalid_role_returns_422(self, client, auth):
        case_id = self._new_case(client, auth)
        r = client.post(
            f"/api/cases/{case_id}/chats/session1/messages",
            json={"role": "admin", "content": "hi"},
            headers=auth,
        )
        assert r.status_code == 422

    def test_full_chat_roundtrip(self, client, auth):
        case_id = self._new_case(client, auth)
        session_id = "session-abc"
        for msg in (
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": "hello"},
        ):
            r = client.post(
                f"/api/cases/{case_id}/chats/{session_id}/messages",
                json=msg,
                headers=auth,
            )
            assert r.status_code == 200
            body = r.json()
            assert body["ts"]  # auto-filled by the router

        listed = client.get(f"/api/cases/{case_id}/chats", headers=auth)
        assert listed.status_code == 200
        assert session_id in listed.json()

        read = client.get(
            f"/api/cases/{case_id}/chats/{session_id}", headers=auth
        )
        assert read.status_code == 200
        msgs = read.json()
        assert [m["role"] for m in msgs] == ["user", "assistant"]
        assert [m["content"] for m in msgs] == ["hi", "hello"]

    def test_read_unknown_session_returns_404(self, client, auth):
        case_id = self._new_case(client, auth)
        r = client.get(
            f"/api/cases/{case_id}/chats/never-existed", headers=auth
        )
        assert r.status_code == 404

    def test_append_invalid_session_id_returns_422(self, client, auth):
        case_id = self._new_case(client, auth)
        r = client.post(
            f"/api/cases/{case_id}/chats/with space/messages",
            json={"role": "user", "content": "hi"},
            headers=auth,
        )
        # FastAPI URL-encodes the path; the inner store rejects it -> 422.
        assert r.status_code in (404, 422)
