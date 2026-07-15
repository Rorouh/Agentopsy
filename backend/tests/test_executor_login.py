"""Web-driven CLI login (2026-07-15).

Exercises ``forensia.executors.login`` end to end against a FAKE login CLI — a
tiny stand-in that prints a url (+ code) and, on a stdin sentinel, "logs in" by
writing a marker file. NEVER a real OAuth/device flow and NEVER the network: the
only thing faked is the external process; the orchestrator and the availability
check are the real ones (the availability probe is redirected to the marker so a
completed fake reads as "available", exactly as the real ``is_available`` would).

Covered:
- Codex (device flow): ``start`` parses url + code, ``needs_code_input`` is False,
  status flips waiting → logged_in when the process exits 0.
- Claude (paste-back flow): ``start`` parses the url, ``submit_code`` relays the
  code to stdin, status flips to logged_in. ``code`` on Codex → error (no such step).
- RULE 2: already-logged-in / unknown id / non-cloud id / relay-unsupported (Gemini)
  all fail loud and actionable, with no fallback.
- ``start`` on a CLI that emits no url fails loud with the captured tail.
- Shell-free: every production spec argv is a fixed list (SECURITY INVARIANT 4/5).
- Endpoints: token-gated (401 without it) and id-confined (422 on unknown id).
"""

from __future__ import annotations

import dataclasses
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from forensia.executors import login as login_mod
from forensia.executors.base import ExecutorAvailability
from forensia.server import create_app

PORT = 50996

# A fake login CLI. mode + marker path arrive as fixed argv (the test substitutes
# the whole spec — production argv stays fixed and user-free).
_FAKE_CLI = r'''
import sys, time
from pathlib import Path

mode = sys.argv[1]
marker = Path(sys.argv[2])

if mode == "noemit":
    sys.exit(7)

if mode == "codex":
    print("Follow these steps to sign in with device code authorization:")
    print("  Open this link in your browser:")
    print("  https://auth.example.test/device")
    print("  Enter this one-time code (expires in 15 minutes)")
    print("  WXYZ-12345")
    sys.stdout.flush()
    time.sleep(0.15)
    marker.write_text("ok")
    sys.exit(0)

if mode == "claude":
    print("Opening browser to sign in...")
    print("If the browser didn't open, visit: https://claude.example.test/authorize?state=abc123")
    sys.stdout.write("Paste code here if prompted > ")
    sys.stdout.flush()
    line = sys.stdin.readline()
    if line.strip() == "SECRET-CODE":
        marker.write_text("ok")
        sys.exit(0)
    sys.exit(3)

sys.exit(9)
'''


@pytest.fixture(autouse=True)
def _reap_sessions() -> object:
    yield
    login_mod._reap_all()  # noqa: SLF001 — test teardown of the in-memory registry


@pytest.fixture
def fake(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Return a helper that rewires one executor's spec to the fake CLI and its
    availability to a marker file, then yields the marker."""
    script = tmp_path / "fake_login.py"
    script.write_text(_FAKE_CLI, encoding="utf-8")

    def install(executor_id: str, mode: str) -> Path:
        marker = tmp_path / f"{executor_id}.marker"
        spec = login_mod.LOGIN_SPECS[executor_id]
        monkeypatch.setitem(
            login_mod.LOGIN_SPECS,
            executor_id,
            dataclasses.replace(spec, argv=(sys.executable, str(script), mode, str(marker))),
        )

        def fake_avail(eid: str) -> ExecutorAvailability:
            return ExecutorAvailability(available=marker.exists())

        monkeypatch.setattr(login_mod, "_availability", fake_avail)
        return marker

    return install


def _wait_state(executor_id: str, target: str, timeout: float = 6.0) -> dict:
    deadline = time.monotonic() + timeout
    st = login_mod.login_status(executor_id)
    while time.monotonic() < deadline and st["state"] != target:
        time.sleep(0.05)
        st = login_mod.login_status(executor_id)
    return st


# ---- Codex: device flow (no code pasted back) ---------------------------------


def test_codex_start_parses_url_and_code_then_logs_in(fake) -> None:
    fake("codex", "codex")
    started = login_mod.start_login("codex")
    assert started["state"] == "waiting"
    assert str(started["url"]).startswith("https://")
    assert started["code"] == "WXYZ-12345"
    assert started["needs_code_input"] is False

    st = _wait_state("codex", "logged_in")
    assert st["state"] == "logged_in"
    assert st["available"] is True


def test_codex_submit_code_is_rejected_no_such_step(fake) -> None:
    # Codex enters the code in the browser; there is no stdin step (RULE 2).
    with pytest.raises(login_mod.LoginError) as exc:
        login_mod.submit_code("codex", "WXYZ-12345")
    assert "no requiere pegar" in str(exc.value)


# ---- Claude: paste-the-code-back flow -----------------------------------------


def test_claude_start_waits_then_submit_code_logs_in(fake) -> None:
    fake("claude-code", "claude")
    started = login_mod.start_login("claude-code")
    assert started["state"] == "waiting"
    assert str(started["url"]).startswith("https://")
    assert started["code"] is None
    assert started["needs_code_input"] is True

    # Still waiting until the operator pastes the browser code.
    assert login_mod.login_status("claude-code")["state"] == "waiting"

    login_mod.submit_code("claude-code", "SECRET-CODE")
    st = _wait_state("claude-code", "logged_in")
    assert st["state"] == "logged_in"
    assert st["available"] is True


def test_claude_wrong_code_ends_in_error(fake) -> None:
    fake("claude-code", "claude")
    login_mod.start_login("claude-code")
    login_mod.submit_code("claude-code", "NOPE")
    st = _wait_state("claude-code", "error")
    assert st["state"] == "error"
    assert st["available"] is False


# ---- RULE 2: loud, actionable failures ----------------------------------------


def test_start_already_logged_in_fails_loud(fake, monkeypatch: pytest.MonkeyPatch) -> None:
    fake("codex", "codex")
    monkeypatch.setattr(
        login_mod, "_availability", lambda _eid: ExecutorAvailability(available=True)
    )
    with pytest.raises(login_mod.LoginError) as exc:
        login_mod.start_login("codex")
    assert "ya tiene sesión" in str(exc.value)


def test_start_unknown_id_is_value_error() -> None:
    with pytest.raises(ValueError) as exc:
        login_mod.start_login("gpt-4o")
    for valid in login_mod.CLOUD_EXECUTOR_IDS:
        assert valid in str(exc.value)


def test_ollama_has_no_web_login() -> None:
    # Ollama is 100% local — "connecting" it is a caller bug, not a default.
    with pytest.raises(ValueError):
        login_mod.login_status("ollama")


def test_gemini_relay_unsupported_carries_manual_command() -> None:
    with pytest.raises(login_mod.LoginRelayUnsupported) as exc:
        login_mod.start_login("gemini")
    assert exc.value.manual_command.startswith("docker compose exec")
    assert "gemini" in exc.value.manual_command


def test_start_without_url_emission_fails_loud(fake) -> None:
    fake("codex", "noemit")
    with pytest.raises(login_mod.LoginError) as exc:
        login_mod.start_login("codex")
    assert "no emitió una URL" in str(exc.value) or "terminó" in str(exc.value)


# ---- shell-free (SECURITY INVARIANT 4/5) --------------------------------------


def test_production_specs_are_fixed_argv_lists() -> None:
    for eid, spec in login_mod.LOGIN_SPECS.items():
        assert isinstance(spec.argv, tuple), eid
        assert all(isinstance(tok, str) for tok in spec.argv), eid
        assert spec.argv, eid
        # First token is the CLI binary, never a shell.
        assert spec.argv[0] in {"codex", "claude", "gemini"}, eid


# ---- relay capabilities (batch) -----------------------------------------------


def test_login_capabilities_reflect_the_diagnosis() -> None:
    caps = login_mod.login_capabilities()
    assert set(caps) == set(login_mod.CLOUD_EXECUTOR_IDS)
    assert caps["codex"]["relay_supported"] is True
    assert caps["codex"]["needs_code_input"] is False
    assert caps["claude-code"]["relay_supported"] is True
    assert caps["claude-code"]["needs_code_input"] is True
    assert caps["gemini"]["relay_supported"] is False
    assert "IneligibleTierError" in str(caps["gemini"]["reason"])


# ---- HTTP surface: token-gated + id-confined ----------------------------------


@pytest.fixture
def client() -> TestClient:
    app = create_app(PORT)
    return TestClient(app, base_url=f"http://127.0.0.1:{PORT}")


def _tok(client: TestClient) -> dict[str, str]:
    return {"X-Forensia-Token": client.app.state.token}


def test_login_endpoints_require_token(client: TestClient) -> None:
    assert client.post("/api/executors/codex/login").status_code == 401
    assert client.get("/api/executors/codex/login/status").status_code == 401
    assert client.post("/api/executors/codex/login/code", json={"code": "x"}).status_code == 401
    assert client.post("/api/executors/codex/login/cancel").status_code == 401
    assert client.get("/api/executors/login-capabilities").status_code == 401


def test_login_start_unknown_id_is_422(client: TestClient) -> None:
    r = client.post("/api/executors/gpt-4o/login", headers=_tok(client))
    assert r.status_code == 422
    assert "gpt-4o" in r.json()["detail"]


def test_login_capabilities_endpoint(client: TestClient) -> None:
    r = client.get("/api/executors/login-capabilities", headers=_tok(client))
    assert r.status_code == 200
    body = r.json()["executors"]
    assert body["gemini"]["relay_supported"] is False
    assert body["codex"]["relay_supported"] is True


def test_gemini_start_degrades_with_manual_command(client: TestClient) -> None:
    # No launch happens (relay check first) — safe to drive over HTTP.
    r = client.post("/api/executors/gemini/login", headers=_tok(client))
    assert r.status_code == 409
    assert "docker compose exec" in r.json()["detail"]
    assert r.headers.get("X-Forensia-Manual-Command", "").startswith("docker compose exec")
