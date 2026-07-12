"""Custody of the timeout boundary: a `timeout=null` run is ALWAYS bounded, and the api's
HTTP client always outlives the exec-agent's process ceiling (INVARIANT 4).

The bug: the agent/MCP call the dispatcher without a timeout → `timeout=None` reaches the
exec-agent, which used to run `subprocess.run(..., timeout=None)` (unbounded). If the api's
HTTP client gave up first, the dispatcher would close and HASH `out/stdout.bin` while the
maletín process was STILL alive writing to it — a custody SHA-256 taken over bytes that keep
mutating (INVARIANT 4 broken).

The fix has two halves, pinned here:
  (a) exec-agent: a `null` timeout applies the hard ceiling `_MAX_TIMEOUT_S` as the EFFECTIVE
      timeout (never None). `subprocess.run` kills AND reaps the child on expiry, so by the
      time its stdout is hashed the process is dead and the file no longer changes.
  (b) maletín: the HTTP read budget is set strictly ABOVE the exec-agent's effective ceiling,
      so the exec-agent always finishes (kill + hash + reply) before the transport gives up —
      the dispatcher never hashes a run whose maletín process is still alive.
  (c) end to end through the dispatcher: the hashed artifact matches the FINAL bytes after the
      process dies, never a file mid-write.

Tests (a) and (b) run everywhere (they drive the interpreter directly / are pure unit). Test
(c) needs a POSIX exec of a script stand-in named after the catalog binary, so it runs in CI
(Linux); on Windows the real chain is driven over docker compose (e2e-ewf-runbook.md).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from forensia.artifacts.store import ArtifactStore
from forensia.cases.manager import CaseManager
from forensia.evidence_context import EvidenceContext
from forensia.toolkit import dispatcher, maletin

REPO_ROOT = Path(__file__).resolve().parents[2]
EXEC_AGENT_PY = REPO_ROOT / "docker" / "docker" / "forensic-toolkit" / "exec_agent.py"

_HEAD = b"HEAD"
# A child that writes a marker then GROWS its stdout forever (one byte per ~10 ms). Redirected
# to the artifact file, a LIVE process keeps enlarging it; once the exec-agent kills it the
# file freezes. "the file stops growing" is thus an observable proof the process is dead.
_GROW = (
    "import sys, time\n"
    "sys.stdout.buffer.write(b'HEAD')\n"
    "sys.stdout.buffer.flush()\n"
    "while True:\n"
    "    sys.stdout.buffer.write(b'.')\n"
    "    sys.stdout.buffer.flush()\n"
    "    time.sleep(0.01)\n"
)


def _load_exec_agent():
    spec = importlib.util.spec_from_file_location("forensia_exec_agent_timeout", EXEC_AGENT_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# (a) exec-agent: a `null` timeout is bounded by the ceiling and kills the child
# --------------------------------------------------------------------------- #
def test_null_timeout_is_bounded_and_kills_process(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("FORENSIA_EXEC_AGENT_TOKEN", raising=False)
    module = _load_exec_agent()
    module._MAX_TIMEOUT_S = 1  # tiny effective ceiling so the runaway child is killed fast

    dst = tmp_path / "stdout.bin"
    server = ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        payload = json.dumps(
            {
                "argv": [sys.executable, "-c", _GROW],
                "timeout": None,  # the api's `null`: no api-imposed timeout
                "stdout_path": str(dst),
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/exec",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        start = time.monotonic()
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 — loopback test
            body = json.loads(resp.read().decode("utf-8"))
        elapsed = time.monotonic() - start
    finally:
        server.shutdown()
        thread.join(timeout=5)

    # Bounded by the ceiling (~1 s), NOT the runaway child: it never ran unbounded.
    assert elapsed < 20
    assert body["timed_out"] is True
    assert body["exit"] == 124
    # subprocess.run kills AND reaps the child on timeout, so the process is dead here.
    # Prove it: the artifact no longer grows.
    size1 = dst.stat().st_size
    time.sleep(1.0)
    size2 = dst.stat().st_size
    assert size1 == size2 and size1 > 0
    # And the SHA-256 the exec-agent returned is over those final, frozen bytes.
    assert body["stdout_sha256"] == hashlib.sha256(dst.read_bytes()).hexdigest()
    assert dst.read_bytes().startswith(_HEAD)


def test_non_positive_timeout_is_rejected(monkeypatch, tmp_path) -> None:
    """A `null` timeout applies the ceiling; an explicit non-positive one is a loud 400
    (never silently coerced to "no limit" — RULE 2)."""
    monkeypatch.delenv("FORENSIA_EXEC_AGENT_TOKEN", raising=False)
    module = _load_exec_agent()

    server = ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        payload = json.dumps({"argv": [sys.executable, "-c", "pass"], "timeout": 0}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/exec",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            urllib.request.urlopen(req, timeout=30)  # noqa: S310 — loopback test
    finally:
        server.shutdown()
        thread.join(timeout=5)
    assert excinfo.value.code == 400


# --------------------------------------------------------------------------- #
# (b) temporal invariant: the maletín's HTTP budget outlives the exec-agent ceiling
# --------------------------------------------------------------------------- #
def test_http_timeout_exceeds_exec_agent_ceiling(monkeypatch) -> None:
    module = _load_exec_agent()
    ceiling = module._MAX_TIMEOUT_S
    # The maletín mirrors the exec-agent's hard ceiling; drift in EITHER file is a bug that
    # would silently reopen the race window.
    assert maletin._EXEC_AGENT_MAX_TIMEOUT == ceiling
    assert maletin._HTTP_TIMEOUT_MARGIN > 0

    captured: dict[str, float] = {}

    def fake_request(method, url, payload=None, *, timeout):
        captured["timeout"] = timeout
        return 200, {"exit": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(maletin, "service_url", lambda _svc: "http://toolkit-unix:8666")
    monkeypatch.setattr(maletin, "_request", fake_request)

    # (i) timeout=None → the exec-agent runs the child bounded by `ceiling`; the client must
    #     wait STRICTLY longer so the exec-agent always replies first.
    maletin.run_argv_in_maletin("toolkit-unix", ["x"], timeout=None)
    assert captured["timeout"] > ceiling

    # (ii) a numeric timeout T → the exec-agent caps at min(T, ceiling); the client still waits
    #      longer than that effective ceiling, for T below, at, and above the ceiling.
    for t in (10, ceiling, ceiling + 5000):
        maletin.run_argv_in_maletin("toolkit-unix", ["x"], timeout=t)
        assert captured["timeout"] > min(float(t), ceiling)


# --------------------------------------------------------------------------- #
# (c) end to end through the dispatcher: the hashed artifact == final bytes (dead process)
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(
    os.name != "posix",
    reason=(
        "runs a POSIX script stand-in for the catalog binary shell-free on PATH; it runs in "
        "CI (Linux). On Windows the real chain is driven over docker compose with a .E01 "
        "(docs/operacion/e2e-ewf-runbook.md)."
    ),
)
def test_dispatcher_hashes_final_bytes_after_process_death(monkeypatch, tmp_path) -> None:
    # A stand-in `icat` (the catalog binary) that GROWS its stdout forever until killed.
    bindir = tmp_path / "toolbin"
    bindir.mkdir()
    icat = bindir / "icat"
    icat.write_text(f"#!{sys.executable}\n{_GROW}", encoding="utf-8")
    icat.chmod(0o755)

    cases = CaseManager(root=tmp_path / "cases")
    store = ArtifactStore(cases)
    case = cases.create(name="op", examiner="alice", os_profile="unix")
    # The image must exist under the case's evidence dir — the EVIDENCE_INPUT path policy
    # gate (P0.5-2) confines it there (the stand-in `icat` ignores the content anyway).
    evidence_image = cases.root / case.id / "evidence" / "original.raw"
    evidence_image.write_bytes(b"\x00" * 512)

    monkeypatch.setattr(dispatcher, "case_manager", cases)
    monkeypatch.setattr(dispatcher, "artifact_store", store)
    monkeypatch.setattr(dispatcher, "resolve", lambda _b: None)  # force the maletín venue
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.delenv("FORENSIA_EXEC_AGENT_TOKEN", raising=False)
    # Fail-fast: shrink the client budget so a broken (unbounded) exec-agent would not hang
    # the test for the full 1800 s ceiling. The invariant (client > exec ceiling) still holds.
    monkeypatch.setattr(maletin, "_EXEC_AGENT_MAX_TIMEOUT", 5)
    monkeypatch.setattr(maletin, "_HTTP_TIMEOUT_MARGIN", 3)

    module = _load_exec_agent()
    module._MAX_TIMEOUT_S = 1  # the exec-agent kills the runaway child after ~1 s
    server = ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("FORENSIA_TOOLKIT_UNIX_URL", f"http://127.0.0.1:{port}")
    try:
        result = dispatcher.execute(
            "tsk_icat",
            {"image_path": str(evidence_image), "inode": 5},
            case_id=case.id,
            os_profile="unix",
            evidence_context=EvidenceContext(
                evidence_id="ffffffff-ffff-4fff-8fff-ffffffffffff",
                baseline_sha256="5" * 64,
            ),
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    # The tool was killed at the ceiling (timed out), not run to completion — a real exit.
    assert result["exit_code"] == 124
    on_disk = cases.root / case.id / "artifacts" / result["run_id"] / "out" / "stdout.bin"
    # The process is DEAD: the artifact no longer grows.
    size1 = on_disk.stat().st_size
    time.sleep(1.0)
    assert on_disk.stat().st_size == size1 and size1 > 0
    # The RECORDED SHA-256 is over those final, frozen bytes — never a file mid-write.
    files = result["artifact_run"]["output_files"]
    stdout_bin = next(f for f in files if f["relpath"] == "stdout.bin")
    assert stdout_bin["sha256"] == hashlib.sha256(on_disk.read_bytes()).hexdigest()
    assert stdout_bin["size"] == size1
    assert on_disk.read_bytes().startswith(_HEAD)
