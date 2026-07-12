"""Binary-safe stdout channel for tools like TSK ``icat`` (bloqueante #2 del audit).

`icat` streams a file's RAW BYTES to stdout (hives, EVTX, `$MFT`, executables). The old
channel decoded stdout as text (`errors="replace"`), so every non-UTF-8 byte became
`U+FFFD` — the derived artifact was silently corrupted, invalidating the relevo
`icat → artefacto → parser`. The fix carries those bytes straight to a hashed artifact
file (`out/stdout.bin`), never decoding them.

These tests pin the property that matters forensically: an EXACT byte round-trip with a
STABLE SHA-256, using a payload that is deliberately invalid UTF-8 (the old text path
would have mangled it). No docker / no maletín needed — the maletín runner is faked and
the exec-agent is exercised in-process over loopback HTTP.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from forensia.artifacts.store import ArtifactStore
from forensia.cases.manager import CaseManager
from forensia.toolkit import dispatcher
from forensia.toolkit.tool import run_argv

REPO_ROOT = Path(__file__).resolve().parents[2]
EXEC_AGENT_PY = REPO_ROOT / "docker" / "docker" / "forensic-toolkit" / "exec_agent.py"

# Deliberately NOT valid UTF-8: lone 0x80/0x81, 0xFF/0xFE, embedded NUL. The old
# `decode("utf-8", errors="replace")` path would have replaced these, changing the bytes.
_BINARY_PAYLOAD = b"MZ\x90\x00\x03\xff\xfe\x00regf\x89PNG\r\n\x1a\n\x80\x81\x82\x00hive-bytes\xc3\x28"
_EXPECTED_SHA = hashlib.sha256(_BINARY_PAYLOAD).hexdigest()

# A tiny stdout-emitting child that writes raw bytes (no newline translation): copies the
# bytes of argv[1] to its stdout buffer. Cross-platform (uses the running interpreter).
_EMIT_STDOUT = "import sys; sys.stdout.buffer.write(open(sys.argv[1], 'rb').read())"


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture
def cases(tmp_path) -> CaseManager:
    return CaseManager(root=tmp_path / "cases")


@pytest.fixture
def store(cases) -> ArtifactStore:
    return ArtifactStore(cases)


@pytest.fixture
def case(cases):
    created = cases.create(name="op", examiner="alice", os_profile="unix")
    evidence = cases.root / created.id / "evidence" / "original.raw"
    evidence.write_bytes(b"disk")
    return created


@pytest.fixture
def wired_dispatcher(monkeypatch, cases, store):
    monkeypatch.setattr(dispatcher, "case_manager", cases)
    monkeypatch.setattr(dispatcher, "artifact_store", store)
    return dispatcher


# --------------------------------------------------------------------------- #
# 1) the local runner (api-PATH venue): raw stdout to file, no decode
# --------------------------------------------------------------------------- #
def test_run_argv_binary_stdout_exact_roundtrip(tmp_path) -> None:
    src = tmp_path / "src.bin"
    src.write_bytes(_BINARY_PAYLOAD)
    dst = tmp_path / "out.bin"

    completed = run_argv(
        [sys.executable, "-c", _EMIT_STDOUT, str(src)], stdout_path=str(dst)
    )

    assert completed.returncode == 0
    # The bytes are on disk, not carried as a (lossy) text field.
    assert completed.stdout == ""
    assert dst.read_bytes() == _BINARY_PAYLOAD
    assert hashlib.sha256(dst.read_bytes()).hexdigest() == _EXPECTED_SHA


# --------------------------------------------------------------------------- #
# 2) end-to-end through the dispatcher (maletín venue faked): the artifact is
#    the exact bytes, hashed by the artifact store (FORENSIC INVARIANT 4)
# --------------------------------------------------------------------------- #
def test_dispatcher_binary_stdout_lands_exact_hashed_artifact(
    wired_dispatcher, monkeypatch, cases, case, store
) -> None:
    # Force the maletín venue and fake the exec-agent: it writes the raw bytes to the
    # stdout_path the dispatcher hands it and returns an empty (text) stdout.
    monkeypatch.setattr(wired_dispatcher, "resolve", lambda _binary: None)

    seen: dict[str, str] = {}

    def fake_maletin(service, argv, *, timeout=None, stdout_path=None):
        assert stdout_path is not None, "binary_stdout tool must receive a stdout_path"
        seen["service"] = service
        seen["stdout_path"] = stdout_path
        Path(stdout_path).write_bytes(_BINARY_PAYLOAD)
        return 0, "", ""

    monkeypatch.setattr(wired_dispatcher.maletin, "run_argv_in_maletin", fake_maletin)

    result = wired_dispatcher.execute(
        "tsk_icat",
        {
            "image_path": str(cases.root / case.id / "evidence" / "original.raw"),
            "inode": 5,
        },
        case_id=case.id,
        os_profile="unix",
    )

    # Routed to the unix maletín with a stdout.bin target inside the run's out/ dir.
    assert seen["service"] == "toolkit-unix"
    assert seen["stdout_path"].replace("\\", "/").endswith(
        f"artifacts/{result['run_id']}/out/stdout.bin"
    )

    # The artifact store hashed the derived file: exact bytes, stable SHA-256, real size.
    output_files = result["artifact_run"]["output_files"]
    stdout_bin = [f for f in output_files if f["relpath"] == "stdout.bin"]
    assert len(stdout_bin) == 1
    assert stdout_bin[0]["sha256"] == _EXPECTED_SHA
    assert stdout_bin[0]["size"] == len(_BINARY_PAYLOAD)

    # And the bytes on disk are byte-for-byte the original.
    run = store.get_run(case.id, result["run_id"])
    on_disk = cases.root / case.id / "artifacts" / run.run_id / "out" / "stdout.bin"
    assert on_disk.read_bytes() == _BINARY_PAYLOAD


# --------------------------------------------------------------------------- #
# 3) RULE 2 / INVARIANT 4: a binary_stdout tool refuses to run un-anchored
# --------------------------------------------------------------------------- #
def test_dispatcher_binary_stdout_requires_case(wired_dispatcher, monkeypatch) -> None:
    monkeypatch.setattr(wired_dispatcher, "resolve", lambda _binary: None)
    with pytest.raises(wired_dispatcher.ToolExecutionError, match="binario|case_id|artefacto"):
        wired_dispatcher.execute("tsk_icat", {"image_path": "/x", "inode": 5})


# --------------------------------------------------------------------------- #
# 4) the exec-agent itself (infra, cross-lane): real loopback HTTP round-trip
# --------------------------------------------------------------------------- #
def _load_exec_agent():
    spec = importlib.util.spec_from_file_location("forensia_exec_agent_test", EXEC_AGENT_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_exec_agent_stdout_path_writes_exact_bytes(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("FORENSIA_EXEC_AGENT_TOKEN", raising=False)
    module = _load_exec_agent()

    src = tmp_path / "src.bin"
    src.write_bytes(_BINARY_PAYLOAD)
    dst = tmp_path / "stdout.bin"

    server = ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        payload = json.dumps(
            {
                "argv": [sys.executable, "-c", _EMIT_STDOUT, str(src)],
                "timeout": 60,
                "stdout_path": str(dst),
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/exec",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 — loopback test
            body = json.loads(resp.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert body["exit"] == 0
    # The response carries hash+size, not the (lossy) text of the bytes.
    assert "stdout" not in body
    assert body["stdout_sha256"] == _EXPECTED_SHA
    assert body["stdout_size"] == len(_BINARY_PAYLOAD)
    # The file the child wrote is byte-for-byte the original.
    assert dst.read_bytes() == _BINARY_PAYLOAD
