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

from _custody import context_for, register_evidence, wire_dispatcher_custody
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
def anchored(cases, tmp_path):
    case = cases.create(name="op", examiner="alice", os_profile="unix")
    handle = register_evidence(cases, case.id, tmp_path, payload=b"disk")
    return {"case": case, "handle": handle, "ctx": context_for(handle)}


@pytest.fixture
def wired_dispatcher(monkeypatch, cases, store):
    wire_dispatcher_custody(monkeypatch, dispatcher, cases, store)
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
    wired_dispatcher, monkeypatch, cases, anchored, store
) -> None:
    case, handle, ctx = anchored["case"], anchored["handle"], anchored["ctx"]
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
            "image_path": str(handle.original_path),
            "inode": 5,
        },
        case_id=case.id,
        os_profile="unix",
        evidence_context=ctx,
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
    # The run manifest carries the evidence provenance (Bloqueante D).
    assert run.evidence_id == ctx.evidence_id
    assert run.evidence_baseline_sha256 == ctx.baseline_sha256


# --------------------------------------------------------------------------- #
# 3) RULE 2 / INVARIANT 4: a binary_stdout tool refuses to run un-anchored
# --------------------------------------------------------------------------- #
def test_dispatcher_binary_stdout_requires_case(wired_dispatcher, monkeypatch) -> None:
    monkeypatch.setattr(wired_dispatcher, "resolve", lambda _binary: None)
    with pytest.raises(wired_dispatcher.ToolExecutionError, match="binario|case_id|artefacto"):
        wired_dispatcher.execute("tsk_icat", {"image_path": "/x", "inode": 5})


# --------------------------------------------------------------------------- #
# 3.bis) DUAL-MODE tool: TSK `fls -m` bodyfile → hashed out/ artifact (the
#        fls→mactime chain regression). Its stdout IS the bodyfile mactime
#        consumes as {run_id, relpath}; without materialising it to out/ the
#        chain had no resolvable input (KeyError: produced no output file).
# --------------------------------------------------------------------------- #
_BODYFILE = "0|/etc/passwd|389|r/rrw-|0|0|4096|1706188200|1706188200|1706188200|1706188200\n"


def test_fls_body_mode_materialises_referenceable_bodyfile(
    wired_dispatcher, monkeypatch, cases, anchored, store
) -> None:
    """`tsk_fls` with body_format=True streams its bodyfile to a hashed out/stdout.bin
    that mactime can resolve as {run_id, relpath} — the fix for the broken chain."""
    case, handle, ctx = anchored["case"], anchored["handle"], anchored["ctx"]
    monkeypatch.setattr(wired_dispatcher, "resolve", lambda _binary: None)

    seen: dict[str, str] = {}

    def fake_maletin(service, argv, *, timeout=None, stdout_path=None):
        # The conditional stdout-artifact capture MUST have triggered for body mode.
        assert stdout_path is not None, "fls -m must receive a stdout_path (Bug 1)"
        seen["stdout_path"] = stdout_path
        Path(stdout_path).write_text(_BODYFILE, encoding="utf-8")
        return 0, "", ""

    monkeypatch.setattr(wired_dispatcher.maletin, "run_argv_in_maletin", fake_maletin)

    result = wired_dispatcher.execute(
        "tsk_fls",
        {"image_path": str(handle.original_path), "body_format": True, "recursive": True},
        case_id=case.id,
        os_profile="unix",
        evidence_context=ctx,
    )

    # The bodyfile landed as a hashed output file (not lost to an unreferenceable stdout).
    output_files = result["artifact_run"]["output_files"]
    bodyfile = [f for f in output_files if f["relpath"] == "stdout.bin"]
    assert len(bodyfile) == 1
    expected_sha = hashlib.sha256(_BODYFILE.encode("utf-8")).hexdigest()
    assert bodyfile[0]["sha256"] == expected_sha

    # The result surfaces the artifact REFERENCE the agent hands to mactime.
    ref = result["parsed"]["artifact"]
    assert ref["relpath"] == "stdout.bin" and ref["run_id"] == result["run_id"]

    # And that reference RESOLVES against the store (custody re-hash) — the chain works.
    path, sha256, _ = store.resolve_output_file(case.id, result["run_id"], "stdout.bin")
    assert sha256 == expected_sha
    assert path.read_text(encoding="utf-8") == _BODYFILE


def test_fls_listing_mode_stays_inline_no_stdout_artifact(
    wired_dispatcher, monkeypatch, cases, anchored
) -> None:
    """Without body_format, fls lists files inline (parsed entries) and does NOT divert
    stdout to an artifact — the dual mode is preserved, only `-m` is redirected."""
    case, handle, ctx = anchored["case"], anchored["handle"], anchored["ctx"]
    monkeypatch.setattr(wired_dispatcher, "resolve", lambda _binary: None)

    def fake_maletin(service, argv, *, timeout=None, stdout_path=None):
        assert stdout_path is None, "listing-mode fls must NOT capture stdout to a file"
        return 0, "r/r 389:\t/etc/passwd\nd/d 12:\t/etc\n", ""

    monkeypatch.setattr(wired_dispatcher.maletin, "run_argv_in_maletin", fake_maletin)

    result = wired_dispatcher.execute(
        "tsk_fls",
        {"image_path": str(handle.original_path), "recursive": True},
        case_id=case.id,
        os_profile="unix",
        evidence_context=ctx,
    )

    # Inline entries were parsed; no stdout.bin artifact was produced.
    assert result["parsed"]["format"] == "list"
    assert result["parsed"]["entries_count"] == 2
    assert all(
        f["relpath"] != "stdout.bin" for f in result["artifact_run"]["output_files"]
    )


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
    # P0.5-4: the binary channel also reports the argv it actually launched.
    assert body["executed_argv"] == [sys.executable, "-c", _EMIT_STDOUT, str(src)]
    # The file the child wrote is byte-for-byte the original.
    assert dst.read_bytes() == _BINARY_PAYLOAD


# A deterministic 8 MiB stream (all 256 byte values, way beyond any pipe buffer): the
# child regenerates it, the test recomputes its SHA-256 — nothing is trusted from the
# response that the test cannot derive independently.
_LARGE_BLOCK = bytes(range(256)) * 4096  # 1 MiB
_LARGE_BLOCKS = 8
_EMIT_LARGE = (
    "import sys\n"
    "block = bytes(range(256)) * 4096\n"
    f"for _ in range({_LARGE_BLOCKS}):\n"
    "    sys.stdout.buffer.write(block)\n"
)


def test_exec_agent_streams_large_binary_stdout_exactly(monkeypatch, tmp_path) -> None:
    """P0.5-5: the binary channel is fd-direct (the child's stdout IS the file) and the
    hash is chunked — an 8 MiB payload round-trips byte-exact with a stable SHA-256,
    never buffered in memory as text."""
    monkeypatch.delenv("FORENSIA_EXEC_AGENT_TOKEN", raising=False)
    module = _load_exec_agent()
    dst = tmp_path / "stdout.bin"

    server = ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        payload = json.dumps(
            {
                "argv": [sys.executable, "-c", _EMIT_LARGE],
                "timeout": 120,
                "stdout_path": str(dst),
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/exec",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 — loopback test
            body = json.loads(resp.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    expected_size = len(_LARGE_BLOCK) * _LARGE_BLOCKS
    digest = hashlib.sha256()
    for _ in range(_LARGE_BLOCKS):
        digest.update(_LARGE_BLOCK)

    assert body["exit"] == 0
    assert body["stdout_size"] == expected_size
    assert body["stdout_sha256"] == digest.hexdigest()
    assert dst.stat().st_size == expected_size
    # Spot-check the tail (a truncated pipe would corrupt the end first).
    with dst.open("rb") as fh:
        fh.seek(-len(_LARGE_BLOCK), 2)
        assert fh.read() == _LARGE_BLOCK
