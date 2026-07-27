"""E2E: the full forensic chain over the PRODUCT PATH, with a real loopback exec-agent.

Exercises ``mmls → fls → icat → RegRipper`` through the real dispatcher (catalog →
build_argv → ArtifactRun → hash-chained audit → exec-agent) with NO Docker: the maletín's
``exec_agent.py`` is loaded in-process and served over loopback HTTP (as in
``test_binary_stdout_channel.py`` / ``test_ewf_routing.py``), and the forensic binaries are
replaced by tiny POSIX stand-ins on ``PATH`` that the exec-agent's shell-free subprocess
resolves and runs. Everything else is the real thing: the evidence goes through
``EvidenceManager``'s hash gate (the context the dispatcher re-validates), the exec-agent
serves the REAL build-manifest ``GET /versions`` the dispatcher consults BEFORE each start,
the binary_stdout channel writes ``icat``'s raw bytes to ``out/stdout.bin`` (hashed), and
RegRipper consumes that artifact as a derived input the dispatcher re-verifies (bytes AND
evidence provenance) before running.

Custody asserted end to end: every run leaves a literal ``tool_run_start`` + a
``tool_run_finish`` (exit + artifact SHA-256 + evidence_id + baseline hash + authoritative
``tool_version``) in ``audit.jsonl``; the log is hash-chained and ``verify()`` passes (and
detects tampering); ``derived_inputs`` links icat's artifact to RegRipper's run with the
re-verified hash and source evidence; and a tamper of ``stdout.bin`` between the two raises
and stops RegRipper (RULE 2).

POSIX only: launching a script stand-in shell-free needs POSIX exec semantics, so this runs
in CI (Linux). On Windows the operator drives the real chain over docker compose with a
``.E01`` — see ``docs/operacion/e2e-ewf-runbook.md``.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from _custody import context_for, register_evidence, wire_dispatcher_custody
from forensia.artifacts.store import ArtifactStore
from forensia.audit.log import AuditLog
from forensia.cases.manager import CaseManager
from forensia.toolkit import dispatcher

pytestmark = pytest.mark.skipif(
    os.name != "posix",
    reason=(
        "the loopback exec-agent E2E runs POSIX stand-in tools shell-free on PATH; it runs "
        "in CI (Linux). Windows shell-free exec cannot launch script stand-ins — the real "
        "chain is driven over docker compose with a .E01 (docs/operacion/e2e-ewf-runbook.md)."
    ),
)

REPO_ROOT = Path(__file__).resolve().parents[2]
EXEC_AGENT_PY = REPO_ROOT / "docker" / "docker" / "forensic-toolkit" / "exec_agent.py"

# The versions the REAL build manifest serves at GET /versions — the shapes
# gen_versions.py bakes at image build (dpkg owner package / git clone SHA).
_TSK_VERSION = "sleuthkit 4.12.1+dfsg-1ppa1 (dpkg)"
_RIP_VERSION = "RegRipper3.0 git:0123456789ab"
_VERSIONS = {"mmls": _TSK_VERSION, "fls": _TSK_VERSION, "icat": _TSK_VERSION,
             "rip.pl": _RIP_VERSION}
_EXPECTED_TOOL_VERSION = {
    "tsk_mmls": _TSK_VERSION,
    "tsk_fls": _TSK_VERSION,
    "tsk_icat": _TSK_VERSION,
    "regripper": _RIP_VERSION,
}

# The hive `icat` "extracts": deliberately not valid UTF-8 (a text round-trip would change
# it). Its identity downstream is its SHA-256.
_HIVE_BYTES = b"regf\x00\x01\xff\xfe\x00SOFTWARE-hive\x80\x81\x00bytes\xc3\x28"
_HIVE_SHA = hashlib.sha256(_HIVE_BYTES).hexdigest()

# Stand-in tool bodies (the shebang is prepended). They ignore the image and emit fixed,
# realistic output — enough for the real wrappers to parse and for the chain to advance.
_MMLS = (
    "import sys\n"
    "sys.stdout.write(\n"
    '    "DOS Partition Table\\n"\n'
    '    "Offset Sector: 0\\n"\n'
    '    "Units are in 512-byte sectors\\n"\n'
    '    "\\n"\n'
    '    "      Slot      Start        End          Length       Description\\n"\n'
    '    "000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)\\n"\n'
    '    "002:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07)\\n"\n'
    ")\n"
)
_FLS = (
    "import sys\n"
    'sys.stdout.write("r/r 13552:\\tWindows/System32/config/SOFTWARE\\n")\n'
    'sys.stdout.write("d/d 107:\\tWindows\\n")\n'
)
# icat streams the RAW hive to stdout; the exec-agent binary channel captures it to a file.
_ICAT = "import sys\nsys.stdout.buffer.write(%r)\n" % (_HIVE_BYTES,)
# RegRipper echoes which hive it parsed so the resolved artifact path is observable.
_RIP = (
    "import sys\n"
    "args = sys.argv[1:]\n"
    'hive = args[args.index("-r") + 1] if "-r" in args else ""\n'
    'sys.stdout.write("Launching plugin\\n")\n'
    'sys.stdout.write("ComputerName = Agentopsy-PC\\n")\n'
    'sys.stdout.write("hive=" + hive + "\\n")\n'
)


def _write_tool(bindir: Path, name: str, body: str) -> None:
    path = bindir / name
    path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    path.chmod(0o755)


def _load_exec_agent():
    spec = importlib.util.spec_from_file_location("forensia_exec_agent_e2e", EXEC_AGENT_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture
def bindir(tmp_path) -> Path:
    d = tmp_path / "toolbin"
    d.mkdir()
    _write_tool(d, "mmls", _MMLS)
    _write_tool(d, "fls", _FLS)
    _write_tool(d, "icat", _ICAT)
    _write_tool(d, "rip.pl", _RIP)
    return d


@pytest.fixture
def cases(tmp_path) -> CaseManager:
    return CaseManager(root=tmp_path / "cases")


@pytest.fixture
def store(cases) -> ArtifactStore:
    return ArtifactStore(cases)


@pytest.fixture
def anchored(cases, tmp_path):
    """Real case + evidence through EvidenceManager's hash gate → verified context."""
    case = cases.create(name="op", examiner="alice", os_profile="windows")
    handle = register_evidence(cases, case.id, tmp_path, payload=b"\x00" * 4096)
    return {"case": case, "handle": handle, "ctx": context_for(handle)}


@pytest.fixture
def chain(monkeypatch, bindir, cases, store, tmp_path):
    """Wire the product path: tmp-backed storage, maletín venue, and a real loopback
    exec-agent whose subprocess resolves the stand-in tools from PATH and whose
    GET /versions serves a REAL build manifest (no faked version transport)."""
    wire_dispatcher_custody(monkeypatch, dispatcher, cases, store, fake_version=None)
    # Force the maletín venue (RULE 1 product path), never the api-PATH local runner —
    # even though the stand-ins are on PATH for the exec-agent's own subprocess.
    monkeypatch.setattr(dispatcher, "resolve", lambda _binary: None)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.delenv("FORENSIA_EXEC_AGENT_TOKEN", raising=False)  # read at import → no auth

    # The build manifest the exec-agent serves — set BEFORE loading (read at import).
    manifest = tmp_path / "versions.json"
    manifest.write_text(
        json.dumps({"schema": 1, "stage": "windows", "versions": _VERSIONS}),
        encoding="utf-8",
    )
    monkeypatch.setenv("FORENSIA_VERSIONS_MANIFEST", str(manifest))

    module = _load_exec_agent()
    server = ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # All catalog tools here live in (or route to) toolkit-windows for os_profile="windows".
    monkeypatch.setenv("FORENSIA_TOOLKIT_WINDOWS_URL", f"http://127.0.0.1:{port}")
    try:
        yield
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _run(tool_id: str, params: dict, case_id: str, ctx) -> dict:
    return dispatcher.execute(
        tool_id, params, case_id=case_id, os_profile="windows", evidence_context=ctx
    )


def _entries(cases: CaseManager, case_id: str) -> list[dict]:
    return AuditLog(cases.root / case_id / "audit.jsonl").entries()


def _one(entries: list[dict], action: str, run_id: str) -> dict:
    hits = [e for e in entries if e.get("action") == action and e.get("run_id") == run_id]
    assert len(hits) == 1, f"expected exactly one {action} for {run_id}, got {len(hits)}"
    return hits[0]


# --------------------------------------------------------------------------- #
# 1) the whole chain, end to end, with custody at every hop
# --------------------------------------------------------------------------- #
def test_full_chain_product_path_custody(chain, cases, store, anchored) -> None:
    case, handle, ctx = anchored["case"], anchored["handle"], anchored["ctx"]
    # The image is the REGISTERED evidence copy — exactly what the path policy confines to.
    image = str(handle.original_path)

    mmls = _run("tsk_mmls", {"image_path": image}, case.id, ctx)
    assert mmls["exit_code"] == 0
    assert mmls["parsed"]["count"] >= 1  # the real mmls wrapper parsed a partition

    fls = _run("tsk_fls", {"image_path": image}, case.id, ctx)
    assert fls["exit_code"] == 0
    assert fls["parsed"]["entries_count"] >= 1  # a hive entry with inode 13552

    icat = _run("tsk_icat", {"image_path": image, "inode": 13552}, case.id, ctx)
    assert icat["exit_code"] == 0
    # (1) the binary result REMITS TO THE ARTIFACT, never content_length:0
    ref = icat["parsed"]["artifact"]
    assert "content_length" not in icat["parsed"]
    assert ref["relpath"] == "stdout.bin"
    assert ref["sha256"] == _HIVE_SHA
    assert ref["size"] == len(_HIVE_BYTES)
    # and the hashed artifact on disk is byte-exact (the raw bytes were never decoded)
    on_disk = cases.root / case.id / "artifacts" / icat["run_id"] / "out" / "stdout.bin"
    assert on_disk.read_bytes() == _HIVE_BYTES

    # (2) the consumer takes icat's artifact ref as its hive_path input — no path invented
    regripper = _run(
        "regripper",
        {"hive_path": ref, "plugin": "compname"},
        case.id,
        ctx,
    )
    assert regripper["exit_code"] == 0

    entries = _entries(cases, case.id)

    # every run left a LITERAL start (argv + params) and a finish (exit + artifact hashes)
    for res, tool_id in (
        (mmls, "tsk_mmls"), (fls, "tsk_fls"), (icat, "tsk_icat"), (regripper, "regripper")
    ):
        start = _one(entries, "tool_run_start", res["run_id"])
        finish = _one(entries, "tool_run_finish", res["run_id"])
        assert isinstance(start["argv"], list) and start["argv"]
        assert "params" in start
        assert finish["status"] == "finished"
        assert finish["exit_code"] == 0
        assert finish["stdout_sha256"]  # the captured stream was hashed (INVARIANT 4)
        # B5: the verified evidence context reaches BOTH start and finish (INVARIANT 4),
        # with identical id + baseline hash on the paired entries — and the authoritative
        # tool_version resolved from the maletín's REAL build manifest before the start.
        assert start["evidence_id"] == finish["evidence_id"] == handle.evidence_id
        assert start["baseline_sha256"] == finish["baseline_sha256"] == handle.sha256
        assert (
            start["tool_version"]
            == finish["tool_version"]
            == _EXPECTED_TOOL_VERSION[tool_id]
        )
        # the run manifest persists the same provenance + version (Bloqueante D)
        run = store.get_run(case.id, res["run_id"])
        assert run.evidence_id == handle.evidence_id
        assert run.evidence_baseline_sha256 == handle.sha256
        assert run.tool_version == _EXPECTED_TOOL_VERSION[tool_id]
    # icat's finish records the hashed out/stdout.bin as an output file
    assert _one(entries, "tool_run_finish", icat["run_id"])["output_files_count"] >= 1

    # the audit is HASH-CHAINED and its integrity verification passes (tamper-evident)
    assert AuditLog(cases.root / case.id / "audit.jsonl").verify() is True

    # the derivation LINK connects icat's artifact to RegRipper's run…
    rr_start = _one(entries, "tool_run_start", regripper["run_id"])
    links = rr_start["derived_inputs"]
    assert len(links) == 1
    assert links[0]["param"] == "hive_path"
    assert links[0]["source_run_id"] == icat["run_id"]
    assert links[0]["source_evidence_id"] == handle.evidence_id  # same-evidence provenance
    assert links[0]["relpath"] == "stdout.bin"
    # …and the hash RegRipper re-verified == the one icat's result advertised == sha(hive)
    assert links[0]["sha256"] == ref["sha256"] == _HIVE_SHA
    # RegRipper ran against the RESOLVED artifact path, not the raw {run_id, relpath} ref
    resolved = str(on_disk.resolve())
    assert resolved in rr_start["argv"]
    assert links[0]["resolved_path"] == resolved


# --------------------------------------------------------------------------- #
# 2) a tamper of the derived artifact between icat and RegRipper is fatal (RULE 2)
# --------------------------------------------------------------------------- #
def test_tamper_between_icat_and_regripper_blocks_run(chain, cases, store, anchored) -> None:
    case, handle, ctx = anchored["case"], anchored["handle"], anchored["ctx"]
    image = str(handle.original_path)

    icat = _run("tsk_icat", {"image_path": image, "inode": 13552}, case.id, ctx)
    on_disk = cases.root / case.id / "artifacts" / icat["run_id"] / "out" / "stdout.bin"
    # Custody break: the bytes change after icat's run recorded their SHA-256.
    on_disk.write_bytes(_HIVE_BYTES + b"TAMPERED")

    starts_before = sum(
        1 for e in _entries(cases, case.id) if e.get("action") == "tool_run_start"
    )
    with pytest.raises(dispatcher.ToolExecutionError, match="custodia|SHA-256|match"):
        _run(
            "regripper",
            {"hive_path": icat["parsed"]["artifact"], "plugin": "compname"},
            case.id,
            ctx,
        )
    starts_after = sum(
        1 for e in _entries(cases, case.id) if e.get("action") == "tool_run_start"
    )
    # RegRipper never started: resolution fails before start_run (no phantom run).
    assert starts_after == starts_before
    # and the audit chain is still intact.
    assert AuditLog(cases.root / case.id / "audit.jsonl").verify() is True


# --------------------------------------------------------------------------- #
# 3) the audit is genuinely tamper-evident (flip a field → verify() fails)
# --------------------------------------------------------------------------- #
def test_audit_chain_is_tamper_evident(chain, cases, anchored) -> None:
    case, handle, ctx = anchored["case"], anchored["handle"], anchored["ctx"]
    _run("tsk_mmls", {"image_path": str(handle.original_path)}, case.id, ctx)

    audit_path = cases.root / case.id / "audit.jsonl"
    assert AuditLog(audit_path).verify() is True

    lines = audit_path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    entry["tool_id"] = "tampered"  # any change to a chained entry must be detected
    lines[0] = json.dumps(entry, sort_keys=True)
    audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert AuditLog(audit_path).verify() is False
