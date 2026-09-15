"""P0.5-3 E2E — the verified evidence context survives the whole PRODUCT path.

Drives the REAL HTTP surface: ``TestClient → POST /api/agent/query → thin router →
real ForensicAgent → deterministic scripted executor (the ONLY fake: the LLM text) →
real ExecutorBackend parse → real dispatcher → REAL loopback exec-agent (the maletín's
``exec_agent.py`` served in-process, with a REAL build-manifest ``/versions``) →
``tsk_icat`` → full ``ArtifactRef`` → RegRipper``. Nothing else is substituted:
ForensicAgent, ExecutorBackend, dispatcher, EvidenceManager, ArtifactStore, AuditLog and
the agent package (the real ``agentes/agentopsy-windows``) are the production objects.

Allowed stand-ins (and only these):
  * the LLM: ``OllamaExecutor.run`` is scripted to answer the response contract
    deterministically (no model, no network) — it decides ONLY tool_id + typed params;
  * the forensic binaries: tiny POSIX scripts named ``icat`` / ``rip.pl`` on PATH;
  * the maletín network: the exec-agent runs on loopback instead of the compose network.

Asserts the P0.5-3 contract end to end:
  1. evidence registered via EvidenceManager carries evidence_id + baseline hash;
  2. icat's full ArtifactRef reaches RegRipper without reconstruction (the scripted
     executor hands back the exact ref it read in the tool-result block);
  3. RegRipper runs against the RESOLVED confined path, never the raw dict;
  4. the derived file is re-hashed before RegRipper runs, and its provenance
     (source evidence) is verified against the consumer's context (Bloqueante D);
  5. tool_run_start AND tool_run_finish of EVERY run carry evidence_id + baseline hash
     AND the authoritative tool_version resolved from the maletín's build manifest
     (GET /versions) BEFORE the start;
  6. AuditLog.verify() is True (hash-chained across register → agent → tool runs);
  7. a tamper of the derived artifact blocks RegRipper before its start;
  8. a context inconsistent with the handle is detectable (matches_handle).

POSIX only (launches script stand-ins shell-free): runs in CI (Linux). On Windows the
real chain is driven over docker compose with a ``.E01``.
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
from fastapi.testclient import TestClient

from agentopsy.artifacts.store import ArtifactStore
from agentopsy.audit.log import AuditLog
from agentopsy.cases.manager import CaseManager
from agentopsy.evidence import EvidenceManager
from agentopsy.evidence_context import EvidenceContext
from agentopsy.executors import ExecutorAvailability, OllamaExecutor
from agentopsy.executors.base import ExecutorResult
from agentopsy.server import create_app
from agentopsy.toolkit import dispatcher

pytestmark = pytest.mark.skipif(
    os.name != "posix",
    reason=(
        "drives POSIX script stand-ins shell-free over a loopback exec-agent; runs in CI "
        "(Linux). On Windows the real chain runs over docker compose with a .E01."
    ),
)

PORT = 51007
REPO_ROOT = Path(__file__).resolve().parents[2]
EXEC_AGENT_PY = REPO_ROOT / "docker" / "docker" / "forensic-toolkit" / "exec_agent.py"

# The versions the (real) build manifest serves through the loopback exec-agent —
# the shapes gen_versions.py produces for a dpkg-owned tool and for the RegRipper clone.
_ICAT_VERSION = "sleuthkit 4.12.1+dfsg-1ppa1 (dpkg)"
_RIP_VERSION = "RegRipper3.0 git:0123456789ab"

# The hive `icat` "extracts": deliberately not valid UTF-8 (a text round-trip would change
# it). Its identity downstream is its SHA-256.
_HIVE_BYTES = b"regf\x00\x01\xff\xfe\x00SOFTWARE-hive\x80\x81\x00bytes\xc3\x28"
_HIVE_SHA = hashlib.sha256(_HIVE_BYTES).hexdigest()

_ICAT = "import sys\nsys.stdout.buffer.write(%r)\n" % (_HIVE_BYTES,)
_RIP = (
    "import sys\n"
    "args = sys.argv[1:]\n"
    'hive = args[args.index("-r") + 1] if "-r" in args else ""\n'
    'sys.stdout.write("ComputerName = Agentopsy-PC\\n")\n'
    'sys.stdout.write("hive=" + hive + "\\n")\n'
)


def _write_tool(bindir: Path, name: str, body: str) -> None:
    path = bindir / name
    path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    path.chmod(0o755)


def _load_exec_agent():
    spec = importlib.util.spec_from_file_location("agentopsy_exec_agent_ctx_e2e", EXEC_AGENT_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# The scripted executor — the ONLY fake in the chain (it plays the LLM's text)
# --------------------------------------------------------------------------- #
_RESULT_HEADER = "## RESULTADO DE TOOL"


def _tool_result_payloads(prompt: str) -> list[dict]:
    """Parse every rendered tool-result block out of the executor prompt — the scripted
    executor reads the SAME degraded-path rendering a real model would (models/base.py
    ``_render_prompt``), so the ArtifactRef it hands back is the exact ref the product
    surface showed it, not a reconstruction."""
    payloads: list[dict] = []
    decoder = json.JSONDecoder()
    pos = 0
    while True:
        head = prompt.find(_RESULT_HEADER, pos)
        if head == -1:
            return payloads
        start = prompt.find("{", head)
        if start == -1:
            return payloads
        payload, consumed = decoder.raw_decode(prompt[start:])
        payloads.append(payload)
        pos = start + consumed


def _scripted_reply(prompt: str) -> str:
    """tsk_icat → regripper(icat's exact ArtifactRef) → final. Deterministic: the step
    is derived from how many tool results the conversation already carries."""
    payloads = _tool_result_payloads(prompt)
    if not payloads:
        return json.dumps(
            {"action": "tool_call", "tool_id": "tsk_icat", "params": {"inode": 13552}}
        )
    if len(payloads) == 1:
        ref = (payloads[0].get("parsed") or {}).get("artifact")
        assert isinstance(ref, dict) and ref.get("run_id"), (
            "icat's tool result did not carry the ArtifactRef the consumer needs"
        )
        return json.dumps(
            {
                "action": "tool_call",
                "tool_id": "regripper",
                "params": {"hive_path": ref, "plugin": "compname"},
            }
        )
    return json.dumps({"action": "final", "text": "cadena completada"})


def _scripted_run(self, prompt: str, context: dict | None = None) -> ExecutorResult:
    text = _scripted_reply(prompt)
    return ExecutorResult(
        executor="ollama",
        text=text,
        argv=("ollama", "run", "scripted"),
        exit_code=0,
        duration_ms=1,
        raw=text,
    )


# --------------------------------------------------------------------------- #
# wiring: real app + real dispatcher + real loopback exec-agent + real manifest
# --------------------------------------------------------------------------- #
@pytest.fixture
def wired(monkeypatch, tmp_path):
    cases = CaseManager(root=tmp_path / "cases")
    store = ArtifactStore(cases)
    evidence = EvidenceManager(cases)

    # POSIX stand-ins for the forensic binaries, resolvable on the exec-agent's PATH.
    bindir = tmp_path / "toolbin"
    bindir.mkdir()
    _write_tool(bindir, "icat", _ICAT)
    _write_tool(bindir, "rip.pl", _RIP)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ.get("PATH", ""))

    # The REAL build manifest the exec-agent serves at GET /versions — same shape
    # gen_versions.py bakes into /opt/agentopsy/versions.json at image build.
    manifest = tmp_path / "versions.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": 1,
                "stage": "windows",
                "versions": {"icat": _ICAT_VERSION, "rip.pl": _RIP_VERSION},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("AGENTOPSY_VERSIONS_MANIFEST", str(manifest))
    monkeypatch.delenv("AGENTOPSY_EXEC_AGENT_TOKEN", raising=False)

    # Point the product singletons at the tmp-rooted storage. NOTHING else is faked:
    # the dispatcher keeps its real execute/gates/version lookup (maletín venue forced
    # by resolving no binary on the api PATH — exactly the compose posture).
    import agentopsy.routers.agent as agent_router

    monkeypatch.setattr(agent_router, "case_manager", cases)
    monkeypatch.setattr(agent_router, "evidence_manager", evidence)
    monkeypatch.setattr(dispatcher, "case_manager", cases)
    monkeypatch.setattr(dispatcher, "artifact_store", store)
    monkeypatch.setattr(dispatcher, "evidence_manager", evidence)
    monkeypatch.setattr(dispatcher, "resolve", lambda _binary: None)

    # The ONLY fake: the LLM's text (SECURITY INVARIANT 5 — it still only emits a
    # closed-enum tool_id + typed params through the real parser).
    monkeypatch.setattr(
        OllamaExecutor, "is_available", lambda self: ExecutorAvailability(available=True)
    )
    monkeypatch.setattr(OllamaExecutor, "run", _scripted_run)

    # Real loopback exec-agent (env read at module load → set FIRST, above).
    module = _load_exec_agent()
    server = ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("AGENTOPSY_TOOLKIT_WINDOWS_URL", f"http://127.0.0.1:{port}")

    # Operator-anchored case + evidence through the REAL hash gate.
    case = cases.create(name="op", examiner="alice", os_profile="windows")
    src = tmp_path / "disk.raw"
    src.write_bytes(b"\x00" * 4096)
    handle = evidence.register(case.id, str(src))

    app = create_app(PORT)
    client = TestClient(app, base_url=f"http://127.0.0.1:{PORT}")
    auth = {"X-Agentopsy-Token": app.state.token}
    try:
        yield {
            "cases": cases,
            "store": store,
            "evidence": evidence,
            "case": case,
            "handle": handle,
            "client": client,
            "auth": auth,
        }
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _entries(cases: CaseManager, case_id: str) -> list[dict]:
    return AuditLog(cases.root / case_id / "audit.jsonl").entries()


def _one(entries: list[dict], action: str, run_id: str) -> dict:
    hits = [e for e in entries if e.get("action") == action and e.get("run_id") == run_id]
    assert len(hits) == 1, f"expected exactly one {action} for {run_id}, got {len(hits)}"
    return hits[0]


# --------------------------------------------------------------------------- #
# 1) the whole chain through POST /api/agent/query, custody verified at every hop
# --------------------------------------------------------------------------- #
def test_router_chain_threads_verified_context_end_to_end(wired) -> None:
    cases, case, handle = wired["cases"], wired["case"], wired["handle"]

    # (1) evidence came through EvidenceManager with a real id + baseline hash.
    assert handle.evidence_id
    assert handle.sha256 == hashlib.sha256(b"\x00" * 4096).hexdigest()

    r = wired["client"].post(
        "/api/agent/query",
        json={
            "case_id": case.id,
            "prompt": "extrae el hive SOFTWARE y parséalo",
            "executor": "ollama",
        },
        headers=wired["auth"],
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["reply"] == "cadena completada"
    assert body["os_profile"] == "windows"
    assert body["executor"]["id"] == "ollama"

    # The scripted chain ran icat then regripper then answered — through the router.
    tool_runs = [c for c in body["tool_calls"] if c.get("run_id")]
    assert [c["tool_id"] for c in tool_runs] == ["tsk_icat", "regripper"]
    icat_run = next(c for c in tool_runs if c["tool_id"] == "tsk_icat")
    rr_run = next(c for c in tool_runs if c["tool_id"] == "regripper")
    assert icat_run["exit_code"] == 0
    assert rr_run["exit_code"] == 0

    entries = _entries(cases, case.id)

    # (5) EVERY run's start AND finish carry the SAME evidence_id + baseline hash AND the
    # authoritative tool_version resolved from the maletín's REAL build manifest
    # (GET /versions on the loopback exec-agent) BEFORE the start (INVARIANT 4).
    expected_version = {"tsk_icat": _ICAT_VERSION, "regripper": _RIP_VERSION}
    for run in (icat_run, rr_run):
        start = _one(entries, "tool_run_start", run["run_id"])
        finish = _one(entries, "tool_run_finish", run["run_id"])
        for entry in (start, finish):
            assert entry["evidence_id"] == handle.evidence_id
            assert entry["baseline_sha256"] == handle.sha256
            assert entry["tool_version"] == expected_version[run["tool_id"]]

    # (2)+(3)+(4) the derived handoff: RegRipper consumed icat's artifact by reference
    # (the scripted executor handed back the EXACT ref rendered in its prompt), the
    # dispatcher resolved it to the confined on-disk path, re-hashed it, and verified
    # the producer's provenance against the consumer's context (Bloqueante D).
    rr_start = _one(entries, "tool_run_start", rr_run["run_id"])
    links = rr_start["derived_inputs"]
    assert len(links) == 1
    assert links[0]["param"] == "hive_path"
    assert links[0]["source_run_id"] == icat_run["run_id"]
    assert links[0]["source_evidence_id"] == handle.evidence_id
    assert links[0]["relpath"] == "stdout.bin"
    assert links[0]["sha256"] == _HIVE_SHA  # re-verified before running
    on_disk = (
        cases.root / case.id / "artifacts" / icat_run["run_id"] / "out" / "stdout.bin"
    ).resolve()
    assert links[0]["resolved_path"] == str(on_disk)
    assert str(on_disk) in rr_start["argv"]  # resolved path, not the raw {run_id, relpath}
    assert on_disk.read_bytes() == _HIVE_BYTES

    # The producer's manifest itself records the provenance (same-evidence, not
    # merely same-case) + the version the audit rows carry.
    producer = wired["store"].get_run(case.id, icat_run["run_id"])
    assert producer.evidence_id == handle.evidence_id
    assert producer.evidence_baseline_sha256 == handle.sha256
    assert producer.tool_version == _ICAT_VERSION

    # (6) the whole chain (evidence_register → agent_run_start → tool runs) is
    # hash-chained and intact.
    audit = AuditLog(cases.root / case.id / "audit.jsonl")
    assert any(e.get("event") == "agent_run_start" for e in entries)
    assert audit.verify() is True


# --------------------------------------------------------------------------- #
# 7) a tamper of the derived artifact blocks RegRipper before its start
# --------------------------------------------------------------------------- #
def test_tamper_between_icat_and_regripper_blocks_with_real_context(wired) -> None:
    cases, case, handle = wired["cases"], wired["case"], wired["handle"]
    ctx = EvidenceContext.from_handle(handle)
    assert ctx.matches_handle(handle)

    icat = dispatcher.execute(
        "tsk_icat",
        {"image_path": str(handle.original_path), "inode": 13552},
        case_id=case.id,
        os_profile="windows",
        evidence_context=ctx,
    )
    ref = icat["parsed"]["artifact"]
    on_disk = cases.root / case.id / "artifacts" / icat["run_id"] / "out" / "stdout.bin"
    on_disk.write_bytes(_HIVE_BYTES + b"TAMPERED")  # custody break after the hash was set

    starts_before = sum(
        1 for e in _entries(cases, case.id) if e.get("action") == "tool_run_start"
    )
    with pytest.raises(dispatcher.ToolExecutionError, match="custodia|SHA-256|match"):
        dispatcher.execute(
            "regripper",
            {"hive_path": ref, "plugin": "compname"},
            case_id=case.id,
            os_profile="windows",
            evidence_context=ctx,
        )
    starts_after = sum(
        1 for e in _entries(cases, case.id) if e.get("action") == "tool_run_start"
    )
    assert starts_after == starts_before  # RegRipper never started
    assert AuditLog(cases.root / case.id / "audit.jsonl").verify() is True


# --------------------------------------------------------------------------- #
# 8) a context inconsistent with the handle is detectable
# --------------------------------------------------------------------------- #
def test_context_inconsistent_with_handle_is_detectable(wired) -> None:
    handle = wired["handle"]
    good = EvidenceContext.from_handle(handle)
    assert good.matches_handle(handle)
    forged = EvidenceContext(evidence_id=handle.evidence_id, baseline_sha256="9" * 64)
    assert not forged.matches_handle(handle)
