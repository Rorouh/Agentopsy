"""P0.5-3 E2E — the verified evidence context survives the whole product path.

Drives ``ForensicAgent`` (a deterministic FAKE model backend — no LLM, no network) over
the REAL dispatcher and a REAL loopback exec-agent (the maletín's ``exec_agent.py`` served
in-process; forensic binaries replaced by tiny POSIX stand-ins on ``PATH``). The evidence is
registered through ``EvidenceManager`` (real hash gate → ``evidence_id`` + baseline SHA-256),
and the model walks ``tsk_icat → RegRipper``, handing icat's ``ArtifactRef`` straight to the
consumer.

Asserts the P0.5-3 contract end to end:
  1. evidence registered via EvidenceManager carries evidence_id + baseline hash;
  2. icat's full ArtifactRef reaches RegRipper without reconstruction;
  3. RegRipper runs against the RESOLVED confined path, never the raw dict;
  4. the derived file is re-hashed before RegRipper runs;
  5. tool_run_start AND tool_run_finish of EVERY run carry the evidence_id + baseline hash
     (``tool_version`` is a documented cross-lane BLOCKER — see docs/operacion/proximos-pasos.md);
  6. AuditLog.verify() is True (hash-chained across register → agent → tool runs);
  7. a tamper of the derived artifact blocks RegRipper before its start;
  8. a context inconsistent with the handle is detectable (matches_handle).

POSIX only (launches script stand-ins shell-free): runs in CI (Linux). On Windows the real
chain is driven over docker compose with a ``.E01`` (docs/operacion/e2e-ewf-runbook.md).
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

from forensia.agent.agent import ForensicAgent
from forensia.agent.package import (
    AgentPackage,
    AgentPackageModel,
    AgentPackagePolicy,
    AgentPackagePrompts,
)
from forensia.artifacts.store import ArtifactStore
from forensia.audit.log import AuditLog
from forensia.cases.manager import CaseManager
from forensia.evidence import EvidenceManager
from forensia.evidence_context import EvidenceContext
from forensia.models.base import FinalAnswer, ModelBackend, ModelCapabilities, ToolCall
from forensia.toolkit import dispatcher

pytestmark = pytest.mark.skipif(
    os.name != "posix",
    reason=(
        "drives POSIX script stand-ins shell-free over a loopback exec-agent; runs in CI "
        "(Linux). On Windows the real chain runs over docker compose with a .E01 "
        "(docs/operacion/e2e-ewf-runbook.md)."
    ),
)

REPO_ROOT = Path(__file__).resolve().parents[2]
EXEC_AGENT_PY = REPO_ROOT / "docker" / "docker" / "forensic-toolkit" / "exec_agent.py"

# The hive `icat` "extracts": deliberately not valid UTF-8 (a text round-trip would change
# it). Its identity downstream is its SHA-256.
_HIVE_BYTES = b"regf\x00\x01\xff\xfe\x00SOFTWARE-hive\x80\x81\x00bytes\xc3\x28"
_HIVE_SHA = hashlib.sha256(_HIVE_BYTES).hexdigest()

_ICAT = "import sys\nsys.stdout.buffer.write(%r)\n" % (_HIVE_BYTES,)
_RIP = (
    "import sys\n"
    "args = sys.argv[1:]\n"
    'hive = args[args.index("-r") + 1] if "-r" in args else ""\n'
    'sys.stdout.write("ComputerName = FORENSIA-PC\\n")\n'
    'sys.stdout.write("hive=" + hive + "\\n")\n'
)


def _write_tool(bindir: Path, name: str, body: str) -> None:
    path = bindir / name
    path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    path.chmod(0o755)


def _load_exec_agent():
    spec = importlib.util.spec_from_file_location("forensia_exec_agent_ctx_e2e", EXEC_AGENT_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _last_artifact_ref(messages: list[dict]) -> dict:
    """Pull icat's ArtifactRef out of the most recent tool-result message — proving the
    consumer takes the EXACT ref the producer emitted, without reconstructing a path."""
    for msg in reversed(messages):
        if msg.get("role") != "tool":
            continue
        payload = json.loads(msg["content"])
        parsed = payload.get("parsed") or {}
        if isinstance(parsed, dict) and parsed.get("artifact"):
            return parsed["artifact"]
    raise AssertionError("no icat artifact ref found in the conversation")


class _ScriptedChain(ModelBackend):
    """Deterministic backend: tsk_icat → regripper(icat's ref) → final."""

    name = "scripted"

    def __init__(self) -> None:
        self.step = 0

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            supports_native_tools=False, json_mode=True, max_context=0, is_local=True
        )

    def next_action(self, state, tools):
        self.step += 1
        if self.step == 1:
            return ToolCall(
                tool_id="tsk_icat",
                params={"inode": 13552},
                call_id="c1",
                assistant_message={"role": "assistant", "content": "{}"},
            )
        if self.step == 2:
            ref = _last_artifact_ref(state["messages"])
            return ToolCall(
                tool_id="regripper",
                params={"hive_path": ref, "plugin": "compname"},
                call_id="c2",
                assistant_message={"role": "assistant", "content": "{}"},
            )
        return FinalAnswer(text="cadena completada")


def _make_package() -> AgentPackage:
    return AgentPackage(
        id="e2e-win",
        name="E2E Windows",
        version="0.1.0",
        os_profile="windows",
        authors=("tester",),
        path=Path("/nonexistent"),
        model=AgentPackageModel(name="scripted", temperature=0.0, max_iterations=6),
        prompts=AgentPackagePrompts(system="SYS", identity="ID", playbook="PB"),
        policy=AgentPackagePolicy(
            allowed_tools=("tsk_icat", "regripper"), redaction_patterns=()
        ),
    )


@pytest.fixture
def wired(monkeypatch, tmp_path):
    """Real EvidenceManager + real dispatcher + real loopback exec-agent (POSIX stand-ins)."""
    cases = CaseManager(root=tmp_path / "cases")
    store = ArtifactStore(cases)
    evidence = EvidenceManager(cases)

    bindir = tmp_path / "toolbin"
    bindir.mkdir()
    _write_tool(bindir, "icat", _ICAT)
    _write_tool(bindir, "rip.pl", _RIP)

    monkeypatch.setattr(dispatcher, "case_manager", cases)
    monkeypatch.setattr(dispatcher, "artifact_store", store)
    monkeypatch.setattr(dispatcher, "resolve", lambda _binary: None)  # force maletín venue
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.delenv("FORENSIA_EXEC_AGENT_TOKEN", raising=False)

    module = _load_exec_agent()
    server = ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("FORENSIA_TOOLKIT_WINDOWS_URL", f"http://127.0.0.1:{port}")

    case = cases.create(name="op", examiner="alice", os_profile="windows")
    src = tmp_path / "disk.raw"
    src.write_bytes(b"\x00" * 4096)
    handle = evidence.register(case.id, str(src))
    try:
        yield {"cases": cases, "store": store, "evidence": evidence, "case": case, "handle": handle}
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
# 1) the whole chain via the agent, with the verified context at every hop
# --------------------------------------------------------------------------- #
def test_agent_chain_threads_verified_context_end_to_end(wired) -> None:
    cases, case, handle = wired["cases"], wired["case"], wired["handle"]

    # (1) evidence came through EvidenceManager with a real id + baseline hash.
    assert handle.evidence_id
    assert handle.sha256 == hashlib.sha256(b"\x00" * 4096).hexdigest()

    audit = AuditLog(cases.root / case.id / "audit.jsonl")
    agent = ForensicAgent(
        _make_package(), _ScriptedChain(), wired["evidence"], audit=audit
    )
    result = agent.run(
        "extrae el hive y parséalo",
        case_id=case.id,
        evidence_id=handle.evidence_id,
    )
    # The scripted chain ran icat then regripper then answered.
    tool_runs = [c for c in result["tool_calls"] if c.get("run_id")]
    assert [c["tool_id"] for c in tool_runs] == ["tsk_icat", "regripper"]
    icat_run = next(c for c in tool_runs if c["tool_id"] == "tsk_icat")
    rr_run = next(c for c in tool_runs if c["tool_id"] == "regripper")
    assert icat_run["exit_code"] == 0
    assert rr_run["exit_code"] == 0

    entries = _entries(cases, case.id)

    # (5) EVERY run's start AND finish carry the SAME evidence_id + baseline hash — the
    # verified context threaded from EvidenceManager (INVARIANT 4). (tool_version is a
    # documented cross-lane blocker — not asserted here; see proximos-pasos.md §B5.)
    for run_id in (icat_run["run_id"], rr_run["run_id"]):
        start = _one(entries, "tool_run_start", run_id)
        finish = _one(entries, "tool_run_finish", run_id)
        for entry in (start, finish):
            assert entry["evidence_id"] == handle.evidence_id
            assert entry["baseline_sha256"] == handle.sha256

    # (2)+(3)+(4) the derived handoff: RegRipper consumed icat's artifact by reference,
    # the dispatcher resolved it to the confined on-disk path and re-hashed it.
    rr_start = _one(entries, "tool_run_start", rr_run["run_id"])
    links = rr_start["derived_inputs"]
    assert len(links) == 1
    assert links[0]["param"] == "hive_path"
    assert links[0]["source_run_id"] == icat_run["run_id"]
    assert links[0]["relpath"] == "stdout.bin"
    assert links[0]["sha256"] == _HIVE_SHA  # re-verified before running
    on_disk = (
        cases.root / case.id / "artifacts" / icat_run["run_id"] / "out" / "stdout.bin"
    ).resolve()
    assert links[0]["resolved_path"] == str(on_disk)
    assert str(on_disk) in rr_start["argv"]  # resolved path, not the raw {run_id, relpath}
    assert on_disk.read_bytes() == _HIVE_BYTES

    # (6) the whole chain (evidence_register → agent_run_start → tool runs) is hash-chained.
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
