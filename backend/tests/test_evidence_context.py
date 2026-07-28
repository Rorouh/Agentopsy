"""P0.5-3 — verified evidence context on EVERY anchored tool run (INVARIANT 4).

Contract pinned here:

  * TYPE: ``EvidenceContext`` is immutable, requires a non-empty ``evidence_id`` and a
    real 64-hex SHA-256, and is built from an ``EvidenceHandle`` (``from_handle``).
  * B — EVERY anchored run (also pure DERIVED_INPUT tools: tsk_mactime, plaso_psort,
    jq-over-ref) requires the context; missing → fail loud BEFORE the runner, the
    ArtifactRun and ``tool_run_start``.
  * C — the dispatcher VALIDATES the context against ``EvidenceManager`` (the single
    owner of evidence): a nonexistent evidence_id, another case's evidence, a
    syntactically-valid-but-wrong hash, or an evidence-B path under evidence-A's
    context all fail before start/runner. Production rejects a forged context — not
    just ``matches_handle`` being available.
  * Both start AND finish carry the same ``evidence_id`` + ``baseline_sha256`` (and
    ``tool_version``) on every closure path.

Evidence is registered for REAL through EvidenceManager's hash gate; only the maletín
transport (runner + version lookup) is faked (see ``_custody``).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from _custody import FAKE_TOOL_VERSION, context_for, register_evidence, wire_dispatcher_custody
from forensia.artifacts.store import ArtifactStore
from forensia.audit.log import AuditLog
from forensia.cases.manager import CaseManager
from forensia.evidence_context import EvidenceContext
from forensia.toolkit import dispatcher

_VALID_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
_VALID_SHA = "a" * 64


# --------------------------------------------------------------------------- #
# 1) the EvidenceContext type
# --------------------------------------------------------------------------- #
def test_valid_context_carries_id_and_hash() -> None:
    ctx = EvidenceContext(evidence_id=_VALID_ID, baseline_sha256=_VALID_SHA)
    assert ctx.evidence_id == _VALID_ID
    assert ctx.baseline_sha256 == _VALID_SHA
    assert ctx.audit_fields() == {
        "evidence_id": _VALID_ID,
        "baseline_sha256": _VALID_SHA,
    }


@pytest.mark.parametrize("bad_id", ["", "   ", None, 123])
def test_empty_or_nonstring_evidence_id_is_rejected(bad_id) -> None:
    with pytest.raises(ValueError, match="evidence_id"):
        EvidenceContext(evidence_id=bad_id, baseline_sha256=_VALID_SHA)


@pytest.mark.parametrize("bad_hash", ["", None, "0", "g" * 64, "a" * 63, "a" * 65])
def test_invalid_baseline_hash_is_rejected(bad_hash) -> None:
    with pytest.raises(ValueError, match="baseline_sha256"):
        EvidenceContext(evidence_id=_VALID_ID, baseline_sha256=bad_hash)


def test_from_handle_copies_id_and_hash() -> None:
    handle = SimpleNamespace(evidence_id=_VALID_ID, sha256=_VALID_SHA)
    ctx = EvidenceContext.from_handle(handle)
    assert ctx.evidence_id == _VALID_ID
    assert ctx.baseline_sha256 == _VALID_SHA
    assert ctx.matches_handle(handle)


def test_matches_handle_detects_a_hash_that_does_not_correspond() -> None:
    handle = SimpleNamespace(evidence_id=_VALID_ID, sha256=_VALID_SHA)
    wrong_hash = EvidenceContext(evidence_id=_VALID_ID, baseline_sha256="b" * 64)
    assert not wrong_hash.matches_handle(handle)
    wrong_id = EvidenceContext(
        evidence_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", baseline_sha256=_VALID_SHA
    )
    assert not wrong_id.matches_handle(handle)


# --------------------------------------------------------------------------- #
# dispatcher fixtures — real hash-gate evidence, maletín venue, faked transport
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
    handle = register_evidence(cases, case.id, tmp_path)
    return {"case": case, "handle": handle, "ctx": context_for(handle)}


@pytest.fixture
def wired(monkeypatch, cases, store):
    wire_dispatcher_custody(monkeypatch, dispatcher, cases, store)
    monkeypatch.setattr(dispatcher, "resolve", lambda _b: None)

    def ok_exec(service, argv, *, timeout=None, stdout_path=None, ewf_image=None):
        del service, argv, timeout, ewf_image
        if stdout_path is not None:
            Path(stdout_path).write_bytes(b"payload")
            return 0, "", ""
        return 0, "DOS Partition Table\n", ""

    monkeypatch.setattr(dispatcher.maletin, "run_argv_in_maletin", ok_exec)
    return dispatcher


def _tool_audit(cases: CaseManager, case_id: str) -> list[dict]:
    return [
        e
        for e in AuditLog(cases.root / case_id / "audit.jsonl").entries()
        if str(e.get("action", "")).startswith("tool_run_")
    ]


def _make_derived_ref(wired, anchored) -> dict:
    """Produce a real derived artifact (icat under the anchored context)."""
    icat = wired.execute(
        "tsk_icat",
        {"image_path": str(anchored["handle"].original_path), "inode": 5},
        case_id=anchored["case"].id,
        os_profile="unix",
        evidence_context=anchored["ctx"],
    )
    return icat["parsed"]["artifact"]


# --------------------------------------------------------------------------- #
# 2) B — EVERY anchored run requires the context (also derived-only tools)
# --------------------------------------------------------------------------- #
def test_evidence_input_tool_without_context_fails_before_start(
    wired, cases, anchored, store
):
    case, handle = anchored["case"], anchored["handle"]
    with pytest.raises(wired.ToolExecutionError, match="contexto de evidencia"):
        wired.execute(
            "tsk_mmls",
            {"image_path": str(handle.original_path)},
            case_id=case.id,
            os_profile="unix",
        )
    assert _tool_audit(cases, case.id) == []
    assert store.list_runs(case.id) == []


@pytest.mark.parametrize(
    ("tool_id", "params_builder"),
    [
        ("tsk_mactime", lambda ref: {"bodyfile_path": ref}),
        ("plaso_psort", lambda ref: {"plaso_path": ref}),
        ("jq", lambda ref: {"filter": ".", "input_path": ref}),
    ],
)
def test_derived_only_tools_without_context_fail_before_start(
    wired, cases, anchored, store, tool_id, params_builder
):
    """Bloqueante B: same-contract for tools that consume ONLY derived inputs."""
    case = anchored["case"]
    ref = _make_derived_ref(wired, anchored)
    runs_before = len(store.list_runs(case.id))
    starts_before = len(
        [e for e in _tool_audit(cases, case.id) if e["action"] == "tool_run_start"]
    )
    with pytest.raises(wired.ToolExecutionError, match="contexto de evidencia"):
        wired.execute(
            tool_id,
            params_builder(ref),
            case_id=case.id,
            os_profile="unix",
        )
    assert len(store.list_runs(case.id)) == runs_before
    starts_after = len(
        [e for e in _tool_audit(cases, case.id) if e["action"] == "tool_run_start"]
    )
    assert starts_after == starts_before


@pytest.mark.parametrize(
    ("tool_id", "params_builder"),
    [
        ("tsk_mactime", lambda ref: {"bodyfile_path": ref}),
        ("plaso_psort", lambda ref: {"plaso_path": ref}),
        ("jq", lambda ref: {"filter": ".", "input_path": ref}),
    ],
)
def test_derived_only_tools_with_context_record_it_in_start_and_finish(
    wired, cases, anchored, tool_id, params_builder
):
    case, ctx = anchored["case"], anchored["ctx"]
    ref = _make_derived_ref(wired, anchored)
    result = wired.execute(
        tool_id,
        params_builder(ref),
        case_id=case.id,
        os_profile="unix",
        evidence_context=ctx,
    )
    entries = [
        e for e in _tool_audit(cases, case.id) if e.get("run_id") == result["run_id"]
    ]
    assert [e["action"] for e in entries] == ["tool_run_start", "tool_run_finish"]
    for entry in entries:
        assert entry["evidence_id"] == ctx.evidence_id
        assert entry["baseline_sha256"] == ctx.baseline_sha256
        assert entry["tool_version"] == FAKE_TOOL_VERSION


def test_context_without_case_id_fails_loud(wired, anchored):
    with pytest.raises(wired.ToolExecutionError, match="case_id"):
        wired.execute(
            "jq",
            {"filter": ".", "input_path": "/tmp/x.json"},
            evidence_context=anchored["ctx"],
        )


def test_invalid_evidence_context_type_is_rejected(wired, cases, anchored, store):
    case, handle = anchored["case"], anchored["handle"]
    with pytest.raises(wired.ToolExecutionError, match="EvidenceContext"):
        wired.execute(
            "tsk_mmls",
            {"image_path": str(handle.original_path)},
            case_id=case.id,
            os_profile="unix",
            evidence_context="not-a-context",
        )
    assert _tool_audit(cases, case.id) == []
    assert store.list_runs(case.id) == []


# --------------------------------------------------------------------------- #
# 3) C — the dispatcher validates the context against EvidenceManager
# --------------------------------------------------------------------------- #
def test_nonexistent_evidence_id_fails_before_start(wired, cases, anchored, store):
    case, handle = anchored["case"], anchored["handle"]
    forged = EvidenceContext(
        evidence_id="99999999-9999-4999-8999-999999999999",
        baseline_sha256=handle.sha256,
    )
    with pytest.raises(wired.ToolExecutionError, match="no corresponde a una"):
        wired.execute(
            "tsk_mmls",
            {"image_path": str(handle.original_path)},
            case_id=case.id,
            os_profile="unix",
            evidence_context=forged,
        )
    assert _tool_audit(cases, case.id) == []
    assert store.list_runs(case.id) == []


def test_other_cases_evidence_context_fails_before_start(
    wired, cases, anchored, store, tmp_path
):
    """A context built from ANOTHER case's evidence cannot anchor runs in this case."""
    case = anchored["case"]
    other = cases.create(name="other", examiner="bob", os_profile="unix")
    other_handle = register_evidence(
        cases, other.id, tmp_path, payload=b"other-disk", name="other.raw"
    )
    with pytest.raises(wired.ToolExecutionError, match="no corresponde a una"):
        wired.execute(
            "tsk_mmls",
            {"image_path": str(anchored["handle"].original_path)},
            case_id=case.id,
            os_profile="unix",
            evidence_context=context_for(other_handle),
        )
    assert _tool_audit(cases, case.id) == []
    assert store.list_runs(case.id) == []


def test_forged_hash_fails_before_start(wired, cases, anchored, store):
    """Syntactically valid SHA-256 that does not match the authoritative handle."""
    case, handle = anchored["case"], anchored["handle"]
    forged = EvidenceContext(
        evidence_id=handle.evidence_id, baseline_sha256="9" * 64
    )
    with pytest.raises(wired.ToolExecutionError, match="falsificado|no coincide"):
        wired.execute(
            "tsk_mmls",
            {"image_path": str(handle.original_path)},
            case_id=case.id,
            os_profile="unix",
            evidence_context=forged,
        )
    assert _tool_audit(cases, case.id) == []
    assert store.list_runs(case.id) == []


def test_context_a_with_path_of_evidence_b_same_case_fails(
    wired, cases, anchored, store, tmp_path
):
    """Same-case is not same-evidence: A's context cannot cover a B path."""
    case, ctx_a = anchored["case"], anchored["ctx"]
    handle_b = register_evidence(
        cases, case.id, tmp_path, payload=b"disk-B", name="b.raw"
    )
    with pytest.raises(wired.ToolExecutionError, match="outside authorized root"):
        wired.execute(
            "tsk_mmls",
            {"image_path": str(handle_b.original_path)},
            case_id=case.id,
            os_profile="unix",
            evidence_context=ctx_a,
        )
    assert _tool_audit(cases, case.id) == []
    assert store.list_runs(case.id) == []


# --------------------------------------------------------------------------- #
# 4) start/finish carry the same context on every closure path
# --------------------------------------------------------------------------- #
def _assert_pair_carries(entries: list[dict], ctx: EvidenceContext) -> None:
    start = next(e for e in entries if e["action"] == "tool_run_start")
    finish = next(e for e in entries if e["action"] == "tool_run_finish")
    for entry in (start, finish):
        assert entry["evidence_id"] == ctx.evidence_id
        assert entry["baseline_sha256"] == ctx.baseline_sha256
        assert entry["tool_version"] == FAKE_TOOL_VERSION


def test_context_recorded_on_success(wired, cases, anchored):
    case, ctx, handle = anchored["case"], anchored["ctx"], anchored["handle"]
    wired.execute(
        "tsk_mmls",
        {"image_path": str(handle.original_path)},
        case_id=case.id,
        os_profile="unix",
        evidence_context=ctx,
    )
    _assert_pair_carries(_tool_audit(cases, case.id), ctx)


def test_context_recorded_on_nonzero_exit(wired, monkeypatch, cases, anchored):
    case, ctx, handle = anchored["case"], anchored["ctx"], anchored["handle"]

    def nonzero(service, argv, *, timeout=None, **_kw):
        del service, argv, timeout
        return 23, "", "invalid partition table"

    monkeypatch.setattr(wired.maletin, "run_argv_in_maletin", nonzero)
    wired.execute(
        "tsk_mmls",
        {"image_path": str(handle.original_path)},
        case_id=case.id,
        os_profile="unix",
        evidence_context=ctx,
    )
    entries = _tool_audit(cases, case.id)
    finish = next(e for e in entries if e["action"] == "tool_run_finish")
    assert finish["status"] == "finished" and finish["exit_code"] == 23
    _assert_pair_carries(entries, ctx)


def test_context_recorded_on_runner_error_close(wired, monkeypatch, cases, anchored):
    case, ctx, handle = anchored["case"], anchored["ctx"], anchored["handle"]

    def boom(service, argv, *, timeout=None, **_kw):
        del service, argv, timeout
        raise wired.maletin.MaletinExecError("exec-agent: connection refused")

    monkeypatch.setattr(wired.maletin, "run_argv_in_maletin", boom)
    with pytest.raises(wired.ToolExecutionError, match="connection refused"):
        wired.execute(
            "tsk_mmls",
            {"image_path": str(handle.original_path)},
            case_id=case.id,
            os_profile="unix",
            evidence_context=ctx,
        )
    entries = _tool_audit(cases, case.id)
    finish = next(e for e in entries if e["action"] == "tool_run_finish")
    assert finish["status"] == "error" and finish["exit_code"] is None
    _assert_pair_carries(entries, ctx)


# --------------------------------------------------------------------------- #
# 5) the surfaces build the context FROM the handle and thread it unchanged
# --------------------------------------------------------------------------- #
def test_agent_threads_context_built_from_handle(monkeypatch, tmp_path):
    from forensia.agent.agent import ForensicAgent
    from _agent_pkg import make_package
    from forensia.models.base import (
        FinalAnswer,
        ModelBackend,
        ModelCapabilities,
        ToolCall,
    )

    captured: dict = {}

    def fake_execute(
        tool_id, params, *, case_id=None, os_profile=None, timeout=None, evidence_context=None
    ):
        captured["ctx"] = evidence_context
        return {
            "tool_id": tool_id,
            "argv": ["fls"],
            "exit_code": 0,
            "stdout_sample": "",
            "stderr_sample": "",
            "parsed": None,
            "run_id": "r",
        }

    monkeypatch.setattr("forensia.toolkit.dispatcher.execute", fake_execute)

    class _OneCall(ModelBackend):
        name = "fake"

        def __init__(self) -> None:
            self.n = 0

        def capabilities(self):
            return ModelCapabilities(
                supports_native_tools=False, json_mode=True, max_context=0, is_local=True
            )

        def next_action(self, state, tools):
            self.n += 1
            if self.n == 1:
                return ToolCall(
                    tool_id="tsk_fls",
                    params={},
                    call_id="x",
                    assistant_message={"role": "assistant", "content": "{}"},
                )
            return FinalAnswer(text="done")

    class _FakeEvidence:
        def get(self, case_id, evidence_id):
            return SimpleNamespace(
                evidence_id=evidence_id,
                original_path=Path("/cases/x/evidence/e/original.raw"),
                detected_os="unix",
                detected_kind="disk",
                sha256="c" * 64,
            )

    pkg = make_package("unix")
    agent = ForensicAgent(pkg, _OneCall(), _FakeEvidence())
    agent.run("lista la raíz", case_id="c", evidence_id="e-abc")

    ctx = captured["ctx"]
    assert isinstance(ctx, EvidenceContext)
    assert ctx.evidence_id == "e-abc"
    assert ctx.baseline_sha256 == "c" * 64


async def test_mcp_threads_context_built_from_handle(monkeypatch, tmp_path):
    from forensia.mcp.toolkit import _dispatch_forensic

    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create("op", "alice", os_profile="windows")
    handle = register_evidence(cases, case.id, tmp_path, payload=b"x")

    from forensia.evidence import EvidenceManager

    monkeypatch.setattr("forensia.evidence.evidence_manager", EvidenceManager(cases))

    captured: dict = {}

    def fake_execute(
        name, params, *, case_id=None, os_profile=None, timeout=None, evidence_context=None
    ):
        captured["ctx"] = evidence_context
        return {
            "tool_id": name,
            "exit_code": 0,
            "run_id": None,
            "artifact_run": {},
            "stdout_sample": "",
            "stderr_sample": "",
            "parsed": None,
        }

    monkeypatch.setattr("forensia.toolkit.dispatcher.execute", fake_execute)

    session = SimpleNamespace(
        case_id=case.id,
        evidence_id=handle.evidence_id,
        agent_package=SimpleNamespace(
            id="p",
            os_profile="windows",
            policy=SimpleNamespace(allowed_tools=("file_info",), redaction_patterns=()),
        ),
    )
    await _dispatch_forensic("file_info", {}, session)

    ctx = captured["ctx"]
    assert isinstance(ctx, EvidenceContext)
    assert ctx.evidence_id == handle.evidence_id
    assert ctx.baseline_sha256 == handle.sha256
