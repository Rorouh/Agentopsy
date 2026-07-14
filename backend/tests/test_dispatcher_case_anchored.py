"""Dispatcher behaviour when anchored to a case: audit log + artifact manifest.

Anchored runs follow the P0.5-3 custody contract: a verified ``EvidenceContext``
(validated against ``EvidenceManager``) and an authoritative maletín ``tool_version``
are BOTH resolved before ``tool_run_start``; the product venue is the maletín
(exec-agent), faked here at the transport level only. An anchored run on the api-PATH
venue is refused (no build manifest → no authoritative version — see
``test_tool_version.py``), so every runner-boundary test here drives the maletín path.
"""

from __future__ import annotations

import hashlib
import json
import subprocess

import pytest

from _custody import FAKE_TOOL_VERSION, context_for, register_evidence, wire_dispatcher_custody
from forensia.artifacts.store import ArtifactStore
from forensia.audit.log import AuditLog
from forensia.cases.manager import CaseManager
from forensia.toolkit import dispatcher


@pytest.fixture
def cases(tmp_path) -> CaseManager:
    return CaseManager(root=tmp_path / "cases")


@pytest.fixture
def store(cases) -> ArtifactStore:
    return ArtifactStore(cases)


@pytest.fixture
def wired_dispatcher(monkeypatch, cases, store):
    """Tmp-rooted storage + evidence, maletín venue, faked version transport."""
    wire_dispatcher_custody(monkeypatch, dispatcher, cases, store)
    monkeypatch.setattr(dispatcher, "resolve", lambda _binary: None)
    return dispatcher


@pytest.fixture
def anchored(cases, tmp_path):
    """A real case + real registered evidence (hash gate) + its verified context."""
    case = cases.create(name="op", examiner="alice", os_profile="unix")
    handle = register_evidence(cases, case.id, tmp_path)
    return {"case": case, "handle": handle, "ctx": context_for(handle)}


def _tool_entries(cases: CaseManager, case_id: str) -> list[dict]:
    """Only the tool_run_* audit entries (evidence registration also appends)."""
    return [
        e
        for e in AuditLog(cases.root / case_id / "audit.jsonl").entries()
        if str(e.get("action", "")).startswith("tool_run_")
    ]


def _tool_runs(store: ArtifactStore, case_id: str) -> list:
    return store.list_runs(case_id)


# --------------------------------------------------------------------------- #
# case_id=None — a case-scoped input cannot run unanchored (P0.5-3)
# --------------------------------------------------------------------------- #
class TestUnanchoredRejection:
    def test_case_scoped_param_without_case_id_is_rejected(
        self, wired_dispatcher, tmp_path
    ):
        inp = tmp_path / "in.json"
        inp.write_text('{"name": "x"}')
        with pytest.raises(wired_dispatcher.ToolExecutionError, match="case_id"):
            wired_dispatcher.execute(
                "jq", {"filter": ".name", "input_path": str(inp)}
            )


# --------------------------------------------------------------------------- #
# Auditable runner boundary — start must be durable before invocation
# --------------------------------------------------------------------------- #
class TestAuditableRunnerBoundary:
    def test_start_append_failure_aborts_runner_and_closes_reserved_run(
        self, wired_dispatcher, monkeypatch, anchored, cases, store
    ):
        case, ctx, handle = anchored["case"], anchored["ctx"], anchored["handle"]
        calls = {"local": 0, "maletin": 0, "append": 0}

        def forbidden_local(argv, *, timeout=None):
            del argv, timeout
            calls["local"] += 1
            raise AssertionError("local runner must not be called")

        def forbidden_maletin(service, argv, *, timeout=None, **_kw):
            del service, argv, timeout
            calls["maletin"] += 1
            raise AssertionError("maletin runner must not be called")

        original_append = AuditLog.append

        def fail_first_tool_append(audit, event):
            calls["append"] += 1
            raise OSError("disk full while writing audit start")

        monkeypatch.setattr(wired_dispatcher, "run_argv", forbidden_local)
        monkeypatch.setattr(
            wired_dispatcher.maletin, "run_argv_in_maletin", forbidden_maletin
        )
        monkeypatch.setattr(AuditLog, "append", fail_first_tool_append)

        with pytest.raises(
            wired_dispatcher.ToolExecutionError,
            match="could not persist tool_run_start",
        ) as raised:
            wired_dispatcher.execute(
                "tsk_mmls",
                {"image_path": str(handle.original_path)},
                case_id=case.id,
                os_profile="unix",
                evidence_context=ctx,
            )
        monkeypatch.setattr(AuditLog, "append", original_append)

        assert "the tool was not executed" in str(raised.value)
        assert isinstance(raised.value.__cause__, OSError)
        assert "disk full while writing audit start" in str(raised.value.__cause__)
        assert calls == {"local": 0, "maletin": 0, "append": 1}
        runs = store.list_runs(case.id)
        assert len(runs) == 1
        run = runs[0]
        assert run.status == "error"
        assert run.finished_at is not None
        assert run.exit_code is None
        assert run.error_type == "OSError"
        assert "disk full while writing audit start" in run.error_message
        assert all(candidate.status != "running" for candidate in runs)
        assert _tool_entries(cases, case.id) == []

    def test_maletin_start_is_present_inside_runner_and_finish_follows(
        self, wired_dispatcher, monkeypatch, anchored, cases
    ):
        case, ctx, handle = anchored["case"], anchored["ctx"], anchored["handle"]
        audit_path = cases.root / case.id / "audit.jsonl"
        executed: dict[str, list[str]] = {}

        def fake_exec(service, argv, *, timeout=None, **_kw):
            del service, timeout
            executed["argv"] = list(argv)
            entries = [
                e for e in AuditLog(audit_path).entries()
                if str(e.get("action", "")).startswith("tool_run_")
            ]
            assert [entry["action"] for entry in entries] == ["tool_run_start"]
            start = entries[0]
            assert start["argv"] == argv
            assert start["case_id"] == case.id
            assert start["run_id"]
            assert start["tool_id"] == "tsk_mmls"
            assert start["params"]["image_path"] == str(handle.original_path)
            # Custody context + authoritative version reached the durable start.
            assert start["evidence_id"] == ctx.evidence_id
            assert start["baseline_sha256"] == ctx.baseline_sha256
            assert start["tool_version"] == FAKE_TOOL_VERSION
            return 0, "DOS Partition Table\n", ""

        monkeypatch.setattr(wired_dispatcher.maletin, "run_argv_in_maletin", fake_exec)
        result = wired_dispatcher.execute(
            "tsk_mmls",
            {"image_path": str(handle.original_path)},
            case_id=case.id,
            os_profile="unix",
            evidence_context=ctx,
        )

        entries = _tool_entries(cases, case.id)
        assert [entry["action"] for entry in entries] == [
            "tool_run_start",
            "tool_run_finish",
        ]
        assert entries[0]["argv"] == executed["argv"] == result["argv"]
        finish = entries[1]
        assert finish["evidence_id"] == ctx.evidence_id
        assert finish["baseline_sha256"] == ctx.baseline_sha256
        assert finish["tool_version"] == FAKE_TOOL_VERSION

    def test_maletin_transport_failure_closes_audit_and_artifact_without_exit_code(
        self, wired_dispatcher, monkeypatch, anchored, cases, store
    ):
        case, ctx, handle = anchored["case"], anchored["ctx"], anchored["handle"]
        calls: list[str] = []

        def failing_exec(service, argv, *, timeout=None, **_kw):
            del argv, timeout
            calls.append(service)
            raise wired_dispatcher.maletin.MaletinExecError(
                "exec-agent toolkit-unix: connection refused"
            )

        monkeypatch.setattr(
            wired_dispatcher.maletin, "run_argv_in_maletin", failing_exec
        )

        with pytest.raises(
            wired_dispatcher.ToolExecutionError,
            match="connection refused",
        ) as raised:
            wired_dispatcher.execute(
                "tsk_mmls",
                {"image_path": str(handle.original_path)},
                case_id=case.id,
                os_profile="unix",
                evidence_context=ctx,
            )

        assert isinstance(raised.value.__cause__, wired_dispatcher.maletin.MaletinExecError)
        entries = _tool_entries(cases, case.id)
        assert [entry["action"] for entry in entries] == [
            "tool_run_start",
            "tool_run_finish",
        ]
        finish = entries[1]
        assert finish["status"] == "error"
        assert finish["exit_code"] is None
        assert finish["error_type"] == "MaletinExecError"
        assert "connection refused" in finish["error_message"]
        # The error closure preserves the full forensic context (INVARIANT 4).
        assert finish["evidence_id"] == ctx.evidence_id
        assert finish["baseline_sha256"] == ctx.baseline_sha256
        assert finish["tool_version"] == FAKE_TOOL_VERSION
        assert AuditLog(cases.root / case.id / "audit.jsonl").verify() is True
        assert calls == ["toolkit-unix"]

        run = store.get_run(case.id, entries[0]["run_id"])
        assert run.status == "error"
        assert run.exit_code is None
        assert run.finished_at is not None
        assert run.error_type == "MaletinExecError"
        assert "connection refused" in run.error_message

    def test_runner_failure_keeps_primary_cause_when_finish_append_fails(
        self, wired_dispatcher, monkeypatch, anchored, cases, store
    ):
        case, ctx, handle = anchored["case"], anchored["ctx"], anchored["handle"]
        runner_calls = 0
        append_calls: list[str] = []
        runner_error = wired_dispatcher.maletin.MaletinExecError(
            "exec-agent transport disconnected"
        )
        original_append = AuditLog.append

        def failing_exec(service, argv, *, timeout=None, **_kw):
            nonlocal runner_calls
            del service, argv, timeout
            runner_calls += 1
            raise runner_error

        def fail_second_append(audit, event):
            append_calls.append(event["action"])
            if len(append_calls) == 2:
                raise OSError("audit disk unavailable for finish")
            return original_append(audit, event)

        monkeypatch.setattr(
            wired_dispatcher.maletin, "run_argv_in_maletin", failing_exec
        )
        monkeypatch.setattr(AuditLog, "append", fail_second_append)

        with pytest.raises(wired_dispatcher.ToolExecutionError) as raised:
            wired_dispatcher.execute(
                "tsk_mmls",
                {"image_path": str(handle.original_path)},
                case_id=case.id,
                os_profile="unix",
                evidence_context=ctx,
            )

        assert raised.value.__cause__ is runner_error
        assert "exec-agent transport disconnected" in str(raised.value)
        assert "could not persist tool_run_finish" in str(raised.value)
        assert "audit disk unavailable for finish" in str(raised.value)
        assert "was not retried" in str(raised.value)
        assert runner_calls == 1
        assert append_calls == ["tool_run_start", "tool_run_finish"]
        entries = _tool_entries(cases, case.id)
        assert [entry["action"] for entry in entries] == ["tool_run_start"]
        run = store.get_run(case.id, entries[0]["run_id"])
        assert run.status == "error"
        assert run.exit_code is None
        assert run.error_type == "MaletinExecError"

    def test_successful_run_is_not_reexecuted_when_finish_append_fails(
        self, wired_dispatcher, monkeypatch, anchored, cases, store
    ):
        case, ctx, handle = anchored["case"], anchored["ctx"], anchored["handle"]
        runner_calls = 0
        append_calls: list[str] = []
        finish_error = OSError("audit fsync failed for successful finish")
        original_append = AuditLog.append

        def successful_exec(service, argv, *, timeout=None, **_kw):
            nonlocal runner_calls
            del service, argv, timeout
            runner_calls += 1
            return 0, "ok", ""

        def fail_second_append(audit, event):
            append_calls.append(event["action"])
            if len(append_calls) == 2:
                raise finish_error
            return original_append(audit, event)

        monkeypatch.setattr(
            wired_dispatcher.maletin, "run_argv_in_maletin", successful_exec
        )
        monkeypatch.setattr(AuditLog, "append", fail_second_append)

        with pytest.raises(wired_dispatcher.ToolExecutionError) as raised:
            wired_dispatcher.execute(
                "tsk_mmls",
                {"image_path": str(handle.original_path)},
                case_id=case.id,
                os_profile="unix",
                evidence_context=ctx,
            )

        assert raised.value.__cause__ is finish_error
        assert "already executed" in str(raised.value)
        assert "ArtifactRun was finalized with exit_code 0" in str(raised.value)
        assert "could not persist tool_run_finish" in str(raised.value)
        assert "was not re-executed" in str(raised.value)
        assert runner_calls == 1
        assert append_calls == ["tool_run_start", "tool_run_finish"]
        entries = _tool_entries(cases, case.id)
        assert [entry["action"] for entry in entries] == ["tool_run_start"]
        run = store.get_run(case.id, entries[0]["run_id"])
        assert run.status == "finished"
        assert run.exit_code == 0

    def test_finalize_and_finish_append_failures_preserve_finalize_cause(
        self, wired_dispatcher, monkeypatch, anchored, cases
    ):
        case, ctx, handle = anchored["case"], anchored["ctx"], anchored["handle"]
        runner_calls = 0
        finalize_calls = 0
        append_calls: list[str] = []
        finalize_error = OSError("manifest replace failed")
        original_append = AuditLog.append

        def successful_exec(service, argv, *, timeout=None, **_kw):
            nonlocal runner_calls
            del service, argv, timeout
            runner_calls += 1
            return 0, "ok", ""

        def failing_finalize(*args, **kwargs):
            nonlocal finalize_calls
            del args, kwargs
            finalize_calls += 1
            raise finalize_error

        def fail_second_append(audit, event):
            append_calls.append(event["action"])
            if len(append_calls) == 2:
                raise OSError("audit append failed after finalize failure")
            return original_append(audit, event)

        monkeypatch.setattr(
            wired_dispatcher.maletin, "run_argv_in_maletin", successful_exec
        )
        monkeypatch.setattr(
            wired_dispatcher.artifact_store, "finalize_run", failing_finalize
        )
        monkeypatch.setattr(AuditLog, "append", fail_second_append)

        with pytest.raises(wired_dispatcher.ToolExecutionError) as raised:
            wired_dispatcher.execute(
                "tsk_mmls",
                {"image_path": str(handle.original_path)},
                case_id=case.id,
                os_profile="unix",
                evidence_context=ctx,
            )

        assert raised.value.__cause__ is finalize_error
        assert "manifest replace failed" in str(raised.value)
        assert "could not persist tool_run_finish" in str(raised.value)
        assert "audit append failed after finalize failure" in str(raised.value)
        assert runner_calls == 1
        assert finalize_calls == 1
        assert append_calls == ["tool_run_start", "tool_run_finish"]
        entries = _tool_entries(cases, case.id)
        assert [entry["action"] for entry in entries] == ["tool_run_start"]

    def test_runner_timeout_exception_preserves_partial_streams_and_closes_once(
        self, wired_dispatcher, monkeypatch, anchored, cases, store
    ):
        """A ``subprocess.TimeoutExpired`` crossing the runner boundary (defensive
        path — the remote exec-agent normally serializes its own timeout as exit
        124) still closes the run ONCE with partial streams and no invented exit."""
        case, ctx, handle = anchored["case"], anchored["ctx"], anchored["handle"]
        calls = {"maletin": 0}
        timeout_error: subprocess.TimeoutExpired | None = None

        def timeout_exec(service, argv, *, timeout=None, **_kw):
            nonlocal timeout_error
            del service
            calls["maletin"] += 1
            timeout_error = subprocess.TimeoutExpired(
                cmd=argv,
                timeout=9,
                output="partial stdout",
                stderr="partial stderr",
            )
            raise timeout_error

        monkeypatch.setattr(
            wired_dispatcher.maletin, "run_argv_in_maletin", timeout_exec
        )

        with pytest.raises(
            wired_dispatcher.ToolExecutionError,
            match="timed out after 9s",
        ) as raised:
            wired_dispatcher.execute(
                "tsk_mmls",
                {"image_path": str(handle.original_path)},
                case_id=case.id,
                os_profile="unix",
                timeout=9,
                evidence_context=ctx,
            )

        assert raised.value.__cause__ is timeout_error
        assert calls == {"maletin": 1}
        entries = _tool_entries(cases, case.id)
        assert [entry["action"] for entry in entries] == [
            "tool_run_start",
            "tool_run_finish",
        ]
        finish = entries[1]
        assert finish["status"] == "error"
        assert finish["exit_code"] is None
        assert finish["error_type"] == "TimeoutExpired"
        assert finish["stdout_sha256"] == hashlib.sha256(b"partial stdout").hexdigest()
        assert finish["stderr_sha256"] == hashlib.sha256(b"partial stderr").hexdigest()
        assert finish["tool_version"] == FAKE_TOOL_VERSION
        assert AuditLog(cases.root / case.id / "audit.jsonl").verify() is True

        run = store.get_run(case.id, entries[0]["run_id"])
        assert run.status == "error"
        assert run.finished_at is not None
        assert run.exit_code is None
        assert run.error_type == "TimeoutExpired"
        run_dir = cases.root / case.id / "artifacts" / run.run_id
        assert (run_dir / "stdout.txt").read_text(encoding="utf-8") == "partial stdout"
        assert (run_dir / "stderr.txt").read_text(encoding="utf-8") == "partial stderr"

    def test_nonzero_exit_is_a_normal_finished_run(
        self, wired_dispatcher, monkeypatch, anchored, cases, store
    ):
        case, ctx, handle = anchored["case"], anchored["ctx"], anchored["handle"]

        def nonzero_exec(service, argv, *, timeout=None, **_kw):
            del service, argv, timeout
            return 23, "", "invalid partition table"

        monkeypatch.setattr(
            wired_dispatcher.maletin, "run_argv_in_maletin", nonzero_exec
        )
        result = wired_dispatcher.execute(
            "tsk_mmls",
            {"image_path": str(handle.original_path)},
            case_id=case.id,
            os_profile="unix",
            evidence_context=ctx,
        )

        assert result["exit_code"] == 23
        assert result["parsed"] is None
        assert result["artifact_run"]["exit_code"] == 23
        assert "status" not in result["artifact_run"]
        assert "error_type" not in result["artifact_run"]
        assert "error_message" not in result["artifact_run"]
        entries = _tool_entries(cases, case.id)
        assert [entry["action"] for entry in entries] == [
            "tool_run_start",
            "tool_run_finish",
        ]
        assert entries[1]["status"] == "finished"
        assert entries[1]["exit_code"] == 23
        # Non-zero exit preserves the full custody context (INVARIANT 4).
        assert entries[1]["evidence_id"] == ctx.evidence_id
        assert entries[1]["baseline_sha256"] == ctx.baseline_sha256
        assert entries[1]["tool_version"] == FAKE_TOOL_VERSION
        run = store.get_run(case.id, result["run_id"])
        assert run.status == "finished"
        assert run.exit_code == 23

    def test_invalid_params_create_neither_start_nor_artifact_run(
        self, wired_dispatcher, anchored, cases, store
    ):
        case, ctx = anchored["case"], anchored["ctx"]
        with pytest.raises(wired_dispatcher.ToolExecutionError, match="image_path"):
            wired_dispatcher.execute(
                "tsk_mmls",
                {"image_path": 123},
                case_id=case.id,
                os_profile="unix",
                evidence_context=ctx,
            )

        assert _tool_entries(cases, case.id) == []
        assert store.list_runs(case.id) == []


# --------------------------------------------------------------------------- #
# case_id="<valid>" — audit + manifest + injection rules
# --------------------------------------------------------------------------- #
def _fake_jq_exec(service, argv, *, timeout=None, **_kw):
    del service, argv, timeout
    return 0, '"x"\n', ""


class TestCaseAnchored:
    def test_returns_case_id_run_id_artifact_run(
        self, wired_dispatcher, monkeypatch, anchored, cases
    ):
        case, ctx = anchored["case"], anchored["ctx"]
        monkeypatch.setattr(
            wired_dispatcher.maletin, "run_argv_in_maletin", _fake_jq_exec
        )
        inp = cases.root / case.id / "input.json"
        inp.write_text('{"name": "x"}')
        result = wired_dispatcher.execute(
            "jq",
            {"filter": ".name", "input_path": str(inp)},
            case_id=case.id,
            os_profile="unix",
            evidence_context=ctx,
        )
        assert result["case_id"] == case.id
        assert result["run_id"]
        assert isinstance(result["artifact_run"], dict)
        # And the manifest landed on disk in 'finished' state, with provenance.
        manifest = json.loads(
            (
                cases.root
                / case.id
                / "artifacts"
                / result["run_id"]
                / "manifest.json"
            ).read_text()
        )
        assert manifest["status"] == "finished"
        assert manifest["exit_code"] == 0
        assert manifest["evidence_id"] == ctx.evidence_id
        assert manifest["evidence_baseline_sha256"] == ctx.baseline_sha256
        assert manifest["tool_version"] == FAKE_TOOL_VERSION

    def test_audit_log_has_start_then_finish_entries(
        self, wired_dispatcher, monkeypatch, anchored, cases
    ):
        case, ctx = anchored["case"], anchored["ctx"]
        monkeypatch.setattr(
            wired_dispatcher.maletin, "run_argv_in_maletin", _fake_jq_exec
        )
        inp = cases.root / case.id / "input.json"
        inp.write_text('{"name": "x"}')
        result = wired_dispatcher.execute(
            "jq",
            {"filter": ".name", "input_path": str(inp)},
            case_id=case.id,
            os_profile="unix",
            evidence_context=ctx,
        )

        entries = _tool_entries(cases, case.id)
        assert len(entries) == 2
        start, finish = entries
        assert start["action"] == "tool_run_start"
        assert finish["action"] == "tool_run_finish"
        # The start entry records the LITERAL argv that ran (not the LLM's intent).
        assert start["tool_id"] == "jq"
        assert start["run_id"] == result["run_id"]
        assert isinstance(start["argv"], list)
        assert any("jq" in a for a in start["argv"])  # binary path or name
        # The params are scrubbed and present.
        assert start["params"]["filter"] == ".name"
        # The finish entry has hashes + counts + custody fields.
        for key in (
            "exit_code",
            "stdout_sha256",
            "stderr_sha256",
            "output_files_count",
            "evidence_id",
            "baseline_sha256",
            "tool_version",
        ):
            assert key in finish

    def test_audit_log_chain_is_intact(
        self, wired_dispatcher, monkeypatch, anchored, cases
    ):
        case, ctx = anchored["case"], anchored["ctx"]
        monkeypatch.setattr(
            wired_dispatcher.maletin, "run_argv_in_maletin", _fake_jq_exec
        )
        inp = cases.root / case.id / "input.json"
        inp.write_text('{"name": "x"}')
        wired_dispatcher.execute(
            "jq",
            {"filter": ".name", "input_path": str(inp)},
            case_id=case.id,
            os_profile="unix",
            evidence_context=ctx,
        )
        audit_path = cases.root / case.id / "audit.jsonl"
        assert AuditLog(audit_path).verify() is True

    def test_two_consecutive_runs_chain_correctly(
        self, wired_dispatcher, monkeypatch, anchored, cases
    ):
        case, ctx = anchored["case"], anchored["ctx"]
        monkeypatch.setattr(
            wired_dispatcher.maletin, "run_argv_in_maletin", _fake_jq_exec
        )
        inp = cases.root / case.id / "input.json"
        inp.write_text('{"name": "x"}')
        # The dispatcher creates a new AuditLog instance per call; verify the second
        # call still chains onto the first.
        for _ in range(2):
            wired_dispatcher.execute(
                "jq",
                {"filter": ".name", "input_path": str(inp)},
                case_id=case.id,
                os_profile="unix",
                evidence_context=ctx,
            )
        audit_path = cases.root / case.id / "audit.jsonl"
        log = AuditLog(audit_path)
        assert log.verify() is True
        lines = [
            json.loads(ln)
            for ln in audit_path.read_text(encoding="utf-8").splitlines()
            if ln.strip()
        ]
        # evidence_register + 2 entries per call (start + finish) -> 5 entries total.
        assert len(lines) == 5
        # And the second run's start entry's prev_hash equals the first run's finish
        # entry_hash.
        assert lines[3]["prev_hash"] == lines[2]["entry_hash"]


class TestOutputDirInjection:
    def test_output_dir_not_injected_when_wrapper_doesnt_accept_it(
        self, wired_dispatcher, monkeypatch, anchored, cases
    ):
        """jq does not declare output_dir in its params; the dispatcher does inject it
        (because the wrapper layer simply ignores unrecognised keys), but it MUST NOT
        end up in the executed argv. We assert on the recorded argv.
        """
        case, ctx = anchored["case"], anchored["ctx"]
        monkeypatch.setattr(
            wired_dispatcher.maletin, "run_argv_in_maletin", _fake_jq_exec
        )
        inp = cases.root / case.id / "input.json"
        inp.write_text('{"name": "x"}')
        result = wired_dispatcher.execute(
            "jq",
            {"filter": ".name", "input_path": str(inp)},
            case_id=case.id,
            os_profile="unix",
            evidence_context=ctx,
        )
        # argv should be [jq, ".name", "<input_path>"] — no output_dir noise.
        argv = result["argv"]
        run_artifact_dir = str(
            cases.root / case.id / "artifacts" / result["run_id"] / "out"
        )
        assert run_artifact_dir not in argv

    def test_output_dir_pre_filled_param_is_rejected_before_runner(
        self, wired_dispatcher, monkeypatch, anchored, cases, tmp_path
    ):
        """RUN_OUTPUT belongs to ArtifactStore even when the caller picks an in-case path."""
        case, ctx, handle = anchored["case"], anchored["ctx"], anchored["handle"]
        captured = {}

        def capture_exec(service, argv, *, timeout=None, **_kw):
            del service, timeout
            captured["argv"] = list(argv)
            return 0, "", ""

        monkeypatch.setattr(
            wired_dispatcher.maletin, "run_argv_in_maletin", capture_exec
        )
        user_out = str(tmp_path / "preferred_out")
        with pytest.raises(wired_dispatcher.ToolExecutionError, match="RUN_OUTPUT"):
            wired_dispatcher.execute(
                "bulk_extractor",
                {
                    "image_path": str(handle.original_path),
                    "output_dir": user_out,
                },
                case_id=case.id,
                os_profile="unix",
                evidence_context=ctx,
            )
        assert captured == {}


class TestInvalidCaseId:
    def test_invalid_case_id_raises(self, wired_dispatcher, anchored):
        # The verified-context gate consults EvidenceManager first; a malformed
        # case_id fails there, wrapped as an actionable ToolExecutionError.
        with pytest.raises(wired_dispatcher.ToolExecutionError, match="contexto"):
            wired_dispatcher.execute(
                "jq",
                {"filter": ".", "input_path": "/tmp/x.json"},
                case_id="not-a-uuid",
                evidence_context=anchored["ctx"],
            )

    def test_unknown_case_id_raises(self, wired_dispatcher, anchored):
        with pytest.raises(wired_dispatcher.ToolExecutionError, match="contexto"):
            wired_dispatcher.execute(
                "jq",
                {"filter": ".", "input_path": "/tmp/x.json"},
                case_id="11111111-1111-4111-8111-111111111111",
                evidence_context=anchored["ctx"],
            )
