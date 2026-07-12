"""Dispatcher behaviour when anchored to a case: audit log + artifact manifest."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from forensia.artifacts.store import ArtifactStore
from forensia.audit.log import AuditLog
from forensia.cases.manager import CaseManager
from forensia.evidence_context import EvidenceContext
from forensia.toolkit import dispatcher

# The verified context EvidenceManager would thread for an evidence-reading, anchored run
# (evidence_id + baseline SHA-256). Required by the dispatcher for tools that read evidence.
_CTX = EvidenceContext(
    evidence_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", baseline_sha256="0" * 64
)


@pytest.fixture
def cases(tmp_path) -> CaseManager:
    return CaseManager(root=tmp_path / "cases")


@pytest.fixture
def store(cases) -> ArtifactStore:
    return ArtifactStore(cases)


@pytest.fixture
def case(cases):
    created = cases.create(name="op", examiner="alice", os_profile="unix")
    (cases.root / created.id / "evidence" / "original.raw").write_bytes(b"disk")
    return created


def _evidence_path(cases: CaseManager, case) -> str:
    return str(cases.root / case.id / "evidence" / "original.raw")


@pytest.fixture
def wired_dispatcher(monkeypatch, cases, store):
    """Swap the module-level singletons used by the dispatcher so storage lives in tmp_path."""
    monkeypatch.setattr(dispatcher, "case_manager", cases)
    monkeypatch.setattr(dispatcher, "artifact_store", store)
    return dispatcher


def _require_jq():
    if not shutil.which("jq"):
        pytest.skip("jq not available on PATH")


def _audit_entries(cases: CaseManager, case_id: str) -> list[dict]:
    return AuditLog(cases.root / case_id / "audit.jsonl").entries()


# --------------------------------------------------------------------------- #
# case_id=None — legacy shape, no persistence
# --------------------------------------------------------------------------- #
class TestLegacyShape:
    def test_no_case_id_returns_legacy_dict_shape(self, wired_dispatcher, tmp_path):
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
        self, wired_dispatcher, monkeypatch, case, cases, store
    ):
        calls = {"local": 0, "maletin": 0, "append": 0}
        monkeypatch.setattr(
            wired_dispatcher,
            "resolve",
            lambda _binary: Path("/opt/forensia/bin/mmls"),
        )

        def forbidden_local(argv, *, timeout=None):
            del argv, timeout
            calls["local"] += 1
            raise AssertionError("local runner must not be called")

        def forbidden_maletin(service, argv, *, timeout=None):
            del service, argv, timeout
            calls["maletin"] += 1
            raise AssertionError("maletin runner must not be called")

        original_append = AuditLog.append

        def fail_first_append(audit, event):
            calls["append"] += 1
            if calls["append"] == 1:
                raise OSError("disk full while writing audit start")
            return original_append(audit, event)

        monkeypatch.setattr(wired_dispatcher, "run_argv", forbidden_local)
        monkeypatch.setattr(
            wired_dispatcher.maletin,
            "run_argv_in_maletin",
            forbidden_maletin,
        )
        monkeypatch.setattr(AuditLog, "append", fail_first_append)

        with pytest.raises(
            wired_dispatcher.ToolExecutionError,
            match="could not persist tool_run_start",
        ) as raised:
            wired_dispatcher.execute(
                "tsk_mmls",
                {"image_path": _evidence_path(cases, case)},
                case_id=case.id,
                os_profile="unix",
                evidence_context=_CTX,
            )

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
        assert _audit_entries(cases, case.id) == []

    def test_local_start_is_present_inside_runner_and_finish_follows(
        self, wired_dispatcher, monkeypatch, case, cases
    ):
        audit_path = cases.root / case.id / "audit.jsonl"
        executed: dict[str, list[str]] = {}
        monkeypatch.setattr(
            wired_dispatcher,
            "resolve",
            lambda _binary: Path("/opt/forensia/bin/mmls"),
        )

        def fake_run_argv(argv, *, timeout=None):
            del timeout
            executed["argv"] = list(argv)
            entries = AuditLog(audit_path).entries()
            assert [entry["action"] for entry in entries] == ["tool_run_start"]
            start = entries[0]
            assert start["argv"] == argv
            assert start["case_id"] == case.id
            assert start["run_id"]
            assert start["tool_id"] == "tsk_mmls"
            assert start["params"]["image_path"] == _evidence_path(cases, case)
            return subprocess.CompletedProcess(argv, 0, "DOS Partition Table\n", "")

        monkeypatch.setattr(wired_dispatcher, "run_argv", fake_run_argv)
        result = wired_dispatcher.execute(
            "tsk_mmls",
            {"image_path": _evidence_path(cases, case)},
            case_id=case.id,
            os_profile="unix",
            evidence_context=_CTX,
        )

        entries = _audit_entries(cases, case.id)
        assert [entry["action"] for entry in entries] == [
            "tool_run_start",
            "tool_run_finish",
        ]
        assert sum(entry["action"] == "tool_run_start" for entry in entries) == 1
        assert sum(entry["action"] == "tool_run_finish" for entry in entries) == 1
        assert entries[0]["argv"] == executed["argv"] == result["argv"]

    def test_maletin_start_precedes_call_and_profile_selects_only_one_service(
        self, wired_dispatcher, monkeypatch, case, cases
    ):
        audit_path = cases.root / case.id / "audit.jsonl"
        calls: list[tuple[str, list[str]]] = []
        monkeypatch.setattr(wired_dispatcher, "resolve", lambda _binary: None)

        def fake_exec(service, argv, *, timeout=None):
            del timeout
            calls.append((service, list(argv)))
            entries = AuditLog(audit_path).entries()
            assert [entry["action"] for entry in entries] == ["tool_run_start"]
            assert entries[0]["argv"] == argv
            return 0, "d/d 769:\thome\n", ""

        monkeypatch.setattr(
            wired_dispatcher.maletin,
            "run_argv_in_maletin",
            fake_exec,
        )
        result = wired_dispatcher.execute(
            "tsk_fls",
            {"image_path": _evidence_path(cases, case)},
            case_id=case.id,
            os_profile="windows",
            evidence_context=_CTX,
        )

        assert calls == [("toolkit-windows", result["argv"])]
        assert [entry["action"] for entry in _audit_entries(cases, case.id)] == [
            "tool_run_start",
            "tool_run_finish",
        ]

    def test_maletin_transport_failure_closes_audit_and_artifact_without_exit_code(
        self, wired_dispatcher, monkeypatch, case, cases, store
    ):
        audit_path = cases.root / case.id / "audit.jsonl"
        calls: list[str] = []
        monkeypatch.setattr(wired_dispatcher, "resolve", lambda _binary: None)

        def failing_exec(service, argv, *, timeout=None):
            del timeout
            calls.append(service)
            entries = AuditLog(audit_path).entries()
            assert [entry["action"] for entry in entries] == ["tool_run_start"]
            assert entries[0]["argv"] == argv
            raise wired_dispatcher.maletin.MaletinExecError(
                "exec-agent toolkit-unix: connection refused"
            )

        monkeypatch.setattr(
            wired_dispatcher.maletin,
            "run_argv_in_maletin",
            failing_exec,
        )

        with pytest.raises(
            wired_dispatcher.ToolExecutionError,
            match="connection refused",
        ) as raised:
            wired_dispatcher.execute(
                "tsk_mmls",
                {"image_path": _evidence_path(cases, case)},
                case_id=case.id,
                os_profile="unix",
                evidence_context=_CTX,
            )

        assert isinstance(raised.value.__cause__, wired_dispatcher.maletin.MaletinExecError)
        entries = _audit_entries(cases, case.id)
        assert [entry["action"] for entry in entries] == [
            "tool_run_start",
            "tool_run_finish",
        ]
        finish = entries[1]
        assert finish["status"] == "error"
        assert finish["exit_code"] is None
        assert finish["error_type"] == "MaletinExecError"
        assert "connection refused" in finish["error_message"]
        assert AuditLog(audit_path).verify() is True
        assert calls == ["toolkit-unix"]

        run = store.get_run(case.id, entries[0]["run_id"])
        assert run.status == "error"
        assert run.exit_code is None
        assert run.finished_at is not None
        assert run.error_type == "MaletinExecError"
        assert "connection refused" in run.error_message

    def test_runner_failure_keeps_primary_cause_when_finish_append_fails(
        self, wired_dispatcher, monkeypatch, case, cases, store
    ):
        runner_calls = 0
        append_calls: list[str] = []
        runner_error = wired_dispatcher.maletin.MaletinExecError(
            "exec-agent transport disconnected"
        )
        original_append = AuditLog.append
        monkeypatch.setattr(wired_dispatcher, "resolve", lambda _binary: None)

        def failing_exec(service, argv, *, timeout=None):
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
            wired_dispatcher.maletin,
            "run_argv_in_maletin",
            failing_exec,
        )
        monkeypatch.setattr(AuditLog, "append", fail_second_append)

        with pytest.raises(wired_dispatcher.ToolExecutionError) as raised:
            wired_dispatcher.execute(
                "tsk_mmls",
                {"image_path": _evidence_path(cases, case)},
                case_id=case.id,
                os_profile="unix",
                evidence_context=_CTX,
            )

        assert raised.value.__cause__ is runner_error
        assert "exec-agent transport disconnected" in str(raised.value)
        assert "could not persist tool_run_finish" in str(raised.value)
        assert "audit disk unavailable for finish" in str(raised.value)
        assert "was not retried" in str(raised.value)
        assert runner_calls == 1
        assert append_calls == ["tool_run_start", "tool_run_finish"]
        entries = _audit_entries(cases, case.id)
        assert [entry["action"] for entry in entries] == ["tool_run_start"]
        run = store.get_run(case.id, entries[0]["run_id"])
        assert run.status == "error"
        assert run.exit_code is None
        assert run.error_type == "MaletinExecError"

    def test_successful_run_is_not_reexecuted_when_finish_append_fails(
        self, wired_dispatcher, monkeypatch, case, cases, store
    ):
        runner_calls = 0
        append_calls: list[str] = []
        finish_error = OSError("audit fsync failed for successful finish")
        original_append = AuditLog.append
        monkeypatch.setattr(
            wired_dispatcher,
            "resolve",
            lambda _binary: Path("/opt/forensia/bin/mmls"),
        )

        def successful_run(argv, *, timeout=None):
            nonlocal runner_calls
            del timeout
            runner_calls += 1
            return subprocess.CompletedProcess(argv, 0, "ok", "")

        def fail_second_append(audit, event):
            append_calls.append(event["action"])
            if len(append_calls) == 2:
                raise finish_error
            return original_append(audit, event)

        monkeypatch.setattr(wired_dispatcher, "run_argv", successful_run)
        monkeypatch.setattr(AuditLog, "append", fail_second_append)

        with pytest.raises(wired_dispatcher.ToolExecutionError) as raised:
            wired_dispatcher.execute(
                "tsk_mmls",
                {"image_path": _evidence_path(cases, case)},
                case_id=case.id,
                os_profile="unix",
                evidence_context=_CTX,
            )

        assert raised.value.__cause__ is finish_error
        assert "already executed" in str(raised.value)
        assert "ArtifactRun was finalized with exit_code 0" in str(raised.value)
        assert "could not persist tool_run_finish" in str(raised.value)
        assert "was not re-executed" in str(raised.value)
        assert runner_calls == 1
        assert append_calls == ["tool_run_start", "tool_run_finish"]
        entries = _audit_entries(cases, case.id)
        assert [entry["action"] for entry in entries] == ["tool_run_start"]
        run = store.get_run(case.id, entries[0]["run_id"])
        assert run.status == "finished"
        assert run.exit_code == 0

    def test_finalize_and_finish_append_failures_preserve_finalize_cause(
        self, wired_dispatcher, monkeypatch, case, cases
    ):
        runner_calls = 0
        finalize_calls = 0
        append_calls: list[str] = []
        finalize_error = OSError("manifest replace failed")
        original_append = AuditLog.append
        monkeypatch.setattr(
            wired_dispatcher,
            "resolve",
            lambda _binary: Path("/opt/forensia/bin/mmls"),
        )

        def successful_run(argv, *, timeout=None):
            nonlocal runner_calls
            del timeout
            runner_calls += 1
            return subprocess.CompletedProcess(argv, 0, "ok", "")

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

        monkeypatch.setattr(wired_dispatcher, "run_argv", successful_run)
        monkeypatch.setattr(
            wired_dispatcher.artifact_store,
            "finalize_run",
            failing_finalize,
        )
        monkeypatch.setattr(AuditLog, "append", fail_second_append)

        with pytest.raises(wired_dispatcher.ToolExecutionError) as raised:
            wired_dispatcher.execute(
                "tsk_mmls",
                {"image_path": _evidence_path(cases, case)},
                case_id=case.id,
                os_profile="unix",
                evidence_context=_CTX,
            )

        assert raised.value.__cause__ is finalize_error
        assert "manifest replace failed" in str(raised.value)
        assert "could not persist tool_run_finish" in str(raised.value)
        assert "audit append failed after finalize failure" in str(raised.value)
        assert runner_calls == 1
        assert finalize_calls == 1
        assert append_calls == ["tool_run_start", "tool_run_finish"]
        entries = _audit_entries(cases, case.id)
        assert [entry["action"] for entry in entries] == ["tool_run_start"]

    def test_local_timeout_preserves_partial_streams_and_closes_once(
        self, wired_dispatcher, monkeypatch, case, cases, store
    ):
        audit_path = cases.root / case.id / "audit.jsonl"
        calls = {"local": 0, "maletin": 0}
        timeout_error: subprocess.TimeoutExpired | None = None
        monkeypatch.setattr(
            wired_dispatcher,
            "resolve",
            lambda _binary: Path("/opt/forensia/bin/mmls"),
        )

        def timeout_run(argv, *, timeout=None):
            nonlocal timeout_error
            calls["local"] += 1
            entries = AuditLog(audit_path).entries()
            assert [entry["action"] for entry in entries] == ["tool_run_start"]
            assert entries[0]["argv"] == argv
            timeout_error = subprocess.TimeoutExpired(
                cmd=argv,
                timeout=timeout,
                output="partial stdout",
                stderr="partial stderr",
            )
            raise timeout_error

        def forbidden_maletin(service, argv, *, timeout=None):
            del service, argv, timeout
            calls["maletin"] += 1
            raise AssertionError("timeout must not fall back to a maletin")

        monkeypatch.setattr(wired_dispatcher, "run_argv", timeout_run)
        monkeypatch.setattr(
            wired_dispatcher.maletin,
            "run_argv_in_maletin",
            forbidden_maletin,
        )

        with pytest.raises(
            wired_dispatcher.ToolExecutionError,
            match="timed out after 9s",
        ) as raised:
            wired_dispatcher.execute(
                "tsk_mmls",
                {"image_path": _evidence_path(cases, case)},
                case_id=case.id,
                os_profile="unix",
                timeout=9,
                evidence_context=_CTX,
            )

        assert raised.value.__cause__ is timeout_error
        assert calls == {"local": 1, "maletin": 0}
        entries = _audit_entries(cases, case.id)
        assert [entry["action"] for entry in entries] == [
            "tool_run_start",
            "tool_run_finish",
        ]
        assert sum(entry["action"] == "tool_run_start" for entry in entries) == 1
        assert sum(entry["action"] == "tool_run_finish" for entry in entries) == 1
        finish = entries[1]
        assert finish["status"] == "error"
        assert finish["exit_code"] is None
        assert finish["error_type"] == "TimeoutExpired"
        assert finish["stdout_sha256"] == hashlib.sha256(b"partial stdout").hexdigest()
        assert finish["stderr_sha256"] == hashlib.sha256(b"partial stderr").hexdigest()
        assert AuditLog(audit_path).verify() is True

        run = store.get_run(case.id, entries[0]["run_id"])
        assert run.status == "error"
        assert run.finished_at is not None
        assert run.exit_code is None
        assert run.error_type == "TimeoutExpired"
        assert run.stdout_sha256 == hashlib.sha256(b"partial stdout").hexdigest()
        assert run.stderr_sha256 == hashlib.sha256(b"partial stderr").hexdigest()
        run_dir = cases.root / case.id / "artifacts" / run.run_id
        assert (run_dir / "stdout.txt").read_text(encoding="utf-8") == "partial stdout"
        assert (run_dir / "stderr.txt").read_text(encoding="utf-8") == "partial stderr"

    def test_nonzero_exit_is_a_normal_finished_run(
        self, wired_dispatcher, monkeypatch, case, cases, store
    ):
        audit_path = cases.root / case.id / "audit.jsonl"
        monkeypatch.setattr(
            wired_dispatcher,
            "resolve",
            lambda _binary: Path("/opt/forensia/bin/mmls"),
        )

        def nonzero_run(argv, *, timeout=None):
            del timeout
            assert [entry["action"] for entry in AuditLog(audit_path).entries()] == [
                "tool_run_start"
            ]
            return subprocess.CompletedProcess(argv, 23, "", "invalid partition table")

        monkeypatch.setattr(wired_dispatcher, "run_argv", nonzero_run)
        result = wired_dispatcher.execute(
            "tsk_mmls",
            {"image_path": _evidence_path(cases, case)},
            case_id=case.id,
            os_profile="unix",
            evidence_context=_CTX,
        )

        assert result["exit_code"] == 23
        assert result["parsed"] is None
        assert result["artifact_run"]["exit_code"] == 23
        assert "status" not in result["artifact_run"]
        assert "error_type" not in result["artifact_run"]
        assert "error_message" not in result["artifact_run"]
        entries = _audit_entries(cases, case.id)
        assert [entry["action"] for entry in entries] == [
            "tool_run_start",
            "tool_run_finish",
        ]
        assert entries[1]["status"] == "finished"
        assert entries[1]["exit_code"] == 23
        run = store.get_run(case.id, result["run_id"])
        assert run.status == "finished"
        assert run.exit_code == 23

    def test_invalid_params_create_neither_start_nor_artifact_run(
        self, wired_dispatcher, case, cases, store
    ):
        with pytest.raises(wired_dispatcher.ToolExecutionError, match="image_path"):
            wired_dispatcher.execute(
                "tsk_mmls",
                {"image_path": 123},
                case_id=case.id,
                os_profile="unix",
            )

        assert _audit_entries(cases, case.id) == []
        assert store.list_runs(case.id) == []


# --------------------------------------------------------------------------- #
# case_id="<valid>" — audit + manifest + injection rules
# --------------------------------------------------------------------------- #
class TestCaseAnchored:
    def test_returns_case_id_run_id_artifact_run(
        self, wired_dispatcher, case, tmp_path, cases
    ):
        _require_jq()
        inp = cases.root / case.id / "input.json"
        inp.write_text('{"name": "x"}')
        result = wired_dispatcher.execute(
            "jq", {"filter": ".name", "input_path": str(inp)}, case_id=case.id
        )
        assert result["case_id"] == case.id
        assert result["run_id"]
        assert isinstance(result["artifact_run"], dict)
        # And the manifest landed on disk in 'finished' state.
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

    def test_audit_log_has_start_then_finish_entries(
        self, wired_dispatcher, case, tmp_path, cases
    ):
        _require_jq()
        inp = cases.root / case.id / "input.json"
        inp.write_text('{"name": "x"}')
        result = wired_dispatcher.execute(
            "jq", {"filter": ".name", "input_path": str(inp)}, case_id=case.id
        )

        audit_path = cases.root / case.id / "audit.jsonl"
        assert audit_path.is_file()
        lines = [
            json.loads(ln)
            for ln in audit_path.read_text(encoding="utf-8").splitlines()
            if ln.strip()
        ]
        assert len(lines) == 2
        start, finish = lines
        assert start["action"] == "tool_run_start"
        assert finish["action"] == "tool_run_finish"
        # The start entry records the LITERAL argv that ran (not the LLM's intent).
        assert start["tool_id"] == "jq"
        assert start["run_id"] == result["run_id"]
        assert isinstance(start["argv"], list)
        assert any("jq" in a for a in start["argv"])  # binary path or name
        # The params are scrubbed and present.
        assert start["params"]["filter"] == ".name"
        # The finish entry has hashes + counts.
        for key in ("exit_code", "stdout_sha256", "stderr_sha256", "output_files_count"):
            assert key in finish

    def test_audit_log_chain_is_intact(self, wired_dispatcher, case, tmp_path, cases):
        _require_jq()
        inp = cases.root / case.id / "input.json"
        inp.write_text('{"name": "x"}')
        wired_dispatcher.execute(
            "jq", {"filter": ".name", "input_path": str(inp)}, case_id=case.id
        )
        audit_path = cases.root / case.id / "audit.jsonl"
        assert AuditLog(audit_path).verify() is True

    def test_two_consecutive_runs_chain_correctly(
        self, wired_dispatcher, case, tmp_path, cases
    ):
        _require_jq()
        inp = cases.root / case.id / "input.json"
        inp.write_text('{"name": "x"}')
        # The dispatcher creates a new AuditLog instance per call; verify the second
        # call still chains onto the first.
        for _ in range(2):
            wired_dispatcher.execute(
                "jq", {"filter": ".name", "input_path": str(inp)}, case_id=case.id
            )
        audit_path = cases.root / case.id / "audit.jsonl"
        log = AuditLog(audit_path)
        assert log.verify() is True
        lines = [
            json.loads(ln)
            for ln in audit_path.read_text(encoding="utf-8").splitlines()
            if ln.strip()
        ]
        # 2 entries per call (start + finish) -> 4 entries total.
        assert len(lines) == 4
        # And the second run's start entry's prev_hash equals the first run's finish entry_hash.
        assert lines[2]["prev_hash"] == lines[1]["entry_hash"]


class TestOutputDirInjection:
    def test_output_dir_not_injected_when_wrapper_doesnt_accept_it(
        self, wired_dispatcher, case, tmp_path, cases
    ):
        """jq does not declare output_dir in its params; the dispatcher does inject it
        (because the wrapper layer simply ignores unrecognised keys), but it MUST NOT
        end up in the executed argv. We assert on the recorded argv.
        """
        _require_jq()
        inp = cases.root / case.id / "input.json"
        inp.write_text('{"name": "x"}')
        result = wired_dispatcher.execute(
            "jq", {"filter": ".name", "input_path": str(inp)}, case_id=case.id
        )
        # argv should be [<jq>, ".name", "<input_path>"] — no output_dir noise.
        argv = result["argv"]
        run_artifact_dir = str(
            cases.root / case.id / "artifacts" / result["run_id"] / "out"
        )
        assert run_artifact_dir not in argv

    def test_output_dir_pre_filled_param_is_rejected_before_runner(
        self, wired_dispatcher, monkeypatch, case, cases, tmp_path
    ):
        """RUN_OUTPUT belongs to ArtifactStore even when the caller picks an in-case path."""
        captured = {}

        def fake_run_argv(argv, *, timeout=None):
            del timeout
            captured["argv"] = list(argv)
            return subprocess.CompletedProcess(argv, 0, "", "")

        # Replace the bundled runner so we never actually call bulk_extractor, and force
        # the bundled venue by making the binary "resolvable" on the api PATH (otherwise
        # the dispatcher would route to the maletín exec-agent — a different path).
        monkeypatch.setattr(wired_dispatcher, "run_argv", fake_run_argv)
        monkeypatch.setattr(
            wired_dispatcher,
            "resolve",
            lambda _binary: Path("/fake/bin/bulk_extractor"),
        )
        user_out = str(tmp_path / "preferred_out")
        with pytest.raises(wired_dispatcher.ToolExecutionError, match="RUN_OUTPUT"):
            wired_dispatcher.execute(
                "bulk_extractor",
                {
                    "image_path": _evidence_path(cases, case),
                    "output_dir": user_out,
                },
                case_id=case.id,
            )
        assert captured == {}


class TestInvalidCaseId:
    def test_invalid_case_id_raises_valueerror(self, wired_dispatcher):
        _require_jq()
        with pytest.raises((ValueError, KeyError)):
            wired_dispatcher.execute(
                "jq",
                {"filter": ".", "input_path": "/tmp/x.json"},
                case_id="not-a-uuid",
            )

    def test_unknown_case_id_raises_keyerror(self, wired_dispatcher):
        _require_jq()
        with pytest.raises(KeyError):
            wired_dispatcher.execute(
                "jq",
                {"filter": ".", "input_path": "/tmp/x.json"},
                case_id="11111111-1111-4111-8111-111111111111",
            )
