"""Dispatcher behaviour when anchored to a case: audit log + artifact manifest."""

from __future__ import annotations

import json
import shutil

import pytest

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
def case(cases):
    return cases.create(name="op", examiner="alice", os_profile="unix")


@pytest.fixture
def wired_dispatcher(monkeypatch, cases, store):
    """Swap the module-level singletons used by the dispatcher so storage lives in tmp_path."""
    monkeypatch.setattr(dispatcher, "case_manager", cases)
    monkeypatch.setattr(dispatcher, "artifact_store", store)
    return dispatcher


def _require_jq():
    if not shutil.which("jq"):
        pytest.skip("jq not available on PATH")


# --------------------------------------------------------------------------- #
# case_id=None — legacy shape, no persistence
# --------------------------------------------------------------------------- #
class TestLegacyShape:
    def test_no_case_id_returns_legacy_dict_shape(self, wired_dispatcher, tmp_path):
        _require_jq()
        inp = tmp_path / "in.json"
        inp.write_text('{"name": "x"}')
        result = wired_dispatcher.execute(
            "jq", {"filter": ".name", "input_path": str(inp)}
        )
        assert "case_id" not in result
        assert "run_id" not in result
        assert "artifact_run" not in result
        assert result["exit_code"] == 0


# --------------------------------------------------------------------------- #
# case_id="<valid>" — audit + manifest + injection rules
# --------------------------------------------------------------------------- #
class TestCaseAnchored:
    def test_returns_case_id_run_id_artifact_run(
        self, wired_dispatcher, case, tmp_path, cases
    ):
        _require_jq()
        inp = tmp_path / "in.json"
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
        inp = tmp_path / "in.json"
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
        inp = tmp_path / "in.json"
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
        inp = tmp_path / "in.json"
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
        inp = tmp_path / "in.json"
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

    def test_output_dir_pre_filled_param_is_preserved(
        self, wired_dispatcher, case, tmp_path, cases
    ):
        """If the caller supplied output_dir explicitly the dispatcher must not overwrite it.
        Use bulk_extractor's wrapper-only build_argv (no need to actually run the binary):
        we monkeypatch `_run_bundled` to capture the argv and skip execution.
        """
        captured = {}

        def fake_run_bundled(tool, argv_tail, *, timeout):
            captured["argv_tail"] = list(argv_tail)
            argv = [f"/fake/{tool.binary}", *argv_tail]
            return argv, 0, "", ""

        # Replace the bundled runner so we never actually call bulk_extractor, and force
        # the bundled venue by making the binary "resolvable" on the api PATH (otherwise
        # the dispatcher would route to the maletín exec-agent — a different path).
        import forensia.toolkit.dispatcher as disp

        original = disp._run_bundled
        original_resolve = disp.resolve
        disp._run_bundled = fake_run_bundled
        disp.resolve = lambda _binary: "/fake/bin"
        try:
            user_out = str(tmp_path / "preferred_out")
            (tmp_path / "image.raw").write_bytes(b"x")
            wired_dispatcher.execute(
                "bulk_extractor",
                {
                    "image_path": str(tmp_path / "image.raw"),
                    "output_dir": user_out,
                },
                case_id=case.id,
            )
            assert user_out in captured["argv_tail"]
        finally:
            disp._run_bundled = original
            disp.resolve = original_resolve


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
