"""ArtifactStore contract: start_run / finalize_run + hashing + atomic manifest."""

from __future__ import annotations

import hashlib
import json

import pytest

from forensia.artifacts.store import ArtifactStore, OutputFile
from forensia.cases.manager import CaseManager


@pytest.fixture
def cases(tmp_path) -> CaseManager:
    return CaseManager(root=tmp_path / "cases")


@pytest.fixture
def store(cases) -> ArtifactStore:
    return ArtifactStore(cases)


@pytest.fixture
def case(cases):
    return cases.create(name="op", examiner="alice", os_profile="unix")


# --------------------------------------------------------------------------- #
# start_run
# --------------------------------------------------------------------------- #
class TestStartRun:
    def test_start_run_creates_out_and_manifest(self, store, cases, case):
        run_id, out_dir = store.start_run(case.id, "tool_x", argv=["x", "--flag"])
        run_dir = cases.root / case.id / "artifacts" / run_id
        assert out_dir == run_dir / "out"
        assert out_dir.is_dir()
        manifest = json.loads((run_dir / "manifest.json").read_text())
        assert manifest["status"] == "running"
        assert manifest["started_at"]
        assert manifest["finished_at"] is None
        assert manifest["exit_code"] is None
        assert manifest["output_files"] == []
        assert manifest["argv"] == ["x", "--flag"]
        assert manifest["tool_id"] == "tool_x"
        assert manifest["run_id"] == run_id

    def test_start_run_unknown_case_raises(self, store):
        with pytest.raises(KeyError):
            store.start_run(
                "11111111-1111-4111-8111-111111111111", "tool_x", argv=[]
            )

    def test_start_run_rejects_non_string_tool_id(self, store, case):
        with pytest.raises(ValueError, match="tool_id"):
            store.start_run(case.id, "", argv=[])

    def test_start_run_rejects_non_list_argv(self, store, case):
        with pytest.raises(ValueError, match="argv"):
            store.start_run(case.id, "tool_x", argv="not-a-list")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# finalize_run
# --------------------------------------------------------------------------- #
class TestFinalizeRun:
    def test_finalize_run_enumerates_and_hashes_outputs(self, store, case):
        run_id, out_dir = store.start_run(case.id, "tool_x", argv=["x"])
        # Write two files we know the hash of.
        a = out_dir / "a.csv"
        b = out_dir / "b.txt"
        a.write_bytes(b"row1,row2\n")
        b.write_bytes(b"hello\n")
        run = store.finalize_run(
            case.id, run_id, exit_code=0, stdout="stdout-bytes", stderr=""
        )
        relpaths = {of.relpath for of in run.output_files}
        assert relpaths == {"a.csv", "b.txt"}
        by_name = {of.relpath: of for of in run.output_files}
        assert by_name["a.csv"].sha256 == hashlib.sha256(b"row1,row2\n").hexdigest()
        assert by_name["a.csv"].size == len(b"row1,row2\n")
        assert by_name["b.txt"].sha256 == hashlib.sha256(b"hello\n").hexdigest()

    def test_finalize_run_hashes_stdout_and_stderr(self, store, case):
        run_id, _ = store.start_run(case.id, "tool_x", argv=["x"])
        run = store.finalize_run(
            case.id, run_id, exit_code=0, stdout="OUT", stderr="ERR"
        )
        assert run.stdout_sha256 == hashlib.sha256(b"OUT").hexdigest()
        assert run.stderr_sha256 == hashlib.sha256(b"ERR").hexdigest()

    def test_finalize_run_empty_streams_use_empty_hash(self, store, case):
        run_id, _ = store.start_run(case.id, "tool_x", argv=["x"])
        run = store.finalize_run(case.id, run_id, exit_code=0, stdout="", stderr="")
        empty = hashlib.sha256(b"").hexdigest()
        assert run.stdout_sha256 == empty
        assert run.stderr_sha256 == empty

    def test_finalize_run_persists_finished_manifest(self, store, cases, case):
        run_id, out_dir = store.start_run(case.id, "tool_x", argv=["x"])
        (out_dir / "f.bin").write_bytes(b"BINARY")
        store.finalize_run(
            case.id, run_id, exit_code=42, stdout="o", stderr="e"
        )
        manifest_path = (
            cases.root / case.id / "artifacts" / run_id / "manifest.json"
        )
        manifest = json.loads(manifest_path.read_text())
        assert manifest["status"] == "finished"
        assert manifest["exit_code"] == 42
        assert manifest["finished_at"]
        assert manifest["stdout_sha256"] == hashlib.sha256(b"o").hexdigest()
        # All hashes captured for each output file.
        rel_to_sha = {of["relpath"]: of["sha256"] for of in manifest["output_files"]}
        assert rel_to_sha == {"f.bin": hashlib.sha256(b"BINARY").hexdigest()}

    def test_finalize_run_atomic_write_no_tmp_left(self, store, cases, case):
        run_id, _ = store.start_run(case.id, "tool_x", argv=["x"])
        store.finalize_run(case.id, run_id, exit_code=0, stdout="", stderr="")
        run_dir = cases.root / case.id / "artifacts" / run_id
        leftovers = list(run_dir.glob("*.tmp"))
        assert leftovers == []

    def test_finalize_run_empty_out_dir_is_valid(self, store, case):
        run_id, _ = store.start_run(case.id, "tool_x", argv=["x"])
        run = store.finalize_run(
            case.id, run_id, exit_code=0, stdout="", stderr=""
        )
        assert run.output_files == []

    def test_finalize_run_handles_nested_files(self, store, case):
        run_id, out_dir = store.start_run(case.id, "tool_x", argv=["x"])
        nested = out_dir / "a" / "b"
        nested.mkdir(parents=True)
        (nested / "c.csv").write_bytes(b"nested-payload")
        run = store.finalize_run(case.id, run_id, exit_code=0, stdout="", stderr="")
        relpaths = {of.relpath for of in run.output_files}
        # POSIX-style relpath inside out/.
        assert relpaths == {"a/b/c.csv"}
        of = run.output_files[0]
        assert of.sha256 == hashlib.sha256(b"nested-payload").hexdigest()

    def test_finalize_run_skips_symlinks_in_out(self, store, case, tmp_path):
        run_id, out_dir = store.start_run(case.id, "tool_x", argv=["x"])
        real = out_dir / "real.csv"
        real.write_bytes(b"real")
        target = tmp_path / "external.csv"
        target.write_bytes(b"external")
        (out_dir / "link.csv").symlink_to(target)
        run = store.finalize_run(case.id, run_id, exit_code=0, stdout="", stderr="")
        relpaths = {of.relpath for of in run.output_files}
        # The symlink is skipped; only the real file is recorded.
        assert relpaths == {"real.csv"}

    def test_finalize_run_unknown_run_raises(self, store, case):
        with pytest.raises(KeyError):
            store.finalize_run(
                case.id,
                "11111111-1111-4111-8111-111111111111",
                exit_code=0,
                stdout="",
                stderr="",
            )

    def test_finalize_run_already_finalized_raises(self, store, case):
        # RULE 2: a silent re-finalize would erode the chain of custody.
        run_id, _ = store.start_run(case.id, "tool_x", argv=["x"])
        store.finalize_run(case.id, run_id, exit_code=0, stdout="", stderr="")
        with pytest.raises(KeyError, match="already finalized"):
            store.finalize_run(case.id, run_id, exit_code=0, stdout="", stderr="")

    def test_finalize_run_invalid_run_id_raises_valueerror(self, store, case):
        with pytest.raises(ValueError, match="run_id"):
            store.finalize_run(
                case.id, "not-a-uuid", exit_code=0, stdout="", stderr=""
            )

    def test_atomic_write_failure_leaves_tmp_file(
        self, store, cases, case, monkeypatch
    ):
        """If ``os.replace`` raises mid-finalize the manifest stays in its
        ``running`` state and the ``.tmp`` siblings are left on disk for forensic
        triage. This documents the v1 behaviour: ``_atomic_write_text`` does not
        catch + cleanup on failure (TODO: add cleanup in v2 — see issue tracker).
        """
        run_id, _ = store.start_run(case.id, "tool_x", argv=["x"])

        import forensia.artifacts.store as store_mod

        def boom(src, dst):
            raise OSError("simulated replace failure")

        monkeypatch.setattr(store_mod.os, "replace", boom)
        with pytest.raises(OSError, match="simulated replace failure"):
            store.finalize_run(case.id, run_id, exit_code=0, stdout="", stderr="")

        run_dir = cases.root / case.id / "artifacts" / run_id
        # The pre-failure manifest is still in 'running' state — we did not corrupt it.
        manifest = json.loads((run_dir / "manifest.json").read_text())
        assert manifest["status"] == "running"


# --------------------------------------------------------------------------- #
# list_runs / get_run
# --------------------------------------------------------------------------- #
class TestListAndGet:
    def test_list_runs_sorted_desc_by_started_at(self, store, case):
        ids = []
        for _ in range(3):
            run_id, _ = store.start_run(case.id, "tool_x", argv=["x"])
            store.finalize_run(case.id, run_id, exit_code=0, stdout="", stderr="")
            ids.append(run_id)
        runs = store.list_runs(case.id)
        assert [r.run_id for r in runs] == list(reversed(ids))

    def test_list_runs_skips_dir_without_manifest(self, store, cases, case):
        run_id, _ = store.start_run(case.id, "tool_x", argv=["x"])
        store.finalize_run(case.id, run_id, exit_code=0, stdout="", stderr="")
        # Manually drop a sibling dir with no manifest.
        orphan = cases.root / case.id / "artifacts" / "22222222-2222-4222-8222-222222222222"
        orphan.mkdir()
        runs = store.list_runs(case.id)
        assert [r.run_id for r in runs] == [run_id]

    def test_list_runs_empty(self, store, case):
        assert store.list_runs(case.id) == []

    def test_get_run_unknown_raises(self, store, case):
        with pytest.raises(KeyError):
            store.get_run(case.id, "11111111-1111-4111-8111-111111111111")

    def test_get_run_returns_full_artifact_run(self, store, case):
        run_id, out_dir = store.start_run(case.id, "tool_x", argv=["x"])
        (out_dir / "f.csv").write_bytes(b"x")
        store.finalize_run(case.id, run_id, exit_code=0, stdout="", stderr="")
        run = store.get_run(case.id, run_id)
        assert run.run_id == run_id
        assert run.exit_code == 0
        assert any(isinstance(of, OutputFile) for of in run.output_files)
