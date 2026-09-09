"""ArtifactStore contract: start_run / finalize_run + hashing + atomic manifest."""

from __future__ import annotations

import hashlib
import json

import pytest
from _procedencia import anclar_run
from _symlink_support import requires_symlinks

from agentopsy.artifacts.store import ArtifactStore, OutputFile
from agentopsy.cases.manager import CaseManager

# Evidence provenance every manifest must carry (P0.5-3, FORENSIC INVARIANT 4): the
# dispatcher passes the verified context's id + baseline hash; direct store users
# (these tests) supply the same shape.
_EVID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
_EVSHA = "a" * 64
_PROV = {
    "evidence_id": _EVID,
    "evidence_baseline_sha256": _EVSHA,
    "tool_version": "tool_x 1.2.3 (dpkg)",
}


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
        run_id, out_dir = store.start_run(case.id, "tool_x", argv=["x", "--flag"], **_PROV)
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
        # P0.5-3: every new manifest records its evidence provenance + tool version.
        assert manifest["evidence_id"] == _EVID
        assert manifest["evidence_baseline_sha256"] == _EVSHA
        assert manifest["tool_version"] == _PROV["tool_version"]

    def test_start_run_rejects_missing_or_invalid_provenance(self, store, case):
        with pytest.raises(TypeError):
            store.start_run(case.id, "tool_x", argv=[])  # type: ignore[call-arg]
        with pytest.raises(ValueError, match="evidence_id"):
            store.start_run(
                case.id, "tool_x", argv=[],
                evidence_id="", evidence_baseline_sha256=_EVSHA,
                tool_version=_PROV["tool_version"],
            )
        with pytest.raises(ValueError, match="evidence_baseline_sha256"):
            store.start_run(
                case.id, "tool_x", argv=[],
                evidence_id=_EVID, evidence_baseline_sha256="not-a-sha",
                tool_version=_PROV["tool_version"],
            )
        for bad_version in ("", "unknown", "latest", "  Unknown ", "hayabusa latest"):
            with pytest.raises(ValueError, match="tool_version"):
                store.start_run(
                    case.id, "tool_x", argv=[],
                    evidence_id=_EVID, evidence_baseline_sha256=_EVSHA,
                    tool_version=bad_version,
                )

    def test_start_run_unknown_case_raises(self, store):
        with pytest.raises(KeyError):
            store.start_run(
                "11111111-1111-4111-8111-111111111111", "tool_x", argv=[], **_PROV
            )

    def test_start_run_rejects_non_string_tool_id(self, store, case):
        with pytest.raises(ValueError, match="tool_id"):
            store.start_run(case.id, "", argv=[], **_PROV)

    def test_start_run_rejects_non_list_argv(self, store, case):
        with pytest.raises(ValueError, match="argv"):
            store.start_run(case.id, "tool_x", argv="not-a-list", **_PROV)  # type: ignore[arg-type]

    def test_set_run_argv_persists_literal_command_while_running(
        self, store, cases, case
    ):
        run_id, _ = store.start_run(case.id, "tool_x", argv=[], **_PROV)
        run = store.set_run_argv(case.id, run_id, ["resolved-x", "--literal"])
        assert run.status == "running"
        assert run.argv == ["resolved-x", "--literal"]
        manifest = json.loads(
            (
                cases.root / case.id / "artifacts" / run_id / "manifest.json"
            ).read_text()
        )
        assert manifest["argv"] == ["resolved-x", "--literal"]


# --------------------------------------------------------------------------- #
# finalize_run
# --------------------------------------------------------------------------- #
class TestFinalizeRun:
    def test_finalize_run_enumerates_and_hashes_outputs(self, store, case):
        run_id, out_dir = store.start_run(case.id, "tool_x", argv=["x"], **_PROV)
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
        run_id, _ = store.start_run(case.id, "tool_x", argv=["x"], **_PROV)
        run = store.finalize_run(
            case.id, run_id, exit_code=0, stdout="OUT", stderr="ERR"
        )
        assert run.stdout_sha256 == hashlib.sha256(b"OUT").hexdigest()
        assert run.stderr_sha256 == hashlib.sha256(b"ERR").hexdigest()

    def test_finalize_run_empty_streams_use_empty_hash(self, store, case):
        run_id, _ = store.start_run(case.id, "tool_x", argv=["x"], **_PROV)
        run = store.finalize_run(case.id, run_id, exit_code=0, stdout="", stderr="")
        empty = hashlib.sha256(b"").hexdigest()
        assert run.stdout_sha256 == empty
        assert run.stderr_sha256 == empty

    def test_finalize_run_persists_finished_manifest(self, store, cases, case):
        run_id, out_dir = store.start_run(case.id, "tool_x", argv=["x"], **_PROV)
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
        run_id, _ = store.start_run(case.id, "tool_x", argv=["x"], **_PROV)
        store.finalize_run(case.id, run_id, exit_code=0, stdout="", stderr="")
        run_dir = cases.root / case.id / "artifacts" / run_id
        leftovers = list(run_dir.glob("*.tmp"))
        assert leftovers == []

    def test_finalize_run_empty_out_dir_is_valid(self, store, case):
        run_id, _ = store.start_run(case.id, "tool_x", argv=["x"], **_PROV)
        run = store.finalize_run(
            case.id, run_id, exit_code=0, stdout="", stderr=""
        )
        assert run.output_files == []

    def test_finalize_run_handles_nested_files(self, store, case):
        run_id, out_dir = store.start_run(case.id, "tool_x", argv=["x"], **_PROV)
        nested = out_dir / "a" / "b"
        nested.mkdir(parents=True)
        (nested / "c.csv").write_bytes(b"nested-payload")
        run = store.finalize_run(case.id, run_id, exit_code=0, stdout="", stderr="")
        relpaths = {of.relpath for of in run.output_files}
        # POSIX-style relpath inside out/.
        assert relpaths == {"a/b/c.csv"}
        of = run.output_files[0]
        assert of.sha256 == hashlib.sha256(b"nested-payload").hexdigest()

    @requires_symlinks
    def test_finalize_run_skips_symlinks_in_out(self, store, case, tmp_path):
        run_id, out_dir = store.start_run(case.id, "tool_x", argv=["x"], **_PROV)
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
        run_id, _ = store.start_run(case.id, "tool_x", argv=["x"], **_PROV)
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
        triage. This documents the current behaviour: ``_atomic_write_text``
        does not catch + cleanup on failure.
        """
        run_id, _ = store.start_run(case.id, "tool_x", argv=["x"], **_PROV)

        import agentopsy.artifacts.store as store_mod

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
# fail_run
# --------------------------------------------------------------------------- #
class TestFailRun:
    def test_fail_run_closes_with_error_and_null_exit_code(
        self, store, cases, case
    ):
        run_id, out_dir = store.start_run(case.id, "tool_x", argv=["x"], **_PROV)
        (out_dir / "partial.bin").write_bytes(b"partial")
        run = store.fail_run(
            case.id,
            run_id,
            error_type="TimeoutExpired",
            error_message="timed out after 10 seconds",
            stdout="partial stdout",
            stderr="",
        )

        assert run.status == "error"
        assert run.exit_code is None
        assert run.finished_at is not None
        assert run.error_type == "TimeoutExpired"
        assert run.error_message == "timed out after 10 seconds"
        assert run.stdout_sha256 == hashlib.sha256(b"partial stdout").hexdigest()
        assert [item.relpath for item in run.output_files] == ["partial.bin"]

        manifest = json.loads(
            (
                cases.root / case.id / "artifacts" / run_id / "manifest.json"
            ).read_text()
        )
        assert manifest["status"] == "error"
        assert manifest["exit_code"] is None
        with pytest.raises(KeyError, match="already finalized"):
            store.finalize_run(
                case.id,
                run_id,
                exit_code=0,
                stdout="",
                stderr="",
            )


# --------------------------------------------------------------------------- #
# list_runs / get_run
# --------------------------------------------------------------------------- #
class TestListAndGet:
    def test_list_runs_sorted_desc_by_started_at(self, store, case):
        ids = []
        for _ in range(3):
            run_id, _ = store.start_run(case.id, "tool_x", argv=["x"], **_PROV)
            store.finalize_run(case.id, run_id, exit_code=0, stdout="", stderr="")
            ids.append(run_id)
        runs = store.list_runs(case.id)
        # Every started run is listed exactly once...
        assert {r.run_id for r in runs} == set(ids)
        # ...sorted by started_at descending (the documented contract). Asserting
        # exact reverse-insertion order would over-specify: timestamps can tie and
        # the sort makes no promise about the relative order of equal stamps.
        stamps = [r.started_at for r in runs]
        assert stamps == sorted(stamps, reverse=True)

    def test_list_runs_skips_dir_without_manifest(self, store, cases, case):
        run_id, _ = store.start_run(case.id, "tool_x", argv=["x"], **_PROV)
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
        run_id, out_dir = store.start_run(case.id, "tool_x", argv=["x"], **_PROV)
        (out_dir / "f.csv").write_bytes(b"x")
        store.finalize_run(case.id, run_id, exit_code=0, stdout="", stderr="")
        run = store.get_run(case.id, run_id)
        assert run.run_id == run_id
        assert run.exit_code == 0
        assert any(isinstance(of, OutputFile) for of in run.output_files)


# --------------------------------------------------------------------------- #
# resolve_output_dir — la custodia de un ARBOL derivado
# --------------------------------------------------------------------------- #
class TestResolveOutputDir:
    """El manifiesto es por FICHERO, así que un directorio no es una entrada suya:
    es el prefijo común de varias. Existe porque `hindsight` consume una CARPETA (un
    perfil de navegador) y `tsk_recover` la produce; sin esto, una tool declarada con
    `PathKind.DIRECTORY` quedaba expuesta con una entrada que nadie podía resolver."""

    def _run_with_tree(self, store, case):
        run_id, out = store.start_run(
            case.id, "tsk_recover", argv=["tsk_recover"], **_PROV
        )
        (out / "recovered").mkdir()
        (out / "recovered" / "places.sqlite").write_bytes(b"historial")
        (out / "recovered" / "sub").mkdir()
        (out / "recovered" / "sub" / "cookies.sqlite").write_bytes(b"galletas")
        (out / "suelto.txt").write_text("no es del arbol")
        anclar_run(store._cases, case.id, store.finalize_run(
            case.id, run_id, exit_code=0, stdout="", stderr=""
        ))
        return run_id, out

    def test_resolves_a_directory_and_sums_its_subtree(self, store, case):
        run_id, out = self._run_with_tree(store, case)
        path, tree_sha, size = store.resolve_output_dir(case.id, run_id, "recovered")
        assert path == (out / "recovered").resolve()
        assert len(tree_sha) == 64
        # Solo el subarbol: `suelto.txt` queda fuera.
        assert size == len(b"historial") + len(b"galletas")

    def test_digest_covers_the_whole_subtree_not_one_file(self, store, case):
        """Cambiar CUALQUIER fichero del árbol tiene que cambiar el digest; si no,
        el re-hash no protegería lo que de verdad se consume."""
        run_id, out = self._run_with_tree(store, case)
        _, before, _ = store.resolve_output_dir(case.id, run_id, "recovered")
        run_id2, out2 = store.start_run(
            case.id, "tsk_recover", argv=["tsk_recover"], **_PROV
        )
        (out2 / "recovered").mkdir()
        (out2 / "recovered" / "places.sqlite").write_bytes(b"historial")
        (out2 / "recovered" / "sub").mkdir()
        (out2 / "recovered" / "sub" / "cookies.sqlite").write_bytes(b"OTRAS galletas")
        anclar_run(store._cases, case.id, store.finalize_run(
            case.id, run_id2, exit_code=0, stdout="", stderr=""
        ))
        _, after, _ = store.resolve_output_dir(case.id, run_id2, "recovered")
        assert before != after

    def test_a_tampered_file_breaks_custody(self, store, case):
        from agentopsy.artifacts.store import ArtifactIntegrityError

        run_id, out = self._run_with_tree(store, case)
        (out / "recovered" / "sub" / "cookies.sqlite").write_bytes(b"manipulado")
        with pytest.raises(ArtifactIntegrityError, match="cookies.sqlite"):
            store.resolve_output_dir(case.id, run_id, "recovered")

    def test_unknown_directory_raises(self, store, case):
        run_id, _ = self._run_with_tree(store, case)
        with pytest.raises(KeyError, match="no produjo el directorio de salida"):
            store.resolve_output_dir(case.id, run_id, "inexistente")

    def test_traversal_is_rejected(self, store, case):
        run_id, _ = self._run_with_tree(store, case)
        for bad in ("../..", "/etc", "recovered/../../..", ""):
            with pytest.raises(ValueError):
                store.resolve_output_dir(case.id, run_id, bad)

    def test_a_file_is_not_a_directory(self, store, case):
        """`suelto.txt` SÍ está en el manifiesto, pero como fichero: pedirlo como
        directorio tiene que fallar, no devolverlo igualmente."""
        run_id, _ = self._run_with_tree(store, case)
        with pytest.raises(KeyError, match="no produjo el directorio de salida"):
            store.resolve_output_dir(case.id, run_id, "suelto.txt")
