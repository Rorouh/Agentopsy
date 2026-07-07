"""EvidenceManager hash-gate contract + read-only invariant + cleanup on failure."""

from __future__ import annotations

import hashlib
import json
import shutil
import stat
import sys

import pytest
from _symlink_support import requires_symlinks

from forensia.cases.manager import CaseManager
from forensia.evidence import EvidenceManager


@pytest.fixture
def cases(tmp_path) -> CaseManager:
    return CaseManager(root=tmp_path / "cases")


@pytest.fixture
def manager(cases) -> EvidenceManager:
    return EvidenceManager(cases)


@pytest.fixture
def case(cases):
    return cases.create(name="op", examiner="alice", os_profile="unix")


@pytest.fixture
def known_file(tmp_path):
    """A file with known content + known sha256."""
    src = tmp_path / "evidence.raw"
    payload = b"FORENSIA-EVIDENCE-PAYLOAD-12345"
    src.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    return src, payload, digest


class TestRegister:
    def test_register_copies_to_case_evidence_dir(self, manager, cases, case, known_file):
        src, _, _ = known_file
        handle = manager.register(case.id, str(src))
        expected_parent = cases.root / case.id / "evidence" / handle.evidence_id
        assert handle.original_path.parent == expected_parent
        assert handle.original_path.name == "original.raw"
        # And the copy actually exists.
        assert handle.original_path.is_file()
        # The handle points at the COPY, not at the source.
        assert handle.original_path != src.resolve()

    def test_register_hashes_match_source(self, manager, case, known_file):
        src, _, expected_sha = known_file
        handle = manager.register(case.id, str(src))
        assert handle.sha256 == expected_sha
        # And the copy on disk has the same bytes.
        assert hashlib.sha256(handle.original_path.read_bytes()).hexdigest() == expected_sha

    def test_register_writes_baseline_json_with_required_fields(
        self, manager, case, known_file
    ):
        src, payload, expected_sha = known_file
        handle = manager.register(case.id, str(src))
        baseline = json.loads(
            (handle.original_path.parent / "baseline.json").read_text()
        )
        assert baseline["sha256"] == expected_sha
        assert baseline["size"] == len(payload)
        assert baseline["registered_at"] == handle.registered_at
        assert baseline["source_path"] == str(src.resolve())

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
    def test_register_chmods_copy_read_only(self, manager, case, known_file):
        src, _, _ = known_file
        handle = manager.register(case.id, str(src))
        mode = stat.S_IMODE(handle.original_path.stat().st_mode)
        assert mode == 0o444

    def test_register_does_not_touch_source(self, manager, case, known_file):
        src, payload, _ = known_file
        before_mtime = src.stat().st_mtime
        before_content = src.read_bytes()
        manager.register(case.id, str(src))
        assert src.read_bytes() == before_content == payload
        assert src.stat().st_mtime == before_mtime

    @requires_symlinks
    def test_register_rejects_symlink(self, manager, case, known_file, tmp_path):
        src, _, _ = known_file
        link = tmp_path / "link_to_evidence.raw"
        link.symlink_to(src)
        with pytest.raises(ValueError, match="symlink"):
            manager.register(case.id, str(link))

    def test_register_rejects_nonexistent_path(self, manager, case, tmp_path):
        with pytest.raises(FileNotFoundError):
            manager.register(case.id, str(tmp_path / "does-not-exist.raw"))

    def test_register_rejects_directory(self, manager, case, tmp_path):
        d = tmp_path / "a_dir"
        d.mkdir()
        with pytest.raises(ValueError, match="not a regular file"):
            manager.register(case.id, str(d))

    def test_register_rejects_empty_source_path(self, manager, case):
        with pytest.raises(ValueError, match="source_path"):
            manager.register(case.id, "")

    def test_register_unknown_case_id_raises(self, manager, known_file):
        src, _, _ = known_file
        # Well-formed UUID4 but no such case on disk -> KeyError from case_dir().
        with pytest.raises(KeyError):
            manager.register("11111111-1111-4111-8111-111111111111", str(src))


class TestHashGateCleanup:
    def test_corrupted_copy_raises_ioerror_and_cleans_up(
        self, manager, cases, case, known_file, monkeypatch
    ):
        """If shutil.copy2 produces a file whose hash does not match the source,
        register() must raise IOError AND leave no orphan evidence directory.
        """
        src, _, _ = known_file
        real_copy2 = shutil.copy2

        def corrupting_copy2(s, d, *args, **kwargs):
            # Run the real copy, then overwrite the destination with bad bytes so
            # the re-hash step trips the mismatch branch.
            real_copy2(s, d, *args, **kwargs)
            with open(d, "wb") as fh:
                fh.write(b"CORRUPTED")
            return d

        # Patch the symbol the evidence module actually calls.
        import forensia.evidence as ev

        monkeypatch.setattr(ev.shutil, "copy2", corrupting_copy2)

        before_dirs = set((cases.root / case.id / "evidence").iterdir())
        with pytest.raises(IOError, match="hash mismatch"):
            manager.register(case.id, str(src))
        after_dirs = set((cases.root / case.id / "evidence").iterdir())
        # Orphan was cleaned up — directory set unchanged.
        assert before_dirs == after_dirs


class TestGetAndList:
    def test_get_unknown_evidence_id_raises_keyerror(self, manager, case):
        with pytest.raises(KeyError):
            manager.get(case.id, "11111111-1111-4111-8111-111111111111")

    def test_get_invalid_uuid_raises_valueerror(self, manager, case):
        with pytest.raises(ValueError, match="UUID4"):
            manager.get(case.id, "not-a-uuid")

    def test_list_returns_handles_sorted_desc(self, manager, case, tmp_path):
        srcs = []
        handles = []
        for n in range(3):
            src = tmp_path / f"e-{n}.raw"
            src.write_bytes(f"payload-{n}".encode())
            srcs.append(src)
            handles.append(manager.register(case.id, str(src)))
        listed = manager.list(case.id)
        # Every registered handle is listed exactly once...
        assert {h.evidence_id for h in listed} == {h.evidence_id for h in handles}
        # ...sorted newest-registered first. Asserting exact reverse-insertion order
        # would over-specify: registered_at has millisecond resolution, so handles
        # registered within the same tick legitimately share a stamp and the sort
        # makes no promise about their relative order.
        stamps = [h.registered_at for h in listed]
        assert stamps == sorted(stamps, reverse=True)

    def test_list_empty_case_returns_empty(self, manager, case):
        assert manager.list(case.id) == []


class TestVerify:
    def test_verify_true_when_untouched(self, manager, case, known_file):
        src, _, _ = known_file
        handle = manager.register(case.id, str(src))
        assert manager.verify(case.id, handle.evidence_id) is True

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod semantics differ")
    def test_verify_false_when_copy_mutated(self, manager, case, known_file):
        src, _, _ = known_file
        handle = manager.register(case.id, str(src))
        # Unlock and tamper the immutable copy to simulate corruption / tampering.
        import os

        os.chmod(handle.original_path, 0o644)
        handle.original_path.write_bytes(b"TAMPERED-CONTENT")
        os.chmod(handle.original_path, 0o444)
        assert manager.verify(case.id, handle.evidence_id) is False
