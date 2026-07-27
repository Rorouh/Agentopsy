"""Multi-segment EWF (``.E01``) ingestion: the whole co-located segment set is
registered as ONE evidence, with the hash gate applied per segment IN ORDER and the
chain of custody attesting every file.

Why this exists: ``ewfmount`` reassembles an EWF image from its FIRST segment by
discovering the rest (``.E02`` … ``.E0N``) IN THE SAME DIRECTORY. Copying only the
``.E01`` (the old single-file behaviour) left the image truncated. ``register`` now
ingests the full set as ``original.E01`` … ``original.E0N`` (shared stem, so libewf
reassembles from ``original.E01``), and ``verify`` re-hashes every segment.

También cubre el INTAKE del set: la bandeja acepta SUBIR cualquier segmento EWF
(las continuaciones ``.E02`` … no están en ``SUPPORTED_EVIDENCE_EXTENSIONS``, pero
sin ellas no hay imagen que reensamblar), mientras que el punto de entrada
REGISTRABLE sigue siendo solo el primer segmento.

No docker / no real ``ewfmount`` needed — this pins the ingestion + custody contract
of ``EvidenceManager``. The mount/assembly mechanism itself lives in
``test_ewf_routing.py``.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import sys

import pytest
from _symlink_support import requires_symlinks

from forensia.cases.manager import CaseManager
from forensia.evidence import (
    EvidenceManager,
    _ewf_segment_index,
    _is_ewf_first_segment,
    _is_ewf_middle_segment,
    is_registrable_evidence_ext,
    is_uploadable_evidence_ext,
    save_uploaded_source,
)


@pytest.fixture
def cases(tmp_path) -> CaseManager:
    return CaseManager(root=tmp_path / "cases")


@pytest.fixture
def manager(cases) -> EvidenceManager:
    return EvidenceManager(cases)


@pytest.fixture
def case(cases):
    return cases.create(name="op", examiner="alice", os_profile="unix")


def _ewf_ext(first_ext: str, index: int) -> str:
    """The extension for segment ``index`` of the same scheme as ``first_ext``
    (``.E01`` → ``.E{index:02d}``; ``.Ex01`` → ``.Ex{index:02d}``). Tests stay within
    the numeric range (index ≤ 99)."""
    prefix = first_ext[:-2]  # ".E" or ".Ex"
    return f"{prefix}{index:02d}"


def _write_ewf_set(directory, stem: str, count: int, *, first_ext: str = ".E01"):
    """Create ``stem.E01`` … ``stem.E0<count>`` with DISTINCT content. Returns the
    list of source paths in segment order."""
    paths = []
    for i in range(1, count + 1):
        seg = directory / f"{stem}{_ewf_ext(first_ext, i)}"
        seg.write_bytes(f"EWF-{stem}-segment-{i:02d}-payload".encode())
        paths.append(seg)
    return paths


def _evidence_dirs(cases: CaseManager, case_id: str) -> set:
    root = cases.root / case_id / "evidence"
    return set(root.iterdir()) if root.is_dir() else set()


# ── pure helpers ─────────────────────────────────────────────────────────────


class TestSegmentHelpers:
    @pytest.mark.parametrize(
        "suffix,index",
        [
            (".E01", 1), (".e01", 1), (".E02", 2), (".E09", 9), (".E10", 10),
            (".E99", 99), (".EAA", 100), (".EAB", 101), (".EAZ", 125),
            (".EBA", 126), (".EZZ", 775), (".Ex01", 1), (".Ex42", 42),
        ],
    )
    def test_index_of_valid_segment(self, suffix, index):
        assert _ewf_segment_index(suffix) == index

    @pytest.mark.parametrize("suffix", [".E00", ".raw", ".vmdk", ".E1", ".E123", ".mem", ""])
    def test_index_of_non_segment_is_none(self, suffix):
        assert _ewf_segment_index(suffix) is None

    @pytest.mark.parametrize("suffix", [".E01", ".e01", ".Ex01", ".EX01"])
    def test_is_first_segment(self, suffix):
        assert _is_ewf_first_segment(suffix)
        assert not _is_ewf_middle_segment(suffix)

    @pytest.mark.parametrize("suffix", [".E02", ".E99", ".EAA", ".Ex02"])
    def test_is_middle_segment(self, suffix):
        assert _is_ewf_middle_segment(suffix)
        assert not _is_ewf_first_segment(suffix)

    @pytest.mark.parametrize("suffix", [".raw", ".vmdk", ".dd", ".mem", ""])
    def test_non_ewf_is_neither(self, suffix):
        assert not _is_ewf_first_segment(suffix)
        assert not _is_ewf_middle_segment(suffix)


# ── the complete-set happy path (acceptance) ─────────────────────────────────


class TestMultiSegmentRegister:
    def test_full_set_copies_every_segment_colocated(self, manager, cases, case, tmp_path):
        srcs = _write_ewf_set(tmp_path, "LoneWolf", 3)
        handle = manager.register(case.id, str(srcs[0]))

        evidence_dir = handle.original_path.parent
        # All three segments are copied, co-located, under the shared ``original``
        # stem — this is what lets ``ewfmount original.E01`` reassemble the image.
        for i in range(1, 4):
            copy = evidence_dir / f"original{_ewf_ext('.E01', i)}"
            assert copy.is_file()
            assert copy.read_bytes() == srcs[i - 1].read_bytes()
        # The handle points at the FIRST segment (the token ``ewfmount`` is given).
        assert handle.original_path.name == "original.E01"

    def test_baseline_records_the_whole_segment_set(self, manager, case, tmp_path):
        srcs = _write_ewf_set(tmp_path, "disk", 3)
        handle = manager.register(case.id, str(srcs[0]))

        baseline = json.loads(
            (handle.original_path.parent / "baseline.json").read_text()
        )
        segments = baseline["segments"]
        assert [s["name"] for s in segments] == [
            "original.E01", "original.E02", "original.E03"
        ]
        # Each segment carries its OWN baseline hash + size, in order.
        for src, seg in zip(srcs, segments, strict=True):
            payload = src.read_bytes()
            assert seg["sha256"] == hashlib.sha256(payload).hexdigest()
            assert seg["size"] == len(payload)
        # Primary sha256 == the .E01's hash (audit / metadata single-value contract).
        assert baseline["sha256"] == segments[0]["sha256"]

    def test_handle_and_metadata_expose_segments(self, manager, case, tmp_path):
        srcs = _write_ewf_set(tmp_path, "disk", 3)
        handle = manager.register(case.id, str(srcs[0]))

        assert [s.name for s in handle.segments] == [
            "original.E01", "original.E02", "original.E03"
        ]
        meta = manager.metadata(case.id, handle.evidence_id)
        assert [s["name"] for s in meta["segments"]] == [
            "original.E01", "original.E02", "original.E03"
        ]
        assert meta["sha256"] == handle.segments[0].sha256

    def test_register_event_attests_every_segment(self, manager, cases, case, tmp_path):
        from forensia.audit.log import AuditLog

        srcs = _write_ewf_set(tmp_path, "disk", 3)
        handle = manager.register(case.id, str(srcs[0]))

        audit = AuditLog(cases.case_dir(case.id) / "audit.jsonl")
        register = next(
            e for e in audit.entries()
            if e.get("action") == "evidence_register"
            and e.get("evidence_id") == handle.evidence_id
        )
        assert [s["name"] for s in register["segments"]] == [
            "original.E01", "original.E02", "original.E03"
        ]
        # The append-only chain still verifies with the extra segment records.
        assert audit.verify() is True

    def test_full_set_verifies_true_when_untouched(self, manager, case, tmp_path):
        srcs = _write_ewf_set(tmp_path, "disk", 4)
        handle = manager.register(case.id, str(srcs[0]))
        assert manager.verify(case.id, handle.evidence_id) is True

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
    def test_every_segment_copy_is_read_only(self, manager, case, tmp_path):
        srcs = _write_ewf_set(tmp_path, "disk", 3)
        handle = manager.register(case.id, str(srcs[0]))
        evidence_dir = handle.original_path.parent
        for i in range(1, 4):
            copy = evidence_dir / f"original{_ewf_ext('.E01', i)}"
            assert stat.S_IMODE(copy.stat().st_mode) == 0o444

    def test_ex01_scheme_is_supported(self, manager, case, tmp_path):
        srcs = _write_ewf_set(tmp_path, "img", 3, first_ext=".Ex01")
        handle = manager.register(case.id, str(srcs[0]))
        evidence_dir = handle.original_path.parent
        assert handle.original_path.name == "original.Ex01"
        for i in range(1, 4):
            assert (evidence_dir / f"original{_ewf_ext('.Ex01', i)}").is_file()


# ── RULE 2: a broken / partial set is refused, registering nothing ───────────


class TestIncompleteSetRejected:
    def test_gap_in_sequence_is_rejected_and_registers_nothing(
        self, manager, cases, case, tmp_path
    ):
        # E01 and E03 present, E02 missing — a hole in the middle.
        (tmp_path / "disk.E01").write_bytes(b"segment-1")
        (tmp_path / "disk.E03").write_bytes(b"segment-3")

        before = _evidence_dirs(cases, case.id)
        with pytest.raises(ValueError, match="incompleto|faltan"):
            manager.register(case.id, str(tmp_path / "disk.E01"))
        # Nothing was registered — no orphan evidence directory left behind.
        assert _evidence_dirs(cases, case.id) == before
        assert manager.list(case.id) == []

    def test_registering_a_middle_segment_alone_is_rejected(
        self, manager, cases, case, tmp_path
    ):
        _write_ewf_set(tmp_path, "disk", 3)
        before = _evidence_dirs(cases, case.id)
        with pytest.raises(ValueError, match="non-first EWF segment"):
            manager.register(case.id, str(tmp_path / "disk.E02"))
        assert _evidence_dirs(cases, case.id) == before

    @requires_symlinks
    def test_symlinked_segment_is_refused(self, manager, cases, case, tmp_path):
        (tmp_path / "disk.E01").write_bytes(b"segment-1")
        real = tmp_path / "elsewhere.bin"
        real.write_bytes(b"segment-2")
        (tmp_path / "disk.E02").symlink_to(real)

        before = _evidence_dirs(cases, case.id)
        with pytest.raises(ValueError, match="symlink"):
            manager.register(case.id, str(tmp_path / "disk.E01"))
        assert _evidence_dirs(cases, case.id) == before


# ── lone .E01 stays valid (single segment) ───────────────────────────────────


class TestLoneFirstSegment:
    def test_lone_e01_registers_as_single_segment(self, manager, case, tmp_path):
        src = tmp_path / "solo.E01"
        payload = b"a-single-standalone-ewf-segment"
        src.write_bytes(payload)

        handle = manager.register(case.id, str(src))
        assert handle.original_path.name == "original.E01"
        assert [s.name for s in handle.segments] == ["original.E01"]
        assert handle.sha256 == hashlib.sha256(payload).hexdigest()
        assert manager.verify(case.id, handle.evidence_id) is True


# ── a single non-EWF file behaves exactly as before (no regression) ──────────


class TestSingleFileNoRegression:
    def test_raw_file_has_no_segments_and_same_shape(self, manager, case, tmp_path):
        src = tmp_path / "disk.raw"
        payload = b"Agentopsy-EVIDENCE-PAYLOAD-12345"
        src.write_bytes(payload)

        handle = manager.register(case.id, str(src))
        assert handle.original_path.name == "original.raw"
        # No segment tracking for a single-file evidence — exactly as before.
        assert handle.segments == ()
        baseline = json.loads(
            (handle.original_path.parent / "baseline.json").read_text()
        )
        assert "segments" not in baseline
        assert handle.sha256 == hashlib.sha256(payload).hexdigest()
        meta = manager.metadata(case.id, handle.evidence_id)
        assert meta["segments"] == []
        assert manager.verify(case.id, handle.evidence_id) is True


# ── verify re-hashes the WHOLE set (a changed non-first segment fails) ────────


class TestVerifyWholeSet:
    def test_missing_segment_after_register_is_surfaced(self, manager, case, tmp_path):
        srcs = _write_ewf_set(tmp_path, "disk", 3)
        handle = manager.register(case.id, str(srcs[0]))
        # Delete a NON-first segment copy (clear read-only first, cross-platform).
        victim = handle.original_path.parent / "original.E02"
        os.chmod(victim, 0o666)
        victim.unlink()
        # get() (and therefore verify()) refuses an evidence with a missing segment.
        with pytest.raises(KeyError, match="segment missing"):
            manager.get(case.id, handle.evidence_id)

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod semantics differ")
    def test_tampered_non_first_segment_fails_verify(self, manager, case, tmp_path):
        srcs = _write_ewf_set(tmp_path, "disk", 3)
        handle = manager.register(case.id, str(srcs[0]))
        # The .E01 is intact; a later segment is tampered. Verify must FAIL — a set
        # is only sound if EVERY segment matches its baseline.
        victim = handle.original_path.parent / "original.E03"
        os.chmod(victim, 0o644)
        victim.write_bytes(b"TAMPERED-SEGMENT-CONTENT")
        os.chmod(victim, 0o444)
        assert manager.verify(case.id, handle.evidence_id) is False


# ── intake: SUBIR el conjunto ≠ REGISTRAR el punto de entrada ────────────────
#
# La bandeja necesita TODOS los segmentos de un EWF partido (si falta uno,
# ``ewfmount`` no reensambla la imagen), así que las continuaciones son subibles
# aunque no estén en ``SUPPORTED_EVIDENCE_EXTENSIONS``. Registrable sigue siendo
# solo el PRIMER segmento (o un formato single-file): registrar una continuación
# suelta lo rechaza ``register`` (RULE 2).


class TestIntakePredicates:
    @pytest.mark.parametrize(
        "ext", [".raw", ".dd", ".vmdk", ".mem", ".e01", ".E01", ".Ex01"]
    )
    def test_single_file_and_first_segment_are_uploadable_and_registrable(self, ext):
        assert is_uploadable_evidence_ext(ext)
        assert is_registrable_evidence_ext(ext)

    @pytest.mark.parametrize("ext", [".E02", ".e02", ".E09", ".E99", ".Ex02"])
    def test_numeric_continuation_segments_are_uploadable_but_not_registrable(self, ext):
        assert is_uploadable_evidence_ext(ext)
        assert not is_registrable_evidence_ext(ext)

    @pytest.mark.parametrize("ext", [".txt", ".pdf", ".exe", ".eml", ".E00", ".E1", ""])
    def test_unsupported_extensions_are_neither(self, ext):
        assert not is_uploadable_evidence_ext(ext)
        assert not is_registrable_evidence_ext(ext)

    @pytest.mark.parametrize("ext", [".EAA", ".EZZ", ".eaa"])
    def test_alpha_continuation_is_not_uploadable_on_its_own(self, ext):
        # Suelta, ``.EAA`` no se distingue de una extensión corriente que empiece
        # por «e» (.exe, .eml…): admitirla convertiría la bandeja en un buzón de
        # ficheros arbitrarios. Un set de >99 segmentos se deposita copiándolo a
        # ./evidence en el host; el descubrimiento del set sí la contempla
        # (``_ewf_segment_index`` la indexa dentro de un set anclado en su .E01).
        assert not is_uploadable_evidence_ext(ext)
        assert not is_registrable_evidence_ext(ext)
        assert _ewf_segment_index(ext) is not None


class TestUploadSegmentSet:
    @pytest.fixture
    def inbox(self, tmp_path, monkeypatch):
        root = tmp_path / "inbox"
        root.mkdir()
        monkeypatch.setenv("FORENSIA_EVIDENCE_DIR", str(root))
        return root

    def _upload(self, name: str, payload: bytes) -> dict:
        return save_uploaded_source(name, io.BytesIO(payload))

    @pytest.mark.parametrize(
        "name",
        ["caso.E02", "caso.E09", "caso.E99", "caso.Ex02", "caso.e03", "disco.raw"],
    )
    def test_uploadable_names_land_in_the_inbox(self, inbox, name):
        entry = self._upload(name, b"payload")
        assert entry["name"] == name
        assert (inbox / name).read_bytes() == b"payload"

    def test_whole_segment_set_can_be_uploaded_then_registered(
        self, inbox, manager, case
    ):
        # El camino del perito: sube los 3 segmentos desde el navegador y luego
        # registra el .E01 — que ingiere el set completo.
        for i in range(1, 4):
            self._upload(f"LoneWolf.E{i:02d}", f"segmento-{i}".encode())
        handle = manager.register(case.id, str(inbox / "LoneWolf.E01"))
        assert [s.name for s in handle.segments] == [
            "original.E01",
            "original.E02",
            "original.E03",
        ]

    def test_unsupported_extension_is_still_rejected(self, inbox):
        with pytest.raises(ValueError, match="Formato no soportado"):
            self._upload("notas.txt", b"nope")
        assert list(inbox.iterdir()) == []

    def test_duplicate_name_never_overwrites(self, inbox):
        self._upload("caso.E02", b"original")
        with pytest.raises(FileExistsError):
            self._upload("caso.E02", b"nuevo")
        assert (inbox / "caso.E02").read_bytes() == b"original"

    def test_traversal_in_a_segment_name_is_rejected(self, inbox, tmp_path):
        with pytest.raises(ValueError, match="no válido"):
            self._upload("../fuera.E02", b"x")
        assert not (tmp_path / "fuera.E02").exists()
