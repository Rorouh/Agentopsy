"""Acquisition metadata + acta de adquisición (custody act).

Gates that matter: the metadata is HONEST about the read-only level (``fs``, not
block-level — RULE 2); the acta is built purely from ``baseline.json`` + the
``evidence_register`` audit event, carries the chain-of-custody ``entry_hash``,
and reports whether the hash chain verifies; failure modes are loud (unknown
case/evidence → KeyError, malformed id → ValueError).
"""

from __future__ import annotations

import hashlib

import pytest

from forensia.audit.log import AuditLog
from forensia.cases.manager import CaseManager
from forensia.custody import build_custody_act
from forensia.evidence import (
    READ_ONLY_LEVEL,
    EvidenceManager,
    human_readable_size,
)


@pytest.fixture
def cases(tmp_path) -> CaseManager:
    return CaseManager(root=tmp_path / "cases")


@pytest.fixture
def manager(cases) -> EvidenceManager:
    return EvidenceManager(cases)


@pytest.fixture
def case(cases):
    return cases.create(name="Murcielago", examiner="Daniel Ramos", os_profile="unix")


@pytest.fixture
def known_file(tmp_path):
    src = tmp_path / "disk.raw"
    payload = b"FORENSIA-EVIDENCE-PAYLOAD-12345" * 40
    src.write_bytes(payload)
    return src, payload, hashlib.sha256(payload).hexdigest()


# ── human_readable_size ──────────────────────────────────────────────────────


class TestHumanReadableSize:
    @pytest.mark.parametrize(
        "size,expected",
        [
            (0, "0 B"),
            (512, "512 B"),
            (1024, "1.0 KB"),
            (1536, "1.5 KB"),
            (1024 * 1024, "1.0 MB"),
            (5 * 1024**3, "5.0 GB"),
        ],
    )
    def test_formats(self, size, expected):
        assert human_readable_size(size) == expected

    def test_rejects_negative(self):
        with pytest.raises(ValueError, match="non-negative"):
            human_readable_size(-1)


# ── metadata ─────────────────────────────────────────────────────────────────


class TestMetadata:
    def test_metadata_reports_baseline_and_honest_read_only_level(
        self, manager, case, known_file
    ):
        src, payload, sha = known_file
        handle = manager.register(case.id, str(src))
        meta = manager.metadata(case.id, handle.evidence_id)

        assert meta["evidence_id"] == handle.evidence_id
        assert meta["case_id"] == case.id
        assert meta["sha256"] == sha
        assert meta["size_bytes"] == len(payload)
        assert meta["size_human"] == human_readable_size(len(payload))
        assert meta["registered_at"] == handle.registered_at
        # RULE 2: read-only level is the level actually enforced (fs / chmod),
        # never an over-claimed "block".
        assert meta["read_only_level"] == READ_ONLY_LEVEL == "fs"
        assert "chmod 0444" in meta["read_only_label"]
        assert "bloque" in meta["read_only_label"]  # mentions block-level is pending
        # No verification run yet.
        assert meta["verification"] is None

    def test_metadata_reflects_verification_after_verify(
        self, manager, case, known_file
    ):
        src, _, sha = known_file
        handle = manager.register(case.id, str(src))
        assert manager.verify(case.id, handle.evidence_id) is True
        meta = manager.metadata(case.id, handle.evidence_id)
        assert meta["verification"] is not None
        assert meta["verification"]["verified"] is True
        assert meta["verification"]["current_sha256"] == sha

    def test_metadata_unknown_evidence_raises_keyerror(self, manager, case):
        with pytest.raises(KeyError):
            manager.metadata(case.id, "11111111-1111-4111-8111-111111111111")

    def test_metadata_malformed_id_raises_valueerror(self, manager, case):
        with pytest.raises(ValueError, match="UUID4"):
            manager.metadata(case.id, "not-a-uuid")


# ── build_custody_act ────────────────────────────────────────────────────────


class TestCustodyAct:
    def test_acta_is_built_from_baseline_and_audit(
        self, cases, manager, case, known_file
    ):
        src, payload, sha = known_file
        handle = manager.register(case.id, str(src))

        acta = build_custody_act(case.id, handle.evidence_id, cases=cases, evidence=manager)

        # Case identity + examiner.
        assert acta["case"]["id"] == case.id
        assert acta["case"]["examiner"] == "Daniel Ramos"
        assert acta["case"]["os_profile"] == "unix"

        # Evidence facts come straight from the baseline / register event.
        ev = acta["evidence"]
        assert ev["evidence_id"] == handle.evidence_id
        assert ev["sha256"] == sha
        assert ev["size_bytes"] == len(payload)
        assert ev["source_path"] == str(src.resolve())
        assert ev["original_basename"] == "original.raw"
        assert ev["registered_at"] == handle.registered_at

        # Read-only level is honest.
        assert acta["read_only"]["level"] == "fs"

        # Tool identity.
        assert acta["tool"]["name"] == "FORENSIA"
        assert acta["tool"]["version"]

        # Chain of custody: the register event's entry_hash is a real 64-hex
        # digest and the whole chain verifies.
        coc = acta["chain_of_custody"]
        assert isinstance(coc["register_entry_hash"], str)
        assert len(coc["register_entry_hash"]) == 64
        assert coc["hash_chain_verified"] is True

    def test_acta_entry_hash_matches_the_audit_log(
        self, cases, manager, case, known_file
    ):
        src, _, _ = known_file
        handle = manager.register(case.id, str(src))
        acta = build_custody_act(case.id, handle.evidence_id, cases=cases, evidence=manager)

        audit = AuditLog(cases.case_dir(case.id) / "audit.jsonl")
        register = next(
            e
            for e in audit.entries()
            if e["action"] == "evidence_register"
            and e["evidence_id"] == handle.evidence_id
        )
        assert acta["chain_of_custody"]["register_entry_hash"] == register["entry_hash"]
        assert acta["chain_of_custody"]["register_prev_hash"] == register["prev_hash"]

    def test_acta_reports_broken_chain(self, cases, manager, case, known_file):
        src, _, _ = known_file
        handle = manager.register(case.id, str(src))
        # Tamper the append-only log: flip a byte in the middle so the chain no
        # longer verifies. The register entry_hash is still readable; the acta
        # must report hash_chain_verified=False rather than pretend it's intact.
        audit_path = cases.case_dir(case.id) / "audit.jsonl"
        lines = audit_path.read_text(encoding="utf-8").splitlines()
        lines.append('{"action":"tampered","prev_hash":"00","entry_hash":"deadbeef"}')
        audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        acta = build_custody_act(case.id, handle.evidence_id, cases=cases, evidence=manager)
        assert acta["chain_of_custody"]["hash_chain_verified"] is False
        # But the register link is still faithfully reported.
        assert len(acta["chain_of_custody"]["register_entry_hash"]) == 64

    def test_acta_unknown_evidence_raises_keyerror(self, cases, manager, case):
        with pytest.raises(KeyError):
            build_custody_act(
                case.id,
                "11111111-1111-4111-8111-111111111111",
                cases=cases,
                evidence=manager,
            )

    def test_acta_malformed_id_raises_valueerror(self, cases, manager, case):
        with pytest.raises(ValueError, match="UUID4"):
            build_custody_act(case.id, "not-a-uuid", cases=cases, evidence=manager)

    def test_acta_unknown_case_raises_keyerror(self, cases, manager):
        with pytest.raises(KeyError):
            build_custody_act(
                "22222222-2222-4222-8222-222222222222",
                "11111111-1111-4111-8111-111111111111",
                cases=cases,
                evidence=manager,
            )
