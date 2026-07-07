"""Auto-detección de SO: os_profile is DERIVED from the evidence content by
triage and routed automatically, escalating to the operator on ambiguity.

Covers (CLAUDE.md RULE 2 enmendada — determina por contenido, escala en
ambigüedad, nunca enruta en silencio):

- ``routable_profile`` predicate: only a confident content-based family routes.
- Confident single-OS evidence → case os_profile auto-set + routing decision
  audited (FORENSIC INVARIANT 4).
- Non-routable evidence (unknown / low confidence) → routing stays unresolved →
  ``resolve_os_profile`` fails loud (operator must anchor).
- Two confident, different OSs in one case → CONFLICT → escalate; the derived
  profile is cleared, the conflict audited.
- Operator anchor resolves the ambiguous/conflict state and is final (a later
  conflicting evidence never flips it).
"""

from __future__ import annotations

import json

import pytest

from forensia.cases.manager import (
    CaseManager,
    OsProfileUnresolved,
    resolve_os_profile,
)
from forensia.evidence import EvidenceManager
from forensia.triage import DetectedEvidence, routable_profile


# --- crafted evidence: minimal byte blobs that triage classifies deterministically.
def _windows_disk() -> bytes:
    data = bytearray(4096)
    data[3:11] = b"NTFS    "  # Phase-3 FS header → confidence "header"
    data += (
        b"Microsoft Windows"
        b"\\Windows\\System32"
        b"NTUSER.DAT"
        b"SOFTWARE\\Microsoft"
        b"BOOTMGR"
    )  # >= _MIN_HITS windows markers → family windows
    return bytes(data)


def _unix_disk() -> bytes:
    data = bytearray(0x440)
    data[0x438:0x43A] = b"\x53\xef"  # ext superblock magic → confidence "header"
    data += (
        b"/etc/passwd"
        b"/etc/shadow"
        b"/bin/bash"
        b"/usr/bin/"
        b"/var/log/syslog"
    )  # >= _MIN_HITS unix markers → family unix
    return bytes(data)


def _unclassifiable() -> bytes:
    # No FS/format header, no OS markers → family unknown, confidence none.
    return b"just some plain text with no os markers at all" * 4


@pytest.fixture
def cases(tmp_path) -> CaseManager:
    return CaseManager(root=tmp_path / "cases")


@pytest.fixture
def evidence(cases) -> EvidenceManager:
    return EvidenceManager(cases)


def _register(evidence, cases, case_id, tmp_path, name, blob) -> str:
    src = tmp_path / name
    src.write_bytes(blob)
    return evidence.register(case_id, str(src)).evidence_id


def _audit(cases, case_id) -> list[dict]:
    path = cases.case_dir(case_id) / "audit.jsonl"
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


# --------------------------------------------------------------------------- #
# routable_profile predicate
# --------------------------------------------------------------------------- #
class TestRoutablePredicate:
    @pytest.mark.parametrize("conf", ["header", "markers"])
    @pytest.mark.parametrize("family", ["unix", "windows"])
    def test_confident_family_is_routable(self, family, conf):
        assert routable_profile(DetectedEvidence(family, "disk", conf, ())) == family

    @pytest.mark.parametrize("conf", ["extension", "none"])
    def test_low_confidence_is_not_routable(self, conf):
        # A bare extension hint or no signal never routes on its own.
        assert routable_profile(DetectedEvidence("windows", "memory", conf, ())) is None

    def test_unknown_family_is_not_routable(self):
        assert routable_profile(DetectedEvidence("unknown", "disk", "header", ())) is None


# --------------------------------------------------------------------------- #
# confident single-OS evidence → auto-route
# --------------------------------------------------------------------------- #
class TestAutoRoute:
    def test_windows_evidence_auto_sets_profile(self, evidence, cases, tmp_path):
        case = cases.create(name="op", examiner="alice")  # no operator anchor
        assert case.os_profile is None
        _register(evidence, cases, case.id, tmp_path, "disk.raw", _windows_disk())

        reloaded = cases.load(case.id)
        assert reloaded.os_profile == "windows"
        assert reloaded.os_profile_source == "derived"
        # And routing resolves cleanly to that profile.
        assert resolve_os_profile(reloaded) == "windows"

    def test_routing_decision_is_audited(self, evidence, cases, tmp_path):
        case = cases.create(name="op", examiner="alice")
        eid = _register(evidence, cases, case.id, tmp_path, "disk.raw", _windows_disk())

        routed = [e for e in _audit(cases, case.id) if e.get("action") == "os_profile_routed"]
        assert len(routed) == 1
        entry = routed[0]
        assert entry["decision"] == "auto_set"
        assert entry["os_profile"] == "windows"
        assert entry["evidence_id"] == eid
        # The triage basis is recorded (family/confidence/signals) — custody.
        assert entry["family"] == "windows"
        assert entry["confidence"] == "header"
        assert isinstance(entry["signals"], list) and entry["signals"]

    def test_second_same_os_evidence_is_noop(self, evidence, cases, tmp_path):
        case = cases.create(name="op", examiner="alice")
        _register(evidence, cases, case.id, tmp_path, "d1.raw", _windows_disk())
        _register(evidence, cases, case.id, tmp_path, "d2.raw", _windows_disk())
        reloaded = cases.load(case.id)
        assert reloaded.os_profile == "windows"
        assert reloaded.os_profile_source == "derived"
        # Only the first evidence produced a routing decision.
        routed = [e for e in _audit(cases, case.id) if e.get("action") == "os_profile_routed"]
        assert len(routed) == 1


# --------------------------------------------------------------------------- #
# ambiguity always escalates — never routes silently
# --------------------------------------------------------------------------- #
class TestEscalation:
    def test_unclassifiable_evidence_stays_unresolved(self, evidence, cases, tmp_path):
        case = cases.create(name="op", examiner="alice")
        _register(evidence, cases, case.id, tmp_path, "blob.bin", _unclassifiable())
        reloaded = cases.load(case.id)
        assert reloaded.os_profile is None
        assert reloaded.os_profile_source is None
        with pytest.raises(OsProfileUnresolved, match="sin determinar"):
            resolve_os_profile(reloaded)
        # Nothing was routed.
        assert not [e for e in _audit(cases, case.id) if e.get("action") == "os_profile_routed"]

    def test_two_different_os_is_a_conflict(self, evidence, cases, tmp_path):
        case = cases.create(name="op", examiner="alice")
        _register(evidence, cases, case.id, tmp_path, "win.raw", _windows_disk())
        _register(evidence, cases, case.id, tmp_path, "nix.raw", _unix_disk())

        reloaded = cases.load(case.id)
        assert reloaded.os_profile is None  # cleared — no silent single pick
        assert reloaded.os_profile_source == "conflict"
        with pytest.raises(OsProfileUnresolved, match="conflicto"):
            resolve_os_profile(reloaded)
        # The conflict is audited (after the initial auto_set for the 1st evidence).
        routed = [e for e in _audit(cases, case.id) if e.get("action") == "os_profile_routed"]
        assert [r["decision"] for r in routed] == ["auto_set", "conflict"]

    def test_conflict_survives_further_evidence(self, evidence, cases, tmp_path):
        # Once ambiguous, more evidence does NOT silently re-resolve it.
        case = cases.create(name="op", examiner="alice")
        _register(evidence, cases, case.id, tmp_path, "win.raw", _windows_disk())
        _register(evidence, cases, case.id, tmp_path, "nix.raw", _unix_disk())
        _register(evidence, cases, case.id, tmp_path, "nix2.raw", _unix_disk())
        reloaded = cases.load(case.id)
        assert reloaded.os_profile_source == "conflict"
        assert reloaded.os_profile is None


# --------------------------------------------------------------------------- #
# operator anchor — the one time the operator sets it
# --------------------------------------------------------------------------- #
class TestOperatorAnchor:
    def test_anchor_resolves_conflict_and_is_final(self, evidence, cases, tmp_path):
        case = cases.create(name="op", examiner="alice")
        _register(evidence, cases, case.id, tmp_path, "win.raw", _windows_disk())
        _register(evidence, cases, case.id, tmp_path, "nix.raw", _unix_disk())
        assert cases.load(case.id).os_profile_source == "conflict"

        anchored = cases.anchor_os_profile(case.id, "unix")
        assert anchored.os_profile == "unix"
        assert anchored.os_profile_source == "operator"
        assert resolve_os_profile(anchored) == "unix"

        # A further conflicting evidence must NOT flip the operator's decision.
        _register(evidence, cases, case.id, tmp_path, "win2.raw", _windows_disk())
        final = cases.load(case.id)
        assert final.os_profile == "unix"
        assert final.os_profile_source == "operator"

    def test_anchor_is_audited(self, evidence, cases, tmp_path):
        case = cases.create(name="op", examiner="alice")
        cases.anchor_os_profile(case.id, "windows")
        anchored = [e for e in _audit(cases, case.id) if e.get("action") == "os_profile_anchored"]
        assert len(anchored) == 1
        assert anchored[0]["os_profile"] == "windows"
        assert anchored[0]["by"] == "operator"

    def test_anchor_rejects_invalid_profile(self, cases):
        case = cases.create(name="op", examiner="alice")
        with pytest.raises(ValueError, match="os_profile"):
            cases.anchor_os_profile(case.id, "macos")

    def test_operator_anchor_at_creation_is_never_flipped(self, evidence, cases, tmp_path):
        # Anchoring at creation is honored and immune to conflicting evidence.
        case = cases.create(name="op", examiner="alice", os_profile="windows")
        _register(evidence, cases, case.id, tmp_path, "nix.raw", _unix_disk())
        reloaded = cases.load(case.id)
        assert reloaded.os_profile == "windows"
        assert reloaded.os_profile_source == "operator"
        # No routing decision was recorded — the operator's word is final.
        assert not [e for e in _audit(cases, case.id) if e.get("action") == "os_profile_routed"]
