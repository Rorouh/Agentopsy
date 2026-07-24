"""Evidence ingestion: hash gate + immutable copy under the owning case directory.

EvidenceManager is the SINGLE owner of evidence (CLAUDE.md forensic invariant 1).
Tools and agents never see the original ``.raw`` / ``.vmdk`` / dump path — they get
a handle that points to the read-only copy inside the case dir. The original on the
analyst's filesystem is never opened for write and never modified.

Hash gate, in strict order (forensic invariant 2):

    1. canonicalize ``source_path`` and refuse symlinks / non-files
    2. stream-hash the source                              (baseline)
    3. copy source -> case_dir/evidence/<eid>/original.<ext>
    4. stream-hash the copy and compare to baseline        (corruption check)
    5. chmod 0o444 the copy                                (read-only at FS level)
    6. write baseline.json
    7. append ``evidence_register`` to the case audit log  (forensic invariant 4)
    8. return the handle

Both ``register`` and ``verify`` write to the case's append-only, hash-chained
``audit.jsonl`` (forensic invariant 4): registration records the baseline hash +
source, verification records the on-demand result.

v1 read-only is enforced via ``chmod 0o444`` on the copy. This is the minimum and is
defeatable by root; Phase 2 will add block-level read-only (Linux ``blockdev --setro`` /
``losetup --read-only``, macOS ``hdiutil attach -readonly``, Windows ``Set-Disk -IsReadOnly``)
and re-verify at session close. The bundled toolkit binaries open evidence ``O_RDONLY``
either way — this layer is defense-in-depth, not the only line.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from forensia.audit.log import AuditLog
from forensia.cases import CaseManager, case_manager
from forensia.triage import DetectedKind, DetectedOS, fingerprint_evidence

logger = logging.getLogger(__name__)

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

_HASH_CHUNK = 1024 * 1024  # 1 MiB — evidence images run to tens of GB.
_READ_ONLY_MODE = 0o444

# Read-only enforcement level actually applied by ``register`` (step 6 below).
# This is the HONEST label the metadata / acquisition-act surfaces show: v1 is
# filesystem-level only (``chmod 0o444``); block-level read-only is Phase 2 and
# is NOT implemented (see the module docstring). RULE 2 — never advertise a
# guarantee we don't enforce.
READ_ONLY_LEVEL = "fs"
READ_ONLY_LEVEL_LABELS: dict[str, str] = {
    "fs": (
        "Solo lectura a nivel de sistema de ficheros (chmod 0444); "
        "bloqueo a nivel de bloque pendiente (Fase 2)"
    ),
}


def human_readable_size(size: int) -> str:
    """Bytes → short human string (``1.5 GB``). Base-1024, one decimal above KB.

    Pure presentation helper; the authoritative value is always ``size`` in bytes.
    """
    if not isinstance(size, int) or size < 0:
        raise ValueError(f"size must be a non-negative int, got {size!r}")
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    if size == 0:
        return "0 B"
    exp = 0
    value = float(size)
    while value >= 1024 and exp < len(units) - 1:
        value /= 1024
        exp += 1
    return f"{int(value)} {units[exp]}" if exp == 0 else f"{value:.1f} {units[exp]}"


@dataclass(frozen=True)
class VerificationRecord:
    """Last on-demand verification result, persisted to ``verification.json``.

    Forensemente, una verificación es un evento timestamped — el examinador
    necesita poder responder "verifiqué este artefacto el día X con resultado
    Y" sin reabrir la app. Por eso se persiste junto al ``baseline.json`` y
    además se apenda al ``audit.jsonl`` del caso (cadena hash-chained).
    """

    verified_at: str
    verified: bool
    current_sha256: str


@dataclass(frozen=True)
class EvidenceSegment:
    """One file of a multi-segment evidence set (an EWF ``.E01`` split), with its
    own baseline hash + size. For a single-file evidence (``.raw`` / a lone ``.E01``)
    there is exactly one segment. The set is stored co-located under a shared
    ``original`` stem (``original.E01``, ``original.E02`` …) so ``ewfmount``
    reassembles the image from the first."""

    name: str
    sha256: str
    size: int


@dataclass(frozen=True)
class EvidenceHandle:
    evidence_id: str
    case_id: str
    original_path: Path
    sha256: str
    size: int
    registered_at: str
    last_verification: VerificationRecord | None = None
    # Triage fingerprint computed at registration (or backfilled lazily on the
    # first ``get()`` for evidence registered before this field existed). It is
    # the CONTENT-based signal the case os_profile is DERIVED from at
    # registration (``CaseManager.apply_detected_evidence`` — auto-detección de
    # SO, never the host platform). When the classification is not confident, or
    # a second evidence conflicts, routing escalates to the operator, who
    # anchors — never a silent pick (RULE 2 enmendada).
    detected_os: DetectedOS = "unknown"
    # Evidence shape — disk image, memory dump, container disk, or unknown.
    # The agent system prompt uses this to route to the right playbook section
    # (disk: TSK; memory: Volatility). Same persistence + lazy backfill as
    # detected_os; same RULE 2 guarantee — never auto-anything.
    detected_kind: DetectedKind = "unknown"
    # The copied files that back this evidence, each hash-gated at registration.
    # One entry for a single-file evidence; N for an EWF ``.E01`` set (in segment
    # order, ``original.E01`` … ``original.E0N``). Empty for legacy evidence
    # registered before segment tracking existed — ``verify`` then falls back to
    # the single ``original_basename`` from ``baseline.json``.
    segments: tuple[EvidenceSegment, ...] = ()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _validate_evidence_id(evidence_id: str) -> str:
    if not isinstance(evidence_id, str):
        raise ValueError(
            f"evidence_id must be a string, got {type(evidence_id).__name__}"
        )
    if not _UUID4_RE.match(evidence_id):
        raise ValueError(f"evidence_id is not a valid UUID4: {evidence_id!r}")
    return evidence_id


def _sha256_file(path: Path) -> tuple[str, int]:
    """Stream-hash ``path`` in chunks. Returns ``(hex_digest, size_bytes)``.

    Never use ``Path.read_bytes()`` here — evidence images are routinely multi-GB.
    """
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_HASH_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


# ── EWF multi-segment sets ───────────────────────────────────────────────────
# Expert Witness Format (EnCase ``.E01`` / libewf) splits a disk image into
# SEGMENTS: ``<stem>.E01``, ``.E02`` … ``.E99``, then ``.EAA``, ``.EAB`` … (and the
# EWF2 ``.Ex01`` / ``.Ex02`` … scheme). Only the FIRST segment carries the ``.E01``
# extension; the rest hold the raw bytes that continue the image. ``ewfmount``
# reassembles the WHOLE image from the first segment, DISCOVERING the others by this
# naming convention IN THE SAME DIRECTORY. So registering ONLY the ``.E01`` (the old
# single-file copy) leaves ``ewfmount`` unable to assemble the image — it reads
# truncated. We copy the whole co-located set, renamed to a shared ``original`` stem
# (``original.E01``, ``original.E02`` …), so libewf reassembles from ``original.E01``.

# Matches ONLY a first segment (``.E01`` / ``.e01`` / ``.Ex01`` / ``.ex01``).
_EWF_FIRST_RE = re.compile(r"^\.(ex?)01$", re.IGNORECASE)
# Matches ANY EWF segment extension: the ``E`` (or EWF2 ``Ex``) prefix + a 2-char
# tail that is either 2 digits (``01`` … ``99``) or 2 letters (``AA`` … ``ZZ``).
_EWF_ANY_RE = re.compile(r"^\.(ex?)(\d{2}|[a-z]{2})$", re.IGNORECASE)
# The 2-char tail addresses 99 (numeric) + 26*26 (alpha) = 775 segments; past that
# libewf bumps the leading letter (``F..``), which no real acquisition reaches. We
# refuse a set beyond this rather than guess an extension scheme we do not model.
_EWF_MAX_SEGMENTS = 99 + 26 * 26  # 775


def _ewf_segment_index(suffix: str) -> int | None:
    """1-based segment index for an EWF extension (``.E01`` → 1 … ``.EAA`` → 100),
    or ``None`` when ``suffix`` is not a valid EWF segment extension.

    The tail is either two digits (``01`` … ``99`` → 1 … 99) or two letters
    (``AA`` → 100, ``AB`` → 101 … ``ZZ`` → 774), mirroring the EnCase/libewf
    continuation. Independent of the ``E`` vs ``Ex`` scheme (both share the tail).
    """
    match = _EWF_ANY_RE.match(suffix)
    if match is None:
        return None
    tail = match.group(2)
    if tail.isdigit():
        index = int(tail)
        return index if index >= 1 else None  # ``.E00`` is not a segment
    tail = tail.upper()
    return 99 + (ord(tail[0]) - ord("A")) * 26 + (ord(tail[1]) - ord("A")) + 1


def _is_ewf_first_segment(suffix: str) -> bool:
    return bool(_EWF_FIRST_RE.match(suffix))


def _is_ewf_middle_segment(suffix: str) -> bool:
    """A non-first EWF segment (``.E02`` … / ``.EAA`` … / ``.Ex02`` …). Registering
    one alone can never assemble the image; the register entry point rejects it."""
    return bool(_EWF_ANY_RE.match(suffix)) and not _is_ewf_first_segment(suffix)


def _discover_ewf_segment_set(first: Path) -> list[Path]:
    """The ordered, GAP-FREE EWF segment set co-located with ``first`` (a
    ``.E01`` / ``.Ex01``).

    Globs ``first``'s directory for every sibling sharing its stem and EWF scheme,
    maps each to its 1-based segment index, and requires the indices to be exactly
    ``{1, 2, … N}`` — a hole (e.g. ``.E01`` + ``.E03`` but no ``.E02``) is a broken
    set and RAISES ``ValueError`` (RULE 2: never register a partial set). A lone
    first segment returns ``[first]``. A symlinked segment is refused (SECURITY
    INVARIANT 6); every path stays inside ``first.parent`` (same directory), so the
    set cannot escape the source tree.
    """
    first_match = _EWF_FIRST_RE.match(first.suffix)
    if first_match is None:  # defensive — callers gate on ``_is_ewf_first_segment``
        raise ValueError(f"not an EWF first segment: {first.name!r}")
    scheme = first_match.group(1).lower()  # "e" or "ex"
    stem = first.stem
    parent = first.parent

    found: dict[int, Path] = {}
    for entry in parent.iterdir():
        if entry.stem != stem:
            continue
        any_match = _EWF_ANY_RE.match(entry.suffix)
        if any_match is None or any_match.group(1).lower() != scheme:
            continue
        index = _ewf_segment_index(entry.suffix)
        if index is None:
            continue
        # A would-be segment that is a symlink is refused (never followed): the
        # target could point outside the source dir / be swapped later.
        if entry.is_symlink():
            raise ValueError(
                f"EWF segment {entry.name!r} is a symlink — refusing (SECURITY "
                "INVARIANT 6). Provide the real, co-located segment files."
            )
        if not entry.is_file():
            continue
        if index in found:
            raise ValueError(
                f"duplicate EWF segment index {index}: {found[index].name!r} and "
                f"{entry.name!r} — ambiguous set, refusing (RULE 2)."
            )
        found[index] = entry

    if 1 not in found:
        # ``first`` is the ``.E01`` and exists, so this is defensive.
        raise ValueError(
            f"EWF first segment not found in its own directory: {first.name!r}"
        )
    top = max(found)
    if top > _EWF_MAX_SEGMENTS:
        raise ValueError(
            f"EWF set for {stem!r} has segment index {top}, beyond the supported "
            f"maximum ({_EWF_MAX_SEGMENTS}); refusing (RULE 2)."
        )
    missing = [i for i in range(1, top + 1) if i not in found]
    if missing:
        raise ValueError(
            f"EWF set incompleto para {stem!r}: faltan los segmentos {missing} "
            f"(presentes {sorted(found)}). Un conjunto EWF debe ser contiguo desde "
            ".E01; no se registra un set parcial (RULE 2)."
        )
    return [found[i] for i in range(1, top + 1)]


class EvidenceManager:
    """Registers evidence into a case and exposes hash-verified, read-only handles."""

    def __init__(self, cases: CaseManager) -> None:
        if cases is None:
            raise ValueError("EvidenceManager requires a CaseManager")
        self._cases = cases

    # ---- public API ---------------------------------------------------------

    def register(self, case_id: str, source_path: str) -> EvidenceHandle:
        if not isinstance(source_path, str) or not source_path.strip():
            raise ValueError("source_path must be a non-empty string")

        # 1. Validate the case exists (load() raises KeyError on bad id / missing
        #    case) and is still open — a closed case is a closed chain of custody;
        #    registering more evidence into it needs an explicit reopen first.
        case = self._cases.load(case_id)
        if case.status != "active":
            raise ValueError(
                f"case {case_id} is closed — reopen it (POST /api/cases/{case_id}"
                "/reopen) before registering evidence"
            )
        case_dir = self._cases.case_dir(case_id)

        # 2. Canonicalize source; reject if missing, non-file, or a symlink.
        #    Symlinks are refused because the target could point outside what the
        #    operator intended (and a hostile drop could swap the target later).
        src = Path(source_path)
        if src.is_symlink():
            raise ValueError(f"source_path is a symlink, refusing: {src}")
        src = src.resolve(strict=False)
        if not src.exists():
            raise FileNotFoundError(f"source_path does not exist: {src}")
        if not src.is_file():
            raise ValueError(f"source_path is not a regular file: {src}")
        if src.is_symlink():
            # ``resolve(strict=False)`` follows the link; re-check after.
            raise ValueError(f"source_path resolves to a symlink: {src}")

        # 2.bis Resolve the SEGMENT SET to ingest. Most evidence is a single file
        #    (``.raw`` / ``.vmdk`` / dump). An EWF ``.E01`` is the FIRST segment of a
        #    set that ``ewfmount`` reassembles from the whole co-located family — so
        #    registering the ``.E01`` must ingest ALL of ``.E01`` … ``.E0N`` as ONE
        #    evidence, or the image reads truncated. Discovery is gap-checked and runs
        #    BEFORE the evidence dir is created, so a broken/partial set leaves no
        #    orphan directory (RULE 2: fail loud, register nothing partial).
        suffix = src.suffix  # may be ""; that's fine
        if _is_ewf_first_segment(suffix):
            segment_sources = _discover_ewf_segment_set(src)
            is_multi_segment = True
        elif _is_ewf_middle_segment(suffix):
            raise ValueError(
                f"{src.name} is a non-first EWF segment. Register the first segment "
                f"of the set (…{suffix[:2]}01) instead — FORENSIA ingests the whole "
                "co-located set from it; a middle segment alone cannot assemble the "
                "image (RULE 2)."
            )
        else:
            segment_sources = [src]
            is_multi_segment = False

        evidence_root = case_dir / "evidence"
        evidence_root.mkdir(parents=True, exist_ok=True)

        evidence_id = str(uuid.uuid4())
        evidence_dir = (evidence_root / evidence_id).resolve()
        if self._cases.root not in evidence_dir.parents:
            # Belt-and-braces: confine inside the cases root.
            raise ValueError(f"evidence dir escapes cases root: {evidence_dir}")
        evidence_dir.mkdir(parents=True, exist_ok=False)

        # 3-6. Copy each segment with the hash gate IN ORDER (forensic invariant 2):
        #    per segment → sha256 the source (baseline) → copy → re-hash the copy →
        #    abort on any mismatch → chmod 0o444. Each segment keeps its own extension
        #    under the shared ``original`` stem (``original.E01`` … ``original.E0N``)
        #    so ``ewfmount`` reassembles the image from the first. A single-file
        #    evidence runs this loop exactly once — identical to the pre-set behaviour.
        #    Any failure (copy error OR hash mismatch) cleans up the half-built dir so
        #    a retry with a fixed source doesn't trip the existence check.
        segments: list[EvidenceSegment] = []
        try:
            for seg_src in segment_sources:
                dest = evidence_dir / f"original{seg_src.suffix}"
                src_sha, src_size = _sha256_file(seg_src)  # baseline for THIS segment
                shutil.copy2(seg_src, dest)
                copy_sha, copy_size = _sha256_file(dest)  # re-hash the copy
                if copy_sha != src_sha or copy_size != src_size:
                    raise OSError(  # noqa: TRY301 — cleanup happens in the handler below
                        f"evidence copy hash mismatch on {seg_src.name} — corruption "
                        f"during copy (source={src_sha} copy={copy_sha})"
                    )
                os.chmod(dest, _READ_ONLY_MODE)
                segments.append(
                    EvidenceSegment(name=dest.name, sha256=src_sha, size=src_size)
                )
        except OSError:
            shutil.rmtree(evidence_dir, ignore_errors=True)
            raise

        # The FIRST segment is the primary: its hash is the baseline the audit and the
        # metadata/custody-act key on (single-value contract preserved), and its copy
        # (``original.E01`` / ``original.<ext>``) is the handle's ``original_path``.
        primary = segments[0]
        baseline_sha, baseline_size = primary.sha256, primary.size
        dest = evidence_dir / primary.name

        # 7. Triage fingerprint over the already-frozen FIRST segment. Pure read, so it
        #    can run AFTER chmod 0o444. For an EWF set this is ``original.E01`` — triage
        #    returns container_disk/unknown (correct for EWF; the operator anchors the
        #    profile). We do this before writing baseline.json so the persisted record
        #    carries the triage axes from day one.
        triage = fingerprint_evidence(dest)

        registered_at = _utc_now_iso()
        # Segment records (dest name + own hash + size). Persisted only for a
        # multi-file (EWF) set — a single-file evidence keeps the legacy baseline
        # shape (no ``segments`` key), so ``.raw`` behaves exactly as before.
        segment_records = [
            {"name": s.name, "sha256": s.sha256, "size": s.size} for s in segments
        ]
        baseline = {
            "sha256": baseline_sha,
            "size": baseline_size,
            "registered_at": registered_at,
            "source_path": str(src),
            "original_basename": dest.name,
            "detected_os": triage.family,
            "detected_kind": triage.kind,
            "triage_confidence": triage.confidence,
            "triage_signals": list(triage.signals),
        }
        if is_multi_segment:
            baseline["segments"] = segment_records
        self._write_baseline(evidence_dir, baseline)

        # 8. Chain-of-custody event (forensic invariant 4): the baseline hash
        #    reaches the append-only audit log the moment the evidence exists,
        #    not only when it is later verified. Records what came in and from
        #    where — the literal source path, like baseline.json. For an EWF set the
        #    WHOLE segment family (names + per-segment hashes) is recorded, so the
        #    chain of custody attests every file that was ingested, not just the .E01.
        register_event = {
            "action": "evidence_register",
            "case_id": case_dir.name,
            "evidence_id": evidence_id,
            "sha256": baseline_sha,
            "size": baseline_size,
            "source_path": str(src),
            "original_basename": dest.name,
            "registered_at": registered_at,
        }
        if is_multi_segment:
            register_event["segments"] = segment_records
        AuditLog(case_dir / "audit.jsonl").append(register_event)

        # 9. Auto-detección de SO: derive the case's os_profile from THIS
        #    evidence's content-based triage (never the host platform). The
        #    CaseManager owns case.json and the transition rules (auto-set /
        #    conflict / no-op) and records the routing decision in the same
        #    append-only audit log. A non-routable evidence (unknown / low
        #    confidence) is a no-op here — routing stays unresolved until a
        #    routable evidence arrives or the operator anchors (RULE 2).
        self._cases.apply_detected_evidence(case_dir.name, triage, evidence_id)

        return EvidenceHandle(
            evidence_id=evidence_id,
            case_id=case_dir.name,
            original_path=dest.resolve(),
            sha256=baseline_sha,
            size=baseline_size,
            registered_at=registered_at,
            detected_os=triage.family,
            detected_kind=triage.kind,
            # Mirror what ``get()`` reconstructs from baseline.json: the set for an
            # EWF evidence, empty for a single-file one (no ``segments`` key persisted).
            segments=tuple(segments) if is_multi_segment else (),
        )

    def get(self, case_id: str, evidence_id: str) -> EvidenceHandle:
        evidence_dir = self._evidence_dir(case_id, evidence_id)
        baseline = self._read_baseline(evidence_dir)
        original = evidence_dir / baseline["original_basename"]
        if not original.is_file():
            raise KeyError(
                f"evidence original missing for evidence_id={evidence_id}: {original}"
            )

        # Segment set (EWF ``.E01`` family), in order; empty for single-file / legacy
        # evidence. Every recorded segment file must still be on disk — a missing one
        # is a broken evidence set, surfaced now rather than at tool-run time.
        segments = tuple(
            EvidenceSegment(name=s["name"], sha256=s["sha256"], size=s["size"])
            for s in baseline.get("segments", [])
        )
        for seg in segments:
            if not (evidence_dir / seg.name).is_file():
                raise KeyError(
                    f"evidence segment missing for evidence_id={evidence_id}: "
                    f"{seg.name}"
                )

        # Lazy backfill: evidence registered before forensia.triage existed
        # may lack ``detected_os`` and/or ``detected_kind`` in baseline.json.
        # We re-run a single triage pass when either is missing, and persist
        # both at once so the next read is cheap. A failure to write back is
        # logged but not fatal — the in-memory handle still gets the values.
        detected_os: DetectedOS = baseline.get("detected_os", "unknown")
        detected_kind: DetectedKind = baseline.get("detected_kind", "unknown")
        needs_backfill = (
            "detected_os" not in baseline or "detected_kind" not in baseline
        )
        if needs_backfill:
            triage = fingerprint_evidence(original.resolve())
            detected_os = triage.family
            detected_kind = triage.kind
            baseline["detected_os"] = detected_os
            baseline["detected_kind"] = detected_kind
            baseline["triage_confidence"] = triage.confidence
            baseline["triage_signals"] = list(triage.signals)
            try:
                self._write_baseline(evidence_dir, baseline)
            except OSError as exc:
                logger.warning(
                    "triage backfill: failed to persist for %s: %s",
                    evidence_id, exc,
                )

        return EvidenceHandle(
            evidence_id=evidence_id,
            case_id=case_id,
            original_path=original.resolve(),
            sha256=baseline["sha256"],
            size=baseline["size"],
            registered_at=baseline["registered_at"],
            last_verification=self._read_verification(evidence_dir),
            detected_os=detected_os,
            detected_kind=detected_kind,
            segments=segments,
        )

    def list(self, case_id: str) -> list[EvidenceHandle]:
        case_dir = self._cases.case_dir(case_id)
        evidence_root = case_dir / "evidence"
        if not evidence_root.is_dir():
            return []
        handles: list[EvidenceHandle] = []
        for entry in evidence_root.iterdir():
            if not entry.is_dir():
                continue
            if not _UUID4_RE.match(entry.name):
                continue
            try:
                handles.append(self.get(case_id, entry.name))
            except (KeyError, OSError, json.JSONDecodeError, ValueError) as exc:
                logger.warning("skipping unreadable evidence at %s: %s", entry, exc)
        handles.sort(key=lambda h: h.registered_at, reverse=True)
        return handles

    def verify(self, case_id: str, evidence_id: str) -> bool:
        handle = self.get(case_id, evidence_id)
        evidence_dir = self._evidence_dir(case_id, evidence_id)

        # Re-hash EVERY file that backs the evidence. For an EWF set that is all of
        # ``original.E01`` … ``original.E0N`` — a change to ANY segment breaks the
        # chain of custody, so verification is the AND over the whole set (a
        # truncated/altered ``.E05`` must NOT pass just because ``.E01`` is intact).
        # Single-file / legacy evidence (no segments recorded) re-hashes the one
        # original file, exactly as before.
        segments = handle.segments or (
            EvidenceSegment(
                name=handle.original_path.name,
                sha256=handle.sha256,
                size=handle.size,
            ),
        )
        segment_results: list[dict] = []
        verified = True
        for seg in segments:
            seg_path = evidence_dir / seg.name
            if seg_path.is_file():
                cur_sha, cur_size = _sha256_file(seg_path)
                ok = cur_sha == seg.sha256 and cur_size == seg.size
            else:
                cur_sha, ok = "", False  # a missing segment fails custody, loudly
            verified = verified and ok
            segment_results.append(
                {"name": seg.name, "verified": ok, "current_sha256": cur_sha}
            )

        # Persist the result so it survives navigation / app restarts. The record
        # lives next to baseline.json and the same fact is hash-chained into the
        # case audit log so the perito can prove WHEN and WITH WHAT RESULT every
        # verification happened. The single-value record keeps the PRIMARY
        # (first-segment) current hash for the metadata/acta contract; ``verified``
        # reflects the WHOLE set.
        primary_current_sha = segment_results[0]["current_sha256"]
        record = VerificationRecord(
            verified_at=_utc_now_iso(),
            verified=verified,
            current_sha256=primary_current_sha,
        )
        self._write_verification(evidence_dir, record)

        case_dir = self._cases.case_dir(case_id)
        verify_event = {
            "action": "evidence_verify",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "verified": verified,
            "current_sha256": primary_current_sha,
            "baseline_sha256": handle.sha256,
        }
        if handle.segments:
            # Attest each segment's result so the audit shows WHICH one changed.
            verify_event["segments"] = segment_results
        AuditLog(case_dir / "audit.jsonl").append(verify_event)
        return verified

    def get_verification(self, case_id: str, evidence_id: str) -> VerificationRecord | None:
        evidence_dir = self._evidence_dir(case_id, evidence_id)
        return self._read_verification(evidence_dir)

    def metadata(self, case_id: str, evidence_id: str) -> dict:
        """Chain-of-custody metadata for ONE registered evidence, JSON-friendly.

        Surfaces what the UI needs to show honestly per evidence: the baseline
        ``sha256`` + size (bytes and a human string), when it was registered,
        the read-only level with a HONEST label (``fs`` today — Phase 2 adds
        block-level; RULE 2: we never claim block-level here), the triage axes,
        and the last on-demand verification if one exists. Unknown case /
        evidence raises ``KeyError``; a malformed id raises ``ValueError`` — the
        router maps these to 404 / 422 (never a silent empty answer, RULE 2).
        """
        handle = self.get(case_id, evidence_id)
        lv = handle.last_verification
        return {
            "evidence_id": handle.evidence_id,
            "case_id": handle.case_id,
            "original_basename": handle.original_path.name,
            "sha256": handle.sha256,
            "size_bytes": handle.size,
            "size_human": human_readable_size(handle.size),
            "registered_at": handle.registered_at,
            "read_only_level": READ_ONLY_LEVEL,
            "read_only_label": READ_ONLY_LEVEL_LABELS[READ_ONLY_LEVEL],
            "detected_os": handle.detected_os,
            "detected_kind": handle.detected_kind,
            # The segment set for an EWF ``.E01`` evidence (each file + its own
            # baseline hash + size); an empty list for a single-file evidence.
            "segments": [
                {
                    "name": s.name,
                    "sha256": s.sha256,
                    "size_bytes": s.size,
                    "size_human": human_readable_size(s.size),
                }
                for s in handle.segments
            ],
            "verification": (
                {
                    "verified_at": lv.verified_at,
                    "verified": lv.verified,
                    "current_sha256": lv.current_sha256,
                }
                if lv is not None
                else None
            ),
        }

    # ---- internals ----------------------------------------------------------

    def _evidence_dir(self, case_id: str, evidence_id: str) -> Path:
        case_dir = self._cases.case_dir(case_id)
        _validate_evidence_id(evidence_id)
        evidence_dir = (case_dir / "evidence" / evidence_id).resolve()
        if self._cases.root not in evidence_dir.parents:
            raise KeyError(f"evidence_id resolves outside cases root: {evidence_id}")
        if not evidence_dir.is_dir():
            raise KeyError(f"unknown evidence_id: {evidence_id}")
        return evidence_dir

    @staticmethod
    def _baseline_path(evidence_dir: Path) -> Path:
        return evidence_dir / "baseline.json"

    @staticmethod
    def _verification_path(evidence_dir: Path) -> Path:
        return evidence_dir / "verification.json"

    def _write_verification(
        self, evidence_dir: Path, record: VerificationRecord
    ) -> None:
        path = self._verification_path(evidence_dir)
        tmp = path.with_suffix(".json.tmp")
        payload = {
            "verified_at": record.verified_at,
            "verified": record.verified,
            "current_sha256": record.current_sha256,
        }
        tmp.write_text(
            json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8"
        )
        tmp.replace(path)

    def _read_verification(self, evidence_dir: Path) -> VerificationRecord | None:
        path = self._verification_path(evidence_dir)
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("ignoring unreadable verification.json at %s: %s", path, exc)
            return None
        required = {"verified_at", "verified", "current_sha256"}
        if not required <= data.keys():
            logger.warning("verification.json at %s missing required fields", path)
            return None
        if not isinstance(data["verified"], bool):
            return None
        return VerificationRecord(
            verified_at=data["verified_at"],
            verified=data["verified"],
            current_sha256=data["current_sha256"],
        )

    def _write_baseline(self, evidence_dir: Path, baseline: dict) -> None:
        path = self._baseline_path(evidence_dir)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(baseline, sort_keys=True, indent=2), encoding="utf-8"
        )
        tmp.replace(path)

    def _read_baseline(self, evidence_dir: Path) -> dict:
        path = self._baseline_path(evidence_dir)
        if not path.is_file():
            raise KeyError(f"baseline.json missing at {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        required = {"sha256", "size", "registered_at", "original_basename"}
        missing = required - data.keys()
        if missing:
            raise ValueError(f"baseline.json missing fields: {sorted(missing)}")
        if not isinstance(data["sha256"], str) or len(data["sha256"]) != 64:
            raise ValueError(f"baseline.json has invalid sha256: {data['sha256']!r}")
        if not isinstance(data["size"], int) or data["size"] < 0:
            raise ValueError(f"baseline.json has invalid size: {data['size']!r}")
        # ``segments`` is optional (only multi-file EWF sets have it). When present it
        # must be a non-empty list of well-formed records — a malformed list is our
        # own corruption and is surfaced loudly, never silently ignored (RULE 2).
        segments = data.get("segments")
        if segments is not None:
            if not isinstance(segments, list) or not segments:
                raise ValueError(
                    "baseline.json 'segments' must be a non-empty list when present"
                )
            for seg in segments:
                if not (
                    isinstance(seg, dict)
                    and isinstance(seg.get("name"), str)
                    and seg["name"]
                    and isinstance(seg.get("sha256"), str)
                    and len(seg["sha256"]) == 64
                    and isinstance(seg.get("size"), int)
                    and seg["size"] >= 0
                ):
                    raise ValueError(f"baseline.json has an invalid segment: {seg!r}")
        return data


# Extensiones que la bandeja acepta al SUBIR evidencia (drag-and-drop del
# perito). Espejo de web/src/utils/evidence.ts SUPPORTED_EXTENSIONS; la fuente
# real de los formatos es toolkit/catalog.py + triage.py. Validación en minúsculas.
SUPPORTED_EVIDENCE_EXTENSIONS: frozenset[str] = frozenset(
    {".raw", ".dd", ".img", ".vmdk", ".vmem", ".e01", ".aff", ".vhd", ".mem", ".lime", ".dmp"}
)

# Tamaño de bloque al escribir un upload en la bandeja (imágenes multi-GB).
_UPLOAD_CHUNK = 1024 * 1024  # 1 MiB


def _inbox_root() -> Path:
    """Resuelve la bandeja de entrada (``FORENSIA_EVIDENCE_DIR``) o lanza un
    ``RuntimeError`` accionable. En el compose es ``/evidence`` (montado desde
    ``./evidence`` del repo); en standalone la exporta el operador. RULE 2:
    nunca un directorio adivinado."""
    root_env = os.environ.get("FORENSIA_EVIDENCE_DIR")
    if not root_env:
        raise RuntimeError(
            "FORENSIA_EVIDENCE_DIR no está definido: no hay bandeja de evidencias. "
            "En el compose la fija el servicio api (/evidence, montado desde "
            "./evidence del repo). En modo standalone, exporta la variable "
            "apuntando a tu carpeta de evidencias."
        )
    root = Path(root_env).resolve()
    if not root.is_dir():
        raise RuntimeError(
            f"FORENSIA_EVIDENCE_DIR apunta a {root}, que no existe o no es un "
            "directorio. Crea la carpeta (./evidence en el repo, si usas el "
            "compose) y deja dentro las imágenes a registrar."
        )
    return root


def save_uploaded_source(filename: str, stream: BinaryIO) -> dict:
    """Deposita una evidencia SUBIDA por el perito en la raíz de la bandeja
    (``FORENSIA_EVIDENCE_DIR``) y devuelve su entrada ``{name, path, size}``.

    Este es el camino de ESCRITURA del perito: la bandeja se monta ``rw`` para
    el servicio ``api`` (nunca para los maletines/agente, que la ven ``ro`` —
    cadena de custodia). Subir NO registra: solo deja el fichero en la bandeja;
    el hash-gate y la copia inmutable siguen ocurriendo después, al pulsar
    «Registrar» (``EvidenceManager.register``, invariante forense 2).

    Guardas (RULE 2 — fallar alto, nunca sanear en silencio; SECURITY INVARIANT 6):

    - ``filename`` debe ser un basename limpio: sin separadores de ruta, sin
      ``..``, sin punto inicial (los ocultos no se listan). Se rechaza, no se
      recorta.
    - la extensión debe estar en ``SUPPORTED_EVIDENCE_EXTENSIONS``.
    - el destino queda confinado a la raíz de la bandeja.
    - si ya existe un fichero con ese nombre → ``FileExistsError`` (nunca se
      sobrescribe evidencia; el operador resuelve el conflicto).

    Se escribe primero a un temporal OCULTO (``.subiendo-…`` — que la bandeja no
    lista) y se renombra atómicamente al terminar, de modo que una subida a
    medias jamás aparece como fuente registrable.
    """
    root = _inbox_root()

    name = (filename or "").strip()
    if not name:
        raise ValueError("El fichero subido no tiene nombre.")
    if name.startswith(".") or "/" in name or "\\" in name or ".." in name:
        raise ValueError(
            f"Nombre de fichero no válido: {name!r}. Debe ser un nombre simple, "
            "sin rutas, sin '..' y sin punto inicial."
        )
    ext = Path(name).suffix.lower()
    if ext not in SUPPORTED_EVIDENCE_EXTENSIONS:
        raise ValueError(
            f"Formato no soportado: {ext or '(sin extensión)'}. Formatos válidos: "
            + ", ".join(sorted(SUPPORTED_EVIDENCE_EXTENSIONS))
        )

    dest = (root / name).resolve()
    if dest.parent != root:
        raise ValueError(f"Ruta de destino fuera de la bandeja: {name!r}.")
    if dest.exists():
        raise FileExistsError(
            f"Ya hay una evidencia llamada {name!r} en la bandeja. Renómbrala o "
            "elimínala antes de volver a subirla (nunca se sobrescribe evidencia)."
        )

    partial = root / f".subiendo-{uuid.uuid4().hex}-{name}"
    try:
        with partial.open("wb") as out:
            shutil.copyfileobj(stream, out, _UPLOAD_CHUNK)
        os.replace(partial, dest)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise

    return {"name": name, "path": str(dest), "size": dest.stat().st_size}


def list_source_files() -> list[dict]:
    """Enumera las evidencias disponibles en la bandeja de entrada
    (``FORENSIA_EVIDENCE_DIR`` — en el compose, ``./evidence`` del repo).

    El perito puede depositar evidencia de dos formas: copiándola a
    ``./evidence`` en el host, o SUBIÉNDOLA desde la web (drag-and-drop →
    ``save_uploaded_source``). En ambos casos el fichero aparece aquí y el
    operador lo ELIGE explícitamente (agencia del operador — RULE 2: nunca se
    registra "el único" ni "el más reciente").

    Se listan los ficheros regulares bajo la bandeja de forma **recursiva** (``rglob``),
    con la ruta relativa como ``name`` (p. ej. ``metasploitable2-linux/…vmdk``), para
    poder organizar la bandeja en subcarpetas por máquina/fuente. Se omiten los ficheros
    y carpetas ocultos (cualquier parte que empiece por ``.`` — incluye los temporales
    de subida a medias) y los symlinks (``register()`` los rechaza, SECURITY INVARIANT 6).

    Sin ``FORENSIA_EVIDENCE_DIR`` no hay bandeja que listar: error accionable,
    jamás un directorio adivinado (RULE 2).
    """
    root = _inbox_root()

    sources: list[dict] = []
    for path in sorted(root.rglob("*")):
        if any(part.startswith(".") for part in path.relative_to(root).parts):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        sources.append(
            {
                "name": str(path.relative_to(root)),
                "path": str(path),
                "size": path.stat().st_size,
            }
        )
    return sources


evidence_manager = EvidenceManager(case_manager)
