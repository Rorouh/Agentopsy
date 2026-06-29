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
    7. return the handle

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

from forensia.audit.log import AuditLog
from forensia.cases import CaseManager, case_manager
from forensia.triage import DetectedOS, fingerprint_os

logger = logging.getLogger(__name__)

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

_HASH_CHUNK = 1024 * 1024  # 1 MiB — evidence images run to tens of GB.
_READ_ONLY_MODE = 0o444


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
class EvidenceHandle:
    evidence_id: str
    case_id: str
    original_path: Path
    sha256: str
    size: int
    registered_at: str
    last_verification: VerificationRecord | None = None
    # Triage fingerprint computed at registration (or backfilled lazily on the
    # first ``get()`` for evidence registered before this field existed). Used
    # by the UI to warn on profile mismatch and by the agent's system prompt
    # to refuse running OS-mismatched plugins. Never used to auto-switch the
    # case's ``os_profile`` — that decision belongs to the operator (RULE 2).
    detected_os: DetectedOS = "unknown"


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

        # 1. Validate the case exists (case_dir() raises on bad id / missing case).
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

        evidence_root = case_dir / "evidence"
        evidence_root.mkdir(parents=True, exist_ok=True)

        evidence_id = str(uuid.uuid4())
        evidence_dir = (evidence_root / evidence_id).resolve()
        if self._cases.root not in evidence_dir.parents:
            # Belt-and-braces: confine inside the cases root.
            raise ValueError(f"evidence dir escapes cases root: {evidence_dir}")
        evidence_dir.mkdir(parents=True, exist_ok=False)

        # 3. Hash the source FIRST (baseline). This is what every downstream
        #    comparison is anchored to.
        baseline_sha, baseline_size = _sha256_file(src)

        # 4. Copy preserving the suffix so downstream tools that key on extension
        #    (e.g. ``.vmdk``, ``.raw``, ``.E01``) behave correctly. ``copy2`` keeps
        #    mtime, which is useful for triage even though the hash is what matters.
        suffix = src.suffix  # may be ""; that's fine
        dest = evidence_dir / f"original{suffix}"
        try:
            shutil.copy2(src, dest)
        except OSError:
            # Clean up the half-created evidence dir before re-raising so a retry
            # with a fixed source doesn't trip the existence check.
            shutil.rmtree(evidence_dir, ignore_errors=True)
            raise

        # 5. Re-hash the COPY. Mismatch == corruption during transfer; refuse.
        copy_sha, copy_size = _sha256_file(dest)
        if copy_sha != baseline_sha or copy_size != baseline_size:
            shutil.rmtree(evidence_dir, ignore_errors=True)
            raise IOError(
                "evidence copy hash mismatch — corruption during copy "
                f"(source={baseline_sha} copy={copy_sha})"
            )

        # 6. Read-only at the FS level. v1 minimum; Phase 2 adds block-level RO.
        os.chmod(dest, _READ_ONLY_MODE)

        # 7. Triage fingerprint over the already-frozen copy. Pure read, so it
        #    can run AFTER chmod 0o444. We do this before writing baseline.json
        #    so the persisted record carries detected_os from day one.
        detected_os = fingerprint_os(dest)

        registered_at = _utc_now_iso()
        baseline = {
            "sha256": baseline_sha,
            "size": baseline_size,
            "registered_at": registered_at,
            "source_path": str(src),
            "original_basename": dest.name,
            "detected_os": detected_os,
        }
        self._write_baseline(evidence_dir, baseline)

        return EvidenceHandle(
            evidence_id=evidence_id,
            case_id=case_dir.name,
            original_path=dest.resolve(),
            sha256=baseline_sha,
            size=baseline_size,
            registered_at=registered_at,
            detected_os=detected_os,
        )

    def get(self, case_id: str, evidence_id: str) -> EvidenceHandle:
        evidence_dir = self._evidence_dir(case_id, evidence_id)
        baseline = self._read_baseline(evidence_dir)
        original = evidence_dir / baseline["original_basename"]
        if not original.is_file():
            raise KeyError(
                f"evidence original missing for evidence_id={evidence_id}: {original}"
            )

        # Lazy backfill: evidence registered before forensia.triage existed
        # carries no ``detected_os`` in baseline.json. Compute it once and
        # persist so subsequent reads are cheap. A failure to write back is
        # logged but not fatal — the in-memory handle still gets the value.
        detected_os: DetectedOS = baseline.get("detected_os", "unknown")
        if "detected_os" not in baseline:
            detected_os = fingerprint_os(original.resolve())
            baseline["detected_os"] = detected_os
            try:
                self._write_baseline(evidence_dir, baseline)
            except OSError as exc:
                logger.warning(
                    "triage backfill: failed to persist detected_os for %s: %s",
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
        current_sha, current_size = _sha256_file(handle.original_path)
        verified = current_sha == handle.sha256 and current_size == handle.size

        # Persist the result so it survives navigation / app restarts. The record
        # lives next to baseline.json and the same fact is hash-chained into the
        # case audit log so the perito can prove WHEN and WITH WHAT RESULT every
        # verification happened.
        record = VerificationRecord(
            verified_at=_utc_now_iso(),
            verified=verified,
            current_sha256=current_sha,
        )
        evidence_dir = self._evidence_dir(case_id, evidence_id)
        self._write_verification(evidence_dir, record)

        case_dir = self._cases.case_dir(case_id)
        AuditLog(case_dir / "audit.jsonl").append(
            {
                "action": "evidence_verify",
                "case_id": case_id,
                "evidence_id": evidence_id,
                "verified": verified,
                "current_sha256": current_sha,
                "baseline_sha256": handle.sha256,
            }
        )
        return verified

    def get_verification(self, case_id: str, evidence_id: str) -> VerificationRecord | None:
        evidence_dir = self._evidence_dir(case_id, evidence_id)
        return self._read_verification(evidence_dir)

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
        return data


evidence_manager = EvidenceManager(case_manager)
