"""Case lifecycle: create / list / load / close, persisted as ``case.json`` per dir.

A case is the root scope of a forensic investigation. Every artifact (evidence copies,
audit log, chats, reports) lives under ``CONFIG_DIR/cases/<case-id>/``. The directory
layout is the source of truth — there is no separate index. Filesystem scan is fine
for v1 (a forensia install is not expected to hold thousands of cases).

RULE 2: no silent defaults. Missing/invalid arguments raise ``ValueError`` immediately.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

from forensia.config import CONFIG_DIR

logger = logging.getLogger(__name__)

# UUID4 canonical form. Used to validate case ids before they touch the filesystem
# (defense against path traversal — a case_id flows from the UI/HTTP into ``Path``).
_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

_VALID_OS_PROFILES = frozenset({"unix", "windows"})
_VALID_STATUSES = frozenset({"active", "closed"})

_MAX_FIELD_LEN = 200
_PER_CASE_SUBDIRS = ("evidence", "artifacts", "chats", "reports")


@dataclass(frozen=True)
class CloudConsent:
    """Per-case record that the operator opted in to cloud egress.

    Cloud is OFF by default (THREAT_MODEL §C / gate 9): a fresh case has
    ``cloud_consent=None`` and no evidence-derived byte may leave the host. The
    ``ref`` is the stable handle the audit log cites on every egress entry."""

    granted: bool
    granted_at: str
    by: str
    ref: str


@dataclass(frozen=True)
class Case:
    id: str
    name: str
    examiner: str
    created_at: str
    os_profile: str
    status: str
    notes: str = ""
    cloud_consent: CloudConsent | None = None


def _utc_now_iso() -> str:
    # ISO-8601 with explicit ``Z`` suffix (the audit log uses ``+00:00``; cases prefer
    # the ``Z`` form because that is what the UI displays unmodified).
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _validate_text_field(value: str, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string, got {type(value).__name__}")
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{field_name} must be a non-empty string")
    if len(stripped) > _MAX_FIELD_LEN:
        raise ValueError(
            f"{field_name} must be <= {_MAX_FIELD_LEN} characters (got {len(stripped)})"
        )
    return stripped


def _validate_notes(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"notes must be a string, got {type(value).__name__}")
    # Notes can be empty, but bounded to keep case.json a sane size on disk.
    if len(value) > 10_000:
        raise ValueError(f"notes must be <= 10000 characters (got {len(value)})")
    return value


def _validate_case_id(case_id: str) -> str:
    if not isinstance(case_id, str):
        raise ValueError(f"case_id must be a string, got {type(case_id).__name__}")
    if not _UUID4_RE.match(case_id):
        raise ValueError(f"case_id is not a valid UUID4: {case_id!r}")
    return case_id


class CaseManager:
    """Owns ``CONFIG_DIR/cases/``. Creates, lists, loads, and closes cases.

    Not thread-safe — the api service is single-process and the UI serializes
    case mutations. If we ever expose a multi-writer surface this needs locking.
    """

    def __init__(self, root: Path | None = None) -> None:
        self.root = Path(root).resolve() if root is not None else (CONFIG_DIR / "cases").resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    # ---- public API ---------------------------------------------------------

    def create(
        self,
        name: str,
        examiner: str,
        os_profile: str,
        notes: str = "",
    ) -> Case:
        name = _validate_text_field(name, "name")
        examiner = _validate_text_field(examiner, "examiner")
        if not isinstance(os_profile, str):
            raise ValueError(
                f"os_profile must be a string, got {type(os_profile).__name__}"
            )
        if os_profile not in _VALID_OS_PROFILES:
            raise ValueError(
                f"os_profile must be one of {sorted(_VALID_OS_PROFILES)}, got {os_profile!r}"
            )
        notes = _validate_notes(notes)

        case_id = str(uuid.uuid4())
        case_dir = (self.root / case_id).resolve()
        if case_dir.exists():
            # Astronomically unlikely with uuid4, but never silently overwrite a case.
            raise FileExistsError(f"case directory already exists: {case_dir}")

        case = Case(
            id=case_id,
            name=name,
            examiner=examiner,
            created_at=_utc_now_iso(),
            os_profile=os_profile,
            status="active",
            notes=notes,
        )

        case_dir.mkdir(parents=True, exist_ok=False)
        for sub in _PER_CASE_SUBDIRS:
            (case_dir / sub).mkdir(parents=True, exist_ok=False)

        self._write_case_json(case_dir, case)
        return case

    def list(self) -> list[Case]:
        cases: list[Case] = []
        for entry in self.root.iterdir():
            if not entry.is_dir():
                continue
            if not _UUID4_RE.match(entry.name):
                continue
            try:
                cases.append(self._read_case_json(entry))
            except (OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
                logger.warning("skipping unreadable case at %s: %s", entry, exc)
        cases.sort(key=lambda c: c.created_at, reverse=True)
        return cases

    def load(self, case_id: str) -> Case:
        case_dir = self.case_dir(case_id)
        try:
            return self._read_case_json(case_dir)
        except FileNotFoundError as exc:
            raise KeyError(f"case.json missing for case_id={case_id}") from exc

    def case_dir(self, case_id: str) -> Path:
        case_id = _validate_case_id(case_id)
        case_dir = (self.root / case_id).resolve()
        # ``resolve()`` collapses traversal, but UUID4 validation already neutralizes
        # the obvious vectors; this is belt-and-braces.
        if not case_dir.is_dir():
            raise KeyError(f"unknown case_id: {case_id}")
        if self.root not in case_dir.parents:
            raise KeyError(f"case_id resolves outside cases root: {case_id}")
        return case_dir

    def close(self, case_id: str) -> Case:
        case_dir = self.case_dir(case_id)
        case = self._read_case_json(case_dir)
        if case.status == "closed":
            return case
        updated = replace(case, status="closed")
        self._write_case_json(case_dir, updated)
        return updated

    def grant_cloud_consent(self, case_id: str, by: str) -> Case:
        """Record per-case opt-in to cloud egress (F2 / gate 9).

        Without this, ``/api/agent/query`` refuses the cloud path and zero
        evidence-derived bytes leave the host. ``by`` identifies who consented
        (audit/custody). Re-granting refreshes the timestamp and mints a new
        ``ref`` so the audit chain can tell consent grants apart.
        """
        by = _validate_text_field(by, "by")
        case_dir = self.case_dir(case_id)
        case = self._read_case_json(case_dir)
        consent = CloudConsent(
            granted=True,
            granted_at=_utc_now_iso(),
            by=by,
            ref=str(uuid.uuid4()),
        )
        updated = replace(case, cloud_consent=consent)
        self._write_case_json(case_dir, updated)
        return updated

    # ---- internals ----------------------------------------------------------

    @staticmethod
    def _case_json_path(case_dir: Path) -> Path:
        return case_dir / "case.json"

    def _write_case_json(self, case_dir: Path, case: Case) -> None:
        payload = asdict(case)
        path = self._case_json_path(case_dir)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8")
        tmp.replace(path)

    def _read_case_json(self, case_dir: Path) -> Case:
        path = self._case_json_path(case_dir)
        data = json.loads(path.read_text(encoding="utf-8"))
        # Validate the shape — refuse to load a case.json that has been tampered with
        # into a state the rest of the code doesn't expect.
        required = {"id", "name", "examiner", "created_at", "os_profile", "status"}
        missing = required - data.keys()
        if missing:
            raise ValueError(f"case.json missing fields: {sorted(missing)}")
        if data["os_profile"] not in _VALID_OS_PROFILES:
            raise ValueError(f"case.json has invalid os_profile: {data['os_profile']!r}")
        if data["status"] not in _VALID_STATUSES:
            raise ValueError(f"case.json has invalid status: {data['status']!r}")
        _validate_case_id(data["id"])
        if data["id"] != case_dir.name:
            raise ValueError(
                f"case.json id={data['id']} does not match directory name {case_dir.name}"
            )
        return Case(
            id=data["id"],
            name=data["name"],
            examiner=data["examiner"],
            created_at=data["created_at"],
            os_profile=data["os_profile"],
            status=data["status"],
            notes=data.get("notes", ""),
            cloud_consent=self._parse_cloud_consent(data.get("cloud_consent")),
        )

    @staticmethod
    def _parse_cloud_consent(value: object) -> CloudConsent | None:
        if value is None:
            return None
        if not isinstance(value, dict):
            raise ValueError(
                f"case.json cloud_consent must be a mapping or null, got {type(value).__name__}"
            )
        required = {"granted", "granted_at", "by", "ref"}
        missing = required - value.keys()
        if missing:
            raise ValueError(f"case.json cloud_consent missing fields: {sorted(missing)}")
        return CloudConsent(
            granted=bool(value["granted"]),
            granted_at=value["granted_at"],
            by=value["by"],
            ref=value["ref"],
        )


# Module-level singleton. Surfaces (routers, IPC) should import this rather than
# instantiate their own — the singleton owns the on-disk layout for the process.
case_manager = CaseManager()
