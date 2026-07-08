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

from forensia.audit.log import AuditLog
from forensia.config import CONFIG_DIR
from forensia.triage import DetectedEvidence, routable_profile

logger = logging.getLogger(__name__)

# UUID4 canonical form. Used to validate case ids before they touch the filesystem
# (defense against path traversal — a case_id flows from the UI/HTTP into ``Path``).
_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

_VALID_OS_PROFILES = frozenset({"unix", "windows"})
_VALID_STATUSES = frozenset({"active", "closed"})

# How a case got its ``os_profile`` — this is what keeps auto-routing honest:
#   - ``derived``  : auto-set from a single evidence whose CONTENT triage
#                    classified confidently (``routable_profile``).
#   - ``operator`` : the operator anchored it manually (the ambiguous case, and
#                    the only time the operator touches the profile). An anchor
#                    is final — later evidence never flips it, never conflicts.
#   - ``conflict`` : evidence of two different OSs landed in the same case. The
#                    profile is cleared to ``None`` and routing escalates until
#                    the operator anchors. (Multi-OS auto-routing is Fase 2b.)
_OS_SOURCE_DERIVED = "derived"
_OS_SOURCE_OPERATOR = "operator"
_OS_SOURCE_CONFLICT = "conflict"
_VALID_OS_SOURCES = frozenset(
    {_OS_SOURCE_DERIVED, _OS_SOURCE_OPERATOR, _OS_SOURCE_CONFLICT}
)


class OsProfileUnresolved(RuntimeError):
    """The case has no ``os_profile`` that can be routed on.

    Raised by ``resolve_os_profile`` when triage could not determine the OS
    confidently from the evidence content (unknown / low confidence), when the
    case holds conflicting evidence (two OSs), or when no routable evidence is
    registered yet. RULE 2 enmendada: in ambiguity we NEVER route silently —
    the operator MUST anchor the profile manually. The message is always
    actionable so the surface can tell the operator exactly what to do.
    """


def _validate_os_profile(os_profile: object) -> str:
    if not isinstance(os_profile, str):
        raise ValueError(
            f"os_profile must be a string, got {type(os_profile).__name__}"
        )
    if os_profile not in _VALID_OS_PROFILES:
        raise ValueError(
            f"os_profile must be one of {sorted(_VALID_OS_PROFILES)}, got {os_profile!r}"
        )
    return os_profile

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
    status: str
    # DERIVED, not operator-chosen at creation (auto-detección de SO). ``None``
    # until triage classifies a routable evidence (``os_profile_source`` records
    # HOW it got set). It is intentionally the SINGLE knob routing reads, via
    # ``resolve_os_profile`` — never inferred from the host platform (RULE 2).
    os_profile: str | None = None
    os_profile_source: str | None = None
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
        os_profile: str | None = None,
        notes: str = "",
    ) -> Case:
        name = _validate_text_field(name, "name")
        examiner = _validate_text_field(examiner, "examiner")
        # The operator no longer PICKS the OS at creation — it is derived from
        # the evidence content by triage (auto-detección de SO). ``os_profile``
        # here is an OPTIONAL manual anchor (operator override for the ambiguous
        # case); ``None`` is the normal path. When given it is validated and
        # recorded as an operator anchor (final — later evidence won't flip it).
        os_source: str | None = None
        if os_profile is not None:
            os_profile = _validate_os_profile(os_profile)
            os_source = _OS_SOURCE_OPERATOR
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
            status="active",
            os_profile=os_profile,
            os_profile_source=os_source,
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
        AuditLog(case_dir / "audit.jsonl").append(
            {"action": "case_closed", "case_id": case_id}
        )
        return updated

    def reopen(self, case_id: str) -> Case:
        """Flip a closed case back to ``active`` — the only way to register
        more evidence or query the agent on it again (``EvidenceManager.register``
        and the ``/agent/query`` gate both require ``status == "active"``).
        Symmetric to ``close()``: idempotent when already active, audited when
        it actually transitions (FORENSIC INVARIANT 4)."""
        case_dir = self.case_dir(case_id)
        case = self._read_case_json(case_dir)
        if case.status == "active":
            return case
        updated = replace(case, status="active")
        self._write_case_json(case_dir, updated)
        AuditLog(case_dir / "audit.jsonl").append(
            {"action": "case_reopened", "case_id": case_id}
        )
        return updated

    def update(
        self,
        case_id: str,
        *,
        name: str | None = None,
        examiner: str | None = None,
        notes: str | None = None,
    ) -> Case:
        """Edit case metadata. Only the provided fields change — ``None`` means
        "leave as is", not "clear" (RULE 2: the operator states intent
        explicitly; a bare no-op call is a caller bug, not a silent success).
        The evidence hash chain, ``os_profile``, and ``id``/``created_at`` are
        never touched here."""
        if name is None and examiner is None and notes is None:
            raise ValueError(
                "update requires at least one field: name, examiner, or notes"
            )
        case_dir = self.case_dir(case_id)
        case = self._read_case_json(case_dir)

        changes: dict[str, tuple[str, str]] = {}
        fields: dict[str, str] = {}
        if name is not None:
            fields["name"] = _validate_text_field(name, "name")
            if fields["name"] != case.name:
                changes["name"] = (case.name, fields["name"])
        if examiner is not None:
            fields["examiner"] = _validate_text_field(examiner, "examiner")
            if fields["examiner"] != case.examiner:
                changes["examiner"] = (case.examiner, fields["examiner"])
        if notes is not None:
            fields["notes"] = _validate_notes(notes)
            if fields["notes"] != case.notes:
                changes["notes"] = (case.notes, fields["notes"])

        updated = replace(case, **fields)
        self._write_case_json(case_dir, updated)
        if changes:
            AuditLog(case_dir / "audit.jsonl").append(
                {
                    "action": "case_updated",
                    "case_id": case_id,
                    "changes": {k: {"from": v[0], "to": v[1]} for k, v in changes.items()},
                }
            )
        return updated

    def apply_detected_evidence(
        self, case_id: str, detected: DetectedEvidence, evidence_id: str
    ) -> Case:
        """Derive/adjust the case ``os_profile`` from a newly registered
        evidence's triage record. Called by ``EvidenceManager.register`` right
        after the fingerprint runs. The determination is from the evidence
        CONTENT (``routable_profile``), never from the host platform (RULE 2).

        Transitions (source in parentheses):
          - not routable (unknown family / low confidence)  → no-op.
          - operator already anchored                       → no-op (final).
          - already in conflict                             → no-op (only an
            operator anchor resolves it).
          - not yet routed (source None)                    → auto-set to the
            evidence family (source ``derived``) + audit ``auto_set``.
          - same family already derived                     → no-op.
          - a DIFFERENT confident family than the derived one → CONFLICT: clear
            the profile, mark ``conflict`` + audit ``conflict``. Multi-OS
            auto-routing (both sub-agents at once) is out of scope here — see
            the Fase 2b TODO in ``resolve_os_profile``.

        Every state-changing branch records the routing decision (family,
        confidence, signals) in the case's append-only, hash-chained audit log
        (FORENSIC INVARIANT 4). Returns the (possibly updated) case.
        """
        profile = routable_profile(detected)
        case = self.load(case_id)
        if profile is None:
            # Not enough signal to route on — nothing to derive. The evidence is
            # still fully registered; routing simply stays unresolved until a
            # routable evidence arrives or the operator anchors.
            return case
        if case.os_profile_source in (_OS_SOURCE_OPERATOR, _OS_SOURCE_CONFLICT):
            # Operator's word is final; a conflict only the operator resolves.
            return case
        if case.os_profile is None:
            updated = replace(
                case, os_profile=profile, os_profile_source=_OS_SOURCE_DERIVED
            )
            self._write_case_json(self.case_dir(case_id), updated)
            self._audit_routing(
                case_id, evidence_id, detected, decision="auto_set", os_profile=profile
            )
            return updated
        if case.os_profile == profile:
            return case
        # Two evidences, two confident OSs → conflict. Do NOT silently keep the
        # first: clear it and escalate (RULE 2). TODO(Fase 2b): route each
        # evidence to its own sub-agent instead of forcing a single profile.
        updated = replace(case, os_profile=None, os_profile_source=_OS_SOURCE_CONFLICT)
        self._write_case_json(self.case_dir(case_id), updated)
        self._audit_routing(
            case_id, evidence_id, detected, decision="conflict", os_profile=None
        )
        return updated

    def anchor_os_profile(self, case_id: str, os_profile: str) -> Case:
        """Operator's explicit manual anchor of the case ``os_profile``.

        This is the ONLY time the operator sets the profile, and the only exit
        from the ambiguous/conflict state (RULE 2 enmendada: on ambiguity the
        operator anchors — never a silent pick). The anchor is final: later
        evidence never flips it and never re-raises a conflict. Recorded in the
        audit log as an operator routing decision (FORENSIC INVARIANT 4).
        """
        os_profile = _validate_os_profile(os_profile)
        case = self.load(case_id)
        updated = replace(
            case, os_profile=os_profile, os_profile_source=_OS_SOURCE_OPERATOR
        )
        self._write_case_json(self.case_dir(case_id), updated)
        AuditLog(self.case_dir(case_id) / "audit.jsonl").append(
            {
                "action": "os_profile_anchored",
                "case_id": case_id,
                "os_profile": os_profile,
                "by": "operator",
            }
        )
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

    def _audit_routing(
        self,
        case_id: str,
        evidence_id: str,
        detected: DetectedEvidence,
        *,
        decision: str,
        os_profile: str | None,
    ) -> None:
        """Append the OS-routing decision to the case audit log with the exact
        triage basis (family, confidence, signals) that justified it — so the
        case file can always answer "which bytes routed this evidence, and to
        what" (FORENSIC INVARIANT 4)."""
        AuditLog(self.case_dir(case_id) / "audit.jsonl").append(
            {
                "action": "os_profile_routed",
                "case_id": case_id,
                "evidence_id": evidence_id,
                "decision": decision,        # "auto_set" | "conflict"
                "os_profile": os_profile,    # routed profile, or null on conflict
                "family": detected.family,
                "confidence": detected.confidence,
                "signals": list(detected.signals),
            }
        )

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
        # into a state the rest of the code doesn't expect. ``os_profile`` is now
        # OPTIONAL (derived, may be null); it is only validated when present.
        required = {"id", "name", "examiner", "created_at", "status"}
        missing = required - data.keys()
        if missing:
            raise ValueError(f"case.json missing fields: {sorted(missing)}")
        os_profile = data.get("os_profile")
        if os_profile is not None and os_profile not in _VALID_OS_PROFILES:
            raise ValueError(f"case.json has invalid os_profile: {os_profile!r}")
        os_profile_source = data.get("os_profile_source")
        if os_profile_source is not None and os_profile_source not in _VALID_OS_SOURCES:
            raise ValueError(
                f"case.json has invalid os_profile_source: {os_profile_source!r}"
            )
        if os_profile_source is None and os_profile is not None:
            # Legacy case.json (pre auto-routing): the profile was operator-chosen
            # at creation, so treat it as an operator anchor — never flip it.
            os_profile_source = _OS_SOURCE_OPERATOR
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
            status=data["status"],
            os_profile=os_profile,
            os_profile_source=os_profile_source,
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


def resolve_os_profile(case: Case) -> str:
    """Resolve the ``os_profile`` a case routes on, or fail loud.

    The SINGLE resolution point every routing caller uses (HTTP ``/agent/query``,
    the MCP ``select_case``). Returns the concrete profile when the case has one
    (auto-derived from evidence content or operator-anchored); raises
    ``OsProfileUnresolved`` with an actionable message otherwise — RULE 2
    enmendada: on ``unknown`` / low confidence / conflict / no evidence we NEVER
    route silently, the operator must anchor. Never inferred from the host.
    """
    if case.os_profile in _VALID_OS_PROFILES:
        return case.os_profile  # type: ignore[return-value]
    anchor_hint = (
        f"Ancla el perfil manualmente (POST /api/cases/{case.id}/os-profile "
        '{"os_profile": "unix"|"windows"}) — RULE 2: en ambigüedad el operador '
        "ancla, nunca se enruta en silencio ni se adivina desde el host."
    )
    if case.os_profile_source == _OS_SOURCE_CONFLICT:
        raise OsProfileUnresolved(
            "os_profile en conflicto: el caso tiene evidencias de más de un SO "
            "(el enrutado multi-SO simultáneo es Fase 2b). " + anchor_hint
        )
    raise OsProfileUnresolved(
        "os_profile sin determinar: el triage no clasificó el SO de la evidencia "
        "con confianza suficiente, o aún no hay evidencia enrutable registrada. "
        + anchor_hint
    )


# Module-level singleton. Surfaces (routers, IPC) should import this rather than
# instantiate their own — the singleton owns the on-disk layout for the process.
case_manager = CaseManager()
