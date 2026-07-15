"""Pure builders for the two timeline layers (CLAUDE.md RULE 3: logic here, thin router).

- ``assemble_investigation_timeline`` / ``build_investigation_timeline`` — merge the
  audit-log tool runs and the case findings into one chronologically ordered list. No
  new tool is executed; everything comes from what the case already holds.
- ``bodyfile_to_fs_events`` — expand a TSK bodyfile (the output of ``fls -m``) into MACB
  filesystem events, exactly the deterministic transform ``mactime`` performs.
- ``run_filesystem_timeline`` — drive the ``tsk_fls -m`` forensic step through the
  dispatcher (shell-free, audited, hashed artifact — never a re-implemented subprocess)
  and parse its bodyfile. Intended to run inside an async job.

Timestamps: the audit log emits ISO-8601 UTC (``…+00:00``), findings emit ``…Z``, and
``fls`` emits epoch seconds (UTC). Everything is normalized to a single explicit
``YYYY-MM-DDTHH:MM:SS(.mmm)Z`` string so the surface can label UTC without guessing
(hallazgo F: the timezone is never left implicit).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from forensia.cases.manager import case_manager
from forensia.evidence_context import EvidenceContext
from forensia.findings.store import Finding, finding_store
from forensia.toolkit import dispatcher

#: The single timezone every timeline timestamp is expressed in. Surfaced to the UI so
#: the label is explicit and never a silent local-time conversion.
TIMEZONE = "UTC"

#: Default cap on the number of filesystem events returned by one super-timeline run. A
#: real disk can yield millions of MACB rows; the cap keeps the payload bounded and is
#: reported back (``total_events`` / ``truncated``) so nothing is hidden silently.
DEFAULT_FS_EVENT_LIMIT = 5000

#: MACB order used by ``mactime``: modified, accessed, changed (metadata), born (created).
_MACB_ORDER: tuple[tuple[str, str], ...] = (
    ("m", "mtime"),
    ("a", "atime"),
    ("c", "ctime"),
    ("b", "crtime"),
)

_FAR_FUTURE = datetime.max.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# Timestamp normalization
# --------------------------------------------------------------------------- #
def _parse_iso_utc(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp to an aware UTC ``datetime``; ``None`` if unparseable.

    Accepts both the audit log's ``…+00:00`` and the findings' ``…Z`` spellings.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _dt_to_z(dt: datetime) -> str:
    """Canonical explicit-UTC ISO-8601 string with millisecond precision and a ``Z``."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _normalize_iso_utc(value: Any) -> str | None:
    dt = _parse_iso_utc(value)
    return _dt_to_z(dt) if dt is not None else None


def _epoch_to_z(epoch: int) -> str | None:
    """Epoch seconds (UTC) → ``YYYY-MM-DDTHH:MM:SSZ``; ``None`` if out of range."""
    try:
        dt = datetime.fromtimestamp(int(epoch), tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# Layer 1 — investigation timeline (deterministic, always available)
# --------------------------------------------------------------------------- #
def assemble_investigation_timeline(
    audit_entries: list[dict[str, Any]],
    findings: list[Finding],
) -> list[dict[str, Any]]:
    """Merge audit tool runs and findings into one chronologically ordered event list.

    Pure: no I/O. ``audit_entries`` are the parsed lines of ``audit.jsonl`` (in append
    order); ``findings`` are the case's :class:`Finding` objects. One ``tool_run`` event
    per ``tool_run_start`` (enriched with its paired ``tool_run_finish``), one
    ``finding`` event per finding. Events with an unparseable timestamp sort last but are
    never dropped (RULE 2: surface everything, hide nothing).
    """
    finishes: dict[str, dict[str, Any]] = {}
    for entry in audit_entries:
        if entry.get("action") == "tool_run_finish":
            run_id = entry.get("run_id")
            if isinstance(run_id, str):
                finishes[run_id] = entry

    events: list[dict[str, Any]] = []
    for entry in audit_entries:
        if entry.get("action") != "tool_run_start":
            continue
        run_id = entry.get("run_id")
        finish = finishes.get(run_id) if isinstance(run_id, str) else None
        events.append(_tool_run_event(entry, finish))

    for finding in findings:
        events.append(_finding_event(finding))

    events.sort(key=lambda e: _parse_iso_utc(e.get("ts")) or _FAR_FUTURE)
    return events


def _tool_run_event(
    start: dict[str, Any], finish: dict[str, Any] | None
) -> dict[str, Any]:
    argv = start.get("argv")
    artifacts: list[dict[str, Any]] = []
    output_files_count: int | None = None
    exit_code: int | None = None
    status = "running"
    if finish is not None:
        status = str(finish.get("status") or "running")
        raw_exit = finish.get("exit_code")
        exit_code = raw_exit if isinstance(raw_exit, int) else None
        raw_count = finish.get("output_files_count")
        output_files_count = raw_count if isinstance(raw_count, int) else None
        for relpath, key in (("stdout.txt", "stdout_sha256"), ("stderr.txt", "stderr_sha256")):
            sha = finish.get(key)
            if isinstance(sha, str) and sha:
                artifacts.append({"relpath": relpath, "sha256": sha})
    return {
        "kind": "tool_run",
        "ts": _normalize_iso_utc(start.get("ts_utc")),
        "tool_id": start.get("tool_id"),
        "run_id": start.get("run_id"),
        "argv": list(argv) if isinstance(argv, list) else [],
        "exit": exit_code,
        "status": status,
        "evidence_id": start.get("evidence_id"),
        "artifacts": artifacts,
        "output_files_count": output_files_count,
    }


def _finding_event(finding: Finding) -> dict[str, Any]:
    return {
        "kind": "finding",
        "ts": _normalize_iso_utc(finding.created_at),
        "finding_id": finding.id,
        "title": finding.title,
        "summary": finding.summary,
        "severity": finding.severity,
        "tool_id": finding.tool_id,
        "evidence_id": finding.evidence_id,
        "mitre_hints": list(finding.mitre_hints),
    }


def build_investigation_timeline(case_id: str) -> list[dict[str, Any]]:
    """Load the case's audit log + findings and assemble the investigation timeline.

    Raises ``KeyError`` for an unknown case and ``ValueError`` for a malformed
    ``case_id`` (surfaced as 404 / 422 by the router). A case with no audit log and no
    findings yields an empty list.
    """
    # Imported here to keep the pure ``assemble_*`` core free of the audit dependency
    # (and so tests can drive the core with fixtures without touching disk).
    from forensia.audit.log import AuditLog

    case_dir = case_manager.case_dir(case_id)
    audit_path = case_dir / "audit.jsonl"
    audit_entries = AuditLog(audit_path).entries() if audit_path.is_file() else []
    findings = finding_store.list(case_id)
    return assemble_investigation_timeline(audit_entries, findings)


# --------------------------------------------------------------------------- #
# Layer 2 — filesystem super-timeline (on demand)
# --------------------------------------------------------------------------- #
def bodyfile_to_fs_events(
    bodyfile_text: str, *, limit: int = DEFAULT_FS_EVENT_LIMIT
) -> tuple[list[dict[str, Any]], int]:
    """Expand a TSK bodyfile (``fls -m`` output) into MACB filesystem events.

    This is exactly the deterministic transform ``mactime`` applies: every non-zero
    timestamp of every entry becomes one event, tagged with the MACB letters
    (``m``/``a``/``c``/``b``) of the times that coincide at that instant. Bodyfile line
    format (pipe-separated, 11 fields):

        ``MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime``

    Returns ``(events, total)`` where ``events`` is sorted chronologically and capped at
    ``limit`` and ``total`` is how many events existed before the cap (so the caller can
    report truncation — RULE 2: never hide the elision).
    """
    events: list[dict[str, Any]] = []
    for line in bodyfile_text.splitlines():
        if not line.strip():
            continue
        fields = line.split("|")
        if len(fields) != 11:
            continue
        name = fields[1]
        inode = fields[2]
        size = _safe_int(fields[6])
        times = {
            "atime": _safe_int(fields[7]),
            "mtime": _safe_int(fields[8]),
            "ctime": _safe_int(fields[9]),
            "crtime": _safe_int(fields[10]),
        }
        # Group this entry's four times by instant, skipping "not set" (epoch 0).
        distinct = sorted({t for t in times.values() if t})
        for instant in distinct:
            ts = _epoch_to_z(instant)
            if ts is None:
                continue
            macb = "".join(
                letter if times[field] == instant else "."
                for letter, field in _MACB_ORDER
            )
            events.append(
                {
                    "kind": "fs",
                    "ts": ts,
                    "path": name,
                    "macb": macb,
                    "size": size,
                    "inode": inode,
                }
            )
    events.sort(key=lambda e: (e["ts"], e["path"]))
    total = len(events)
    if limit is not None and total > limit:
        return events[:limit], total
    return events, total


def _safe_int(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def run_filesystem_timeline(
    case_id: str,
    handle: Any,
    evidence_context: EvidenceContext,
    os_profile: str,
    *,
    emit: Any = None,
    limit: int = DEFAULT_FS_EVENT_LIMIT,
) -> dict[str, Any]:
    """Run ``tsk_fls -m -r`` through the dispatcher and expand its bodyfile to events.

    ``handle`` is the verified :class:`EvidenceHandle` (``EvidenceManager.get``);
    ``evidence_context`` was built from it and anchors the run to the evidence (id +
    baseline hash) in the hash-chained audit log. ``os_profile`` selects the maletín (fls
    lives in both, so it is required — RULE 2: no silent pick). Execution is shell-free
    argv arrays via the dispatcher / maletín (SECURITY INVARIANTS 4-5) — no subprocess is
    re-implemented here.

    A non-zero ``fls`` exit fails loud with the tool's stderr (RULE 2: no silent partial
    timeline). Returns a job-result dict with the parsed ``events`` and truncation
    metadata.
    """
    def _emit(event: dict[str, Any]) -> None:
        if emit is not None:
            emit(event)

    _emit({"type": "status", "stage": "fls", "message": "Ejecutando tsk_fls -m sobre la evidencia…"})
    result = dispatcher.execute(
        "tsk_fls",
        {"image_path": str(handle.original_path), "body_format": True, "recursive": True},
        case_id=case_id,
        os_profile=os_profile,
        evidence_context=evidence_context,
    )
    exit_code = result.get("exit_code")
    run_id = result.get("run_id")
    if exit_code != 0:
        raise RuntimeError(
            f"tsk_fls terminó con exit_code {exit_code!r} sobre la evidencia "
            f"{evidence_context.evidence_id}; no se construye una super-timeline parcial "
            f"(RULE 2). stderr: {result.get('stderr_sample', '')[:2000]}"
        )
    if not isinstance(run_id, str):
        raise RuntimeError(
            "tsk_fls no devolvió run_id (la ejecución no quedó anclada al caso); "
            "no se puede recuperar el bodyfile."
        )

    _emit({"type": "status", "stage": "mactime", "message": "Generando la super-timeline MACB…"})
    bodyfile_text = _read_run_stdout(case_id, run_id)
    events, total = bodyfile_to_fs_events(bodyfile_text, limit=limit)
    _emit({
        "type": "status",
        "stage": "done",
        "message": f"Super-timeline lista: {len(events)} eventos (de {total}).",
    })
    return {
        "timezone": TIMEZONE,
        "evidence_id": evidence_context.evidence_id,
        "os_profile": os_profile,
        "fls_run_id": run_id,
        "total_events": total,
        "returned": len(events),
        "truncated": total > len(events),
        "events": events,
    }


def _read_run_stdout(case_id: str, run_id: str) -> str:
    """Read the captured stdout (the ``fls -m`` bodyfile) of an anchored run.

    ``fls`` streams its bodyfile to stdout, which the artifact store persists (and
    hashes) at ``<case_dir>/artifacts/<run_id>/stdout.txt``. Reading it is confined to
    the case directory the dispatcher just wrote to.
    """
    stdout_path = case_manager.case_dir(case_id) / "artifacts" / run_id / "stdout.txt"
    if not stdout_path.is_file():
        raise RuntimeError(
            f"no se encontró el bodyfile de tsk_fls en {stdout_path} — el run "
            f"{run_id} no persistió su stdout."
        )
    return stdout_path.read_text(encoding="utf-8", errors="replace")
