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

import json
import re
from datetime import datetime, timezone
from typing import Any

from forensia.cases.manager import case_manager
from forensia.evidence_context import EvidenceContext
from forensia.findings.store import Finding, finding_store
from forensia.timeline.relevance import (
    KNOWN_CATEGORIES,
    classify,
    select_relevant_events,
)
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

#: Evidence ids are UUID4 (``EvidenceManager``); we use them as the filename of the
#: persisted super-timeline, so reject anything else before touching the filesystem
#: (SECURITY INVARIANT 6: no traversal via a crafted id).
_EVIDENCE_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


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
    events = _bodyfile_to_all_events(bodyfile_text)
    total = len(events)
    if limit is not None and total > limit:
        return events[:limit], total
    return events, total


def _bodyfile_to_all_events(bodyfile_text: str) -> list[dict[str, Any]]:
    """Parse a TSK bodyfile into the FULL chronologically-sorted MACB event list (no cap).

    Shared by ``bodyfile_to_fs_events`` (which caps it) and ``run_filesystem_timeline``
    (which also needs the uncapped list to select the relevant events over EVERYTHING, not
    just the capped window).
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
    return events


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
    all_events = _bodyfile_to_all_events(bodyfile_text)
    total = len(all_events)
    events = all_events[:limit] if (limit is not None and total > limit) else all_events
    # Relevancia calculada sobre TODOS los eventos, no solo la ventana recortada:
    # los eventos importantes suelen quedar fuera del corte cronológico.
    relevant, total_relevant = select_relevant_events(all_events)
    _emit({
        "type": "status",
        "stage": "done",
        "message": (
            f"Super-timeline lista: {len(events)} eventos (de {total}); "
            f"{total_relevant} relevantes."
        ),
    })
    result = {
        "timezone": TIMEZONE,
        "evidence_id": evidence_context.evidence_id,
        "os_profile": os_profile,
        "fls_run_id": run_id,
        "total_events": total,
        "returned": len(events),
        "truncated": total > len(events),
        "events": events,
        "relevant_events": relevant,
        "total_relevant": total_relevant,
        "relevant_returned": len(relevant),
        "relevant_truncated": total_relevant > len(relevant),
        "generated_at": _dt_to_z(datetime.now(timezone.utc)),
    }
    # Persistir el resultado (acotado) por evidencia bajo el caso, para que la
    # super-timeline SOBREVIVA a recargas de la página y reinicios del api (el
    # job_registry es solo en memoria). La fuente forense sigue siendo el
    # bodyfile anclado en artifacts/<run_id>/out/stdout.bin; esto es la vista
    # materializada, regenerable en cualquier momento con «Generar».
    _persist_fs_timeline(case_id, evidence_context.evidence_id, result)
    return result


def _fs_timeline_path(case_id: str, evidence_id: str) -> Any:
    """Ruta del resultado persistido de la super-timeline de una evidencia,
    ``<case_dir>/timeline/<evidence_id>.json``. Valida el ``evidence_id`` (UUID4)
    antes de construir la ruta — nunca un id con separadores/traversal."""
    if not _EVIDENCE_ID_RE.match(evidence_id):
        raise ValueError(f"evidence_id inválido: {evidence_id!r}")
    return case_manager.case_dir(case_id) / "timeline" / f"{evidence_id}.json"


def _persist_fs_timeline(case_id: str, evidence_id: str, result: dict[str, Any]) -> None:
    path = _fs_timeline_path(case_id, evidence_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Escritura atómica: tmp + replace, para no dejar un JSON a medias si el
    # proceso muere mientras escribe una super-timeline grande.
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def load_filesystem_timeline(case_id: str, evidence_id: str) -> dict[str, Any] | None:
    """Carga la última super-timeline persistida de una evidencia, o ``None`` si
    nunca se generó (el operador verá el estado «Pulsa Generar»). Determinista y
    sin ejecutar herramientas — solo lee el JSON materializado.

    ``ValueError`` si el ``evidence_id`` está malformado (lo mapea el router a 422)."""
    path = _fs_timeline_path(case_id, evidence_id)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        # Un JSON corrupto no es una super-timeline: se trata como "no hay",
        # regenerable con «Generar» (RULE 2: nunca una línea temporal a medias).
        return None


def _parse_query_bound(value: str, *, end: bool) -> datetime:
    """Parse a query date/datetime bound to an aware UTC ``datetime``.

    Accepts a plain ``YYYY-MM-DD`` (expanded to start- or end-of-day depending on
    ``end``) or a full ISO-8601 timestamp (``Z`` or offset). Raises ``ValueError`` on
    anything else — the caller surfaces it as an actionable error (RULE 2)."""
    raw = value.strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
        suffix = "T23:59:59.999999+00:00" if end else "T00:00:00+00:00"
        return datetime.fromisoformat(raw + suffix)
    dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def query_filesystem_timeline(
    case_id: str,
    evidence_id: str,
    *,
    date_from: str | None = None,
    date_to: str | None = None,
    category: str | None = None,
    path_contains: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Query the persisted filesystem super-timeline of an evidence WITHOUT re-running fls.

    The deterministic projection the agent uses to answer «¿qué actividad hubo entre X e
    Y?» or «¿hubo algún registro el <fecha>?» without re-scanning the image. It reads the
    HASHED bodyfile artifact the super-timeline was built from (``out/stdout.bin`` of the
    ``fls -m`` run), expands its FULL MACB event set and filters it — so the answer is
    exhaustive over the real timeline, not over a capped view.

    Requires the super-timeline to have been generated first: if it has not, returns a
    structured ``status='no_timeline'`` telling the caller to generate it — never a silent
    empty result that reads as «nothing happened» (RULE 2). ``category`` must be one of
    ``relevance.KNOWN_CATEGORIES``; an unknown value is rejected, not matched to nothing.

    Returns ``{status, evidence_id, timezone, fls_run_id, total_events, matched, returned,
    truncated, query, events, by_category}``.
    """
    persisted = load_filesystem_timeline(case_id, evidence_id)  # ValueError on bad id
    if persisted is None:
        return {
            "status": "no_timeline",
            "evidence_id": evidence_id,
            "message": (
                "La super-timeline de esta evidencia aún no está generada. Genérala "
                "primero (tsk_fls -m sobre la evidencia, o el botón «Generar» de la "
                "vista Timeline) y vuelve a consultar; no infiero actividad sin ella."
            ),
        }
    run_id = persisted.get("fls_run_id")
    if not isinstance(run_id, str):
        return {
            "status": "no_timeline",
            "evidence_id": evidence_id,
            "message": (
                "La super-timeline persistida no referencia el run de tsk_fls que la "
                "produjo; regenérala antes de consultarla."
            ),
        }

    cat = category.strip() if isinstance(category, str) and category.strip() else None
    if cat is not None and cat not in KNOWN_CATEGORIES:
        raise ValueError(
            f"categoría desconocida: {cat!r}. Válidas: {sorted(KNOWN_CATEGORIES)}"
        )
    lo = _parse_query_bound(date_from, end=False) if date_from else None
    hi = _parse_query_bound(date_to, end=True) if date_to else None
    if lo is not None and hi is not None and lo > hi:
        raise ValueError(
            f"rango de fechas invertido: date_from ({date_from}) es posterior a "
            f"date_to ({date_to})"
        )
    needle = path_contains.replace("\\", "/").lower() if path_contains else None
    if not isinstance(limit, int) or limit <= 0:
        limit = 100
    limit = min(limit, 500)  # tope duro; el schema declara maximum:500 pero es advisory

    all_events = _bodyfile_to_all_events(_read_run_stdout(case_id, run_id))

    matched: list[dict[str, Any]] = []
    by_category: dict[str, int] = {}
    for ev in all_events:
        if lo is not None or hi is not None:
            ts = ev.get("ts")
            if not ts:
                continue
            when = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            if lo is not None and when < lo:
                continue
            if hi is not None and when > hi:
                continue
        if needle is not None and needle not in ev.get("path", "").replace("\\", "/").lower():
            continue
        hit = classify(ev.get("path", ""), ev.get("macb", ""))
        if cat is not None and (hit is None or hit["category"] != cat):
            continue
        enriched = {**ev, **hit} if hit else ev
        if hit:
            by_category[hit["category"]] = by_category.get(hit["category"], 0) + 1
        matched.append(enriched)

    return {
        "status": "ok",
        "evidence_id": evidence_id,
        "timezone": TIMEZONE,
        "fls_run_id": run_id,
        "total_events": len(all_events),
        "matched": len(matched),
        "returned": min(len(matched), limit),
        "truncated": len(matched) > limit,
        "query": {
            "date_from": date_from,
            "date_to": date_to,
            "category": cat,
            "path_contains": path_contains,
        },
        "events": matched[:limit],
        "by_category": by_category,
    }


def _read_run_stdout(case_id: str, run_id: str) -> str:
    """Read the ``fls -m`` bodyfile of an anchored run.

    In `-m` mode fls's stdout IS the bodyfile, and the dispatcher captures it (byte-exact,
    hashed) as the run's ``out/stdout.bin`` output artifact — the same referenceable file
    ``mactime`` consumes as a ``{run_id, relpath}`` input. Reading it is confined to the
    case directory the dispatcher just wrote to.
    """
    bodyfile_path = (
        case_manager.case_dir(case_id) / "artifacts" / run_id / "out" / "stdout.bin"
    )
    if not bodyfile_path.is_file():
        raise RuntimeError(
            f"no se encontró el bodyfile de tsk_fls en {bodyfile_path} — el run "
            f"{run_id} no materializó su artefacto de bodyfile."
        )
    return bodyfile_path.read_text(encoding="utf-8", errors="replace")
