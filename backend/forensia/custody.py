"""Acta de adquisición — structured chain-of-custody record for one evidence.

Pure logic (CLAUDE.md RULE 3): builds the "acta" from data that already exists —
the ``baseline.json`` written by ``EvidenceManager`` at registration and the
``evidence_register`` event in the case's append-only, hash-chained
``audit.jsonl`` (forensic invariant 4). It invents nothing: every field is read
back from those two authoritative sources, so the acta is a faithful,
reproducible rendering of the custody facts, not a fresh narrative.

What the acta answers, for a court-style annex:

- **Qué** entró: source path, original basename, baseline ``sha256``, size.
- **Cuándo**: ``registered_at`` (baseline == audit event, same instant).
- **Quién / qué caso**: examiner + case identity.
- **Cadena de custodia**: the ``entry_hash`` (and ``prev_hash``) of the register
  event in the hash chain, plus whether the whole chain currently verifies.
- **Nivel de solo-lectura**: the HONEST label from ``forensia.evidence`` —
  ``fs`` (chmod 0444) today; block-level is Phase 2, NOT implemented. RULE 2:
  the acta never claims a guarantee we don't enforce.
- **Herramienta / versión**: FORENSIA + ``__version__`` and the concrete
  acquisition mechanism (``EvidenceManager`` stream-hash + verified copy).

Failure modes are loud, never guessed (RULE 2): an unknown case/evidence raises
``KeyError``; a malformed evidence id raises ``ValueError``; an evidence whose
registration event is missing from the audit log raises ``KeyError`` (we cannot
attest a chain link that isn't there). The router maps these to 404 / 422.

Persisting the acta as a Document is intentionally NOT done here — if wanted, a
surface may pass ``build_custody_act(...)`` output through the existing
``forensia.reports`` ``DocumentStore.create(...)`` API. This module stays pure.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from forensia import __version__
from forensia.audit.log import AuditLog
from forensia.cases.manager import CaseManager, case_manager
from forensia.evidence import (
    EvidenceManager,
    evidence_manager,
    human_readable_size,
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _find_register_entry(
    audit: AuditLog, evidence_id: str
) -> dict[str, Any] | None:
    """The ``evidence_register`` audit event for ``evidence_id`` (first match).

    Registration appends exactly one such event per evidence, so the first match
    is the one. Returns ``None`` when there is none — the caller decides that is
    a loud error, not a silent empty acta (RULE 2).
    """
    for entry in audit.entries():
        if (
            entry.get("action") == "evidence_register"
            and entry.get("evidence_id") == evidence_id
        ):
            return entry
    return None


def build_custody_act(
    case_id: str,
    evidence_id: str,
    *,
    cases: CaseManager = case_manager,
    evidence: EvidenceManager = evidence_manager,
) -> dict[str, Any]:
    """Build the structured acquisition act for ``(case_id, evidence_id)``.

    ``cases`` / ``evidence`` are injectable for tests; in production they are the
    module singletons (a design default, not an operator value — RULE 2 allows
    ``def f(dep=SINGLETON)``). Raises ``KeyError`` (unknown case/evidence, or a
    missing register event) / ``ValueError`` (malformed id).
    """
    # 1. Case identity — load() raises KeyError on an unknown / missing case.
    case = cases.load(case_id)

    # 2. Verified evidence handle — the single owner of evidence re-reads the
    #    baseline (raises KeyError / ValueError on unknown / malformed id).
    handle = evidence.get(case_id, evidence_id)

    # 3. The chain-of-custody link: the register event in the hash-chained log.
    case_dir = cases.case_dir(case_id)
    audit = AuditLog(case_dir / "audit.jsonl")
    register_entry = _find_register_entry(audit, evidence_id)
    if register_entry is None:
        raise KeyError(
            f"no 'evidence_register' audit entry for evidence_id={evidence_id} "
            f"in case {case_id}: cannot attest the chain-of-custody link for the "
            "acquisition act"
        )

    # 4. Read-only level + verification come from the authoritative metadata.
    meta = evidence.metadata(case_id, evidence_id)

    # 5. Whether the whole hash chain currently verifies (tamper-evidence).
    chain_verified = audit.verify()

    return {
        "generated_at": _utc_now_iso(),
        "tool": {
            "name": "FORENSIA",
            "version": __version__,
            "component": "forensia.evidence.EvidenceManager",
            "method": "SHA-256 stream hash + verified copy (chmod 0444)",
        },
        "case": {
            "id": case.id,
            "name": case.name,
            "examiner": case.examiner,
            "created_at": case.created_at,
            "status": case.status,
            "os_profile": case.os_profile,
            "os_profile_source": case.os_profile_source,
        },
        "evidence": {
            "evidence_id": handle.evidence_id,
            "source_path": register_entry.get("source_path"),
            "original_basename": register_entry.get("original_basename"),
            "sha256": handle.sha256,
            "size_bytes": handle.size,
            "size_human": human_readable_size(handle.size),
            "registered_at": handle.registered_at,
            "detected_os": handle.detected_os,
            "detected_kind": handle.detected_kind,
            # For an EWF ``.E01`` evidence, the whole segment family (each file + its
            # own baseline hash + size) so the annex attests every ingested file, not
            # just the first segment. Empty for a single-file evidence.
            "segments": [
                {
                    "name": s.name,
                    "sha256": s.sha256,
                    "size_bytes": s.size,
                    "size_human": human_readable_size(s.size),
                }
                for s in handle.segments
            ],
        },
        "read_only": {
            "level": meta["read_only_level"],
            "label": meta["read_only_label"],
        },
        "chain_of_custody": {
            "audit_log": "audit.jsonl",
            "register_entry_hash": register_entry.get("entry_hash"),
            "register_prev_hash": register_entry.get("prev_hash"),
            "register_ts_utc": register_entry.get("ts_utc"),
            "hash_chain_verified": chain_verified,
        },
        "verification": meta["verification"],
    }
