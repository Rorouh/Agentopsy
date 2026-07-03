"""Unit tests para ``forensia.consent`` — el dueño del gate de consentimiento cloud.

La ruta HTTP se prueba en ``test_web_surface.py``; aquí se fija el contrato de las
dos funciones puras: registrar el consentimiento y comprobarlo con emparejamiento
EXACTO por (caso, ejecutor). Un falso positivo aquí abriría egreso de datos a un
proveedor cloud sin consentimiento (SECURITY INVARIANT 7 / RGPD).
"""

from __future__ import annotations

from pathlib import Path

from forensia.audit.log import AuditLog
from forensia.consent import (
    CLOUD_CONSENT_ACTION,
    has_cloud_consent,
    record_cloud_consent,
)


def _audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


def test_no_consent_by_default(tmp_path: Path) -> None:
    assert has_cloud_consent(_audit(tmp_path), "case-1", "claude-code") is False


def test_record_then_has_consent(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    entry = record_cloud_consent(audit, "case-1", "claude-code", "Claude Code")
    assert entry["action"] == CLOUD_CONSENT_ACTION
    assert has_cloud_consent(audit, "case-1", "claude-code") is True


def test_consent_is_scoped_to_the_executor(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    record_cloud_consent(audit, "case-1", "claude-code", "Claude Code")
    # Consentir claude-code NO habilita gemini para el mismo caso.
    assert has_cloud_consent(audit, "case-1", "gemini") is False


def test_consent_is_scoped_to_the_case(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    record_cloud_consent(audit, "case-1", "claude-code", "Claude Code")
    # Consentir en case-1 NO habilita el mismo ejecutor en case-2.
    assert has_cloud_consent(audit, "case-2", "claude-code") is False


def test_consent_survives_other_audit_entries(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    audit.append({"action": "evidence_register", "case_id": "case-1"})
    record_cloud_consent(audit, "case-1", "codex", "Codex CLI")
    audit.append({"action": "executor_run_start", "case_id": "case-1"})
    assert has_cloud_consent(audit, "case-1", "codex") is True
    # La cadena hash sigue íntegra tras los appends.
    assert audit.verify() is True


def test_entries_empty_on_missing_log(tmp_path: Path) -> None:
    assert AuditLog(tmp_path / "nope.jsonl").entries() == []
