"""El ledger de hallazgos del replay DEBE exponer el finding_id real.

Regresión (2026-07-15): sin el id, el agente no tenía un `finding_id` que pasar a
`annotate_mitre` y se inventaba un UUID → el store lo rechazaba y la correlación
MITRE nunca se anclaba. El id entre backticks es lo que arregla la relación.
"""

from __future__ import annotations

import pytest

from forensia.agent import history
from forensia.findings.store import Finding


def _finding(fid: str, title: str) -> Finding:
    return Finding(
        id=fid,
        case_id="c1",
        title=title,
        summary="…",
        severity="high",
        evidence_id=None,
        tool_id="volatility3",
        run_id=None,
        created_at="2026-07-15T00:00:00.000Z",
        mitre_hints=[],
    )


def test_findings_ledger_exposes_the_real_finding_id(monkeypatch: pytest.MonkeyPatch) -> None:
    fid = "c4a9e2f7-5b8d-4c1a-a3f6-9d2b7e0c8a53"
    monkeypatch.setattr(
        history.finding_store, "list", lambda case_id: [_finding(fid, "Inyección RWX")]
    )
    block = history._findings_ledger("c1")
    assert f"`{fid}`" in block  # el id REAL, entre backticks
    assert "annotate_mitre" in block  # y la instrucción de usarlo
    assert "Inyección RWX" in block


def test_findings_ledger_empty_when_no_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(history.finding_store, "list", lambda case_id: [])
    assert history._findings_ledger("c1") == ""
