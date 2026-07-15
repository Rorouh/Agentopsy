"""Exportaciones de la cobertura ATT&CK — CSV y ATT&CK Navigator layer (hallazgo D).

Los gates que importan:
- El CSV se DERIVA de la cobertura real (propuestas del agente + dictámenes del
  perito), con nombres/tácticas del catálogo Enterprise — nunca inventados.
- Un caso con **cero** técnicas evaluadas da un CSV con sólo la cabecera (0 filas,
  honesto) y un layer válido sin celdas — nunca un error.
- El layer del Navigator es válido: formato 4.5, dominio enterprise-attack, colores
  por eje (dictamen del perito vs propuesta del agente), que no se funden.
"""

from __future__ import annotations

import csv
import io
import json

import pytest

from forensia.cases import CaseManager
from forensia.findings.store import FindingStore
from forensia.mitre.coverage import CoverageStore
from forensia.mitre.export import (
    CSV_HEADER,
    NAVIGATOR_LAYER_VERSION,
    coverage_to_csv,
    coverage_to_navigator_layer,
)


@pytest.fixture
def tmp_case(tmp_path) -> tuple[CaseManager, str]:
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Caso export", examiner="ramos", os_profile="windows")
    return cases, case.id


def _rows(csv_text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(csv_text)))


# ── CSV ──────────────────────────────────────────────────────────────────────


def test_csv_empty_case_is_header_only(tmp_case) -> None:
    """Cero técnicas evaluadas → cabecera y 0 filas, no un error."""
    cases, case_id = tmp_case
    coverage = CoverageStore(cases, FindingStore(cases))
    rows = _rows(coverage_to_csv(coverage.coverage(case_id)))
    assert rows == [list(CSV_HEADER)]


def test_csv_row_for_an_agent_proposal(tmp_case) -> None:
    cases, case_id = tmp_case
    findings = FindingStore(cases)
    coverage = CoverageStore(cases, findings)
    f = findings.append(case_id, {
        "title": "Inyección",
        "summary": "malfind: región RWX.",
        "severity": "high",
        "mitre_hints": ["T1055"],
    })
    rows = _rows(coverage_to_csv(coverage.coverage(case_id)))
    assert rows[0] == list(CSV_HEADER)
    body = {r[0]: r for r in rows[1:]}
    row = body["T1055"]
    idx = {name: i for i, name in enumerate(CSV_HEADER)}
    # Nombre y táctica salen del catálogo Enterprise, NO inventados.
    assert row[idx["technique_name"]] == "Process Injection"
    assert row[idx["tactic_id"]] == "TA0005"
    assert row[idx["tactic"]] != ""
    assert row[idx["agent_proposed"]] == "true"
    assert row[idx["examiner_verdict"]] == ""  # gris = no evaluada
    assert row[idx["findings"]] == f.id
    assert row[idx["enterprise_display_id"]] == "T1055"


def test_csv_carries_the_examiner_verdict_and_rationale(tmp_case) -> None:
    cases, case_id = tmp_case
    findings = FindingStore(cases)
    coverage = CoverageStore(cases, findings)
    f = findings.append(case_id, {
        "title": "Inyección", "summary": "malfind.", "severity": "high",
        "mitre_hints": ["T1055"],
    })
    coverage.adjudicate(
        case_id, "T1055", "confirmada", "RWX + shellcode.", related_finding_ids=[f.id]
    )
    rows = _rows(coverage_to_csv(coverage.coverage(case_id)))
    idx = {name: i for i, name in enumerate(CSV_HEADER)}
    row = {r[0]: r for r in rows[1:]}["T1055"]
    assert row[idx["examiner_verdict"]] == "confirmada"
    assert row[idx["rationale"]] == "RWX + shellcode."
    assert row[idx["agent_proposed"]] == "true"


def test_csv_row_for_a_verdict_without_an_agent_proposal(tmp_case) -> None:
    """El perito puede dictaminar una técnica que el agente no propuso."""
    cases, case_id = tmp_case
    coverage = CoverageStore(cases, FindingStore(cases))
    coverage.adjudicate(case_id, "T1070", "descartada", "Los logs están intactos.")
    rows = _rows(coverage_to_csv(coverage.coverage(case_id)))
    idx = {name: i for i, name in enumerate(CSV_HEADER)}
    row = {r[0]: r for r in rows[1:]}["T1070"]
    assert row[idx["agent_proposed"]] == "false"
    assert row[idx["examiner_verdict"]] == "descartada"
    assert row[idx["findings"]] == ""


def test_csv_is_parseable_and_quotes_commas(tmp_case) -> None:
    cases, case_id = tmp_case
    coverage = CoverageStore(cases, FindingStore(cases))
    coverage.adjudicate(
        case_id, "T1055", "sospechosa", "Motivo, con coma y \"comillas\"."
    )
    rows = _rows(coverage_to_csv(coverage.coverage(case_id)))
    idx = {name: i for i, name in enumerate(CSV_HEADER)}
    row = {r[0]: r for r in rows[1:]}["T1055"]
    # csv.reader devuelve el valor original desescapado.
    assert row[idx["rationale"]] == 'Motivo, con coma y "comillas".'


# ── ATT&CK Navigator layer ───────────────────────────────────────────────────


def test_navigator_layer_is_valid_and_empty_when_no_coverage(tmp_case) -> None:
    cases, case_id = tmp_case
    coverage = CoverageStore(cases, FindingStore(cases))
    layer = coverage_to_navigator_layer(
        coverage.coverage(case_id), case_id=case_id, case_name="Caso export"
    )
    json.dumps(layer)  # serializable
    assert layer["versions"]["layer"] == NAVIGATOR_LAYER_VERSION == "4.5"
    assert layer["domain"] == "enterprise-attack"
    assert layer["techniques"] == []
    assert "Caso export" in layer["name"]


def test_navigator_layer_colors_by_axis(tmp_case) -> None:
    cases, case_id = tmp_case
    findings = FindingStore(cases)
    coverage = CoverageStore(cases, findings)
    # Propuesta del agente sin dictaminar → color de propuesta.
    findings.append(case_id, {
        "title": "Persistencia", "summary": "run key.", "severity": "medium",
        "mitre_hints": ["T1547.001"],
    })
    # Dictamen del perito → color de veredicto.
    coverage.adjudicate(case_id, "T1055", "confirmada", "RWX + shellcode.")

    layer = coverage_to_navigator_layer(
        coverage.coverage(case_id), case_id=case_id, case_name="c"
    )
    by_id = {t["techniqueID"]: t for t in layer["techniques"]}
    # La sub-técnica de la semilla se pinta en su celda Enterprise padre.
    assert "T1547" in by_id
    assert by_id["T1547"]["color"] == "#2f6fed"  # propuesta (azul)
    assert by_id["T1055"]["color"] == "#c1121f"  # confirmada (rojo)
    assert "Dictamen del perito: Confirmada" in by_id["T1055"]["comment"]
    assert all(t["enabled"] for t in layer["techniques"])


def test_navigator_layer_verdict_wins_over_proposal_color(tmp_case) -> None:
    """Si una técnica está propuesta Y dictaminada, el color lo manda el dictamen."""
    cases, case_id = tmp_case
    findings = FindingStore(cases)
    coverage = CoverageStore(cases, findings)
    findings.append(case_id, {
        "title": "Inyección", "summary": "malfind.", "severity": "high",
        "mitre_hints": ["T1055"],
    })
    coverage.adjudicate(case_id, "T1055", "sospechosa", "Indicio.")
    layer = coverage_to_navigator_layer(
        coverage.coverage(case_id), case_id=case_id, case_name="c"
    )
    t = {t["techniqueID"]: t for t in layer["techniques"]}["T1055"]
    assert t["color"] == "#e08a00"  # sospechosa (ámbar), no el azul de propuesta
    assert "Propuesta del agente" in t["comment"]  # pero la propuesta también consta
