"""Exportaciones de la cobertura ATT&CK — CSV y ATT&CK Navigator layer (hallazgo D).

Los gates que importan:
- El CSV se DERIVA de la cobertura real (propuestas del agente + dictámenes del
  perito), con nombres/tácticas del catálogo Enterprise — nunca inventados.
- Un caso con **cero** técnicas evaluadas da una hoja con su procedencia y la
  cabecera, 0 filas — nunca un error; y un layer válido sin celdas.
- La hoja se ABRE bien en una hoja de cálculo: BOM (o Excel lee UTF-8 como ANSI y
  «Exfiltración» sale «ExfiltraciÃ³n»), punto y coma (o la fila entera cae en la
  columna A) y un bloque de procedencia que dice de qué caso es.
- El layer del Navigator es válido: formato 4.5, dominio enterprise-attack, colores
  por eje (dictamen del perito vs propuesta del agente), que no se funden.
"""

from __future__ import annotations

import csv
import io
import json

import pytest

from forensia.cases import CaseManager
from forensia.export_csv import BOM, DELIMITADOR, filas_de_preambulo
from forensia.findings.store import FindingStore
from forensia.mitre.coverage import CoverageStore
from forensia.mitre.export import (
    CSV_HEADER,
    NAVIGATOR_LAYER_VERSION,
    SIN_DICTAMEN,
    coverage_to_csv,
    coverage_to_navigator_layer,
)


#: Procedencia válida (UUID4) para hallazgos afirmativos — el store la exige
#: (anti-alucinación, RULE 2); estos tests ejercitan la export MITRE, no ese gate.
_RUN_ID = "11111111-1111-4111-8111-111111111111"


@pytest.fixture
def tmp_case(tmp_path) -> tuple[CaseManager, str]:
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Caso export", examiner="ramos", os_profile="windows")
    return cases, case.id


#: El bloque de procedencia de la hoja de cobertura (lo que hay antes de la tabla).
_PROCEDENCIA_FILAS = 8


def _sheet(csv_text: str) -> list[list[str]]:
    """Todas las líneas de la hoja, incluida la declaración del separador y el
    bloque de procedencia."""
    assert csv_text.startswith(BOM), "sin BOM, Excel abre el fichero como ANSI"
    body = csv_text[len(BOM) :]
    assert body.startswith(f"sep={DELIMITADOR}\r\n")
    return list(
        csv.reader(io.StringIO(body.split("\r\n", 1)[1]), delimiter=DELIMITADOR)
    )


def _rows(csv_text: str) -> list[list[str]]:
    """Sólo la TABLA: la cabecera y sus filas, ya sin el preámbulo. `_sheet` se ha
    comido la línea del separador, así que la cabecera va tras la procedencia y su
    línea vacía."""
    assert filas_de_preambulo([("x", "y")] * _PROCEDENCIA_FILAS) == (
        _PROCEDENCIA_FILAS + 2
    )
    return [r for r in _sheet(csv_text)[_PROCEDENCIA_FILAS + 1 :] if r]


# ── CSV ──────────────────────────────────────────────────────────────────────


def test_csv_opens_as_a_spreadsheet_and_declares_its_provenance(tmp_case) -> None:
    """BOM + `sep=;` + procedencia: los tres motivos por los que la hoja anterior
    se abría en una sola columna y con los acentos roto."""
    cases, case_id = tmp_case
    coverage = CoverageStore(cases, FindingStore(cases))
    coverage.adjudicate(case_id, "T1055", "confirmada", "Motivo con acentuación.")
    text = coverage_to_csv(
        coverage.coverage(case_id),
        case_id=case_id,
        case_name="Caso export",
        exported_at="2026-08-06T13:05:42Z",
    )
    assert text.startswith(BOM)
    assert "ó" in text  # el texto viaja en UTF-8, no transliterado
    procedencia = dict(r[0:2] for r in _sheet(text)[:_PROCEDENCIA_FILAS])
    assert procedencia["Caso"] == "Caso export"
    assert procedencia["Identificador del caso"] == case_id
    assert procedencia["Exportado (UTC)"] == "2026-08-06T13:05:42Z"
    assert procedencia["Técnicas en la hoja"] == "1"
    # Una línea vacía separa la procedencia de la tabla: es el contrato para
    # quien lea la hoja con un programa.
    assert _sheet(text)[_PROCEDENCIA_FILAS] == []
    assert _rows(text)[0] == list(CSV_HEADER)


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
        "run_id": _RUN_ID,
        "mitre_hints": ["T1055"],
    })
    rows = _rows(coverage_to_csv(coverage.coverage(case_id)))
    assert rows[0] == list(CSV_HEADER)
    idx = {name: i for i, name in enumerate(CSV_HEADER)}
    body = {r[idx["ID de la técnica"]]: r for r in rows[1:]}
    row = body["T1055"]
    assert row[idx["N"]] == "1"
    # Nombre y táctica salen del catálogo Enterprise, NO inventados.
    assert row[idx["Técnica"]] == "Process Injection"
    assert row[idx["ID de la táctica"]] == "TA0005"
    assert row[idx["Táctica"]] != ""
    assert row[idx["Propuesta por el análisis"]] == "Sí"
    assert row[idx["Hallazgos que la proponen"]] == "1"
    # Sin dictamen se DICE que está pendiente: en blanco se leería «no aplica».
    assert row[idx["Veredicto del perito"]] == SIN_DICTAMEN
    assert row[idx["Identificadores de hallazgo"]] == f.id
    assert row[idx["Celda de la matriz"]] == "T1055"


def test_csv_carries_the_examiner_verdict_and_rationale(tmp_case) -> None:
    cases, case_id = tmp_case
    findings = FindingStore(cases)
    coverage = CoverageStore(cases, findings)
    f = findings.append(case_id, {
        "title": "Inyección", "summary": "malfind.", "severity": "high",
        "run_id": _RUN_ID,
        "mitre_hints": ["T1055"],
    })
    coverage.adjudicate(
        case_id, "T1055", "confirmada", "RWX + shellcode.", related_finding_ids=[f.id]
    )
    rows = _rows(coverage_to_csv(coverage.coverage(case_id)))
    idx = {name: i for i, name in enumerate(CSV_HEADER)}
    row = {r[idx["ID de la técnica"]]: r for r in rows[1:]}["T1055"]
    assert row[idx["Veredicto del perito"]] == "Confirmada"
    assert row[idx["Motivo del veredicto"]] == "RWX + shellcode."
    assert row[idx["Propuesta por el análisis"]] == "Sí"
    assert row[idx["Fecha del veredicto (UTC)"]] != ""


def test_csv_row_for_a_verdict_without_an_agent_proposal(tmp_case) -> None:
    """El perito puede dictaminar una técnica que el agente no propuso."""
    cases, case_id = tmp_case
    coverage = CoverageStore(cases, FindingStore(cases))
    coverage.adjudicate(case_id, "T1070", "descartada", "Los logs están intactos.")
    rows = _rows(coverage_to_csv(coverage.coverage(case_id)))
    idx = {name: i for i, name in enumerate(CSV_HEADER)}
    row = {r[idx["ID de la técnica"]]: r for r in rows[1:]}["T1070"]
    assert row[idx["Propuesta por el análisis"]] == "No"
    assert row[idx["Veredicto del perito"]] == "Descartada"
    assert row[idx["Identificadores de hallazgo"]] == ""


def test_csv_is_parseable_and_quotes_the_delimiter(tmp_case) -> None:
    cases, case_id = tmp_case
    coverage = CoverageStore(cases, FindingStore(cases))
    coverage.adjudicate(
        case_id, "T1055", "sospechosa", 'Motivo; con punto y coma y "comillas".'
    )
    rows = _rows(coverage_to_csv(coverage.coverage(case_id)))
    idx = {name: i for i, name in enumerate(CSV_HEADER)}
    row = {r[idx["ID de la técnica"]]: r for r in rows[1:]}["T1055"]
    # csv.reader devuelve el valor original desescapado.
    assert row[idx["Motivo del veredicto"]] == 'Motivo; con punto y coma y "comillas".'


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
        "run_id": _RUN_ID,
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
        "run_id": _RUN_ID,
        "mitre_hints": ["T1055"],
    })
    coverage.adjudicate(case_id, "T1055", "sospechosa", "Indicio.")
    layer = coverage_to_navigator_layer(
        coverage.coverage(case_id), case_id=case_id, case_name="c"
    )
    t = {t["techniqueID"]: t for t in layer["techniques"]}["T1055"]
    assert t["color"] == "#e08a00"  # sospechosa (ámbar), no el azul de propuesta
    assert "Propuesta del agente" in t["comment"]  # pero la propuesta también consta
