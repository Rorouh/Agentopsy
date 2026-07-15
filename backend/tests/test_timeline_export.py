"""Exportación CSV del timeline de investigación (hallazgo D).

Reusa el builder existente (``assemble_investigation_timeline``) para producir los
eventos y verifica que el CSV es honesto: cabecera estable, una fila por evento (tanto
``tool_run`` como ``finding``), y un caso sin actividad da sólo la cabecera.
"""

from __future__ import annotations

import csv
import io

from forensia.findings.store import Finding
from forensia.timeline.builder import assemble_investigation_timeline
from forensia.timeline.export import CSV_HEADER, timeline_to_csv


def _rows(csv_text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(csv_text)))


def _finding(fid: str, created_at: str) -> Finding:
    return Finding(
        id=fid,
        case_id="c1",
        title="Persistencia detectada",
        summary="run key sospechosa",
        severity="high",
        evidence_id="e1",
        tool_id="RegRipper",
        run_id=None,
        created_at=created_at,
        mitre_hints=["T1547.001"],
    )


def test_empty_timeline_is_header_only() -> None:
    rows = _rows(timeline_to_csv([]))
    assert rows == [list(CSV_HEADER)]


def test_csv_has_one_row_per_event_across_both_kinds() -> None:
    audit = [
        {
            "action": "tool_run_start",
            "ts_utc": "2026-07-15T10:00:00+00:00",
            "run_id": "r1",
            "tool_id": "tsk_fls",
            "argv": ["fls", "-m", "/", "img.raw"],
            "evidence_id": "e1",
        },
        {
            "action": "tool_run_finish",
            "ts_utc": "2026-07-15T10:00:05+00:00",
            "run_id": "r1",
            "status": "finished",
            "exit_code": 0,
            "stdout_sha256": "a" * 64,
            "stderr_sha256": "b" * 64,
            "output_files_count": 0,
        },
    ]
    events = assemble_investigation_timeline(
        audit, [_finding("f1", "2026-07-15T11:00:00.000Z")]
    )
    rows = _rows(timeline_to_csv(events))
    assert rows[0] == list(CSV_HEADER)
    assert len(rows) == 3  # header + tool_run + finding

    idx = {name: i for i, name in enumerate(CSV_HEADER)}
    by_kind = {r[idx["kind"]]: r for r in rows[1:]}

    tool = by_kind["tool_run"]
    assert tool[idx["tool_id"]] == "tsk_fls"
    assert tool[idx["argv"]] == "fls -m / img.raw"
    assert tool[idx["exit"]] == "0"
    assert tool[idx["status"]] == "finished"
    assert tool[idx["ts_utc"]].endswith("Z")  # UTC explícito

    finding = by_kind["finding"]
    assert finding[idx["title"]] == "Persistencia detectada"
    assert finding[idx["severity"]] == "high"
    assert finding[idx["mitre_hints"]] == "T1547.001"
    assert finding[idx["tool_id"]] == "RegRipper"


def test_running_tool_run_has_empty_exit_but_is_kept() -> None:
    audit = [
        {
            "action": "tool_run_start",
            "ts_utc": "2026-07-15T10:00:00+00:00",
            "run_id": "r1",
            "tool_id": "tsk_mmls",
            "argv": ["mmls", "img.raw"],
        },
    ]
    events = assemble_investigation_timeline(audit, [])
    rows = _rows(timeline_to_csv(events))
    idx = {name: i for i, name in enumerate(CSV_HEADER)}
    row = rows[1]
    assert row[idx["exit"]] == ""  # sin exit todavía
    assert row[idx["status"]] == "running"


def test_unparseable_timestamp_becomes_empty_but_row_is_not_dropped() -> None:
    audit = [
        {
            "action": "tool_run_start",
            "ts_utc": "not-a-date",
            "run_id": "r-bad",
            "tool_id": "tsk_fls",
            "argv": [],
        },
    ]
    events = assemble_investigation_timeline(audit, [])
    rows = _rows(timeline_to_csv(events))
    idx = {name: i for i, name in enumerate(CSV_HEADER)}
    assert len(rows) == 2  # header + la fila, nunca descartada
    assert rows[1][idx["ts_utc"]] == ""
