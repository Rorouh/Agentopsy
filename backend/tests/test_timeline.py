"""Timeline builders: the deterministic investigation layer and the MACB expansion of a
TSK bodyfile (the ``fls -m`` → ``mactime`` transform), plus the ``fls`` pipeline driver.

No docker / no real TSK: the pure builders are exercised with fixtures, and the pipeline
driver fakes ONLY the dispatcher (which the case-anchored dispatcher tests cover for
real) — so no test fakes the property it claims to prove.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from forensia.cases.manager import CaseManager
from forensia.findings.store import Finding, FindingStore
from forensia.timeline import builder
from forensia.timeline.builder import (
    assemble_investigation_timeline,
    bodyfile_to_fs_events,
    build_investigation_timeline,
    run_filesystem_timeline,
)


# --------------------------------------------------------------------------- #
# Layer 1 — investigation timeline (pure assemble)
# --------------------------------------------------------------------------- #
def _finding(fid: str, created_at: str, *, title: str = "hallazgo") -> Finding:
    return Finding(
        id=fid,
        case_id="c1",
        title=title,
        summary="resumen",
        severity="high",
        evidence_id=None,
        tool_id="tsk_fls",
        run_id=None,
        created_at=created_at,
        mitre_hints=[],
    )


def test_assemble_orders_tool_runs_and_findings_chronologically() -> None:
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
        {
            "action": "tool_run_start",
            "ts_utc": "2026-07-15T12:00:00+00:00",
            "run_id": "r2",
            "tool_id": "tsk_mmls",
            "argv": ["mmls", "img.raw"],
            "evidence_id": "e1",
        },
    ]
    findings = [
        _finding("f-late", "2026-07-15T13:00:00.000Z"),
        _finding("f-early", "2026-07-15T09:00:00.000Z"),
    ]
    events = assemble_investigation_timeline(audit, findings)

    # chronological across BOTH sources: f-early, r1, r2, f-late.
    assert [_id(e) for e in events] == ["f-early", "r1", "r2", "f-late"]
    assert [e["kind"] for e in events] == ["finding", "tool_run", "tool_run", "finding"]


def test_tool_run_event_pairs_start_with_finish() -> None:
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
            "output_files_count": 2,
        },
    ]
    (ev,) = assemble_investigation_timeline(audit, [])
    assert ev["kind"] == "tool_run"
    assert ev["tool_id"] == "tsk_fls"
    assert ev["argv"] == ["fls", "-m", "/", "img.raw"]
    assert ev["exit"] == 0
    assert ev["status"] == "finished"
    assert ev["output_files_count"] == 2
    assert {"relpath": "stdout.txt", "sha256": "a" * 64} in ev["artifacts"]
    assert {"relpath": "stderr.txt", "sha256": "b" * 64} in ev["artifacts"]
    assert ev["ts"].endswith("Z")  # explicit UTC


def test_tool_run_without_finish_is_running_and_kept() -> None:
    audit = [
        {
            "action": "tool_run_start",
            "ts_utc": "2026-07-15T10:00:00+00:00",
            "run_id": "r1",
            "tool_id": "tsk_fls",
            "argv": ["fls"],
        },
    ]
    (ev,) = assemble_investigation_timeline(audit, [])
    assert ev["status"] == "running"
    assert ev["exit"] is None


def test_unparseable_timestamp_sorts_last_never_dropped() -> None:
    audit = [
        {
            "action": "tool_run_start",
            "ts_utc": "not-a-date",
            "run_id": "r-bad",
            "tool_id": "tsk_fls",
            "argv": [],
        },
    ]
    findings = [_finding("f-ok", "2026-07-15T09:00:00.000Z")]
    events = assemble_investigation_timeline(audit, findings)
    assert [_id(e) for e in events] == ["f-ok", "r-bad"]
    assert events[-1]["ts"] is None  # surfaced, not hidden


# --------------------------------------------------------------------------- #
# Layer 1 — build_investigation_timeline (I/O against a real temp case)
# --------------------------------------------------------------------------- #
def test_build_investigation_timeline_reads_audit_and_findings(
    monkeypatch, tmp_path
) -> None:
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="op", examiner="alice", os_profile="unix")
    findings = FindingStore(cases)
    monkeypatch.setattr(builder, "case_manager", cases)
    monkeypatch.setattr(builder, "finding_store", findings)

    audit_path = cases.case_dir(case.id) / "audit.jsonl"
    audit_path.write_text(
        json.dumps(
            {
                "action": "tool_run_start",
                "ts_utc": "2026-07-15T10:00:00+00:00",
                "run_id": "r1",
                "tool_id": "tsk_fls",
                "argv": ["fls"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    findings.append(
        case.id,
        {
            "title": "t", "summary": "s", "severity": "low", "tool_id": "tsk_fls",
            # Hallazgo afirmativo: el store exige procedencia (run_id) — RULE 2.
            "run_id": "11111111-1111-4111-8111-111111111111",
        },
    )

    events = build_investigation_timeline(case.id)
    kinds = sorted(e["kind"] for e in events)
    assert kinds == ["finding", "tool_run"]


def test_build_investigation_timeline_empty_case(monkeypatch, tmp_path) -> None:
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="op", examiner="alice", os_profile="unix")
    monkeypatch.setattr(builder, "case_manager", cases)
    monkeypatch.setattr(builder, "finding_store", FindingStore(cases))
    assert build_investigation_timeline(case.id) == []


# --------------------------------------------------------------------------- #
# Layer 2 — bodyfile → MACB events
# --------------------------------------------------------------------------- #
def test_bodyfile_macb_grouping_and_letters() -> None:
    # crtime == 100 (b), atime == mtime == ctime == 200 (m,a,c share the instant).
    body = "0|/etc/passwd|128-1-1|r/rrw-|0|0|4096|200|200|200|100"
    events, total = bodyfile_to_fs_events(body)
    assert total == 2  # two distinct instants: 100 and 200
    by_ts = {e["ts"]: e for e in events}
    born = by_ts["1970-01-01T00:01:40Z"]  # epoch 100
    macb = by_ts["1970-01-01T00:03:20Z"]  # epoch 200
    assert born["macb"] == "...b"
    assert macb["macb"] == "mac."
    assert macb["path"] == "/etc/passwd"
    assert macb["inode"] == "128-1-1"
    assert macb["size"] == 4096
    assert macb["kind"] == "fs"


def test_bodyfile_all_times_equal_yields_full_macb() -> None:
    body = "0|/a|5|r/r|0|0|10|500|500|500|500"
    events, total = bodyfile_to_fs_events(body)
    assert total == 1
    assert events[0]["macb"] == "macb"


def test_bodyfile_skips_zero_times_and_malformed_lines() -> None:
    body = "\n".join(
        [
            "0|/only-mtime|5|r/r|0|0|10|0|300|0|0",  # only mtime set
            "not-a-body-line",  # wrong field count → skipped
            "",  # blank → skipped
            "0|/no-times|6|r/r|0|0|0|0|0|0|0",  # all zero → no events
        ]
    )
    events, total = bodyfile_to_fs_events(body)
    assert total == 1
    assert events[0]["path"] == "/only-mtime"
    assert events[0]["macb"] == "m..."


def test_bodyfile_events_sorted_chronologically_and_capped() -> None:
    body = "\n".join(
        f"0|/f{i}|{i}|r/r|0|0|0|0|{1000 - i}|0|0" for i in range(10)
    )
    events, total = bodyfile_to_fs_events(body, limit=3)
    assert total == 10
    assert len(events) == 3
    ts = [e["ts"] for e in events]
    assert ts == sorted(ts)  # earliest kept after the cap


# --------------------------------------------------------------------------- #
# Layer 2 — run_filesystem_timeline (dispatcher faked)
# --------------------------------------------------------------------------- #
class _Handle:
    def __init__(self, path: Path) -> None:
        self.original_path = path


class _Ctx:
    evidence_id = "e-1"


def _fake_cases(tmp_path):
    class _Cases:
        def case_dir(self, case_id: str) -> Path:
            d = tmp_path / "cases" / case_id
            (d / "artifacts").mkdir(parents=True, exist_ok=True)
            return d

    return _Cases()


def test_run_filesystem_timeline_runs_fls_and_parses_bodyfile(
    monkeypatch, tmp_path
) -> None:
    cases = _fake_cases(tmp_path)
    monkeypatch.setattr(builder, "case_manager", cases)

    body = "0|/etc/passwd|5|r/r|0|0|4096|100|100|100|100"

    def fake_execute(tool_id, params, *, case_id, os_profile, evidence_context):
        assert tool_id == "tsk_fls"
        assert params["body_format"] is True and params["recursive"] is True
        run_id = "run-abc"
        run_dir = cases.case_dir(case_id) / "artifacts" / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "stdout.txt").write_text(body, encoding="utf-8")
        return {"exit_code": 0, "run_id": run_id, "stderr_sample": ""}

    monkeypatch.setattr(builder.dispatcher, "execute", fake_execute)

    emitted: list[dict] = []
    result = run_filesystem_timeline(
        "case-1", _Handle(tmp_path / "img.raw"), _Ctx(), "unix", emit=emitted.append
    )
    assert result["timezone"] == "UTC"
    assert result["total_events"] == 1
    assert result["events"][0]["macb"] == "macb"
    assert result["fls_run_id"] == "run-abc"
    assert any(e.get("stage") == "done" for e in emitted)


def test_run_filesystem_timeline_fails_loud_on_nonzero_exit(
    monkeypatch, tmp_path
) -> None:
    cases = _fake_cases(tmp_path)
    monkeypatch.setattr(builder, "case_manager", cases)

    def fake_execute(tool_id, params, *, case_id, os_profile, evidence_context):
        return {"exit_code": 1, "run_id": "r", "stderr_sample": "Cannot determine file system type"}

    monkeypatch.setattr(builder.dispatcher, "execute", fake_execute)

    with pytest.raises(RuntimeError, match="exit_code 1|super-timeline parcial"):
        run_filesystem_timeline("case-1", _Handle(tmp_path / "img.raw"), _Ctx(), "unix")


def _id(event: dict) -> str:
    return event.get("run_id") or event.get("finding_id")
