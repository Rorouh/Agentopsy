"""«Trabajos realizados»: las ejecuciones reensambladas del audit log.

Los gates que importan (``agentopsy.reports.works``), todos derivados de FORENSIC
INVARIANT 4:

1. El ``argv`` del informe es TOKEN A TOKEN el de ``tool_run_start`` — nunca una
   reconstrucción a partir de los params.
2. Un run con ``exit_code != 0`` aparece igual: un informe que solo muestra lo
   que funcionó no es reproducible.
3. ``tool_version`` viaja si el audit la trae, y NO se inventa ``"unknown"``
   cuando no (RULE 2).
4. Un ``run_id`` sin ``tool_run_finish`` aparece como ``incompleto``, no se
   descarta.
5. Los ``finding_ids`` cruzados son exactamente los que citan ese ``run_id``.
"""

from __future__ import annotations

import uuid

import pytest

from agentopsy.audit.log import AuditLog
from agentopsy.cases import CaseManager
from agentopsy.findings.store import FindingStore
from agentopsy.reports.works import STATUS_INCOMPLETO, audited_argvs, tool_runs


@pytest.fixture
def caso(tmp_path) -> tuple[CaseManager, FindingStore, str]:
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Murcielago", examiner="ramos", os_profile="windows")
    return cases, FindingStore(cases), case.id


def _audit(cases: CaseManager, case_id: str) -> AuditLog:
    return AuditLog(cases.case_dir(case_id) / "audit.jsonl")


ARGV_FLS = ["tsk_fls", "-m", "C:/", "-r", "-o", "2048", "/evidence/original.E01"]


def test_case_without_audit_has_no_runs(caso) -> None:
    cases, findings, case_id = caso
    assert tool_runs(case_id, cases=cases, findings=findings) == []


def test_argv_is_the_audited_one_token_by_token(caso) -> None:
    cases, findings, case_id = caso
    audit = _audit(cases, case_id)
    audit.append({
        "action": "tool_run_start", "case_id": case_id, "run_id": "run-1",
        "tool_id": "tsk_fls", "argv": ARGV_FLS, "tool_version": "4.12.1",
        "evidence_id": "ev-1", "baseline_sha256": "a" * 64,
    })
    audit.append({
        "action": "tool_run_finish", "case_id": case_id, "run_id": "run-1",
        "status": "finished", "exit_code": 0, "output_files_count": 1,
    })

    runs = tool_runs(case_id, cases=cases, findings=findings)
    assert len(runs) == 1
    assert runs[0]["argv"] == ARGV_FLS
    assert runs[0]["argv_literal"] == " ".join(ARGV_FLS)
    assert runs[0]["tool_version"] == "4.12.1"
    assert runs[0]["status"] == "finished"
    assert runs[0]["exit_code"] == 0


def test_failed_run_is_reported_too(caso) -> None:
    cases, findings, case_id = caso
    audit = _audit(cases, case_id)
    for i, (exit_code, status) in enumerate(((0, "finished"), (1, "finished")), start=1):
        audit.append({
            "action": "tool_run_start", "case_id": case_id, "run_id": f"run-{i}",
            "tool_id": "tsk_mmls", "argv": ["tsk_mmls", f"/evidence/{i}.raw"],
        })
        audit.append({
            "action": "tool_run_finish", "case_id": case_id, "run_id": f"run-{i}",
            "status": status, "exit_code": exit_code,
        })

    runs = tool_runs(case_id, cases=cases, findings=findings)
    assert [r["exit_code"] for r in runs] == [0, 1]


def test_missing_tool_version_is_absent_not_unknown(caso) -> None:
    cases, findings, case_id = caso
    audit = _audit(cases, case_id)
    audit.append({
        "action": "tool_run_start", "case_id": case_id, "run_id": "run-1",
        "tool_id": "xxd", "argv": ["xxd", "-l", "64", "/evidence/x.raw"],
    })
    audit.append({
        "action": "tool_run_finish", "case_id": case_id, "run_id": "run-1",
        "status": "finished", "exit_code": 0,
    })

    run = tool_runs(case_id, cases=cases, findings=findings)[0]
    assert "tool_version" not in run  # RULE 2: no se fabrica "unknown"


def test_run_without_finish_is_incomplete_not_dropped(caso) -> None:
    cases, findings, case_id = caso
    _audit(cases, case_id).append({
        "action": "tool_run_start", "case_id": case_id, "run_id": "run-huerfano",
        "tool_id": "volatility3", "argv": ["vol", "-f", "/evidence/mem.raw", "pslist"],
    })

    runs = tool_runs(case_id, cases=cases, findings=findings)
    assert len(runs) == 1
    assert runs[0]["status"] == STATUS_INCOMPLETO
    assert runs[0]["finished_at"] is None


def test_findings_are_crossed_by_run_id(caso) -> None:
    cases, findings, case_id = caso
    audit = _audit(cases, case_id)
    run_a, run_b = str(uuid.uuid4()), str(uuid.uuid4())
    for rid in (run_a, run_b):
        audit.append({
            "action": "tool_run_start", "case_id": case_id, "run_id": rid,
            "tool_id": "tsk_fls", "argv": ["tsk_fls", "-r", f"/evidence/{rid}.E01"],
        })
        audit.append({
            "action": "tool_run_finish", "case_id": case_id, "run_id": rid,
            "status": "finished", "exit_code": 0,
        })
    f1 = findings.append(case_id, {
        "title": "Tarea programada", "summary": "updater", "severity": "high",
        "run_id": run_a, "artifact_sha256": "b" * 64, "tool_id": "tsk_fls",
    })
    f2 = findings.append(case_id, {
        "title": "Otro", "summary": "otro", "severity": "low",
        "run_id": run_b, "artifact_sha256": "c" * 64, "tool_id": "tsk_fls",
    })
    # Un descarte sin run_id no cuelga de ninguna corrida.
    findings.append(case_id, {
        "title": "Via cerrada", "summary": "sin resultado", "severity": "low",
        "finding_kind": "descarte",
    })

    runs = {r["run_id"]: r for r in tool_runs(case_id, cases=cases, findings=findings)}
    assert runs[run_a]["finding_ids"] == [f1.id]
    assert runs[run_b]["finding_ids"] == [f2.id]


def test_audited_argvs_normalises_whitespace_only() -> None:
    runs = [{"argv_literal": "tsk_fls  -m   C:/ /evidence/x.E01"}, {"argv_literal": ""}]
    assert audited_argvs(runs) == {"tsk_fls -m C:/ /evidence/x.E01"}
