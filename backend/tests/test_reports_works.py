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


import pytest

from agentopsy.audit.log import AuditLog
from _procedencia import crear_run, procedencia
from agentopsy.cases import CaseManager
from agentopsy.findings.store import FindingStore
from agentopsy.reports.works import (
    STATUS_INCOMPLETO,
    audited_argvs,
    render_argv,
    tokenizar_comando,
    tool_runs,
)


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
    # Ejecuciones REALES: desde F03 un hallazgo no cita un run inventado.
    ejecuciones = [crear_run(cases, case_id) for _ in range(2)]
    run_a, run_b = (e["run_id"] for e in ejecuciones)
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
        **procedencia(ejecuciones[0]),
    })
    f2 = findings.append(case_id, {
        "title": "Otro", "summary": "otro", "severity": "low",
        **procedencia(ejecuciones[1]),
    })
    # Un descarte sin run_id no cuelga de ninguna corrida, pero SÍ declara qué
    # se examinó y con qué límite (F03: «no se pudo» no es «no se encontró»).
    findings.append(case_id, {
        "title": "Via cerrada", "summary": "sin resultado", "severity": "low",
        "finding_kind": "descarte",
        "alcance_examinado": (
            "Se listó el arranque con tsk_fls sobre la particion 2; no hay "
            "entradas de persistencia. Limite: no se examinaron los hives."
        ),
    })

    runs = {r["run_id"]: r for r in tool_runs(case_id, cases=cases, findings=findings)}
    assert runs[run_a]["finding_ids"] == [f1.id]
    assert runs[run_b]["finding_ids"] == [f2.id]


def test_audited_argvs_renders_the_argv_preserving_boundaries() -> None:
    """El corpus sale del ARRAY, no de un texto: los límites entre argumentos
    sobreviven y un argumento con espacios no se confunde con dos.

    Colapsar espacios, que es lo que se hacía hasta 2026-09-08, hacía idénticos
    `grep "a b" f` y `grep a b f`, que buscan cosas distintas (F04)."""
    runs = [
        {"argv": ["tsk_fls", "-m", "C:/", "/evidence/x.E01"]},
        {"argv": ["grep", "a b", "f.txt"]},
        {"argv": []},
        {"argv_literal": "sin argv no entra"},
    ]
    corpus = audited_argvs(runs)
    assert corpus == {
        "tsk_fls -m C:/ /evidence/x.E01": ["tsk_fls", "-m", "C:/", "/evidence/x.E01"],
        'grep "a b" f.txt': ["grep", "a b", "f.txt"],
    }
    # Y el texto canónico se vuelve a tokenizar EXACTAMENTE en el array de origen.
    for canonico, argv in corpus.items():
        assert tokenizar_comando(canonico) == argv

# -- F04: los comandos conservan sus límites entre argumentos ----------------


@pytest.mark.parametrize(
    "argv",
    [
        ["grep", "a b", "f.txt"],
        ["grep", "a", "b", "f.txt"],
        ["regripper", "-r", "/evidence/SOFTWARE hive", "-f", "software"],
        ["tsk_fls", "-r", r"C:\Users\perito\disco.raw"],
        ["python", "-c", 'print("hola mundo")'],
        ["eco", "comilla simple: it's"],
        ["eco", ""],
        ["eco", "tab\there"],
    ],
)
def test_render_argv_round_trips_every_shape(argv) -> None:
    """Espacios, comillas, barras invertidas y vacíos: el texto que se publica
    se vuelve a tokenizar EXACTAMENTE en el array registrado."""
    texto = render_argv(argv)
    assert tokenizar_comando(texto) == argv


def test_collapsing_spaces_is_not_an_equivalence() -> None:
    """El defecto reproducido: dos comandos distintos daban la misma cadena."""
    con_frase = ["grep", "a b", "f.txt"]
    con_dos = ["grep", "a", "b", "f.txt"]
    assert render_argv(con_frase) != render_argv(con_dos)
    # Y la comparación por tokens no los confunde en ninguna dirección.
    assert tokenizar_comando(render_argv(con_frase)) != con_dos
    assert tokenizar_comando(render_argv(con_dos)) != con_frase


def test_a_malformed_command_is_not_tokenised_into_something_plausible() -> None:
    """Una comilla sin cerrar no es un comando: se dice, no se adivina."""
    assert tokenizar_comando('grep "a b f.txt') is None
