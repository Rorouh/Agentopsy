"""Reglas de `findings.atribucion`: de qué evidencia sale un hallazgo.

La evidencia de un hallazgo es la de la ejecución (`run_id`) que lo sostiene, leída
del registro; sin ejecución, la declarada; sin nada, la única del caso o ninguna
(hallazgo del caso entero). Nunca una evidencia «primaria», nunca la que el modelo
diga contra lo que dice el registro (RULE 2, FORENSIC INVARIANT 4).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from agentopsy.artifacts.store import ArtifactStore
from agentopsy.cases.manager import CaseManager
from agentopsy.findings.atribucion import atribuir_evidencia
from agentopsy.i18n import codigo_de

RAM = "11111111-1111-4111-8111-111111111111"
DISK = "22222222-2222-4222-8222-222222222222"
AJENA = "99999999-9999-4999-8999-999999999999"
RUN_DISK = "44444444-4444-4444-8444-444444444444"
RUN_LEGACY = "55555555-5555-4555-8555-555555555555"
RUN_AJENO = "66666666-6666-4666-8666-666666666666"
RUN_INEXISTENTE = "77777777-7777-4777-8777-777777777777"


class _Runs:
    def __init__(self) -> None:
        self._runs = {RUN_DISK: DISK, RUN_LEGACY: None, RUN_AJENO: AJENA}

    def get_run(self, case_id: str, run_id: str) -> SimpleNamespace:
        if run_id not in self._runs:
            raise KeyError(f"unknown run_id for case {case_id}: {run_id}")
        return SimpleNamespace(run_id=run_id, evidence_id=self._runs[run_id])


def _atribuir(**kwargs):
    base = {
        "run_id": None,
        "declarada": None,
        "evidencias_del_caso": (RAM, DISK),
        "store": _Runs(),
    }
    base.update(kwargs)
    return atribuir_evidencia("c", **base)


def test_con_run_la_evidencia_es_la_de_la_ejecucion() -> None:
    a = _atribuir(run_id=RUN_DISK)
    assert (a.evidence_id, a.origen) == (DISK, "run")


def test_con_run_la_declaracion_coincidente_se_acepta() -> None:
    a = _atribuir(run_id=RUN_DISK, declarada=DISK)
    assert (a.evidence_id, a.origen) == (DISK, "run")


def test_con_run_una_declaracion_distinta_se_rechaza() -> None:
    with pytest.raises(ValueError) as exc:
        _atribuir(run_id=RUN_DISK, declarada=RAM)
    assert codigo_de(exc.value) == "findings.evidenceMismatch"


@pytest.mark.parametrize(
    ("run_id", "codigo"),
    [
        (RUN_INEXISTENTE, "findings.runNotInCase"),
        ("no-es-un-uuid", "findings.runNotInCase"),
        (RUN_LEGACY, "findings.runWithoutEvidence"),
        (RUN_AJENO, "findings.runEvidenceNotInCase"),
    ],
)
def test_una_ejecucion_que_no_permite_atribuir_se_rechaza(run_id: str, codigo: str) -> None:
    with pytest.raises(ValueError) as exc:
        _atribuir(run_id=run_id)
    assert codigo_de(exc.value) == codigo


def test_sin_run_vale_la_evidencia_declarada_del_caso() -> None:
    a = _atribuir(declarada=RAM)
    assert (a.evidence_id, a.origen) == (RAM, "declared")


def test_sin_run_una_evidencia_ajena_al_caso_se_rechaza() -> None:
    with pytest.raises(ValueError) as exc:
        _atribuir(declarada=AJENA)
    assert codigo_de(exc.value) == "findings.evidenceNotInCase"


def test_sin_run_ni_declaracion_con_una_evidencia_es_esa() -> None:
    a = _atribuir(evidencias_del_caso=(DISK,))
    assert (a.evidence_id, a.origen) == (DISK, "single_evidence")


def test_sin_run_ni_declaracion_con_varias_es_del_caso() -> None:
    a = _atribuir()
    assert (a.evidence_id, a.origen) == (None, "case")


def test_un_run_id_que_no_es_texto_se_rechaza_como_en_el_almacen() -> None:
    with pytest.raises(ValueError, match="run_id must be a UUID4 or null"):
        _atribuir(run_id=123)


def test_con_el_almacen_real_de_artefactos(tmp_path: Path) -> None:
    """Contra el `ArtifactStore` de verdad: el manifiesto de un run registra su
    evidencia y es lo que manda."""
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="op", examiner="alice", os_profile="windows")
    store = ArtifactStore(cases)
    run_id, _out = store.start_run(
        case.id,
        "tsk_icat",
        ["icat", "original.vmdk", "71418"],
        evidence_id=DISK,
        evidence_baseline_sha256="b" * 64,
        tool_version="4.12.1",
    )
    a = atribuir_evidencia(
        case.id,
        run_id=run_id,
        declarada=None,
        evidencias_del_caso=(RAM, DISK),
        store=store,
    )
    assert (a.evidence_id, a.origen) == (DISK, "run")
