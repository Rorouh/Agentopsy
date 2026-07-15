"""MITRE ATT&CK — catálogo (enum cerrada) y cobertura (propuesta vs dictamen).

Los gates que importan:
- El catálogo se DERIVA de la semilla del orquestador; no hay una segunda lista
  tecleada a mano que pueda aceptar ids que el agente tiene prohibido emitir.
- Un `mitre_hint` fuera de la semilla RECHAZA el hallazgo (anti-alucinación).
- Los hallazgos escritos ANTES de que existiera el campo siguen cargando.
- El dictamen del operador es un acto pericial: exige motivo y queda auditado.
"""

from __future__ import annotations

import json

import pytest

from forensia.audit.log import AuditLog
from forensia.cases import CaseManager
from forensia.findings.store import FindingStore
from forensia.mitre import catalog
from forensia.mitre.coverage import CoverageStore


@pytest.fixture
def tmp_case(tmp_path) -> tuple[CaseManager, str]:
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Caso MITRE", examiner="ramos", os_profile="windows")
    return cases, case.id


# ── catálogo ─────────────────────────────────────────────────────────────────


def test_catalog_is_derived_from_the_orchestrator_seed() -> None:
    """La fuente es la semilla, no una lista transcrita en Python."""
    cat = catalog.load()
    assert cat.available
    assert cat.source is not None
    assert cat.source.name == "mitre_attack_seed.md"
    assert cat.tactics


def test_catalog_closed_enum_rejects_ids_outside_the_seed() -> None:
    assert catalog.is_known("T1055")
    assert catalog.is_known("T1547.001")
    # Técnica real de ATT&CK Enterprise, pero FUERA de la semilla: el agente no
    # puede emitirla, así que el backend tampoco la acepta.
    assert not catalog.is_known("T1486.999")
    assert not catalog.is_known("T9999")
    with pytest.raises(KeyError, match="not in the ATT&CK seed"):
        catalog.technique("T9999")


def test_catalog_links_subtechniques_to_their_parent() -> None:
    assert catalog.technique("T1547.001").parent_id == "T1547"
    assert catalog.technique("T1547").parent_id is None


def test_catalog_carries_the_forensic_artifact_that_supports_each_technique() -> None:
    """La columna «Se sostiene con» de la semilla llega hasta la UI."""
    assert "malfind" in catalog.technique("T1055").supported_by


def test_catalog_as_dict_is_serialisable_and_flags_availability() -> None:
    payload = catalog.as_dict()
    json.dumps(payload)  # no explota
    assert payload["available"] is True
    assert payload["reason"] is None
    assert {p["key"] for p in payload["phases"]} == {"access", "root", "act", "goal"}


# ── mitre_hints en los hallazgos ─────────────────────────────────────────────


def test_finding_accepts_mitre_hints_from_the_seed(tmp_case) -> None:
    cases, case_id = tmp_case
    store = FindingStore(cases)
    finding = store.append(case_id, {
        "title": "Inyección de código en explorer.exe",
        "summary": "malfind encontró una región RWX con shellcode.",
        "severity": "high",
        "mitre_hints": ["T1055"],
    })
    assert finding.mitre_hints == ["T1055"]


def test_finding_rejects_a_hallucinated_technique_id(tmp_case) -> None:
    """SECURITY INVARIANT 5: el LLM no inventa ids; el servidor lo hace cumplir."""
    cases, case_id = tmp_case
    store = FindingStore(cases)
    with pytest.raises(ValueError, match="not in the ATT&CK seed"):
        store.append(case_id, {
            "title": "Hallazgo con técnica inventada",
            "summary": "El modelo se sacó un id de la manga.",
            "severity": "high",
            "mitre_hints": ["T9999"],
        })
    # Y no se ha persistido nada.
    assert store.list(case_id) == []


def test_finding_deduplicates_hints(tmp_case) -> None:
    cases, case_id = tmp_case
    store = FindingStore(cases)
    f = store.append(case_id, {
        "title": "Hallazgo",
        "summary": "Resumen.",
        "severity": "low",
        "mitre_hints": ["T1055", "T1055"],
    })
    assert f.mitre_hints == ["T1055"]


def test_findings_written_before_the_field_existed_still_load(tmp_case) -> None:
    """Regresión: sin default, `Finding(**data)` reventaría y los hallazgos
    antiguos DESAPARECERÍAN de la UI con sólo un warning."""
    cases, case_id = tmp_case
    legacy = {
        "id": "0a5b1f2c-1111-4222-8333-444455556666",
        "case_id": case_id,
        "title": "Hallazgo antiguo",
        "summary": "Escrito antes de que mitre_hints existiera.",
        "severity": "medium",
        "evidence_id": None,
        "tool_id": "volatility3",
        "run_id": None,
        "created_at": "2026-07-04T03:49:32.834Z",
    }
    path = cases.case_dir(case_id) / "findings.jsonl"
    path.write_text(json.dumps(legacy) + "\n", encoding="utf-8")

    loaded = FindingStore(cases).list(case_id)
    assert len(loaded) == 1
    assert loaded[0].title == "Hallazgo antiguo"
    assert loaded[0].mitre_hints == []


# ── cobertura: propuesta del agente vs dictamen del operador ─────────────────


def test_agent_proposals_are_derived_from_real_findings(tmp_case) -> None:
    cases, case_id = tmp_case
    findings = FindingStore(cases)
    coverage = CoverageStore(cases, findings)

    f = findings.append(case_id, {
        "title": "Inyección",
        "summary": "malfind: región RWX.",
        "severity": "high",
        "mitre_hints": ["T1055"],
    })

    entries = coverage.coverage(case_id)
    assert len(entries) == 1
    assert entries[0]["technique_id"] == "T1055"
    assert entries[0]["tactic_id"] == "TA0005"
    assert entries[0]["proposed_by"] == [f.id]
    # Propuesta por el agente ≠ confirmada. Gris significa NO EVALUADA.
    assert entries[0]["status"] is None


def test_a_proposal_never_counts_as_a_verdict(tmp_case) -> None:
    """El eje del agente y el del operador no se funden nunca."""
    cases, case_id = tmp_case
    findings = FindingStore(cases)
    coverage = CoverageStore(cases, findings)
    findings.append(case_id, {
        "title": "Pista",
        "summary": "Sugiere T1055.",
        "severity": "high",
        "mitre_hints": ["T1055"],
    })
    assert coverage.adjudications(case_id) == {}


def test_operator_adjudication_requires_a_rationale(tmp_case) -> None:
    """Un «confirmada» sin motivo no vale nada en un informe pericial."""
    cases, case_id = tmp_case
    coverage = CoverageStore(cases, FindingStore(cases))
    with pytest.raises(ValueError, match="requires a rationale"):
        coverage.adjudicate(case_id, "T1055", "confirmada", "")


def test_operator_adjudication_is_persisted_and_audited(tmp_case) -> None:
    """FORENSIC INVARIANT 4: el dictamen entra en la cadena hash-encadenada."""
    cases, case_id = tmp_case
    coverage = CoverageStore(cases, FindingStore(cases))

    coverage.adjudicate(
        case_id, "T1055", "confirmada", "malfind muestra RWX con shellcode."
    )

    adjudications = coverage.adjudications(case_id)
    assert adjudications["T1055"].status == "confirmada"
    assert "malfind" in adjudications["T1055"].rationale

    audit = AuditLog(cases.case_dir(case_id) / "audit.jsonl")
    actions = [e["action"] for e in audit.entries()]
    assert "mitre_adjudicated" in actions
    assert audit.verify() is True


def test_adjudication_is_append_only_and_last_one_wins(tmp_case) -> None:
    cases, case_id = tmp_case
    coverage = CoverageStore(cases, FindingStore(cases))

    coverage.adjudicate(case_id, "T1055", "sospechosa", "Indicio débil.")
    coverage.adjudicate(case_id, "T1055", "confirmada", "Confirmado con malfind.")

    assert coverage.adjudications(case_id)["T1055"].status == "confirmada"
    # El historial se conserva: dos líneas, no una mutación.
    path = cases.case_dir(case_id) / "mitre_adjudications.jsonl"
    assert len(path.read_text(encoding="utf-8").strip().splitlines()) == 2


def test_unmarking_retires_the_verdict_without_requiring_a_rationale(tmp_case) -> None:
    cases, case_id = tmp_case
    coverage = CoverageStore(cases, FindingStore(cases))
    coverage.adjudicate(case_id, "T1055", "confirmada", "Motivo.")
    coverage.adjudicate(case_id, "T1055", "none", "")
    assert "T1055" not in coverage.adjudications(case_id)


def test_cannot_adjudicate_a_technique_outside_the_seed(tmp_case) -> None:
    cases, case_id = tmp_case
    coverage = CoverageStore(cases, FindingStore(cases))
    with pytest.raises(ValueError, match="not in the ATT&CK seed"):
        coverage.adjudicate(case_id, "T9999", "confirmada", "Motivo.")


def test_cannot_anchor_a_verdict_to_a_finding_from_another_case(tmp_case) -> None:
    cases, case_id = tmp_case
    coverage = CoverageStore(cases, FindingStore(cases))
    with pytest.raises(ValueError, match="not found in this case"):
        coverage.adjudicate(
            case_id, "T1055", "confirmada", "Motivo.",
            related_finding_ids=["deadbeef-0000-4000-8000-000000000000"],
        )


def test_coverage_merges_both_axes_without_confusing_them(tmp_case) -> None:
    cases, case_id = tmp_case
    findings = FindingStore(cases)
    coverage = CoverageStore(cases, findings)

    f = findings.append(case_id, {
        "title": "Inyección",
        "summary": "malfind.",
        "severity": "high",
        "mitre_hints": ["T1055"],
    })
    # Una técnica dictaminada SIN propuesta del agente (el perito la vio a mano).
    coverage.adjudicate(case_id, "T1070", "descartada", "Los logs están intactos.")
    coverage.adjudicate(
        case_id, "T1055", "confirmada", "RWX + shellcode.", related_finding_ids=[f.id]
    )

    by_id = {e["technique_id"]: e for e in coverage.coverage(case_id)}

    assert by_id["T1055"]["proposed_by"] == [f.id]
    assert by_id["T1055"]["status"] == "confirmada"
    assert by_id["T1055"]["related_finding_ids"] == [f.id]

    assert by_id["T1070"]["proposed_by"] == []       # el agente no la propuso
    assert by_id["T1070"]["status"] == "descartada"  # el perito la descartó
