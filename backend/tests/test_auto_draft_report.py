"""Borrador AUTOMÁTICO del informe pericial al cerrar un análisis.

Los gates que importan (``forensia.reports.generate_draft_report``):

- con ≥1 hallazgo deja un BORRADOR (estado ``draft``) con el título reservado,
  que atraviesa la validación + SHA-256 del store;
- refrescar NO apila: un segundo cierre reemplaza el borrador auto anterior (un
  id nuevo, y sigue habiendo UNO solo con ese título);
- un documento ``final`` (firmado) NO se borra en el refresco — cadena de
  custodia — aunque lleve el título reservado;
- 0 hallazgos → ``None`` y CERO documentos (RULE 2: no se fabrica un informe);
- un documento del operador con OTRO título (p. ej. el de «Generar informe») no
  lo toca el refresco.
"""

from __future__ import annotations

import pytest

from forensia.cases import CaseManager
from forensia.evidence import EvidenceManager
from forensia.findings.store import FindingStore
from forensia.mitre.coverage import CoverageStore
from forensia.reports.generator import AUTO_DRAFT_TITLE, generate_draft_report
from forensia.reports.store import DocumentStore


@pytest.fixture
def wiring(tmp_path):
    cases = CaseManager(root=tmp_path / "cases")
    findings = FindingStore(cases)
    coverage = CoverageStore(cases, findings)
    evidence = EvidenceManager(cases)
    documents = DocumentStore(cases)
    return {
        "tmp": tmp_path,
        "cases": cases,
        "findings": findings,
        "coverage": coverage,
        "evidence": evidence,
        "documents": documents,
    }


def _draft(w, case_id):
    return generate_draft_report(
        case_id,
        documents=w["documents"],
        cases=w["cases"],
        evidence=w["evidence"],
        findings=w["findings"],
        coverage=w["coverage"],
        # El caso vive en un CaseManager temporal; se stubea tool_usage para no
        # tocar ~/.forensia (igual que test_report_generator).
        usage_fn=lambda _cid: [],
    )


def _register_evidence(w, case_id) -> str:
    src = w["tmp"] / "disk.raw"
    src.write_bytes(b"\x00Agentopsy-TEST-IMAGE\x00" * 64)
    return w["evidence"].register(case_id, str(src)).evidence_id


def _add_finding(w, case_id, ev_id, *, title="Volcado LSASS", sev="critical") -> None:
    w["findings"].append(case_id, {
        "title": title,
        "summary": "Acceso a la memoria de lsass compatible con dumping.",
        "severity": sev,
        "evidence_id": ev_id,
        "tool_id": "volatility3",
        "run_id": "11111111-1111-4111-8111-111111111111",
    })


def test_no_findings_creates_nothing(wiring) -> None:
    w = wiring
    case = w["cases"].create(name="Vacío", examiner="ramos", os_profile="unix")
    assert _draft(w, case.id) is None
    assert w["documents"].list(case.id) == []


def test_with_findings_leaves_a_verifiable_draft(wiring) -> None:
    w = wiring
    case = w["cases"].create(name="Murciélago", examiner="ramos", os_profile="windows")
    ev_id = _register_evidence(w, case.id)
    _add_finding(w, case.id, ev_id)

    doc = _draft(w, case.id)
    assert doc is not None
    assert doc.status == "draft"
    assert doc.title == AUTO_DRAFT_TITLE
    assert doc.type == "pericial"
    # Atraviesa la integridad real del store.
    assert w["documents"].verify(case.id, doc.id)["ok"] is True
    assert [d.id for d in w["documents"].list(case.id)] == [doc.id]


def test_refresh_replaces_without_stacking(wiring) -> None:
    w = wiring
    case = w["cases"].create(name="Refresco", examiner="ramos", os_profile="windows")
    ev_id = _register_evidence(w, case.id)
    _add_finding(w, case.id, ev_id, title="Primer hallazgo")

    first = _draft(w, case.id)
    _add_finding(w, case.id, ev_id, title="Segundo hallazgo", sev="high")
    second = _draft(w, case.id)

    assert second is not None
    assert second.id != first.id  # es un borrador NUEVO
    # No apila: sigue habiendo UN solo documento, y es el auto-borrador al día.
    docs = w["documents"].list(case.id)
    assert [d.id for d in docs] == [second.id]
    assert all(d.title == AUTO_DRAFT_TITLE for d in docs)


def test_signed_final_is_never_deleted_by_refresh(wiring) -> None:
    w = wiring
    case = w["cases"].create(name="Firmado", examiner="ramos", os_profile="windows")
    ev_id = _register_evidence(w, case.id)
    _add_finding(w, case.id, ev_id)

    first = _draft(w, case.id)
    # El perito firma ese borrador auto → pasa a final (cadena de custodia).
    w["documents"].sign(case.id, first.id)

    # Un nuevo cierre NO puede borrar el final, aunque comparta el título reservado.
    second = _draft(w, case.id)
    ids = {d.id for d in w["documents"].list(case.id)}
    assert first.id in ids  # el final sobrevive
    assert second.id in ids  # y hay un borrador auto nuevo junto a él
    signed = w["documents"].get(case.id, first.id)
    assert signed.status == "final"


def test_refresh_leaves_operator_documents_alone(wiring) -> None:
    w = wiring
    case = w["cases"].create(name="Convive", examiner="ramos", os_profile="windows")
    ev_id = _register_evidence(w, case.id)
    _add_finding(w, case.id, ev_id)

    # Un borrador del operador con OTRO título (p. ej. el de «Generar informe»).
    manual = w["documents"].create(case.id, {
        "title": "Informe pericial forense — Convive",
        "type": "pericial",
        "summary": "Informe manual del perito.",
        "sections": [{"num": "1", "title": "Resumen", "blocks": [
            {"t": "p", "text": "Contenido del perito."}]}],
    })

    auto = _draft(w, case.id)
    ids = {d.id for d in w["documents"].list(case.id)}
    # El refresco solo toca su propio borrador auto: el del operador sigue ahí.
    assert manual.id in ids
    assert auto.id in ids
