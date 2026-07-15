"""Almacén de documentos + integridad + PDF pericial.

Los gates que importan: el SHA-256 es real y verificable; firmar no invalida el
hash (cambia estado, no contenido); un final no se borra (cadena de custodia);
crear/firmar/eliminar quedan en el audit hash-encadenado; el PDF sale bien
formado. RULE 2: caso sin docs → []; id inexistente → KeyError.
"""

from __future__ import annotations

import json

import pytest

from forensia.audit.log import AuditLog
from forensia.cases import CaseManager
from forensia.reports.pdf import render_pdf
from forensia.reports.store import DocumentStore


@pytest.fixture
def tmp_case(tmp_path) -> tuple[CaseManager, str]:
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Murcielago", examiner="ramos", os_profile="windows")
    return cases, case.id


def _payload(**over):
    base = {
        "title": "Informe pericial forense — Caso Murciélago",
        "type": "Informe final",
        "author": "Daniel Ramos Camargo",
        "version": "v1.0",
        "summary": "Análisis de exfiltración de datos.",
        "sections": [
            {"num": "1", "title": "Resumen ejecutivo", "blocks": [
                {"t": "p", "text": "Confirma la exfiltración."},
                {"t": "quote", "text": "Los archivos filtrados eran .xls"},
            ]},
            {"num": "2", "title": "Hallazgos", "blocks": [
                {"t": "h3", "text": "2.1 Credenciales"},
                {"t": "list", "ordered": True, "items": ["IEUser", "Administrator"]},
                {"t": "finding", "sev": "critical", "title": "Exfiltración", "text": "mbox",
                 "tags": ["Volatility3", "T1048"]},
                {"t": "table", "headers": ["Hora", "Evento"], "rows": [["19:07", "backdoor"]]},
                {"t": "kv", "pairs": [{"k": "SO", "v": "Windows 7"}]},
            ]},
        ],
    }
    base.update(over)
    return base


def test_empty_case_lists_no_documents(tmp_case) -> None:
    cases, case_id = tmp_case
    assert DocumentStore(cases).list(case_id) == []


def test_create_persists_with_real_sha256(tmp_case) -> None:
    cases, case_id = tmp_case
    store = DocumentStore(cases)
    doc = store.create(case_id, _payload())
    assert doc.status == "draft"
    assert len(doc.sha256) == 64
    assert doc.page_count >= 1
    assert store.verify(case_id, doc.id)["ok"] is True
    assert [d.id for d in store.list(case_id)] == [doc.id]


def test_signing_marks_final_without_breaking_integrity(tmp_case) -> None:
    cases, case_id = tmp_case
    store = DocumentStore(cases)
    doc = store.create(case_id, _payload())
    signed = store.sign(case_id, doc.id)
    assert signed.status == "final"
    # Firmar cambia el estado, NO el contenido → el hash sigue válido.
    assert store.verify(case_id, doc.id)["ok"] is True
    assert signed.sha256 == doc.sha256


def test_final_document_cannot_be_deleted(tmp_case) -> None:
    cases, case_id = tmp_case
    store = DocumentStore(cases)
    doc = store.create(case_id, _payload())
    store.sign(case_id, doc.id)
    with pytest.raises(ValueError, match="chain of custody"):
        store.delete(case_id, doc.id)


def test_draft_delete_and_missing_is_keyerror(tmp_case) -> None:
    cases, case_id = tmp_case
    store = DocumentStore(cases)
    doc = store.create(case_id, _payload())
    store.delete(case_id, doc.id)
    assert store.list(case_id) == []
    with pytest.raises(KeyError, match="not found"):
        store.get(case_id, doc.id)


def test_bad_doc_id_is_rejected_not_traversed(tmp_case) -> None:
    cases, case_id = tmp_case
    with pytest.raises(ValueError, match="UUID4"):
        DocumentStore(cases).get(case_id, "../../etc/passwd")


def test_create_rejects_unknown_block_type(tmp_case) -> None:
    cases, case_id = tmp_case
    with pytest.raises(ValueError, match="block.t must be one of"):
        DocumentStore(cases).create(case_id, _payload(
            sections=[{"num": "1", "title": "x", "blocks": [{"t": "video"}]}]))


def test_create_and_actions_are_audited(tmp_case) -> None:
    cases, case_id = tmp_case
    store = DocumentStore(cases)
    doc = store.create(case_id, _payload())
    store.sign(case_id, doc.id)
    log = AuditLog(cases.case_dir(case_id) / "audit.jsonl")
    assert log.verify()
    actions = [json.loads(x)["action"] for x in
               (cases.case_dir(case_id) / "audit.jsonl").read_text().splitlines() if x.strip()]
    assert "document_created" in actions
    assert "document_signed" in actions


def test_pdf_is_well_formed(tmp_case) -> None:
    cases, case_id = tmp_case
    store = DocumentStore(cases)
    doc = store.create(case_id, _payload())
    pdf = render_pdf(doc)
    assert pdf[:5] == b"%PDF-"
    assert len(pdf) > 1500
