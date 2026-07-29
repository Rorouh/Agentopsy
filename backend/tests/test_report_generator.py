"""Síntesis del informe pericial desde los datos reales del caso.

Los gates que importan: las secciones que ensambla ``build_pericial_report``
salen bien formadas y ATRAVIESAN ``DocumentStore.create`` (validación + SHA-256)
y ``render_pdf`` (PDF real). Un caso con hallazgos + evidencia + correlación MITRE
produce un informe con esa sustancia; un caso vacío produce uno HONESTO que lo
dice (RULE 2), no uno falso; un caso inexistente falla fuerte.
"""

from __future__ import annotations

import pytest

from forensia.cases import CaseManager
from forensia.evidence import EvidenceManager
from forensia.findings.store import FindingStore
from forensia.mitre.coverage import CoverageStore
from forensia.reports.generator import build_pericial_report
from forensia.reports.pdf import render_pdf
from forensia.reports.store import DocumentStore


@pytest.fixture
def wiring(tmp_path):
    """Un stack de almacenes sobre un ``CaseManager`` temporal (aislado del real)."""
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


def _generate(w, case_id, perito=None):
    return build_pericial_report(
        case_id,
        perito,
        cases=w["cases"],
        evidence=w["evidence"],
        findings=w["findings"],
        coverage=w["coverage"],
        # El caso vive en un CaseManager temporal, no en el singleton global que
        # usa tool_usage; se inyecta un stub para no tocar ~/.forensia.
        usage_fn=lambda _cid: [
            {"tool_id": "tsk_fls", "total": 2, "ok": 2, "failed": 0}
        ],
    )


def _register_evidence(w, case_id) -> str:
    src = w["tmp"] / "disk.raw"
    src.write_bytes(b"\x00Agentopsy-TEST-IMAGE\x00" * 64)
    return w["evidence"].register(case_id, str(src)).evidence_id


def test_full_report_is_well_formed_and_persists(wiring) -> None:
    w = wiring
    case = w["cases"].create(name="Murciélago", examiner="ramos", os_profile="windows")

    ev_id = _register_evidence(w, case.id)
    f1 = w["findings"].append(case.id, {
        "title": "Volcado de credenciales LSASS",
        "summary": "Se observa acceso a la memoria de lsass compatible con dumping.",
        "severity": "critical",
        "evidence_id": ev_id,
        "tool_id": "volatility3",
        # Procedencia + confianza + marca del artefacto (esquema de hallazgo cerrado).
        "run_id": "11111111-1111-4111-8111-111111111111",
        "confidence": 0.9,
        "observed_at": "2026-07-15T13:42:00Z",
        "artifact_sha256": "a" * 64,
        "mitre_hints": ["T1003"],
    })
    w["findings"].append(case.id, {
        "title": "Exfiltración por canal C2",
        "summary": "Transferencia de datos hacia host externo.",
        "severity": "high",
        "evidence_id": ev_id,
        "tool_id": "bulk_extractor",
        "run_id": "22222222-2222-4222-8222-222222222222",
        "mitre_hints": ["T1048"],
    })
    # Dictamen del perito sobre una técnica (eje 2, persistido y auditado).
    w["coverage"].adjudicate(
        case.id, "T1003", "confirmada", "El patrón de acceso a lsass lo sostiene."
    )

    data = build_pericial_report(
        case.id,
        {"name": "Daniel Ramos", "colegiado": "COL-42", "organization": "Auria"},
        cases=w["cases"], evidence=w["evidence"], findings=w["findings"],
        coverage=w["coverage"], usage_fn=lambda _c: [
            {"tool_id": "volatility3", "total": 3, "ok": 2, "failed": 1}
        ],
    )

    # Forma: 8 secciones numeradas 1..8 (con el relato de la investigación como
    # §5 — 2026-07-30), título y autor del perito.
    assert data["type"] == "pericial"
    assert data["author"] == "Daniel Ramos"
    assert [s["num"] for s in data["sections"]] == [
        "1", "2", "3", "4", "5", "6", "7", "8",
    ]

    # El resumen ejecutivo NARRA (no enumera): anticipa la secuencia de hechos
    # con el hallazgo fechado y remite al relato (§5) que la desarrolla.
    resumen = next(s for s in data["sections"] if s["num"] == "1")
    resumen_texto = " ".join(b.get("text", "") for b in resumen["blocks"])
    assert "secuencia de hechos" in resumen_texto
    assert "Volcado de credenciales LSASS" in resumen_texto
    assert "2026-07-15" in resumen_texto
    assert "§5" in resumen_texto

    # El relato de la investigación (§5) es la reconstrucción narrativa: la
    # cronología arranca en el hecho fechado (con su detalle técnico íntegro y
    # su procedencia) y lo no fechado se narra aparte, sin disfrazarse de
    # cronología del incidente.
    relato = next(s for s in data["sections"] if s["num"] == "5")
    assert relato["title"] == "Relato de la investigación"
    relato_texto = " ".join(b.get("text", "") for b in relato["blocks"])
    assert "arranca el 2026-07-15" in relato_texto
    assert "compatible con dumping" in relato_texto      # el summary viaja íntegro
    assert "11111111" in relato_texto                    # …con su run de procedencia
    assert "T1003" in relato_texto                       # …y su encuadre ATT&CK
    assert "fecha directa en la evidencia" in relato_texto  # carril no fechado
    assert "Exfiltración por canal C2" in relato_texto

    # La sección de hallazgos lleva bloques finding con severidad válida.
    hallazgos = next(s for s in data["sections"] if s["num"] == "6")
    findings_blocks = [b for b in hallazgos["blocks"] if b["t"] == "finding"]
    assert len(findings_blocks) == 2
    assert {b["sev"] for b in findings_blocks} == {"critical", "high"}
    assert any("T1003" in b["tags"] for b in findings_blocks)

    # El hallazgo con confianza + procedencia pinta su línea meta (confianza,
    # observado, run, sha256 del artefacto).
    lsass = next(b for b in findings_blocks if b["title"].startswith("Volcado"))
    assert "Confianza: 0.90" in lsass["meta"]
    assert "2026-07-15T13:42:00Z" in lsass["meta"]
    assert f1.run_id[:8] in lsass["meta"]
    assert "SHA-256 artefacto: aaaaaaaaaaaa" in lsass["meta"]

    # La correlación MITRE lleva una tabla con la técnica dictaminada.
    mitre = next(s for s in data["sections"] if s["num"] == "7")
    table = next(b for b in mitre["blocks"] if b["t"] == "table")
    assert "Hallazgos que la sostienen" in table["headers"]
    flat = [cell for row in table["rows"] for cell in row]
    assert "T1003" in flat
    assert "Confirmada" in flat
    # La columna de hallazgos LISTA el finding que la sostiene (id + título), no
    # sólo el recuento.
    supporting = "\n".join(flat)
    assert f1.id[:8] in supporting
    assert "Volcado de credenciales LSASS" in supporting

    # Las conclusiones CIERRAN el hilo: lo más severo restatado con su soporte y
    # el dictamen confirmado citando la técnica.
    conclusiones = next(s for s in data["sections"] if s["num"] == "8")
    concl_texto = " ".join(b.get("text", "") for b in conclusiones["blocks"])
    assert "Volcado de credenciales LSASS" in concl_texto
    assert "T1003" in concl_texto
    assert "BORRADOR" in concl_texto

    # Custodia: aparece el SHA-256 baseline de la evidencia registrada.
    custodia = next(s for s in data["sections"] if s["num"] == "3")
    assert any(b["t"] == "kv" for b in custodia["blocks"])

    # ATRAVIESA el store (validación + SHA-256 real) y el PDF real.
    doc = w["documents"].create(case.id, data)
    assert doc.status == "draft"
    assert len(doc.sha256) == 64
    assert w["documents"].verify(case.id, doc.id)["ok"] is True
    pdf = render_pdf(doc)
    assert pdf[:5] == b"%PDF-"
    assert len(pdf) > 1500


def test_empty_case_report_is_honest_not_fake(wiring) -> None:
    w = wiring
    case = w["cases"].create(name="Caso vacío", examiner="ramos", os_profile="unix")

    data = _generate(w, case.id)

    # Sigue teniendo las 8 secciones y pasa la validación del store.
    assert [s["num"] for s in data["sections"]] == [
        "1", "2", "3", "4", "5", "6", "7", "8",
    ]
    hallazgos = next(s for s in data["sections"] if s["num"] == "6")
    # NO fabrica hallazgos: sin bloques finding, y lo dice en prosa.
    assert not any(b["t"] == "finding" for b in hallazgos["blocks"])
    text = " ".join(b.get("text", "") for b in hallazgos["blocks"])
    assert "no se han registrado hallazgos" in text.lower()

    doc = w["documents"].create(case.id, data)
    assert w["documents"].verify(case.id, doc.id)["ok"] is True
    assert render_pdf(doc)[:5] == b"%PDF-"


def test_unknown_case_fails_loud(wiring) -> None:
    w = wiring
    with pytest.raises((KeyError, ValueError)):
        _generate(w, "00000000-0000-4000-8000-000000000000")


def test_perito_defaults_to_case_examiner(wiring) -> None:
    w = wiring
    case = w["cases"].create(name="Sin perito", examiner="mencia", os_profile="unix")
    data = _generate(w, case.id)
    # Sin datos de perito, el autor es el examinador del caso (dato autoritativo,
    # no un default silencioso de negocio).
    assert data["author"] == "mencia"
