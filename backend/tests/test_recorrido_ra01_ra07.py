"""El RECORRIDO completo por la superficie HTTP, y qué se rompe al tocarlo.

Los ficheros ``test_ra0*.py`` comprueban cada puerta por separado, en el dominio.
Este comprueba que encajan Y que la comprobación ocurre en el BACKEND aunque el
cliente llame a las rutas directamente, que es lo que un botón deshabilitado no
impide:

    evidencia -> ejecución -> hallazgo con su cita -> informe con sus
    conclusiones respaldadas -> comprobaciones -> aprobación -> exportación ->
    abrir la fuente de una conclusión

y después se altera cada eslabón para ver que la ruta correspondiente lo dice.

Todo con almacenes REALES sobre un directorio temporal: ni una llamada a un
proveedor, ni un byte de evidencia real.
"""

from __future__ import annotations

import hashlib
import json
import stat

import pytest
from _informe import hallazgo, informe, montar_caso
from fastapi.testclient import TestClient

from agentopsy.server import create_app

PORT = 51193


@pytest.fixture
def caso(tmp_path):
    entorno = montar_caso(tmp_path)
    h = hallazgo(entorno)
    entorno["hallazgo"] = h
    entorno["doc"] = informe(entorno, h)
    return entorno


@pytest.fixture
def http(caso, monkeypatch):
    import agentopsy.routers.documents as docs_router
    import agentopsy.routers.findings as findings_router

    monkeypatch.setattr(docs_router, "case_manager", caso["cases"])
    monkeypatch.setattr(docs_router, "document_store", caso["documents"])
    monkeypatch.setattr(docs_router, "finding_store", caso["findings"])
    monkeypatch.setattr(findings_router, "finding_store", caso["findings"])
    client = TestClient(create_app(PORT), base_url=f"http://127.0.0.1:{PORT}")
    return {"client": client, "auth": {"X-Agentopsy-Token": client.app.state.token}}


def _base(caso) -> str:
    return f"/api/cases/{caso['case'].id}/documents/{caso['doc'].id}"


def _checks(caso, http) -> dict:
    r = http["client"].get(f"{_base(caso)}/checks", headers=http["auth"])
    assert r.status_code == 200, r.text
    return r.json()


def _aprobar(caso, http, sha: str | None = None):
    return http["client"].post(
        f"{_base(caso)}/sign",
        json={"sha256": sha or _checks(caso, http)["sha256_actual"],
              "approved_by": "ramos"},
        headers=http["auth"],
    )


def _pdf(caso, http):
    return http["client"].get(f"{_base(caso)}/pdf", headers=http["auth"])


# -- el recorrido válido, entero ----------------------------------------------


def test_el_recorrido_completo_llega_a_la_fuente_de_cada_conclusion(caso, http) -> None:
    checks = _checks(caso, http)
    assert checks["aprobable"] is True, checks["bloqueos"]

    # La procedencia: los tres digests coinciden (manifiesto, documento, ancla).
    proc = checks["procedencia"]
    assert proc["digest_actual"] == proc["digest_declarado"] == proc["digest_anclado"]

    # Cada conclusión forense declara en qué se apoya.
    assert checks["citas"]
    assert all(c["en_manifiesto"] for c in checks["citas"])

    # Y la fuente se abre desde la conclusión, con su localizador y su extracto.
    cita = checks["citas"][0]
    r = http["client"].get(
        f"{_base(caso)}/citas/{cita['finding_id']}?revision={cita['revision']}",
        headers=http["auth"],
    )
    assert r.status_code == 200, r.text
    cuerpo = r.json()
    assert cuerpo["integridad_ok"] is True
    assert cuerpo["en_manifiesto"] is True
    fuente = cuerpo["fuentes"][0]
    assert fuente["estado"] == "verificada"
    assert fuente["localizador"] == {"tipo": "lineas", "desde": 2, "hasta": 2}
    assert "updater.exe" in fuente["extracto"]

    # Se aprueba, y el PDF sale como final con el hash de los bytes servidos.
    aprobado = _aprobar(caso, http)
    assert aprobado.status_code == 200, aprobado.text
    assert aprobado.json()["status"] == "final"

    pdf = _pdf(caso, http)
    assert pdf.status_code == 200
    assert pdf.headers["X-Agentopsy-Pdf-Draft"] == "0"
    assert pdf.headers["X-Agentopsy-Pdf-Sha256"] == hashlib.sha256(pdf.content).hexdigest()
    assert pdf.content.startswith(b"%PDF-")

    # La cadena de auditoría sigue verificando después de todo el recorrido.
    assert caso["audit"].verify() is True


# -- cada eslabón, roto -------------------------------------------------------


def _reescribir_doc(caso, cambios) -> None:
    ruta = (
        caso["cases"].case_dir(caso["case"].id)
        / "documents" / f"{caso['doc'].id}.json"
    )
    crudo = json.loads(ruta.read_text(encoding="utf-8"))
    cambios(crudo)
    ruta.write_text(json.dumps(crudo), encoding="utf-8")


def test_una_evidencia_alterada_bloquea_la_ruta_de_aprobacion(caso, http) -> None:
    ruta = caso["evidencia"].original_path
    ruta.chmod(stat.S_IWRITE | stat.S_IREAD)
    ruta.write_bytes(b"ALTERADA")

    r = _aprobar(caso, http, sha=caso["doc"].sha256)
    assert r.status_code == 409
    codigos = {b["codigo"] for b in r.json()["detail"]["bloqueos"]}
    assert "evidencia_alterada" in codigos


def test_retirar_las_fuentes_bloquea_la_ruta_de_aprobacion(caso, http) -> None:
    _reescribir_doc(caso, lambda d: d.update(fuentes={"case_id": caso["case"].id}))
    r = _aprobar(caso, http, sha=caso["doc"].sha256)
    assert r.status_code == 409
    codigos = {b["codigo"] for b in r.json()["detail"]["bloqueos"]}
    assert "procedencia_alterada" in codigos


def test_un_final_forjado_se_exporta_marcado_como_borrador(caso, http) -> None:
    _reescribir_doc(caso, lambda d: d.update(
        status="final",
        approved_by="REVISOR FICTICIO",
        approved_at="2026-09-08T00:00:00Z",
        approved_sha256=caso["doc"].sha256,
    ))
    pdf = _pdf(caso, http)
    assert pdf.status_code == 200
    assert pdf.headers["X-Agentopsy-Pdf-Draft"] == "1"
    assert b"REVISOR FICTICIO" not in pdf.content

    checks = _checks(caso, http)
    assert "aprobacion_sin_acta" in {b["codigo"] for b in checks["bloqueos"]}


def test_la_ruta_de_la_cita_no_sirve_un_hallazgo_que_el_informe_no_cita(
    caso, http
) -> None:
    ajeno = hallazgo(caso)
    r = http["client"].get(
        f"{_base(caso)}/citas/{ajeno.id}?revision=1", headers=http["auth"]
    )
    assert r.status_code == 404


def test_una_fuente_alterada_se_dice_al_abrir_la_cita_sin_extracto(caso, http) -> None:
    (
        caso["cases"].case_dir(caso["case"].id)
        / "artifacts" / caso["run_id"] / "stdout.txt"
    ).write_text("MANIPULADO\n", encoding="utf-8")

    r = http["client"].get(
        f"{_base(caso)}/citas/{caso['hallazgo'].id}?revision=1", headers=http["auth"]
    )
    assert r.status_code == 200
    fuente = r.json()["fuentes"][0]
    assert fuente["estado"] != "verificada"
    assert fuente.get("motivo")
    assert not fuente.get("extracto")


def test_aprobar_exige_la_revision_exacta_que_se_reviso(caso, http) -> None:
    r = _aprobar(caso, http, sha="f" * 64)
    assert r.status_code == 409
    codigos = {b["codigo"] for b in r.json()["detail"]["bloqueos"]}
    assert "revision_no_coincide" in codigos
