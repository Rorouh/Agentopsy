"""El RECORRIDO completo, de la evidencia al PDF, y qué se rompe al tocarla.

Los tests de F02, F03 y F04 comprueban cada puerta por separado. Este comprueba
que las tres encajan, que es lo que un perito hace de verdad:

    evidencia sintética -> ejecución -> artefacto -> hallazgo con su cita ->
    borrador -> revisión humana -> aprobación -> exportación a PDF

y después altera una fuente para ver que las verificaciones correspondientes se
rompen: la lectura del artefacto, la escritura de un hallazgo nuevo que lo cite,
la apertura de la cita desde la interfaz y la aprobación del informe.

Todo con almacenes REALES sobre un directorio temporal y un ejecutor SIMULADO:
ni una llamada a un proveedor, ni un byte de evidencia real.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from agentopsy.artifacts import lectura
from agentopsy.artifacts.store import ArtifactStore
from agentopsy.audit.log import AuditLog
from agentopsy.cases import CaseManager
from agentopsy.evidence import EvidenceManager
from agentopsy.findings.procedencia import ProcedenciaError
from agentopsy.findings.store import FindingStore
from agentopsy.reports.aprobacion import AprobacionBloqueada, comprobar, manifiesto_de_fuentes
from agentopsy.reports.store import DocumentStore
from agentopsy.reports.works import render_argv
from agentopsy.server import create_app

PORT = 51191

#: La salida de la herramienta: tres líneas, para poder citar la segunda.
_STDOUT = (
    "r/r 128-128-1: Windows/System32/config/SOFTWARE\n"
    "r/r 512-128-3: Users/jcloudy/AppData/updater.exe\n"
    "r/r 900-128-4: Windows/Tasks/updater.job\n"
)
_ARGV = ["tsk_fls", "-r", "-o", "2048", "/evidence/disco con espacio.raw"]


@pytest.fixture
def caso(tmp_path):
    """Evidencia registrada + ejecución cerrada con su manifiesto anclado."""
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Recorrido", examiner="ramos", os_profile="windows")

    origen = tmp_path / "disco.raw"
    origen.write_bytes(b"AGENTOPSY-DISCO-SINTETICO" * 32)
    evidencia = EvidenceManager(cases).register(case.id, str(origen))

    artefactos = ArtifactStore(cases)
    audit = AuditLog(cases.case_dir(case.id) / "audit.jsonl")
    run_id, _out = artefactos.start_run(
        case.id,
        "tsk_fls",
        _ARGV,
        evidence_id=evidencia.evidence_id,
        evidence_baseline_sha256=evidencia.sha256,
        tool_version="sleuthkit 4.12.1",
    )
    artefactos.set_run_argv(case.id, run_id, _ARGV)
    audit.append({
        "action": "tool_run_start", "case_id": case.id, "run_id": run_id,
        "tool_id": "tsk_fls", "argv": _ARGV,
        "evidence_id": evidencia.evidence_id,
        "baseline_sha256": evidencia.sha256, "tool_version": "sleuthkit 4.12.1",
    })
    run = artefactos.finalize_run(
        case.id, run_id, exit_code=0, stdout=_STDOUT, stderr=""
    )
    audit.append({
        "action": "tool_run_finish", "case_id": case.id, "run_id": run_id,
        "status": "finished", "exit_code": 0,
        "stdout_sha256": run.stdout_sha256, "stderr_sha256": run.stderr_sha256,
        "output_files_count": 0,
        # El ANCLA del manifiesto: es lo que hace detectable una reescritura
        # coherente de artefacto + manifiesto (F02).
        "manifest_sha256": run.manifest_sha256,
    })
    return {
        "cases": cases, "case": case, "evidencia": evidencia,
        "artefactos": artefactos, "run": run, "run_id": run_id, "audit": audit,
        "findings": FindingStore(cases), "documents": DocumentStore(cases),
    }


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


def _hallazgo(caso):
    """Un hallazgo que cita la SEGUNDA línea de la salida, con su extracto."""
    return caso["findings"].append(caso["case"].id, {
        "title": "Ejecutable de persistencia en el perfil de jcloudy",
        "summary": (
            "El listado del sistema de ficheros sitúa updater.exe en el perfil "
            "de jcloudy, coherente con la tarea programada updater.job."
        ),
        "severity": "high",
        "observed_at": "2026-03-14T08:12:44Z",
        "references": [
            {
                "run_id": caso["run_id"],
                "evidence_id": caso["evidencia"].evidence_id,
                "tool_id": "tsk_fls",
                "artefacto": "stdout",
                "sha256": caso["run"].stdout_sha256,
                "localizador": {"tipo": "lineas", "desde": 2, "hasta": 2},
                "extracto": "r/r 512-128-3: Users/jcloudy/AppData/updater.exe",
            }
        ],
    })


def _informe(caso, hallazgo):
    """El borrador, con su manifiesto de fuentes y su apartado de limitaciones."""
    material = {
        "caso": {"id": caso["case"].id},
        "evidencias": [{
            "evidence_id": caso["evidencia"].evidence_id,
            "sha256_baseline": caso["evidencia"].sha256,
        }],
        "hallazgos": [{
            "id": hallazgo.id,
            "revision": hallazgo.revision,
            "content_sha256": hallazgo.content_sha256,
            "procedencia": hallazgo.provenance_state,
            "tipo": hallazgo.finding_kind,
            "referencias": hallazgo.references,
        }],
        "trabajos": [{
            "run_id": caso["run_id"], "status": "finished",
            "argv": _ARGV, "argv_literal": render_argv(_ARGV),
        }],
        "integridad": {"hash_chain_verified": True},
    }
    return caso["documents"].create(caso["case"].id, {
        "title": "Informe pericial del recorrido",
        "type": "pericial",
        "author": "ramos",
        "version": "v1.0",
        "summary": "Se confirma la persistencia en el perfil de jcloudy.",
        "sections": [
            {"num": "1", "title": "Resumen", "blocks": [
                {"t": "p", "text": "Se confirma la persistencia."},
                # El comando se imprime desde el argv REGISTRADO, con sus
                # límites entre argumentos intactos.
                {"t": "code", "text": render_argv(_ARGV)},
            ]},
            {"num": "9", "title": "Conclusiones y limitaciones", "blocks": [
                # La conclusión CITA la revisión que la sostiene: es lo que
                # permite abrirla hasta su localizador, y sin ello no se aprueba.
                {"t": "p", "text": "Se confirma la persistencia en el perfil.",
                 "refs": [{"finding_id": hallazgo.id, "revision": hallazgo.revision}]},
                # Una limitación no afirma sobre la evidencia: declara su código.
                {"t": "p", "text": "No se examinó la memoria RAM del equipo.",
                 "limitacion": "alcance_declarado"},
            ]},
        ],
        "fuentes": manifiesto_de_fuentes(caso["case"].id, material),
    })


def _alterar_fuente(caso) -> None:
    ruta = (
        caso["cases"].case_dir(caso["case"].id)
        / "artifacts" / caso["run_id"] / "stdout.txt"
    )
    ruta.write_text("MANIPULADO\n", encoding="utf-8")


# -- el recorrido, de punta a punta ------------------------------------------


def test_el_recorrido_completo_llega_al_pdf_con_su_hash(caso, http) -> None:
    client, auth = http["client"], http["auth"]
    case_id = caso["case"].id

    # 1. El artefacto se lee VERIFICADO, y su procedencia viaja con él.
    lectura_pagina = caso["artefactos"].read_run_output(
        case_id, caso["run_id"], fichero="stdout"
    )
    assert lectura_pagina["devueltas"] == 3
    assert lectura_pagina["procedencia"]["anclaje"] == "anclado"
    assert lectura_pagina["procedencia"]["sha256"] == caso["run"].stdout_sha256

    # 2. El hallazgo se registra con su cita verificada.
    hallazgo = _hallazgo(caso)
    assert hallazgo.provenance_state == "verificada"
    assert hallazgo.references[0]["localizador"] == {
        "tipo": "lineas", "desde": 2, "hasta": 2
    }

    # 3. La cita se abre desde la interfaz y enseña el extracto REAL.
    res = client.get(
        f"/api/cases/{case_id}/findings/{hallazgo.id}/sources", headers=auth
    )
    assert res.status_code == 200, res.text
    fuente = res.json()["fuentes"][0]
    assert fuente["estado"] == "verificada"
    assert fuente["tool_id"] == "tsk_fls"
    assert fuente["evidence_id"] == caso["evidencia"].evidence_id
    assert "updater.exe" in fuente["extracto"]
    assert fuente["anclaje"] == "anclado"

    # 4. El borrador se genera con su manifiesto de fuentes.
    doc = _informe(caso, hallazgo)
    assert doc.status == "draft"
    assert doc.fuentes["hallazgos"][0]["finding_id"] == hallazgo.id

    # 5. La revisión humana: la pantalla dice qué se va a aprobar y qué falta.
    checks = client.get(
        f"/api/cases/{case_id}/documents/{doc.id}/checks", headers=auth
    ).json()
    assert checks["aprobable"] is True, checks["bloqueos"]
    assert checks["bloqueos"] == []

    # 6. La aprobación, atada a la revisión EXACTA que se revisó.
    aprobado = client.post(
        f"/api/cases/{case_id}/documents/{doc.id}/sign",
        headers=auth,
        json={"sha256": checks["sha256_actual"], "approved_by": "ramos"},
    )
    assert aprobado.status_code == 200, aprobado.text
    assert aprobado.json()["status"] == "final"
    assert aprobado.json()["approved_sha256"] == checks["sha256_actual"]

    # 7. La exportación: bytes reproducibles y su hash en el audit.
    pdf = client.get(f"/api/cases/{case_id}/documents/{doc.id}/pdf", headers=auth)
    assert pdf.status_code == 200
    assert pdf.content.startswith(b"%PDF")
    assert pdf.headers["X-Agentopsy-Pdf-Draft"] == "0"
    assert pdf.headers["X-Agentopsy-Pdf-Sha256"] == hashlib.sha256(pdf.content).hexdigest()

    entradas = caso["audit"].entries()
    assert caso["audit"].verify() is True
    acciones = [e["action"] for e in entradas]
    for esperada in (
        "evidence_register", "tool_run_start", "tool_run_finish",
        "finding_recorded", "document_created", "document_approved",
        "document_exported",
    ):
        assert esperada in acciones, esperada


# -- y qué se rompe al tocar la fuente ---------------------------------------


def test_alterar_la_fuente_rompe_las_cuatro_verificaciones(caso, http) -> None:
    """Una sola alteración, cuatro puertas distintas, ninguna en silencio."""
    client, auth = http["client"], http["auth"]
    case_id = caso["case"].id
    hallazgo = _hallazgo(caso)
    doc = _informe(caso, hallazgo)
    checks = client.get(
        f"/api/cases/{case_id}/documents/{doc.id}/checks", headers=auth
    ).json()
    assert checks["aprobable"] is True

    _alterar_fuente(caso)

    # (1) F02: leer el artefacto es un error de integridad, no una lectura vacía.
    with pytest.raises(lectura.ArtefactoIntegridadError):
        caso["artefactos"].read_run_output(case_id, caso["run_id"], fichero="stdout")

    # (2) F03: un hallazgo NUEVO que lo cite no se registra.
    with pytest.raises(ProcedenciaError):
        _hallazgo(caso)

    # (3) F03/interfaz: abrir la cita dice que está alterada y NO enseña extracto.
    fuente = client.get(
        f"/api/cases/{case_id}/findings/{hallazgo.id}/sources", headers=auth
    ).json()["fuentes"][0]
    assert fuente["estado"] == "alterada"
    assert fuente.get("extracto") is None
    assert fuente["motivo"]

    # (4) F04: el informe ya no se aprueba, y el motivo lo nombra.
    with pytest.raises(AprobacionBloqueada) as exc:
        caso["documents"].approve(
            case_id, doc.id,
            sha256_revisado=checks["sha256_actual"], revisor="ramos",
        )
    assert "fuente_alterada" in {b.codigo for b in exc.value.comprobacion.bloqueos}

    # Y sigue siendo un borrador: el intento fallido no le cambió el estado.
    assert caso["documents"].get(case_id, doc.id).status == "draft"


def test_un_informe_aprobado_y_luego_roto_no_se_exporta_como_valido(
    caso, http
) -> None:
    """La comprobación precede TAMBIÉN a la exportación de un final."""
    client, auth = http["client"], http["auth"]
    case_id = caso["case"].id
    hallazgo = _hallazgo(caso)
    doc = _informe(caso, hallazgo)
    checks = client.get(
        f"/api/cases/{case_id}/documents/{doc.id}/checks", headers=auth
    ).json()
    caso["documents"].approve(
        case_id, doc.id, sha256_revisado=checks["sha256_actual"], revisor="ramos"
    )

    _alterar_fuente(caso)

    pdf = client.get(f"/api/cases/{case_id}/documents/{doc.id}/pdf", headers=auth)
    assert pdf.status_code == 200
    # Sale marcado como borrador aunque su estado diga «final»: no se exporta un
    # documento cuyas fuentes ya no verifican como si fuera válido.
    assert pdf.headers["X-Agentopsy-Pdf-Draft"] == "1"
    export = next(
        e for e in caso["audit"].entries() if e["action"] == "document_exported"
    )
    assert export["draft"] is True
    assert export["status"] == "final"


def test_la_revision_del_hallazgo_conserva_lo_que_el_informe_citaba(
    caso, http
) -> None:
    """Revisar no sobrescribe: la revisión citada sigue siendo inspeccionable."""
    client, auth = http["client"], http["auth"]
    case_id = caso["case"].id
    hallazgo = _hallazgo(caso)
    doc = _informe(caso, hallazgo)

    caso["findings"].revise(case_id, hallazgo.id, {
        "title": "Ejecutable de persistencia en el perfil de jcloudy",
        "summary": "Corregido: la ruta es AppData/Roaming/updater.exe.",
        "severity": "high",
        "references": list(hallazgo.references),
        "motivo_revision": "La ruta estaba incompleta en la primera lectura.",
    })

    # La revisión 1, que es la que el informe cita, sigue ahí y sin tocar.
    revisiones = client.get(
        f"/api/cases/{case_id}/findings/{hallazgo.id}/revisions", headers=auth
    ).json()
    assert [r["revision"] for r in revisiones] == [1, 2]
    assert revisiones[0]["content_sha256"] == hallazgo.content_sha256
    assert revisiones[0]["summary"] == hallazgo.summary
    assert "AppData/Roaming" in revisiones[1]["summary"]
    assert revisiones[1]["supersedes"] == hallazgo.content_sha256

    # Pero el informe NO se aprueba sin que alguien mire si sigue valiendo.
    comprobacion = comprobar(
        case_id, doc.id, documents=caso["documents"], cases=caso["cases"]
    )
    assert not comprobacion.aprobable
    assert "hallazgo_revisado" in {b.codigo for b in comprobacion.bloqueos}


def test_el_comando_del_informe_conserva_el_argumento_con_espacios(caso) -> None:
    """El argv tiene una ruta con un espacio: sobrevive al viaje al informe."""
    hallazgo = _hallazgo(caso)
    doc = _informe(caso, hallazgo)
    bloque = next(
        b for s in doc.sections for b in s["blocks"] if b.get("t") == "code"
    )
    from agentopsy.reports.works import tokenizar_comando

    assert tokenizar_comando(bloque["text"]) == _ARGV
    assert '"/evidence/disco con espacio.raw"' in bloque["text"]


def test_alterar_el_manifiesto_para_encajar_con_la_salida_se_detecta(caso) -> None:
    """La reescritura COHERENTE de artefacto + manifiesto: la caza el ancla."""
    case_id = caso["case"].id
    ruta_stdout = (
        caso["cases"].case_dir(case_id) / "artifacts" / caso["run_id"] / "stdout.txt"
    )
    ruta_manifiesto = (
        caso["cases"].case_dir(case_id) / "artifacts" / caso["run_id"] / "manifest.json"
    )
    nuevo = "MANIPULADO COHERENTEMENTE\n"
    ruta_stdout.write_text(nuevo, encoding="utf-8")
    manifiesto = json.loads(ruta_manifiesto.read_text(encoding="utf-8"))
    # Se recalcula el hash de la salida Y el digest del manifiesto: en el disco
    # todo cuadra consigo mismo.
    manifiesto["stdout_sha256"] = hashlib.sha256(
        ruta_stdout.read_bytes()
    ).hexdigest()
    manifiesto["manifest_sha256"] = lectura.manifest_digest(manifiesto)
    ruta_manifiesto.write_text(json.dumps(manifiesto), encoding="utf-8")

    # Aun así no cuela: el ancla que el `tool_run_finish` dejó en la cadena
    # encadenada es la del manifiesto ORIGINAL.
    with pytest.raises(lectura.ArtefactoIntegridadError, match="ancla"):
        caso["artefactos"].read_run_output(case_id, caso["run_id"], fichero="stdout")


def test_las_fuentes_de_un_hallazgo_historico_se_muestran_sin_verificar(
    caso, http
) -> None:
    """El material antiguo sigue accesible, pero no se presenta como validado."""
    case_id = caso["case"].id
    ruta = caso["cases"].case_dir(case_id) / "findings.jsonl"
    ruta.write_text(
        json.dumps({
            "id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "case_id": case_id, "title": "Hallazgo antiguo", "summary": "s",
            "severity": "low", "evidence_id": None, "tool_id": "tsk_fls",
            "run_id": "11111111-1111-4111-8111-111111111111",
            "created_at": "2026-01-01T00:00:00.000Z", "mitre_hints": [],
            "confidence": None, "observed_at": None,
            "artifact_sha256": "a" * 64, "finding_kind": "afirmacion",
        }) + "\n",
        encoding="utf-8",
    )
    antiguo = caso["findings"].list(case_id)[0]
    assert antiguo.provenance_state == "no_verificada"
    assert antiguo.references == []
    # Y su ficha de fuentes está vacía en lugar de fabricar una cita.
    assert caso["findings"].sources(case_id, antiguo.id)["fuentes"] == []
