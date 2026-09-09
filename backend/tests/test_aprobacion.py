"""F04: un informe alterado no se aprueba, y no se exporta como si valiera.

Lo que la auditoría reprodujo (2026-09-07): se creó un documento, se alteró su
contenido en el disco, ``verify`` devolvió falso y ``sign`` lo pasó a ``final``
igualmente, manteniendo la integridad fallida. La exportación a PDF tampoco
exigía esa comprobación. Y un documento que YA figuraba como final se devolvía
tal cual sin mirar nada: «ya era final» valía como respuesta correcta para un
documento alterado.

Los gates de este fichero, todos sobre almacenes reales en directorios
temporales:

- Un documento alterado no se aprueba, ni recién creado ni ya final.
- Alterar el contenido Y su hash local no elude el ancla de la auditoría.
- Una cadena de auditoría inválida bloquea la aprobación.
- Una fuente alterada DESPUÉS de generar el borrador la bloquea.
- Un hallazgo revisado entre el borrador y la aprobación la bloquea.
- Aprobar exige declarar la revisión EXACTA que se revisó, y un cambio entre
  esa revisión y la aprobación no aprueba contenido distinto.
- Un informe con material recortado o ejecuciones fallidas tiene que declarar
  sus limitaciones.
- El PDF de un documento que no supera sus comprobaciones sale marcado como
  borrador, con sus bloqueos, y su SHA-256 registrado es el de los bytes
  exactos servidos.
- Un documento histórico (sin manifiesto de fuentes) se lee y se exporta, pero
  NO se aprueba con garantías que nunca tuvo.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from _procedencia import crear_run, procedencia
from fastapi.testclient import TestClient

from agentopsy.audit.log import AuditLog
from agentopsy.cases import CaseManager
from agentopsy.findings.store import FindingStore
from agentopsy.reports.aprobacion import (
    AprobacionBloqueada,
    comprobar,
    manifiesto_de_fuentes,
)
from agentopsy.reports.store import DocumentStore
from agentopsy.server import create_app


@pytest.fixture
def entorno(tmp_path):
    """Caso real con evidencia, ejecución, hallazgo citado y su informe."""
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Caso F04", examiner="ramos", os_profile="unix")
    findings = FindingStore(cases)
    documents = DocumentStore(cases)

    run = crear_run(cases, case.id)
    hallazgo = findings.append(case.id, {
        "title": "Tarea programada de persistencia",
        "summary": "La tarea updater aparece en la salida de tsk_fls.",
        "severity": "high",
        **procedencia(run),
    })

    material = {
        "caso": {"id": case.id},
        "evidencias": [
            {"evidence_id": run["evidence_id"], "sha256_baseline": _sha_evidencia(cases, case.id, run)}
        ],
        "hallazgos": [
            {
                "id": hallazgo.id,
                "revision": hallazgo.revision,
                "content_sha256": hallazgo.content_sha256,
                "procedencia": hallazgo.provenance_state,
                "tipo": hallazgo.finding_kind,
                "referencias": hallazgo.references,
            }
        ],
        "trabajos": [{"run_id": run["run_id"], "status": "finished"}],
        "integridad": {"hash_chain_verified": True},
    }
    doc = documents.create(case.id, {
        "title": "Informe pericial",
        "type": "pericial",
        "author": "ramos",
        "version": "v1.0",
        "summary": "Se confirma la persistencia.",
        "sections": _secciones(hallazgo),
        "fuentes": manifiesto_de_fuentes(case.id, material),
    })
    return {
        "cases": cases, "case_id": case.id, "documents": documents,
        "findings": findings, "run": run, "hallazgo": hallazgo, "doc": doc,
        "material": material,
    }


PORT = 51190


@pytest.fixture
def http(entorno, monkeypatch):
    """La superficie HTTP real, atada a los almacenes de este caso temporal.

    Importa que sea la de producción: la comprobación tiene que ocurrir en el
    BACKEND aunque el cliente llame a la ruta directamente, que es lo que un
    botón deshabilitado no impide (F04).
    """
    import agentopsy.routers.documents as docs_router

    monkeypatch.setattr(docs_router, "case_manager", entorno["cases"])
    monkeypatch.setattr(docs_router, "document_store", entorno["documents"])
    monkeypatch.setattr(docs_router, "finding_store", entorno["findings"])
    client = TestClient(create_app(PORT), base_url=f"http://127.0.0.1:{PORT}")
    return {"client": client, "auth": {"X-Agentopsy-Token": client.app.state.token}}


def _sha_evidencia(cases, case_id, run):
    from agentopsy.evidence import EvidenceManager

    return EvidenceManager(cases).get(case_id, run["evidence_id"]).sha256


def _secciones(hallazgo=None, *, codigos: tuple[str, ...] = ()) -> list[dict]:
    """Un cuerpo mínimo que cumple el contrato de respaldo.

    La conclusión del apartado 9 cita la revisión que la sostiene, y cada
    limitación exigida se declara con su CÓDIGO, no con prosa suelta: desde la
    reauditoría de 2026-09-08 «el apartado 9 tiene texto» ya no vale como «el
    informe declara sus limitaciones».
    """
    refs = (
        [{"finding_id": hallazgo.id, "revision": hallazgo.revision}]
        if hallazgo is not None
        else []
    )
    conclusion = {"t": "p", "text": "Se confirma la persistencia."}
    if refs:
        conclusion["refs"] = refs
    return [
        {"num": "1", "title": "Resumen", "blocks": [{"t": "p", "text": "Resumen."}]},
        {
            "num": "9",
            "title": "Conclusiones y limitaciones",
            "blocks": [
                conclusion,
                *[
                    {
                        "t": "p",
                        "text": f"Limitación declarada: {codigo}.",
                        "limitacion": codigo,
                    }
                    for codigo in codigos
                ],
            ],
        },
    ]


def _aprobar(entorno, *, sha: str | None = None):
    documents, case_id, doc = entorno["documents"], entorno["case_id"], entorno["doc"]
    if sha is None:
        sha = documents.verify(case_id, doc.id)["recomputed_sha256"]
    return documents.approve(
        case_id, doc.id, sha256_revisado=sha, revisor="ramos",
    )


def _alterar(entorno, *, tambien_el_hash: bool = False) -> None:
    """Reescribe el documento en el disco, como haría quien lo manipula."""
    ruta = (
        entorno["cases"].case_dir(entorno["case_id"])
        / "documents" / f"{entorno['doc'].id}.json"
    )
    crudo = json.loads(ruta.read_text(encoding="utf-8"))
    crudo["summary"] = "Contenido ALTERADO tras la generación."
    if tambien_el_hash:
        from agentopsy.reports.store import _content_sha256

        crudo["sha256"] = _content_sha256(crudo)
    ruta.write_text(json.dumps(crudo), encoding="utf-8")


# -- el caso reproducido por la auditoría ------------------------------------


def test_a_tampered_document_cannot_be_approved(entorno) -> None:
    _alterar(entorno)
    assert entorno["documents"].verify(entorno["case_id"], entorno["doc"].id)["ok"] is False
    with pytest.raises(AprobacionBloqueada) as exc:
        _aprobar(entorno)
    codigos = {b.codigo for b in exc.value.comprobacion.bloqueos}
    assert "contenido_alterado" in codigos
    # Y sigue siendo un borrador: no ha cambiado de estado por el intento.
    assert entorno["documents"].get(entorno["case_id"], entorno["doc"].id).status == "draft"


def test_a_document_that_is_already_final_is_re_checked_before_being_served(
    entorno,
) -> None:
    """«Ya era final» no convierte en válido un documento ahora alterado."""
    aprobado = _aprobar(entorno)
    assert aprobado.status == "final"
    _alterar(entorno)
    with pytest.raises(AprobacionBloqueada) as exc:
        entorno["documents"].approve(
            entorno["case_id"], entorno["doc"].id,
            sha256_revisado="0" * 64, revisor="ramos",
        )
    assert "contenido_alterado" in {b.codigo for b in exc.value.comprobacion.bloqueos}


def test_altering_the_content_and_its_local_hash_does_not_beat_the_audit_anchor(
    entorno,
) -> None:
    """El hash local se puede recalcular; el de la cadena encadenada, no."""
    _alterar(entorno, tambien_el_hash=True)
    # La integridad LOCAL vuelve a cuadrar, que es el truco.
    assert entorno["documents"].verify(entorno["case_id"], entorno["doc"].id)["ok"] is True
    comprobacion = comprobar(
        entorno["case_id"], entorno["doc"].id,
        documents=entorno["documents"], cases=entorno["cases"],
    )
    assert not comprobacion.aprobable
    assert "ancla_no_casa" in {b.codigo for b in comprobacion.bloqueos}


def test_a_broken_audit_chain_blocks_approval(entorno) -> None:
    ruta = entorno["cases"].case_dir(entorno["case_id"]) / "audit.jsonl"
    lineas = ruta.read_text(encoding="utf-8").splitlines()
    primera = json.loads(lineas[0])
    primera["case_id"] = "otro-caso"  # rompe el hash de esa entrada
    lineas[0] = json.dumps(primera, sort_keys=True)
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")

    assert AuditLog(ruta).verify() is False
    with pytest.raises(AprobacionBloqueada) as exc:
        _aprobar(entorno)
    assert "cadena_rota" in {b.codigo for b in exc.value.comprobacion.bloqueos}


# -- las fuentes que el informe declaró --------------------------------------


def test_a_source_altered_after_the_draft_blocks_its_approval(entorno) -> None:
    ruta = (
        entorno["cases"].case_dir(entorno["case_id"])
        / "artifacts" / entorno["run"]["run_id"] / "stdout.txt"
    )
    ruta.write_text("MANIPULADO\n", encoding="utf-8")
    with pytest.raises(AprobacionBloqueada) as exc:
        _aprobar(entorno)
    codigos = {b.codigo for b in exc.value.comprobacion.bloqueos}
    assert "fuente_alterada" in codigos


def test_a_finding_revised_after_the_draft_blocks_its_approval(entorno) -> None:
    """Revisar un hallazgo citado no cambia el informe en silencio: lo bloquea."""
    entorno["findings"].revise(
        entorno["case_id"], entorno["hallazgo"].id,
        {
            "title": "Tarea programada de persistencia",
            "summary": "Corregido: la tarea es updater2, no updater.",
            "severity": "high",
            **procedencia(entorno["run"]),
            "motivo_revision": "El nombre de la tarea estaba mal transcrito.",
        },
    )
    with pytest.raises(AprobacionBloqueada) as exc:
        _aprobar(entorno)
    assert "hallazgo_revisado" in {b.codigo for b in exc.value.comprobacion.bloqueos}


def test_a_missing_evidence_blocks_approval(entorno) -> None:
    """La evidencia que el informe usó tiene que seguir en el caso."""
    fuentes = dict(entorno["doc"].fuentes)
    fuentes["evidencias"] = ["11111111-1111-4111-8111-111111111111"]
    ruta = (
        entorno["cases"].case_dir(entorno["case_id"])
        / "documents" / f"{entorno['doc'].id}.json"
    )
    crudo = json.loads(ruta.read_text(encoding="utf-8"))
    crudo["fuentes"] = fuentes
    ruta.write_text(json.dumps(crudo), encoding="utf-8")

    with pytest.raises(AprobacionBloqueada) as exc:
        _aprobar(entorno)
    assert "evidencia_ausente" in {b.codigo for b in exc.value.comprobacion.bloqueos}


# -- la revisión humana ------------------------------------------------------


def test_approving_requires_declaring_the_reviewed_revision(entorno) -> None:
    with pytest.raises(AprobacionBloqueada) as exc:
        _aprobar(entorno, sha="")
    assert "revision_no_declarada" in {b.codigo for b in exc.value.comprobacion.bloqueos}


def test_a_content_change_between_review_and_approval_approves_nothing(entorno) -> None:
    """El caso que la comprobación (h) existe para impedir."""
    revisado = entorno["documents"].verify(
        entorno["case_id"], entorno["doc"].id
    )["recomputed_sha256"]
    _alterar(entorno, tambien_el_hash=True)  # el contenido cambia bajo los pies
    with pytest.raises(AprobacionBloqueada) as exc:
        _aprobar(entorno, sha=revisado)
    codigos = {b.codigo for b in exc.value.comprobacion.bloqueos}
    assert "revision_no_coincide" in codigos
    assert entorno["documents"].get(entorno["case_id"], entorno["doc"].id).status == "draft"


# -- limitaciones obligatorias -----------------------------------------------


def test_a_report_with_cut_material_must_declare_its_limitations(entorno) -> None:
    material = dict(entorno["material"])
    material["truncado"] = {"hallazgos": {"total": 500, "incluidos": 400}}
    doc = entorno["documents"].create(entorno["case_id"], {
        "title": "Informe sin limitaciones", "type": "pericial", "author": "ramos",
        "version": "v1.1", "summary": "resumen",
        # El apartado 9 existe y tiene texto, pero NO declara el código de la
        # limitación que el material exige: existir no es declarar.
        "sections": _secciones(entorno["hallazgo"]),
        "fuentes": manifiesto_de_fuentes(entorno["case_id"], material),
    })
    comprobacion = comprobar(
        entorno["case_id"], doc.id,
        documents=entorno["documents"], cases=entorno["cases"],
    )
    assert "limitaciones_ausentes" in {b.codigo for b in comprobacion.bloqueos}


def test_the_same_report_declaring_them_is_approvable(entorno) -> None:
    material = dict(entorno["material"])
    material["truncado"] = {"hallazgos": {"total": 500, "incluidos": 400}}
    doc = entorno["documents"].create(entorno["case_id"], {
        "title": "Informe con limitaciones", "type": "pericial", "author": "ramos",
        "version": "v1.2", "summary": "resumen",
        "sections": _secciones(
            entorno["hallazgo"], codigos=("material_truncado:hallazgos",)
        ),
        "fuentes": manifiesto_de_fuentes(entorno["case_id"], material),
    })
    comprobacion = comprobar(
        entorno["case_id"], doc.id,
        documents=entorno["documents"], cases=entorno["cases"],
    )
    assert comprobacion.aprobable, [b.mensaje for b in comprobacion.bloqueos]


# -- compatibilidad con lo histórico -----------------------------------------


def test_a_legacy_document_without_a_manifest_is_readable_but_not_approvable(
    entorno,
) -> None:
    """Se conserva y se lee; lo que no se hace es atribuirle garantías nuevas."""
    ruta = (
        entorno["cases"].case_dir(entorno["case_id"])
        / "documents" / f"{entorno['doc'].id}.json"
    )
    crudo = json.loads(ruta.read_text(encoding="utf-8"))
    crudo.pop("fuentes", None)
    crudo.pop("approved_at", None)
    crudo.pop("approved_by", None)
    crudo.pop("approved_sha256", None)
    crudo["schema_version"] = 1
    crudo.pop("fuentes_sha256", None)
    # Un documento histórico DE VERDAD lleva el hash que su esquema calculaba:
    # el contenido canónico del esquema 1 no incluía identidad ni digest de
    # procedencia. Recomputarlo aquí es construir el fichero que aquella versión
    # escribía, no repararle el hash para que parezca verificado.
    from agentopsy.reports.store import _content_sha256

    crudo["sha256"] = _content_sha256(crudo)
    ruta.write_text(json.dumps(crudo), encoding="utf-8")

    # Sigue siendo legible, con su contenido intacto.
    doc = entorno["documents"].get(entorno["case_id"], entorno["doc"].id)
    assert doc.fuentes == {}
    assert doc.schema_version == 1
    assert entorno["documents"].verify(entorno["case_id"], doc.id)["ok"] is True

    comprobacion = comprobar(
        entorno["case_id"], doc.id,
        documents=entorno["documents"], cases=entorno["cases"],
    )
    assert "sin_manifiesto" in {b.codigo for b in comprobacion.bloqueos}
    # Y el motivo dice qué hacer, no solo que no se puede.
    motivo = next(b for b in comprobacion.bloqueos if b.codigo == "sin_manifiesto")
    # El motivo se lee en el idioma de quien lo lee, así que se comprueba en los
    # dos y sin distinguir mayúsculas: lo que importa es que diga la SALIDA.
    texto = motivo.mensaje.lower()
    assert "finalizar la investigación" in texto or "finalise the investigation" in texto


# -- el camino feliz ---------------------------------------------------------


def test_an_intact_report_with_its_sources_is_approvable(entorno) -> None:
    comprobacion = comprobar(
        entorno["case_id"], entorno["doc"].id,
        documents=entorno["documents"], cases=entorno["cases"],
    )
    assert comprobacion.aprobable, [b.mensaje for b in comprobacion.bloqueos]
    # Y las fuentes viajan con su estado, para que la interfaz las pinte.
    tipos = {f["tipo"] for f in comprobacion.fuentes}
    assert {"evidencia", "artefacto", "hallazgo"} <= tipos
    assert all(f["estado"] == "verificada" for f in comprobacion.fuentes)

    aprobado = _aprobar(entorno)
    assert aprobado.status == "final"
    assert aprobado.approved_sha256 == comprobacion.sha256_actual
    assert AuditLog(
        entorno["cases"].case_dir(entorno["case_id"]) / "audit.jsonl"
    ).verify() is True

# -- exportación: identidad, estado y hashes verificables --------------------


def _pdf(client, auth, case_id, doc_id):
    return client.get(
        f"/api/cases/{case_id}/documents/{doc_id}/pdf", headers=auth
    )


def test_the_recorded_pdf_hash_is_that_of_the_exact_bytes_served(
    entorno, http
) -> None:
    """El hash del PDF es el de los BYTES servidos, no el del contenido."""
    client, auth = http["client"], http["auth"]
    _aprobar(entorno)
    res = _pdf(client, auth, entorno["case_id"], entorno["doc"].id)
    assert res.status_code == 200, res.text
    esperado = hashlib.sha256(res.content).hexdigest()
    assert res.headers["X-Agentopsy-Pdf-Sha256"] == esperado
    assert res.headers["X-Agentopsy-Pdf-Draft"] == "0"

    entradas = AuditLog(
        entorno["cases"].case_dir(entorno["case_id"]) / "audit.jsonl"
    ).entries()
    export = next(e for e in entradas if e["action"] == "document_exported")
    assert export["pdf_sha256"] == esperado
    assert export["pdf_bytes"] == len(res.content)
    assert export["draft"] is False
    # El hash del PDF y el del contenido son DISTINTOS y viajan por separado.
    assert export["document_sha256"] == entorno["doc"].sha256
    assert export["pdf_sha256"] != export["document_sha256"]
    assert export["generator"].startswith("Agentopsy ")


def test_a_draft_is_exported_marked_as_such(entorno, http) -> None:
    client, auth = http["client"], http["auth"]
    res = _pdf(client, auth, entorno["case_id"], entorno["doc"].id)
    assert res.status_code == 200
    assert res.headers["X-Agentopsy-Pdf-Draft"] == "1"
    entradas = AuditLog(
        entorno["cases"].case_dir(entorno["case_id"]) / "audit.jsonl"
    ).entries()
    export = next(e for e in entradas if e["action"] == "document_exported")
    assert export["draft"] is True
    assert export["status"] == "draft"


def test_a_tampered_final_document_is_not_exported_as_valid(entorno, http) -> None:
    """Ya era final, pero está alterado: sale como BORRADOR con sus bloqueos."""
    client, auth = http["client"], http["auth"]
    _aprobar(entorno)
    _alterar(entorno)
    res = _pdf(client, auth, entorno["case_id"], entorno["doc"].id)
    assert res.status_code == 200
    assert res.headers["X-Agentopsy-Pdf-Draft"] == "1"
    entradas = AuditLog(
        entorno["cases"].case_dir(entorno["case_id"]) / "audit.jsonl"
    ).entries()
    export = next(e for e in entradas if e["action"] == "document_exported")
    assert export["draft"] is True


def test_a_registered_final_export_is_not_silently_replaced(entorno, http) -> None:
    """Dos exportaciones finales del mismo documento dan los mismos bytes; una
    que no coincidiera con la registrada NO la sustituye en silencio."""
    client, auth = http["client"], http["auth"]
    _aprobar(entorno)
    primera = _pdf(client, auth, entorno["case_id"], entorno["doc"].id)
    assert primera.status_code == 200

    # Se falsea una exportación final previa con OTROS bytes: la siguiente
    # exportación tiene que fallar fuerte en vez de pisarla.
    AuditLog(entorno["cases"].case_dir(entorno["case_id"]) / "audit.jsonl").append({
        "action": "document_exported",
        "case_id": entorno["case_id"],
        "document_id": entorno["doc"].id,
        "pdf_sha256": "f" * 64,
        "draft": False,
    })
    segunda = _pdf(client, auth, entorno["case_id"], entorno["doc"].id)
    assert segunda.status_code == 409
    assert "f" * 64 in segunda.json()["detail"]


def test_approving_over_http_requires_the_reviewed_revision(entorno, http) -> None:
    """La comprobación es del BACKEND aunque el cliente llame directamente."""
    client, auth = http["client"], http["auth"]
    case_id, doc_id = entorno["case_id"], entorno["doc"].id

    # Sin el hash revisado: 422 de contrato (el campo es obligatorio).
    assert client.post(
        f"/api/cases/{case_id}/documents/{doc_id}/sign", headers=auth, json={}
    ).status_code == 422

    # Con un hash que no es el del contenido actual: 409 con sus bloqueos.
    res = client.post(
        f"/api/cases/{case_id}/documents/{doc_id}/sign",
        headers=auth,
        json={"sha256": "0" * 64, "approved_by": "ramos"},
    )
    assert res.status_code == 409
    codigos = {b["codigo"] for b in res.json()["detail"]["bloqueos"]}
    assert "revision_no_coincide" in codigos

    # Con el correcto: aprueba, y la respuesta trae la traza del acto.
    checks = client.get(
        f"/api/cases/{case_id}/documents/{doc_id}/checks", headers=auth
    ).json()
    assert checks["aprobable"] is True
    ok = client.post(
        f"/api/cases/{case_id}/documents/{doc_id}/sign",
        headers=auth,
        json={"sha256": checks["sha256_actual"], "approved_by": "ramos"},
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["status"] == "final"
    assert ok.json()["approved_by"] == "ramos"


def test_the_checks_endpoint_lists_the_sources_and_their_state(entorno, http) -> None:
    """Lo que pinta la pantalla de aprobación: la revisión y sus bloqueos."""
    client, auth = http["client"], http["auth"]
    ruta = (
        entorno["cases"].case_dir(entorno["case_id"])
        / "artifacts" / entorno["run"]["run_id"] / "stdout.txt"
    )
    ruta.write_text("MANIPULADO\n", encoding="utf-8")

    body = client.get(
        f"/api/cases/{entorno['case_id']}/documents/{entorno['doc'].id}/checks",
        headers=auth,
    ).json()
    assert body["aprobable"] is False
    assert body["version"] == "v1.0"
    assert body["sha256_actual"] == entorno["doc"].sha256
    assert "fuente_alterada" in {b["codigo"] for b in body["bloqueos"]}
    artefacto = next(f for f in body["fuentes"] if f["tipo"] == "artefacto")
    assert artefacto["estado"] == "alterada"


def test_the_exported_pdf_is_reproducible(entorno, http) -> None:
    """Dos exportaciones del MISMO informe dan los MISMOS bytes.

    Sin esto el SHA-256 que se registra no le sirve a nadie: un tercero no
    podría comprobar el fichero que tiene en la mano contra el del expediente,
    porque la fecha de creación embebida cambiaría en cada descarga.
    """
    client, auth = http["client"], http["auth"]
    _aprobar(entorno)
    a = _pdf(client, auth, entorno["case_id"], entorno["doc"].id)
    b = _pdf(client, auth, entorno["case_id"], entorno["doc"].id)
    assert a.content == b.content
    assert a.headers["X-Agentopsy-Pdf-Sha256"] == b.headers["X-Agentopsy-Pdf-Sha256"]
