"""RA04: el estado final exige un acto de aprobación auditado, no un campo.

Lo que la reauditoría del 2026-09-08 reprodujo: se edita el JSON de un borrador,
se pone ``status: "final"`` y unos datos de aprobador inventados, y el endpoint
del PDF responde 200 con ``X-Agentopsy-Pdf-Draft: 0``. No hacía falta un solo
evento ``document_approved`` en la cadena: la condición de final se creía.

Los gates de este fichero:

- Forjar el estado final sin acta: bloquea, y el PDF sale marcado borrador y sin
  una sola señal de aprobación.
- Un acta de OTRO documento o de otra revisión no sirve.
- Cambiar el contenido o las fuentes DESPUÉS de aprobar invalida el acta.
- Un fallo entre persistir y auditar no deja un final sin respaldo.
- Un escritor concurrente de la aplicación no cuela un borrado entre la
  comprobación y la aprobación.
- Aprobar y exportar un documento válido funciona.

Lo que este fichero NO afirma: que el cerrojo proteja frente a quien edite los
ficheros por fuera de la aplicación. No lo hace, y no se prueba como si lo
hiciera.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from _informe import aprobar, hallazgo, informe, montar_caso
from agentopsy.audit.log import AuditLog
from agentopsy.reports.aprobacion import comprobar
from agentopsy.reports.pdf import render_pdf
from agentopsy.reports.store import _content_sha256


@pytest.fixture
def caso(tmp_path):
    entorno = montar_caso(tmp_path)
    h = hallazgo(entorno)
    return entorno, h, informe(entorno, h)


def _checks(entorno, doc):
    return comprobar(
        entorno["case"].id, doc.id,
        documents=entorno["documents"], cases=entorno["cases"],
    )


def _ruta(entorno, doc):
    return entorno["cases"].case_dir(entorno["case"].id) / "documents" / f"{doc.id}.json"


def _reescribir(entorno, doc, cambios) -> None:
    ruta = _ruta(entorno, doc)
    crudo = json.loads(ruta.read_text(encoding="utf-8"))
    cambios(crudo)
    ruta.write_text(json.dumps(crudo), encoding="utf-8")


def _pdf_de(entorno, doc):
    """Los bytes del PDF y si sale marcado como borrador, igual que la ruta."""
    comprobacion = _checks(entorno, doc)
    actual = entorno["documents"].get(entorno["case"].id, doc.id)
    bloqueos = [b.como_dict() for b in comprobacion.bloqueos]
    borrador = actual.status != "final" or bool(bloqueos)
    return render_pdf(actual, bloqueos=bloqueos), borrador


# -- la reproducción ----------------------------------------------------------


def test_forjar_el_estado_final_sin_acta_no_produce_un_final(caso) -> None:
    entorno, _h, doc = caso
    _reescribir(entorno, doc, lambda d: d.update(
        status="final",
        approved_by="REVISOR FICTICIO",
        approved_at="2026-09-08T00:00:00Z",
        approved_sha256=doc.sha256,
    ))

    # No hay un solo evento de aprobación en la cadena.
    assert not [
        e for e in entorno["audit"].entries() if e.get("action") == "document_approved"
    ]
    comprobacion = _checks(entorno, doc)
    assert not comprobacion.aprobable
    assert "aprobacion_sin_acta" in {b.codigo for b in comprobacion.bloqueos}


def test_el_pdf_de_un_final_forjado_sale_marcado_y_sin_senales_de_aprobacion(
    caso,
) -> None:
    """Se puede exportar (un perito quiere leerlo), pero no como si valiera: ni
    la marca de borrador ni el pie pueden decir cosas distintas."""
    entorno, _h, doc = caso
    _reescribir(entorno, doc, lambda d: d.update(
        status="final",
        approved_by="REVISOR FICTICIO",
        approved_at="2026-09-08T00:00:00Z",
        approved_sha256=doc.sha256,
    ))
    pdf, borrador = _pdf_de(entorno, doc)
    assert borrador is True
    assert pdf.startswith(b"%PDF-")
    # El nombre del aprobador inventado no aparece por ninguna parte del fichero.
    assert b"REVISOR FICTICIO" not in pdf


def test_un_acta_de_otro_documento_no_sirve(caso) -> None:
    """Dos documentos del mismo caso: el acta de uno no vale para el otro,
    porque la identidad entra en el hash del contenido (esquema 3)."""
    entorno, h, doc = caso
    otro = informe(entorno, h, titulo=doc.title)
    aprobar(entorno, otro)

    _reescribir(entorno, doc, lambda d: d.update(
        status="final",
        approved_by=otro.author,
        approved_at="2026-09-08T00:00:00Z",
        approved_sha256=otro.sha256,
    ))
    codigos = {b.codigo for b in _checks(entorno, doc).bloqueos}
    assert "aprobacion_sin_acta" in codigos


def test_un_acta_de_otra_revision_del_mismo_documento_no_sirve(caso) -> None:
    """Se copia el acta real cambiándole el documento: la cadena la rechaza
    porque el hash del contenido y el de las fuentes no son los de este."""
    entorno, h, doc = caso
    otro = informe(entorno, h, titulo="Revisión distinta")
    aprobar(entorno, otro)

    acta = next(
        e for e in entorno["audit"].entries()
        if e.get("action") == "document_approved" and e.get("document_id") == otro.id
    )
    # Se inyecta un acta a nombre de `doc` con el CONTENIDO del otro. Se escribe
    # con `append`, así que la cadena sigue siendo válida: lo que no casa es lo
    # que el acta dice haber aprobado.
    entorno["audit"].append({**acta, "document_id": doc.id})
    _reescribir(entorno, doc, lambda d: d.update(
        status="final",
        approved_by=acta["approved_by"],
        approved_at=acta["approved_at"],
        approved_sha256=acta["approved_sha256"],
    ))
    codigos = {b.codigo for b in _checks(entorno, doc).bloqueos}
    assert "aprobacion_sin_acta" in codigos


def test_cambiar_el_contenido_despues_de_aprobar_invalida_el_acta(caso) -> None:
    entorno, _h, doc = caso
    aprobado = aprobar(entorno, doc)
    assert _checks(entorno, doc).aprobable

    def _mutar(crudo):
        crudo["summary"] = "RESUMEN CAMBIADO DESPUES DE APROBAR"
        crudo["sha256"] = _content_sha256(crudo)

    _reescribir(entorno, aprobado, _mutar)
    codigos = {b.codigo for b in _checks(entorno, doc).bloqueos}
    assert "ancla_no_casa" in codigos
    assert "aprobacion_sin_acta" in codigos
    pdf, borrador = _pdf_de(entorno, doc)
    assert borrador is True
    assert b"%PDF-" in pdf[:8]


def test_cambiar_las_fuentes_despues_de_aprobar_invalida_el_acta(caso) -> None:
    entorno, _h, doc = caso
    aprobar(entorno, doc)
    _reescribir(entorno, doc, lambda d: d.update(fuentes={"case_id": entorno["case"].id}))
    codigos = {b.codigo for b in _checks(entorno, doc).bloqueos}
    assert "procedencia_alterada" in codigos
    assert "aprobacion_sin_acta" in codigos


def test_un_fallo_al_auditar_no_deja_un_final_sin_respaldo(caso, monkeypatch) -> None:
    """Se persiste, se audita y, si la auditoría falla, se deshace la transición.
    Y aunque no se deshiciera, el documento no pasaría por final: sin acta, la
    comprobación lo bloquea igual."""
    entorno, _h, doc = caso
    store = entorno["documents"]
    original = store._audit

    def _revienta(case_id, action, documento):
        if action == "document_approved":
            raise OSError("disco lleno al escribir el acta")
        return original(case_id, action, documento)

    monkeypatch.setattr(store, "_audit", _revienta)
    with pytest.raises(OSError, match="disco lleno"):
        aprobar(entorno, doc)

    # El documento vuelve a ser borrador y la cadena no miente.
    assert store.get(entorno["case"].id, doc.id).status == "draft"
    assert AuditLog(
        entorno["cases"].case_dir(entorno["case"].id) / "audit.jsonl"
    ).verify() is True
    monkeypatch.undo()
    # Y sigue siendo aprobable: el fallo no ha dejado el caso en un estado del
    # que no se pueda salir.
    assert _checks(entorno, doc).aprobable


def test_un_borrado_concurrente_no_se_cuela_en_la_aprobacion(caso) -> None:
    """El protocolo de cerrojo es uno solo: todo escritor de un documento entra
    por SU cerrojo y vuelve a leer el estado dentro. Aquí se comprueba el orden
    con un borrado disparado desde la propia comprobación, que es el punto
    exacto en el que antes había ventana.

    Lo que esto NO demuestra es protección frente a una edición externa del
    sistema de ficheros: el cerrojo serializa a los escritores de la aplicación,
    y nada más.
    """
    entorno, _h, doc = caso
    store, case_id = entorno["documents"], entorno["case"].id
    disparado: list[str] = []

    def _comprobar_y_borrar(*args, **kwargs):
        if not disparado:
            disparado.append("si")
            # Otro escritor de la aplicación intenta borrar el borrador mientras
            # se comprueba. El cerrojo es reentrante en el mismo proceso, así
            # que esto llega a ejecutarse: lo que importa es que la aprobación
            # NO acabe escribiendo un final sobre un documento que ya no está.
            store.delete(case_id, doc.id)
        return comprobar(*args, **kwargs)

    with pytest.raises(KeyError):
        store.approve(
            case_id, doc.id,
            sha256_revisado=doc.sha256,
            revisor="ramos",
            comprobar_fn=_comprobar_y_borrar,
        )
    assert store.list(case_id) == []


def test_aprobar_y_exportar_un_documento_valido(caso) -> None:
    entorno, _h, doc = caso
    aprobado = aprobar(entorno, doc)
    assert aprobado.status == "final"

    acta = next(
        e for e in entorno["audit"].entries()
        if e.get("action") == "document_approved" and e.get("document_id") == doc.id
    )
    # El acta ata caso, documento, revisión, contenido, fuentes, revisor y fecha.
    assert acta["case_id"] == entorno["case"].id
    assert acta["version"] == doc.version
    assert acta["sha256"] == doc.sha256
    assert acta["fuentes_sha256"] == doc.fuentes_sha256
    assert acta["approved_by"] == "ramos"
    assert acta["approved_at"] == aprobado.approved_at

    pdf, borrador = _pdf_de(entorno, doc)
    assert borrador is False
    assert pdf.startswith(b"%PDF-")
    # El PDF es reproducible: dos exportaciones dan los MISMOS bytes.
    otra, _ = _pdf_de(entorno, doc)
    assert hashlib.sha256(pdf).hexdigest() == hashlib.sha256(otra).hexdigest()
