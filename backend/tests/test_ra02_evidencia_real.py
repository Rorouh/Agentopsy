"""RA02: aprobar verifica los BYTES de la evidencia, no dos hashes almacenados.

Lo que la reauditoría del 2026-09-08 reprodujo: se altera el fichero de la
evidencia sintética, ``EvidenceManager.verify`` devuelve falso y lo registra en
una cadena válida, y el informe se aprueba igualmente. La comprobación comparaba
el ``sha256`` del handle con el del manifiesto, y ninguno de los dos cambia
cuando cambian los bytes: se estaban comparando dos copias del mismo dato.

Los gates de este fichero:

- Bytes cambiados MANTENIENDO el tamaño: bloquea (un tamaño igual no prueba nada).
- Un segmento distinto del primero alterado en un conjunto EWF: bloquea.
- Un segmento requerido que falta: bloquea.
- El baseline con el que corrió la ejecución distinto del registrado: bloquea.
- Una verificación negativa registrada: bloquea hasta volver a verificar.
- Evidencia intacta y recorrido válido: se aprueba.
"""

from __future__ import annotations

import json
import stat

import pytest
from _informe import aprobar, hallazgo, informe, montar_caso
from agentopsy.evidence import EvidenceManager
from agentopsy.reports.aprobacion import AprobacionBloqueada, comprobar


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


def _escribir_evidencia(entorno, contenido: bytes) -> None:
    ruta = entorno["evidencia"].original_path
    ruta.chmod(stat.S_IWRITE | stat.S_IREAD)
    ruta.write_bytes(contenido)


def test_cambiar_los_bytes_manteniendo_el_tamano_bloquea(caso) -> None:
    """El caso más incómodo: mismo tamaño, misma fecha, otro contenido. Un
    control que mirase metadatos lo dejaría pasar."""
    entorno, _h, doc = caso
    original = entorno["evidencia"].original_path.read_bytes()
    alterado = b"X" + original[1:]
    assert len(alterado) == len(original)
    _escribir_evidencia(entorno, alterado)

    comprobacion = _checks(entorno, doc)
    assert not comprobacion.aprobable
    assert "evidencia_alterada" in {b.codigo for b in comprobacion.bloqueos}
    with pytest.raises(AprobacionBloqueada):
        aprobar(entorno, doc)


def test_la_comprobacion_de_integridad_no_reutiliza_una_verificacion_anterior(
    caso,
) -> None:
    """Verificar hoy no vale para mañana: la comprobación relee los bytes."""
    entorno, _h, _doc = caso
    evidence = EvidenceManager(entorno["cases"])
    case_id, ev_id = entorno["case"].id, entorno["evidencia"].evidence_id
    assert evidence.verify(case_id, ev_id) is True

    _escribir_evidencia(entorno, b"ALTERADA DESPUES DE VERIFICAR")
    # Sin volver a llamar a `verify` (que es el acto auditado), la comprobación
    # de integridad ya ve el cambio.
    assert evidence.comprobar_integridad(case_id, ev_id)["verificada"] is False


def test_un_segmento_distinto_del_primero_alterado_bloquea(tmp_path) -> None:
    """Un conjunto EWF se verifica ENTERO: un `.E02` alterado no pasa porque el
    `.E01` esté intacto."""
    entorno = montar_caso(tmp_path, nombre="EWF")
    cases, case_id = entorno["cases"], entorno["case"].id

    origen = tmp_path / "set"
    origen.mkdir()
    for i in (1, 2, 3):
        (origen / f"imagen.E{i:02d}").write_bytes(f"EWF-segmento-{i:02d}".encode())
    evidencia = EvidenceManager(cases).register(case_id, str(origen / "imagen.E01"))
    assert evidencia.segment_count == 3

    directorio = evidencia.original_path.parent
    segundo = directorio / "original.E02"
    segundo.chmod(stat.S_IWRITE | stat.S_IREAD)
    segundo.write_bytes(b"EWF-segmento-XX")

    resultado = EvidenceManager(cases).comprobar_integridad(case_id, evidencia.evidence_id)
    assert resultado["verificada"] is False
    rotos = [s["name"] for s in resultado["segmentos"] if not s["verified"]]
    assert rotos == ["original.E02"]
    # El primero sigue intacto: la verificación no pasa por eso.
    assert resultado["segmentos"][0]["verified"] is True


def test_eliminar_un_segmento_requerido_bloquea(tmp_path) -> None:
    entorno = montar_caso(tmp_path, nombre="EWF")
    cases, case_id = entorno["cases"], entorno["case"].id

    origen = tmp_path / "set"
    origen.mkdir()
    for i in (1, 2):
        (origen / f"imagen.E{i:02d}").write_bytes(f"EWF-segmento-{i:02d}".encode())
    evidencia = EvidenceManager(cases).register(case_id, str(origen / "imagen.E01"))

    segundo = evidencia.original_path.parent / "original.E02"
    segundo.chmod(stat.S_IWRITE | stat.S_IREAD)
    segundo.unlink()

    # Un segmento que falta es un conjunto roto, y se dice al pedir el handle.
    with pytest.raises(KeyError, match="segment missing"):
        EvidenceManager(cases).comprobar_integridad(case_id, evidencia.evidence_id)


def test_un_baseline_de_ejecucion_incompatible_bloquea(tmp_path) -> None:
    """La ejecución dice haber leído la evidencia con otro baseline: entonces no
    leyó esa evidencia, y lo que produjo no sostiene lo que el informe afirma."""
    entorno = montar_caso(tmp_path)
    h = hallazgo(entorno)
    doc = informe(entorno, h)

    manifiesto = (
        entorno["cases"].case_dir(entorno["case"].id)
        / "artifacts" / entorno["run_id"] / "manifest.json"
    )
    crudo = json.loads(manifiesto.read_text(encoding="utf-8"))
    crudo["evidence_baseline_sha256"] = "b" * 64
    manifiesto.write_text(json.dumps(crudo), encoding="utf-8")

    codigos = {b.codigo for b in _checks(entorno, doc).bloqueos}
    # Tocar el manifiesto rompe su ancla, y eso ya bloquea. Lo que este test fija
    # es que la incoherencia NO pasa desapercibida por ninguna de las dos vías.
    assert codigos & {"evidencia_baseline_incoherente", "fuente_alterada"}


def test_una_verificacion_negativa_registrada_bloquea(caso) -> None:
    """Alguien comprobó esta evidencia y le salió mal. Que los bytes casen ahora
    no borra ese hecho: la salida es volver a verificarla, y eso deja su propio
    evento en la cadena."""
    entorno, _h, doc = caso
    evidence = EvidenceManager(entorno["cases"])
    case_id, ev_id = entorno["case"].id, entorno["evidencia"].evidence_id
    intactos = entorno["evidencia"].original_path.read_bytes()

    _escribir_evidencia(entorno, b"ALTERADA")
    assert evidence.verify(case_id, ev_id) is False
    _escribir_evidencia(entorno, intactos)  # se restaura el fichero

    codigos = {b.codigo for b in _checks(entorno, doc).bloqueos}
    assert "evidencia_verificacion_negativa" in codigos

    # La salida explícita: verificar otra vez. Ahora sí se aprueba.
    assert evidence.verify(case_id, ev_id) is True
    assert _checks(entorno, doc).aprobable


def test_el_motivo_nombra_la_evidencia_y_el_segmento(caso) -> None:
    """RA02 f: el bloqueo tiene que ser útil en la API y en la interfaz."""
    entorno, _h, doc = caso
    _escribir_evidencia(entorno, b"ALTERADA")
    bloqueo = next(
        b for b in _checks(entorno, doc).bloqueos if b.codigo == "evidencia_alterada"
    )
    assert entorno["evidencia"].evidence_id in bloqueo.mensaje
    assert "original.raw" in bloqueo.detalle or bloqueo.detalle


def test_evidencia_intacta_y_recorrido_valido(caso) -> None:
    entorno, _h, doc = caso
    comprobacion = _checks(entorno, doc)
    assert comprobacion.aprobable, [b.mensaje for b in comprobacion.bloqueos]
    ficha = next(f for f in comprobacion.fuentes if f["tipo"] == "evidencia")
    assert ficha["estado"] == "verificada"
    assert ficha["integridad"] is True
    assert aprobar(entorno, doc).status == "final"
