"""RA03: un hallazgo no se cree por su hash declarado, y su procedencia decide.

Dos reproducciones de la reauditoría del 2026-09-08:

1. Se cambia el ``summary`` de un hallazgo SIN tocar su ``content_sha256`` y el
   informe se sigue aprobando: se comparaban dos valores almacenados (el del
   hallazgo y el del manifiesto), y ninguno de los dos cambia al reescribir el
   texto.
2. Se genera un informe nuevo a partir de un hallazgo histórico con
   ``provenance_state=no_verificada`` y sin referencias, y también se aprueba: el
   estado de procedencia viajaba como dato informativo, no como requisito.

Los gates de este fichero:

- Resumen alterado con el hash declarado intacto: bloquea.
- Resumen alterado Y hash recalculado en local: bloquea (el ancla no cambia).
- Cambiar las referencias, la identidad o la revisión: bloquea.
- Hallazgo histórico sin referencias en un informe nuevo: bloquea.
- Los históricos SIGUEN siendo legibles, declarados como no verificados.
- Un descarte sin fuente pero con alcance declarado es legítimo.
- Una revisión válida con referencias verificadas se aprueba.
"""

from __future__ import annotations

import json
from dataclasses import asdict

import pytest
from _informe import aprobar, hallazgo, informe, material_de, montar_caso, secciones
from agentopsy.findings.store import content_sha256
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


def _codigos(entorno, doc) -> set[str]:
    return {b.codigo for b in _checks(entorno, doc).bloqueos}


def _reescribir_hallazgo(entorno, mutacion) -> dict:
    """Reescribe la línea del hallazgo en ``findings.jsonl``, en el disco."""
    ruta = entorno["cases"].case_dir(entorno["case"].id) / "findings.jsonl"
    registro = json.loads(ruta.read_text(encoding="utf-8").strip())
    mutacion(registro)
    ruta.write_text(json.dumps(registro) + "\n", encoding="utf-8")
    return registro


# -- reproducción 1: el hash declarado no se cree ----------------------------


def test_alterar_el_resumen_conservando_el_hash_declarado_bloquea(caso) -> None:
    entorno, _h, doc = caso
    registro = _reescribir_hallazgo(
        entorno,
        lambda r: r.update(summary="CONCLUSION ALTERADA SIN MODIFICAR EL HASH"),
    )
    # Los dos valores almacenados siguen de acuerdo entre sí...
    assert registro["content_sha256"] == doc.fuentes["hallazgos"][0]["content_sha256"]
    # ...y el hash REAL del contenido ya no es ese.
    assert content_sha256(registro) != registro["content_sha256"]

    assert "hallazgo_alterado" in _codigos(entorno, doc)
    with pytest.raises(AprobacionBloqueada):
        aprobar(entorno, doc)


def test_alterar_el_resumen_y_recalcular_su_hash_tampoco_pasa(caso) -> None:
    """El hallazgo vuelve a ser coherente consigo mismo, pero el manifiesto del
    informe y el evento de auditoría siguen diciendo lo que decían."""
    entorno, _h, doc = caso

    def _mutar(r):
        r["summary"] = "CONCLUSION ALTERADA CON SU HASH RECALCULADO"
        r["content_sha256"] = content_sha256(r)

    _reescribir_hallazgo(entorno, _mutar)
    assert "hallazgo_revisado" in _codigos(entorno, doc)


def test_alterar_el_resumen_y_el_manifiesto_choca_con_el_ancla(caso) -> None:
    """Se rehacen hallazgo y manifiesto de forma coherente. Lo que no se puede
    rehacer sin reescribir la cadena es el evento que ancló ese contenido."""
    entorno, _h, doc = caso

    def _mutar(r):
        r["summary"] = "CONCLUSION ALTERADA, TODO RECALCULADO"
        r["content_sha256"] = content_sha256(r)

    registro = _reescribir_hallazgo(entorno, _mutar)

    ruta_doc = (
        entorno["cases"].case_dir(entorno["case"].id) / "documents" / f"{doc.id}.json"
    )
    crudo = json.loads(ruta_doc.read_text(encoding="utf-8"))
    crudo["fuentes"]["hallazgos"][0]["content_sha256"] = registro["content_sha256"]
    ruta_doc.write_text(json.dumps(crudo), encoding="utf-8")

    codigos = _codigos(entorno, doc)
    assert "hallazgo_sin_ancla" in codigos or "procedencia_alterada" in codigos


@pytest.mark.parametrize(
    "mutacion, motivo",
    [
        pytest.param(lambda r: r.update(references=[]), "referencias", id="referencias"),
        pytest.param(
            lambda r: r.update(evidence_id="11111111-1111-4111-8111-111111111111"),
            "identidad",
            id="identidad",
        ),
        pytest.param(lambda r: r.update(revision=7), "revision", id="revision"),
    ],
)
def test_cambiar_referencias_identidad_o_revision_bloquea(caso, mutacion, motivo) -> None:
    entorno, _h, doc = caso
    _reescribir_hallazgo(entorno, mutacion)
    comprobacion = _checks(entorno, doc)
    assert not comprobacion.aprobable, motivo


# -- reproducción 2: un histórico no adquiere garantías por citarse -----------


def _volver_historico(entorno, h) -> None:
    """Deja el hallazgo como los que se escribieron antes del contrato de citas:
    sin referencias, sin estado de procedencia y sin alcance.

    Se le ancla su contenido en la cadena con ``append``, para que el histórico
    quede COHERENTE: así el único motivo posible de bloqueo es su procedencia y
    no un ancla que no casa. Un histórico legítimo es exactamente eso, un
    hallazgo bien registrado en su momento, cuando aún no se le exigían citas.
    """
    registro = asdict(h)
    registro["references"] = []
    registro["provenance_state"] = "no_verificada"
    registro["alcance_examinado"] = None
    registro["content_sha256"] = content_sha256(registro)
    ruta = entorno["cases"].case_dir(entorno["case"].id) / "findings.jsonl"
    ruta.write_text(json.dumps(registro) + "\n", encoding="utf-8")
    entorno["audit"].append({
        "action": "finding_recorded",
        "case_id": entorno["case"].id,
        "finding_id": h.id,
        "revision": 1,
        "content_sha256": registro["content_sha256"],
        "provenance_state": "no_verificada",
        "references": [],
    })


def test_un_historico_sin_referencias_no_sostiene_un_informe_nuevo(tmp_path) -> None:
    entorno = montar_caso(tmp_path)
    h = hallazgo(entorno)
    _volver_historico(entorno, h)

    historico = entorno["findings"].get(entorno["case"].id, h.id)
    assert historico.provenance_state == "no_verificada"
    assert historico.references == []

    # Se genera un informe NUEVO que lo cita: eso no lo convierte en verificable.
    doc = informe(entorno, historico)
    codigos = _codigos(entorno, doc)
    assert not _checks(entorno, doc).aprobable
    assert "hallazgo_sin_procedencia" in codigos


def test_un_historico_sigue_siendo_legible(tmp_path) -> None:
    """Compatibilidad honesta: se lee y se muestra, declarado como lo que es."""
    entorno = montar_caso(tmp_path)
    h = hallazgo(entorno)
    _volver_historico(entorno, h)

    historico = entorno["findings"].get(entorno["case"].id, h.id)
    assert historico.title == h.title
    assert historico.summary == h.summary
    assert [f.id for f in entorno["findings"].list(entorno["case"].id)] == [h.id]

    fuentes = entorno["findings"].sources(entorno["case"].id, h.id)
    assert fuentes["provenance_state"] == "no_verificada"
    assert fuentes["fuentes"] == []


def test_un_descarte_sin_fuente_pero_con_alcance_es_legitimo(tmp_path) -> None:
    """No todo hallazgo sin cita es un histórico roto: un descarte documenta que
    una vía no aportó, y lo que se le exige es declarar QUÉ se examinó."""
    entorno = montar_caso(tmp_path)
    descarte = entorno["findings"].append(entorno["case"].id, {
        "title": "Sin rastro de exfiltración por USB",
        "summary": "No consta ningún dispositivo de almacenamiento masivo montado.",
        "severity": "low",
        "finding_kind": "descarte",
        "alcance_examinado": (
            "Claves USBSTOR del hive SYSTEM, con RegRipper, sobre la partición 2."
        ),
        "references": [],
    })
    doc = informe(entorno, descarte)
    comprobacion = _checks(entorno, doc)
    assert comprobacion.aprobable, [b.mensaje for b in comprobacion.bloqueos]


def test_un_descarte_sin_fuente_y_sin_alcance_bloquea(tmp_path) -> None:
    """«No se encontró» y «no se pudo analizar» no son la misma frase."""
    entorno = montar_caso(tmp_path)
    descarte = entorno["findings"].append(entorno["case"].id, {
        "title": "Sin rastro de exfiltración por USB",
        "summary": "No consta ningún dispositivo montado.",
        "severity": "low",
        "finding_kind": "descarte",
        "alcance_examinado": "Claves USBSTOR del hive SYSTEM con RegRipper.",
        "references": [],
    })
    doc = informe(entorno, descarte)

    ruta = entorno["cases"].case_dir(entorno["case"].id) / "findings.jsonl"
    registro = json.loads(ruta.read_text(encoding="utf-8").strip())
    registro["alcance_examinado"] = None
    registro["content_sha256"] = content_sha256(registro)
    ruta.write_text(json.dumps(registro) + "\n", encoding="utf-8")

    codigos = _codigos(entorno, doc)
    assert codigos & {"hallazgo_sin_procedencia", "hallazgo_revisado"}


# -- el recorrido válido ------------------------------------------------------


def test_una_revision_valida_con_referencias_verificadas_se_aprueba(caso) -> None:
    entorno, h, doc = caso
    comprobacion = _checks(entorno, doc)
    assert comprobacion.aprobable, [b.mensaje for b in comprobacion.bloqueos]
    ficha = next(f for f in comprobacion.fuentes if f["tipo"] == "hallazgo")
    assert ficha["estado"] == "verificada"
    assert ficha["content_sha256_recomputado"] == h.content_sha256
    assert aprobar(entorno, doc).status == "final"


def test_una_revision_posterior_bloquea_el_informe_que_citaba_la_anterior(caso) -> None:
    """Revisar un hallazgo citado no cambia el informe a escondidas: lo bloquea
    hasta que alguien mire si sigue diciendo lo correcto."""
    entorno, h, doc = caso
    entorno["findings"].revise(entorno["case"].id, h.id, {
        "title": h.title,
        "summary": "Corregido: la tarea es updater2, no updater.",
        "severity": "high",
        "observed_at": "2026-03-14T08:12:44Z",
        "references": h.references,
        "motivo_revision": "El nombre de la tarea estaba mal transcrito.",
    })
    assert "hallazgo_revisado" in _codigos(entorno, doc)

    # Y el informe NUEVO, que cita la revisión vigente, sí se aprueba: la
    # procedencia se puede reconstruir, conservando la historia anterior.
    vigente = entorno["findings"].get(entorno["case"].id, h.id)
    assert vigente.revision == 2
    assert len(entorno["findings"].revisions(entorno["case"].id, h.id)) == 2
    nuevo = informe(
        entorno, vigente,
        material=material_de(entorno, vigente),
        sections=secciones(vigente),
    )
    assert _checks(entorno, nuevo).aprobable
