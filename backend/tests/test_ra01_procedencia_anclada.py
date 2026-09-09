"""RA01: no se puede retirar el respaldo de un informe sin que se note.

Lo que la reauditoría del 2026-09-08 reprodujo: se altera una fuente y la
aprobación queda bloqueada, correcto. Pero después se sustituye ÚNICAMENTE el
objeto ``fuentes`` del documento por ``{"case_id": "..."}``, sin tocar el texto,
y el informe vuelve a ser aprobable. El hash del documento seguía siendo válido
porque se calculaba sobre el contenido EXCLUYENDO las fuentes, y la comprobación
recorría solo las fuentes que ese objeto declaraba, que ya eran ninguna.

Los gates de este fichero, todos con almacenes reales sobre directorios
temporales y una procedencia sintética pero completa:

- Una fuente alterada bloquea (esto ya funcionaba, y se conserva).
- Sustituir el manifiesto por el objeto mínimo NO desbloquea: bloquea más.
- Vaciarlo, quitarlo o quitarle un miembro bloquea.
- Recalcular el digest en local no basta: el ancla del audit no cambia sola.
- Recalcular ADEMÁS el hash del documento tampoco: el ancla sigue sin casar.
- Un documento íntegro con su snapshot completo se aprueba.
"""

from __future__ import annotations

import json

import pytest
from _informe import aprobar, hallazgo, informe, montar_caso
from agentopsy.reports.aprobacion import AprobacionBloqueada, comprobar
from agentopsy.reports.fuentes import digest_de_fuentes
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


def _codigos(entorno, doc) -> set[str]:
    return {b.codigo for b in _checks(entorno, doc).bloqueos}


def _reescribir(entorno, doc, cambios) -> None:
    """Reescribe el JSON del documento en el disco, como haría quien lo manipula."""
    ruta = (
        entorno["cases"].case_dir(entorno["case"].id) / "documents" / f"{doc.id}.json"
    )
    crudo = json.loads(ruta.read_text(encoding="utf-8"))
    cambios(crudo)
    ruta.write_text(json.dumps(crudo), encoding="utf-8")


def _alterar_fuente(entorno) -> None:
    (
        entorno["cases"].case_dir(entorno["case"].id)
        / "artifacts" / entorno["run_id"] / "stdout.txt"
    ).write_text("MANIPULADO\n", encoding="utf-8")


# -- la reproducción, paso a paso --------------------------------------------


def test_una_fuente_alterada_bloquea_la_aprobacion(caso) -> None:
    entorno, _h, doc = caso
    _alterar_fuente(entorno)
    assert "fuente_alterada" in _codigos(entorno, doc)


def test_sustituir_las_fuentes_por_el_objeto_minimo_no_desbloquea(caso) -> None:
    """El paso EXACTO de la reauditoría: la fuente alterada ya no se recorre
    porque el manifiesto ya no la declara. Antes eso bastaba para aprobar."""
    entorno, _h, doc = caso
    _alterar_fuente(entorno)
    assert not _checks(entorno, doc).aprobable

    _reescribir(entorno, doc, lambda d: d.update(fuentes={"case_id": entorno["case"].id}))

    comprobacion = _checks(entorno, doc)
    assert not comprobacion.aprobable
    # Y el motivo es el correcto: no es que falte una fuente, es que el
    # manifiesto ya no da su digest.
    assert "procedencia_alterada" in {b.codigo for b in comprobacion.bloqueos}
    with pytest.raises(AprobacionBloqueada):
        aprobar(entorno, doc)


@pytest.mark.parametrize(
    "mutacion",
    [
        pytest.param(lambda f: {}, id="vaciado"),
        pytest.param(lambda f: {**f, "hallazgos": []}, id="sin_hallazgos"),
        pytest.param(lambda f: {**f, "artefactos": []}, id="sin_artefactos"),
        pytest.param(lambda f: {**f, "evidencias": []}, id="sin_evidencias"),
        pytest.param(
            lambda f: {k: v for k, v in f.items() if k != "hallazgos"},
            id="clave_hallazgos_eliminada",
        ),
    ],
)
def test_vaciar_o_recortar_el_manifiesto_bloquea(caso, mutacion) -> None:
    """Quitar miembros del snapshot es retirar respaldo, y se ve."""
    entorno, _h, doc = caso
    _reescribir(entorno, doc, lambda d: d.update(fuentes=mutacion(d["fuentes"])))
    codigos = _codigos(entorno, doc)
    assert not _checks(entorno, doc).aprobable
    assert codigos & {"procedencia_alterada", "sin_manifiesto"}


def test_recalcular_el_digest_en_local_no_basta(caso) -> None:
    """El digest casa con el manifiesto nuevo, pero el ancla del audit sigue
    siendo la del manifiesto viejo: para cambiarla hay que reescribir la cadena."""
    entorno, _h, doc = caso

    def _mutar(crudo):
        crudo["fuentes"] = {"case_id": entorno["case"].id}
        crudo["fuentes_sha256"] = digest_de_fuentes(crudo["fuentes"])

    _reescribir(entorno, doc, _mutar)
    codigos = _codigos(entorno, doc)
    assert "procedencia_no_casa" in codigos
    # El hash del documento cubre el digest, así que además deja de casar.
    assert "contenido_alterado" in codigos


def test_recalcular_tambien_el_hash_del_documento_no_basta(caso) -> None:
    """Se rehacen manifiesto, digest y hash del documento de forma coherente. Lo
    que no se puede rehacer sin romper la cadena es el ancla del audit."""
    entorno, _h, doc = caso

    def _mutar(crudo):
        crudo["fuentes"] = {"case_id": entorno["case"].id}
        crudo["fuentes_sha256"] = digest_de_fuentes(crudo["fuentes"])
        crudo["sha256"] = _content_sha256(crudo)

    _reescribir(entorno, doc, _mutar)
    codigos = _codigos(entorno, doc)
    # El contenido vuelve a verificar contra su propio hash local...
    assert entorno["documents"].verify(entorno["case"].id, doc.id)["ok"] is True
    # ...y aun así no se aprueba: el ancla dice otra cosa.
    assert "ancla_no_casa" in codigos
    assert "procedencia_no_casa" in codigos


def test_el_digest_esta_anclado_en_el_audit_al_crear_el_documento(caso) -> None:
    entorno, _h, doc = caso
    ancla = next(
        e for e in entorno["audit"].entries()
        if e.get("action") == "document_created" and e.get("document_id") == doc.id
    )
    assert ancla["fuentes_sha256"] == doc.fuentes_sha256
    assert ancla["sha256"] == doc.sha256


def test_el_hash_del_documento_cubre_su_identidad(caso) -> None:
    """Dos documentos con el mismo texto NO tienen el mismo hash: si lo tuvieran,
    el acta de aprobación de uno serviría para el otro (RA04 f)."""
    entorno, h, doc = caso
    gemelo = informe(entorno, h, titulo=doc.title)
    assert gemelo.title == doc.title
    assert gemelo.sha256 != doc.sha256


def test_un_documento_integro_con_su_snapshot_se_aprueba(caso) -> None:
    """El recorrido válido sigue funcionando: una solución que bloquease todo no
    sería una solución."""
    entorno, _h, doc = caso
    comprobacion = _checks(entorno, doc)
    assert comprobacion.aprobable, [b.mensaje for b in comprobacion.bloqueos]
    assert comprobacion.procedencia["digest_actual"] == doc.fuentes_sha256
    assert comprobacion.procedencia["digest_anclado"] == doc.fuentes_sha256
    assert aprobar(entorno, doc).status == "final"
