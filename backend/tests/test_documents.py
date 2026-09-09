"""Almacén de documentos + integridad + aprobación + PDF pericial.

Los gates que importan: el SHA-256 es real y verificable; aprobar no invalida el
hash (cambia estado, no contenido); un final no se borra (cadena de custodia);
crear, aprobar y eliminar quedan en el audit hash-encadenado; el PDF sale bien
formado. RULE 2: caso sin docs a []; id inexistente a KeyError.

Y los de F04: un documento ALTERADO no se aprueba, ni siquiera si ya figuraba
como final; aprobar exige declarar la revisión exacta que se revisó; el
manifiesto de fuentes es obligatorio para aprobar; y el PDF de un documento que
no supera sus comprobaciones sale marcado como borrador, no como si fuera válido.
"""

from __future__ import annotations

import re
import zlib

import pytest
from _informe import aprobar as _aprobar_caso, hallazgo, informe, montar_caso

from agentopsy.audit.log import AuditLog
from agentopsy.cases import CaseManager
from agentopsy.reports.pdf import render_pdf
from agentopsy.reports.store import DocumentStore


@pytest.fixture
def tmp_case(tmp_path) -> tuple[CaseManager, str]:
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Murcielago", examiner="ramos", os_profile="windows")
    return cases, case.id


@pytest.fixture
def aprobable(tmp_path):
    """Un caso con evidencia, ejecución, hallazgo e informe: aprobable de verdad.

    Los tests que APRUEBAN no pueden trabajar sobre un documento con el
    manifiesto vacío: desde la reauditoría de 2026-09-08 un informe sin un solo
    hallazgo detrás no se aprueba, y eso es lo correcto. El resto de tests de
    este fichero (hash, listado, PDF, traversal) siguen con ``tmp_case``, que es
    todo lo que necesitan.
    """
    caso = montar_caso(tmp_path, nombre="Murcielago")
    h = hallazgo(caso)
    return caso, informe(caso, h)


#: Un manifiesto de fuentes VACÍO pero presente: el documento declara que no se
#: apoya en ninguna evidencia, ejecución ni hallazgo, lo cual es cierto para
#: estos documentos sintéticos. Sin la clave no se podría aprobar, y con ella se
#: aprueba comprobando (que es el punto): declarar cero fuentes es distinto de
#: no declarar ninguna.
_SIN_FUENTES = {
    "case_id": "",
    "evidencias": [],
    "evidencias_sha256": {},
    "artefactos": [],
    "hallazgos": [],
    "limitaciones_exigidas": [],
}


def _aprobar(store, case_id: str, doc):
    """Aprueba declarando la revisión exacta, como hace la superficie."""
    return store.approve(
        case_id,
        doc.id,
        sha256_revisado=store.verify(case_id, doc.id)["recomputed_sha256"],
        revisor="Daniel Ramos Camargo",
    )


def _payload(**over):
    base = {
        "fuentes": dict(_SIN_FUENTES),
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


def test_signing_marks_final_without_breaking_integrity(aprobable) -> None:
    caso, doc = aprobable
    store, case_id = caso["documents"], caso["case"].id
    aprobado = _aprobar_caso(caso, doc, revisor="Daniel Ramos Camargo")
    assert aprobado.status == "final"
    # Aprobar cambia el estado, NO el contenido: el hash sigue válido.
    assert store.verify(case_id, doc.id)["ok"] is True
    assert aprobado.sha256 == doc.sha256
    # Y queda la traza del acto humano: quién, cuándo y sobre qué contenido.
    assert aprobado.approved_by == "Daniel Ramos Camargo"
    assert aprobado.approved_at
    assert aprobado.approved_sha256 == doc.sha256


def test_final_document_cannot_be_deleted(aprobable) -> None:
    caso, doc = aprobable
    _aprobar_caso(caso, doc)
    with pytest.raises(ValueError, match="chain of custody"):
        caso["documents"].delete(caso["case"].id, doc.id)


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


def test_create_and_actions_are_audited(aprobable) -> None:
    caso, doc = aprobable
    cases, case_id = caso["cases"], caso["case"].id
    _aprobar_caso(caso, doc, revisor="Daniel Ramos Camargo")
    log = AuditLog(cases.case_dir(case_id) / "audit.jsonl")
    assert log.verify()
    entradas = log.entries()
    actions = [e["action"] for e in entradas]
    assert "document_created" in actions
    assert "document_approved" in actions
    # La entrada de aprobación lleva quién, cuándo y el hash aprobado.
    aprobacion = next(e for e in entradas if e["action"] == "document_approved")
    assert aprobacion["approved_by"] == "Daniel Ramos Camargo"
    assert aprobacion["approved_sha256"] == doc.sha256


def test_pdf_is_well_formed(tmp_case) -> None:
    cases, case_id = tmp_case
    store = DocumentStore(cases)
    doc = store.create(case_id, _payload())
    pdf = render_pdf(doc)
    assert pdf[:5] == b"%PDF-"
    assert len(pdf) > 1500


# ── paginación del PDF ────────────────────────────────────────────────────────
#
# El defecto que fijan estos tests salió de un informe real: el PDF traía hojas
# con una sola columna de una tabla y nada más. La causa era que un bloque `kv`
# se dibujaba pareja a pareja, guardando la `y` de partida y volviendo a ella con
# `set_xy` para escribir el valor al lado de su clave. Cuando la clave disparaba
# el salto de página automático, la clave se pintaba ya en la hoja siguiente,
# pero el `set_xy` devolvía la `y` a su valor de la hoja ANTERIOR, cerca del pie,
# así que el valor disparaba OTRO salto y aterrizaba dos hojas más allá. Medido
# sobre el informe real del caso LoneWolf: 34 páginas con 5 casi vacías, que
# pasaron a 30 sin ninguna.

_MARCA_TEXTO = re.compile(r"\((.*?)\)\s*T[jJ]")
_FLUJO = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.S)

#: Por debajo de esto una hoja no tiene contenido PROPIO: la cabecera y el pie
#: que van en todas ya suman unos 100 caracteres.
_MINIMO_POR_PAGINA = 260


def _texto_por_pagina(pdf: bytes) -> list[str]:
    """El texto que lleva cada hoja, leído de los flujos de contenido.

    El corte del flujo se busca con una expresión regular sobre los bytes del
    PDF, así que de vez en cuando los datos COMPRIMIDOS contienen la secuencia
    ``endstream`` y el flujo sale truncado. Con ``decompress`` eso levantaba, se
    caía al camino del texto plano y la hoja se leía con cero caracteres: el
    test fallaba una vez de cada treinta y pico, sin que el PDF tuviera nada.

    ``decompressobj`` infla el prefijo que sí es válido, que es lo que este
    ayudante necesita: una lectura aproximada del texto de cada hoja para
    comprobar que no queda ninguna casi vacía. No es un lector de PDF y no
    pretende serlo.
    """
    hojas = []
    for m in _FLUJO.finditer(pdf):
        try:
            crudo = zlib.decompressobj().decompress(m.group(1))
        except zlib.error:
            crudo = m.group(1)
        hojas.append(" ".join(_MARCA_TEXTO.findall(crudo.decode("latin-1", "replace"))))
    return hojas


def _kv_largo(parejas: int) -> dict:
    """Un bloque `kv` lo bastante largo para cruzar varias veces el pie.

    Cada pareja lleva su propia marca en la clave y otra en el valor, que es lo
    que permite comprobar que las dos mitades de una fila caen en la misma hoja.
    """
    return {
        "t": "kv",
        "pairs": [
            {"k": f"CLAVE-{i:03d}", "v": f"VALOR-{i:03d} " + "texto de relleno " * (2 + i % 4)}
            for i in range(parejas)
        ],
    }


def test_a_key_value_row_is_never_split_across_two_pages(tmp_case) -> None:
    """Las dos mitades de una fila viajan SIEMPRE en la misma hoja.

    Es el gate del defecto. Antes de arreglarlo, dos de estas noventa filas
    quedaban partidas, y la hoja que recibía la clave huérfana no tenía nada
    más."""
    cases, case_id = tmp_case
    store = DocumentStore(cases)
    doc = store.create(case_id, _payload(
        sections=[{"num": "10", "title": "Recomendaciones", "blocks": [_kv_largo(90)]}],
    ))
    hojas = _texto_por_pagina(render_pdf(doc))

    pagina_clave: dict[int, int] = {}
    pagina_valor: dict[int, int] = {}
    for numero, hoja in enumerate(hojas, 1):
        for i in re.findall(r"CLAVE-(\d{3})", hoja):
            pagina_clave[int(i)] = numero
        for i in re.findall(r"VALOR-(\d{3})", hoja):
            pagina_valor[int(i)] = numero

    # Ninguna pareja se pierde por el camino, y ninguna se parte.
    assert len(pagina_clave) == 90
    assert len(pagina_valor) == 90
    partidas = [i for i, pag in pagina_clave.items() if pagina_valor.get(i) != pag]
    assert not partidas, f"filas partidas entre dos hojas: {partidas}"


def test_no_page_of_a_long_report_is_left_almost_empty(tmp_case) -> None:
    """Ninguna hoja sale con la cabecera, el pie y nada más.

    Es el síntoma tal y como se ve en el PDF, comprobado sobre un informe que
    mezcla los bloques que sí pueden quedarse a medias en un salto de página."""
    cases, case_id = tmp_case
    store = DocumentStore(cases)
    doc = store.create(case_id, _payload(
        sections=[
            {"num": str(n), "title": f"Apartado {n}", "blocks": [
                {"t": "p", "text": "Parrafo de contexto. " * 12},
                _kv_largo(11),
                {"t": "h3", "text": f"Subapartado {n}.1"},
                {"t": "finding", "sev": "high", "title": f"Hallazgo {n}",
                 "text": "Descripcion del hallazgo. " * 8},
                {"t": "table", "headers": ["a", "b"], "rows": [["x", "y"]] * 6},
            ]}
            for n in range(1, 9)
        ],
    ))
    flacas = [
        (numero, len(hoja))
        for numero, hoja in enumerate(_texto_por_pagina(render_pdf(doc)), 1)
        if len(hoja) < _MINIMO_POR_PAGINA
    ]
    assert not flacas, f"hojas casi vacias (pagina, caracteres): {flacas}"


def test_a_section_heading_is_never_the_last_thing_on_its_page(tmp_case) -> None:
    """Un rótulo se lleva consigo el arranque de su cuerpo.

    Un apartado que se titula al pie de una hoja y empieza en la siguiente
    obliga a volver atrás para saber de qué se estaba hablando, que es el mismo
    defecto de lectura que una fila partida."""
    cases, case_id = tmp_case
    store = DocumentStore(cases)
    # Longitudes crecientes: alguna deja el rótulo siguiente justo en el borde.
    doc = store.create(case_id, _payload(
        sections=[
            {"num": str(n), "title": f"Apartado {n} con titulo largo de verdad",
             "blocks": [{"t": "p", "text": "Relleno de cuerpo. " * (18 + n * 7)}]}
            for n in range(1, 16)
        ],
    ))
    for numero, hoja in enumerate(_texto_por_pagina(render_pdf(doc)), 1):
        for n in range(1, 16):
            rotulo = f"{n} - Apartado {n} con titulo largo de verdad"
            if rotulo not in hoja:
                continue
            # Detrás del rótulo tiene que quedar cuerpo, no solo el pie de página.
            despues = hoja.split(rotulo, 1)[1]
            assert len(despues) > 120, (
                f"el rotulo del apartado {n} se queda casi solo al pie de la pagina {numero}"
            )
