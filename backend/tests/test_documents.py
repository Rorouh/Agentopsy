"""Almacén de documentos + integridad + PDF pericial.

Los gates que importan: el SHA-256 es real y verificable; firmar no invalida el
hash (cambia estado, no contenido); un final no se borra (cadena de custodia);
crear/firmar/eliminar quedan en el audit hash-encadenado; el PDF sale bien
formado. RULE 2: caso sin docs → []; id inexistente → KeyError.
"""

from __future__ import annotations

import json
import re
import zlib

import pytest

from agentopsy.audit.log import AuditLog
from agentopsy.cases import CaseManager
from agentopsy.reports.pdf import render_pdf
from agentopsy.reports.store import DocumentStore


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
    """El texto que lleva cada hoja, leído de los flujos de contenido."""
    hojas = []
    for m in _FLUJO.finditer(pdf):
        try:
            crudo = zlib.decompress(m.group(1))
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
