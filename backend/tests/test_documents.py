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
from dataclasses import asdict

import pytest

from agentopsy.audit.log import AuditLog
from agentopsy.cases import CaseManager
from agentopsy.reports import pdf as pdf_mod
from agentopsy.reports.pdf import render_pdf
from agentopsy.reports.store import Document, DocumentStore
from agentopsy.reports.svg import PAPEL, SVG_NS, Figura


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



# ── figuras (anexo C) ─────────────────────────────────────────────────────────
#
# El bloque `figure` lleva un SVG que la web pinta como imagen y el PDF imprime
# como vector. Un documento también se crea por `POST …/documents` con el cuerpo
# que se quiera, así que el almacén solo admite el vocabulario que Agentopsy
# dibuja, y el PDF lo vuelve a comprobar antes de imprimir.

_SVG_HOSTIL = (
    f'<svg xmlns="{SVG_NS}" width="10" height="10" viewBox="0 0 10 10">'
    '<image href="file:///etc/passwd" width="10" height="10"/></svg>'
)


def _svg_de_prueba(alto: float = 320.0) -> str:
    figura = Figura(840, alto)
    figura.texto(32, 40, "FIGURA-DE-PRUEBA", tamano=15, color=PAPEL["tinta"], negrita=True)
    figura.linea(32, 60, 808, 60, stroke=PAPEL["filete"], grosor=1)
    figura.circulo(252, 100, 5, fill=PAPEL["acento"])
    figura.poligono([(10, 10), (20, 10), (15, 20)], fill="#6b4bab")
    figura.rect(100, 100, 50, 20, stroke=PAPEL["filete"], grosor=0.8, trazo="3 3")
    figura.texto(420, alto - 20, "pie · con acento", tamano=12, color=PAPEL["apagado"],
                 mono=True, ancla="middle", espaciado=0.6)
    return figura.svg()


def _figura(**cambios) -> dict:
    bloque = {
        "t": "figure", "kind": "incident_timeline",
        "title": "Línea de tiempo del incidente", "svg": _svg_de_prueba(),
    }
    bloque.update(cambios)
    return bloque


def _anexo(*bloques) -> list[dict]:
    return [{"num": "C", "title": "Anexo: Figuras del caso", "blocks": list(bloques)}]


def test_a_figure_is_stored_under_the_content_hash(tmp_case) -> None:
    cases, case_id = tmp_case
    store = DocumentStore(cases)
    doc = store.create(case_id, _payload(sections=_anexo(_figura())))
    assert store.verify(case_id, doc.id)["ok"] is True

    # Retocar el dibujo en disco rompe la integridad: la figura es contenido.
    path = cases.case_dir(case_id) / "documents" / f"{doc.id}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    bloque = data["sections"][0]["blocks"][0]
    bloque["svg"] = bloque["svg"].replace("FIGURA-DE-PRUEBA", "OTRA-FIGURA")
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    assert store.verify(case_id, doc.id)["ok"] is False


@pytest.mark.parametrize(
    ("cambio", "motivo"),
    [
        ({"kind": "grafico_de_tarta"}, "kind"),
        ({"title": "   "}, "title"),
        ({"leyenda": "sobra"}, "unknown keys"),
        ({"svg": _SVG_HOSTIL}, "not allowed"),
        ({"svg": None}, "non-empty string"),
    ],
)
def test_a_figure_block_outside_its_contract_is_rejected(tmp_case, cambio, motivo) -> None:
    cases, case_id = tmp_case
    with pytest.raises(ValueError, match=motivo):
        DocumentStore(cases).create(case_id, _payload(sections=_anexo(_figura(**cambio))))


def test_the_pdf_prints_the_figure_as_vector_with_real_text(tmp_case) -> None:
    cases, case_id = tmp_case
    doc = DocumentStore(cases).create(case_id, _payload(sections=_anexo(_figura())))
    hojas = _texto_por_pagina(render_pdf(doc))
    assert any("FIGURA-DE-PRUEBA" in hoja for hoja in hojas)


def test_the_pdf_checks_the_figure_again_before_printing_it(tmp_case) -> None:
    """Lo que se imprime es lo que hay en disco AHORA, no lo que el almacén
    aceptó al crear: un SVG hostil no llega a fpdf2, que leería el fichero."""
    cases, case_id = tmp_case
    doc = DocumentStore(cases).create(case_id, _payload(sections=_anexo(_figura())))
    manipulado = Document(**{**asdict(doc), "sections": _anexo(_figura(svg=_SVG_HOSTIL))})
    with pytest.raises(ValueError, match="not allowed"):
        render_pdf(manipulado)


def test_a_heading_that_opens_a_figure_travels_with_it(tmp_case) -> None:
    """El rótulo de una figura no se queda al pie de una hoja con la figura en
    la siguiente: se reserva la figura entera, no un par de líneas."""
    cases, case_id = tmp_case
    store = DocumentStore(cases)
    for relleno in range(4, 40, 3):
        doc = store.create(case_id, _payload(sections=_anexo(
            {"t": "p", "text": "Relleno de cuerpo. " * relleno * 10},
            {"t": "h3", "text": "C.1 ROTULO-DE-FIGURA"},
            _figura(svg=_svg_de_prueba(alto=1100.0)),
        )))
        for hoja in _texto_por_pagina(render_pdf(doc)):
            if "ROTULO-DE-FIGURA" in hoja:
                assert "FIGURA-DE-PRUEBA" in hoja, f"relleno {relleno}"


def test_a_figure_counts_about_a_page_in_the_estimate(tmp_case) -> None:
    cases, case_id = tmp_case
    store = DocumentStore(cases)
    sin = store.create(case_id, _payload(sections=_anexo({"t": "p", "text": "x"})))
    con = store.create(case_id, _payload(
        sections=_anexo({"t": "p", "text": "x"}, _figura(), _figura()),
    ))
    assert con.page_count == sin.page_count + 2


def test_a_figure_heading_is_not_orphaned_even_by_a_millimetre() -> None:
    """Barrido fino alrededor del punto en el que el rótulo y la figura dejan de
    caber juntos: en ningún arranque el rótulo se queda en una hoja y la figura
    en la siguiente. La reserva del rótulo contaba un milímetro de menos (su aire
    de abajo), y justo en ese milímetro la figura saltaba sola."""
    figura = _figura(svg=_svg_de_prueba(alto=600.0))
    rotulo = {"t": "h3", "text": "C.1 ROTULO-DE-FIGURA"}
    huerfanos = []
    for decimas in range(1600, 1720, 2):
        pdf = pdf_mod._Report(orientation="P", unit="mm", format="A4")
        pdf.set_margins(
            left=pdf_mod.MARGEN_LATERAL_MM,
            top=pdf_mod.MARGEN_SUPERIOR_MM,
            right=pdf_mod.MARGEN_LATERAL_MM,
        )
        pdf.set_auto_page_break(auto=True, margin=pdf_mod.MARGEN_INFERIOR_MM)
        pdf.add_page()
        pdf.set_y(decimas / 10)
        pdf_mod._block(pdf, rotulo, figura)
        hoja_del_rotulo = pdf.page
        pdf_mod._block(pdf, figura, None)
        if pdf.page != hoja_del_rotulo:
            huerfanos.append(decimas / 10)
    assert not huerfanos, f"rotulo huerfano arrancando en y = {huerfanos}"
