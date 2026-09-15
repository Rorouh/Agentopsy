"""Las figuras del anexo C del informe pericial (``agentopsy.reports.figuras``).

Los gates que importan:

- Las figuras se DIBUJAN con los datos del caso y se congelan en el documento:
  mismo caso, mismo SVG, byte a byte.
- El SVG solo lleva el vocabulario que Agentopsy dibuja. El texto de la
  evidencia viaja escapado, y la lista blanca rechaza todo lo demás (una imagen
  externa, un script, un DOCTYPE), porque el PDF lo imprime en el servidor.
- La línea de tiempo se trocea en EVENTOS ENTEROS que caben en una hoja, y lo
  que no se sitúa en el eje se declara en la última parte.
- El grafo es la MISMA composición que la vista Grafos, y su leyenda enumera todo
  lo que se pinta.
- Nada se omite en silencio: sin eventos, sin grafos o con hallazgos por extraer,
  el anexo lo dice.
- La paleta es de papel en cualquier tema: la del PDF, y los colores semánticos
  del cliente en claro.
"""

from __future__ import annotations

import hashlib
import re
import uuid
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentopsy.cases.manager import CaseManager
from agentopsy.findings.store import FindingStore
from agentopsy.graph.figura import figura_del_caso
from agentopsy.graph.store import GraphStore
from agentopsy.graph.vocabulario import NODO_COLOR, NODO_KEY, RELACION_COLOR, RELACION_KEY
from agentopsy.i18n import _LANG_ACTUAL, set_current_lang, t
from agentopsy.mitre.coverage import CoverageStore
from agentopsy.reports import pdf as pdf_mod
from agentopsy.reports import svg as svg_mod
from agentopsy.reports.figura_cronologia import ALTO_MAX_PARTE, marca_utc, svg_linea_de_tiempo
from agentopsy.reports.figura_grafo import svg_grafo_del_caso
from agentopsy.reports.figuras import componer_anexo, figuras_del_caso
from agentopsy.reports.indice import NUM_ANEXO_FIGURAS, titulos
from agentopsy.reports.pdf import render_pdf
from agentopsy.reports.store import DocumentStore
from agentopsy.reports.svg import (
    PAPEL,
    SEVERIDAD_PAPEL,
    SVG_NS,
    Figura,
    SvgNoAdmitido,
    ancho_de_texto,
    partir_en_lineas,
    rgb,
    svg_para_imprimir,
    validar_svg,
)
from agentopsy.timeline.hallazgos import assemble_findings_timeline

REPO_ROOT = Path(__file__).resolve().parents[2]
WEB_SRC = REPO_ROOT / "web" / "src"

CASO = "11111111-2222-4333-8444-555555555555"
F1 = "aaaaaaaa-0000-4000-8000-000000000001"
F2 = "aaaaaaaa-0000-4000-8000-000000000002"
F3 = "aaaaaaaa-0000-4000-8000-000000000003"
MOMENTO = "2026-09-15T10:00:00Z"


@pytest.fixture
def castellano():
    token = set_current_lang("es")
    yield
    _LANG_ACTUAL.reset(token)


@pytest.fixture
def ingles():
    token = set_current_lang("en")
    yield
    _LANG_ACTUAL.reset(token)


def _hallazgo(n: int, **cambios):
    base = {
        "id": f"{n:08x}-0000-4000-8000-000000000000",
        "title": f"Hallazgo numero {n}",
        "severity": "high",
        "observed_at": f"2021-03-{1 + n % 28:02d}T10:{n % 60:02d}:00Z",
        "evidence_id": None,
        "run_id": None,
        "mitre_hints": [],
    }
    base.update(cambios)
    return SimpleNamespace(**base)


def _grafos():
    """Una red de dos entidades y dos entidades sueltas, una de ellas de un tipo
    (dominio) que solo aparece en la banda."""
    return [
        SimpleNamespace(
            finding_id=F1,
            nodos=[
                {"tipo": "user", "valor": "IEUser"},
                {"tipo": "file", "valor": "key.exe"},
                {"tipo": "hostname", "valor": "WIN7-PC"},
            ],
            relaciones=[{"origen": "IEUser", "destino": "key.exe", "tipo": "process_spawn"}],
        ),
        SimpleNamespace(
            finding_id=F2, nodos=[{"tipo": "domain", "valor": "modern.ie"}], relaciones=[]
        ),
    ]


def _anexo(hallazgos=None, grafos=None, finding_ids=None):
    hallazgos = [_hallazgo(i) for i in range(3)] if hallazgos is None else hallazgos
    return componer_anexo(
        case_id=CASO,
        case_name="Murcielago",
        compuesta_en=MOMENTO,
        cronologia=assemble_findings_timeline(hallazgos, {}),
        grafos=_grafos() if grafos is None else grafos,
        finding_ids=[F1, F2] if finding_ids is None else finding_ids,
    )


def _textos(svg: str) -> list[str]:
    return [el.text or "" for el in ET.fromstring(svg).iter(f"{{{SVG_NS}}}text")]


def _figuras(anexo) -> list[dict]:
    return [b for b in anexo.seccion["blocks"] if b["t"] == "figure"]


# ── escritura y lista blanca ──────────────────────────────────────────────────


def test_evidence_text_travels_escaped_and_never_as_markup() -> None:
    hostil = '</text><image href="file:///etc/passwd"/><text>'
    figura = Figura(100, 50)
    figura.texto(10, 20, hostil, tamano=12, color=PAPEL["tinta"])
    svg = figura.svg()

    validar_svg(svg)
    assert _textos(svg) == [hostil]
    assert "<image" not in svg


def test_a_control_character_in_the_evidence_does_not_break_the_figure() -> None:
    figura = Figura(100, 50)
    figura.texto(10, 20, "ruta\x00con\x1bcontrol", tamano=12, color=PAPEL["tinta"])
    validar_svg(figura.svg())
    assert _textos(figura.svg()) == ["ruta\ufffdcon\ufffdcontrol"]


def test_a_line_never_outgrows_its_width_and_no_character_is_lost() -> None:
    texto = (
        "C:\\Users\\IEUser\\AppData\\Local\\Temp\\" + "a" * 120
        + " y despues unas palabras normales que se parten por espacios"
    )
    lineas = partir_en_lineas(texto, 200, 12)
    assert len(lineas) > 1
    assert all(ancho_de_texto(linea, 12) <= 200 for linea in lineas)
    assert "".join(lineas).replace(" ", "") == texto.replace(" ", "")


def test_text_is_measured_with_the_metrics_the_pdf_prints_with() -> None:
    """Helvetica no es monoespaciada: una línea de «W» no mide lo que una de «i»,
    y partir por número de caracteres desbordaría con las mayúsculas."""
    assert ancho_de_texto("WWWW", 12) > 2 * ancho_de_texto("iiii", 12)
    assert ancho_de_texto("WWWW", 12, mono=True) == ancho_de_texto("iiii", 12, mono=True)


_CABEZA = f'<svg xmlns="{SVG_NS}" width="10" height="10" viewBox="0 0 10 10">'


@pytest.mark.parametrize(
    "fuente",
    [
        _CABEZA + '<image href="file:///etc/passwd" width="10" height="10"/></svg>',
        _CABEZA + "<script>alert(1)</script></svg>",
        '<!DOCTYPE svg [<!ENTITY a "b">]>' + _CABEZA + '<text x="1" y="1">&a;</text></svg>',
        _CABEZA + '<rect x="0" y="0" width="1" height="1" onload="alert(1)"/></svg>',
        _CABEZA + '<rect x="0" y="0" width="1" height="1" style="fill:red"/></svg>',
        _CABEZA + '<rect x="0" y="0" width="1" height="1" fill="url(#x)"/></svg>',
        _CABEZA + '<text x="1" y="1"><tspan>a</tspan></text></svg>',
        _CABEZA + f'<svg xmlns="{SVG_NS}" width="1" height="1" viewBox="0 0 1 1"></svg></svg>',
        _CABEZA
        + '<rect xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="x" '
        'x="0" y="0" width="1" height="1"/></svg>',
        _CABEZA + 'suelto<rect x="0" y="0" width="1" height="1"/></svg>',
        _CABEZA + "<!-- nota --></svg>",
        '<?xml version="1.0"?>' + _CABEZA + "</svg>",
        _CABEZA
        + '<foreignObject><div xmlns="http://www.w3.org/1999/xhtml">a</div>'
        "</foreignObject></svg>",
        _CABEZA + '<text x="1" y="1" font-family="Comic Sans MS">a</text></svg>',
        f'<g xmlns="{SVG_NS}"></g>',
        '<svg width="10" height="10" viewBox="0 0 10 10"></svg>',
        f'<svg xmlns="{SVG_NS}" width="10" height="10" viewBox="0 0 20 20"></svg>',
        f'<svg xmlns="{SVG_NS}" width="10" height="10"></svg>',
        f'<svg xmlns="{SVG_NS}" width="0" height="10" viewBox="0 0 0 10"></svg>',
        _CABEZA + "<rect",
        # Lo que fpdf2 no sabría imprimir aunque no sea peligroso:
        _CABEZA + '<rect x="\u0663" y="0" width="1" height="1" fill="#ffffff"/></svg>',
        f'<svg xmlns="{SVG_NS}" width="\uff11\uff10" height="10" viewBox="0 0 \uff11\uff10 10"></svg>',
        f'<svg xmlns="{SVG_NS}" width="{"9" * 400}" height="10" viewBox="0 0 {"9" * 400} 10"></svg>',
        f'<svg xmlns="{SVG_NS}" width="200000" height="10" viewBox="0 0 200000 10"></svg>',
        _CABEZA + '<line stroke="#000000" stroke-width="1"/></svg>',
        _CABEZA + '<rect x="0" y="0" width="1" height="1"/></svg>',
        f'<svg\nxmlns="{SVG_NS}" width="10" height="10" viewBox="0 0 10 10"></svg>',
        _CABEZA
        + '<rect x="0" y="0" width="1" height="1" fill="#ffffff">'
        '<circle cx="1" cy="1" r="1" fill="#ffffff"/></rect></svg>',
        "",
        None,
    ],
)
def test_only_the_drawing_vocabulary_of_agentopsy_passes(fuente) -> None:
    with pytest.raises(SvgNoAdmitido):
        validar_svg(fuente)


def test_a_rejection_does_not_echo_megabytes_back() -> None:
    enorme = "9" * 100_000
    with pytest.raises(SvgNoAdmitido) as exc:
        validar_svg(f'<svg xmlns="{SVG_NS}" width="{enorme}" height="1" viewBox="0 0 1 1"></svg>')
    assert len(str(exc.value)) < 300


def test_what_reaches_the_pdf_is_rewritten_so_transliteration_cannot_break_it() -> None:
    """La transliteración del PDF convierte «←» en «<-»: aplicada a la cadena,
    dejaría un «<» sin escapar dentro de un texto y un XML que fpdf2 no lee."""
    from agentopsy.reports.pdf import _s

    figura = Figura(200, 50)
    figura.texto(10, 20, "payload.bin ← 185.10.10.10 & C2 € «x»", tamano=12, color=PAPEL["tinta"])
    salida, ancho, alto = svg_para_imprimir(figura.svg(), _s)

    assert (ancho, alto) == (200.0, 50.0)
    validar_svg(salida)
    assert _textos(salida) == ["payload.bin <- 185.10.10.10 & C2 ? «x»"]
    # Una referencia numérica llega resuelta y también se translitera.
    con_referencia = figura.svg().replace("C2", "&#8364;")
    (texto,) = _textos(svg_para_imprimir(con_referencia, _s)[0])
    assert "?" in texto and "\u20ac" not in texto


def test_an_absurdly_large_figure_is_rejected(monkeypatch) -> None:
    monkeypatch.setattr(svg_mod, "MAX_CARACTERES_SVG", 200)
    figura = Figura(100, 50)
    for i in range(10):
        figura.texto(10, 20, f"linea {i}", tamano=12, color=PAPEL["tinta"])
    with pytest.raises(ValueError, match="characters"):
        validar_svg(figura.svg())


# ── paleta ────────────────────────────────────────────────────────────────────


def test_the_pdf_takes_its_colours_from_the_paper_palette() -> None:
    """Una sola fuente de color: el texto del informe y sus figuras no divergen."""
    assert pdf_mod._INK == rgb(PAPEL["tinta"])
    assert pdf_mod._BODY == rgb(PAPEL["cuerpo"])
    assert pdf_mod._MUTED == rgb(PAPEL["apagado"])
    assert pdf_mod._FAINT == rgb(PAPEL["tenue"])
    assert pdf_mod._RULE == rgb(PAPEL["filete"])
    assert pdf_mod._SURFACE == rgb(PAPEL["superficie"])
    assert pdf_mod._ACCENT == rgb(PAPEL["acento"])
    assert pdf_mod._SEV_COLOR == {s: rgb(c) for s, c in SEVERIDAD_PAPEL.items()}
    assert PAPEL["fondo"] == "#ffffff"


def test_every_figure_is_painted_on_white_paper(castellano) -> None:
    """El fondo de la figura no sale del tema de la interfaz: es blanco siempre."""
    for figura in _figuras(_anexo()):
        primero = next(iter(ET.fromstring(figura["svg"])))
        assert primero.tag == f"{{{SVG_NS}}}rect"
        assert primero.attrib["fill"] == "#ffffff"
        ancho, alto = validar_svg(figura["svg"])
        assert (float(primero.attrib["width"]), float(primero.attrib["height"])) == (ancho, alto)


def _colores_claros(ts: str, tabla: str) -> dict[str, str]:
    bloque = ts.split(f"const {tabla}")[1].split("};")[0]
    return dict(re.findall(r'(\w+): \{ claro: "(#[0-9a-f]{6})"', bloque))


def test_the_semantic_colours_are_the_light_ones_of_the_client() -> None:
    ts = (WEB_SRC / "pages" / "graphs" / "vocabulario.ts").read_text(encoding="utf-8")
    assert _colores_claros(ts, "NODO_COLOR") == NODO_COLOR
    assert _colores_claros(ts, "RELACION_COLOR") == RELACION_COLOR


@pytest.mark.parametrize("lang", ["es", "en"])
def test_the_type_labels_are_the_ones_the_client_shows(lang: str) -> None:
    ts = (WEB_SRC / "i18n" / f"{lang}.ts").read_text(encoding="utf-8")
    web = dict(re.findall(r'"(graph(?:Node|Edge)\.\w+)": "([^"]+)"', ts))
    for clave in [*NODO_KEY.values(), *RELACION_KEY.values()]:
        assert t(clave, lang) == web[clave], clave


# ── línea de tiempo ───────────────────────────────────────────────────────────


def test_the_timestamp_keeps_the_format_and_the_zone_of_the_view() -> None:
    assert marca_utc("2021-04-01T15:32:11Z") == "01/04/2021, 15:32:11 (UTC)"


def test_a_long_timeline_is_split_in_whole_events_that_fit_a_page(castellano) -> None:
    hallazgos = [
        _hallazgo(i, title=f"Evento {i:02d} " + "con un titulo bastante largo " * (i % 4))
        for i in range(40)
    ]
    linea = svg_linea_de_tiempo(
        assemble_findings_timeline(hallazgos, {}), case_name="Caso", compuesta_en=MOMENTO
    )
    assert len(linea.partes) > 1

    vistos: list[str] = []
    for parte in linea.partes:
        _ancho, alto = validar_svg(parte)
        assert alto <= ALTO_MAX_PARTE
        vistos += [m for texto in _textos(parte) for m in re.findall(r"Evento \d\d", texto)]
    # Cada evento aparece UNA vez: ni se pierde ni se reparte entre dos partes.
    assert sorted(vistos) == sorted(f"Evento {i:02d}" for i in range(40))
    # Y lo que quedó fuera del eje se declara solo al final.
    fuera = t("figure.rail.outside")
    assert [fuera in _textos(p) for p in linea.partes] == (
        [False] * (len(linea.partes) - 1) + [True]
    )


def test_each_part_of_the_timeline_says_which_part_it_is(castellano) -> None:
    anexo = _anexo(hallazgos=[_hallazgo(i) for i in range(60)])
    partes = [f for f in _figuras(anexo) if f["kind"] == "incident_timeline"]
    total = len(partes)
    assert total > 1
    for numero, parte in enumerate(partes, 1):
        titulo = t("figure.rail.titlePart", part=numero, parts=total)
        assert parte["title"] == titulo
        assert titulo in _textos(parte["svg"])


def test_what_cannot_be_placed_on_the_axis_is_declared_inside_the_figure(castellano) -> None:
    hallazgos = [
        _hallazgo(1),
        _hallazgo(2, observed_at=None),
        _hallazgo(3, observed_at="ayer por la tarde"),
    ]
    (parte,) = svg_linea_de_tiempo(
        assemble_findings_timeline(hallazgos, {}), case_name="Caso", compuesta_en=MOMENTO
    ).partes
    texto = " ".join(_textos(parte))
    assert t("figure.rail.outside") in texto
    assert t("figure.rail.noObservedAt", count=1) in texto
    assert t("figure.rail.unparseable", count=1) + ": ayer por la tarde" in texto


def test_the_titles_in_the_figure_follow_the_report_typography(castellano) -> None:
    hallazgos = [_hallazgo(1, title="Persistencia — tarea programada ✅")]
    linea = svg_linea_de_tiempo(
        assemble_findings_timeline(hallazgos, {}), case_name="Caso", compuesta_en=MOMENTO
    )
    texto = " ".join(_textos(linea.partes[0]))
    assert "—" not in texto and "✅" not in texto
    assert "Persistencia, tarea programada" in texto
    assert linea.titulos_normalizados == 1


def test_the_techniques_of_an_event_travel_with_it(castellano) -> None:
    hallazgos = [_hallazgo(1, mitre_hints=["T1055"])]
    (parte,) = svg_linea_de_tiempo(
        assemble_findings_timeline(hallazgos, {}), case_name="Caso", compuesta_en=MOMENTO
    ).partes
    assert any(texto.startswith("T1055") for texto in _textos(parte))


# ── grafo ─────────────────────────────────────────────────────────────────────


def test_the_graph_figure_paints_the_view_composition_and_names_all_of_it(castellano) -> None:
    figura = figura_del_caso(CASO, _grafos())
    svg = svg_grafo_del_caso(figura, case_name="Murcielago", compuesta_en=MOMENTO)
    validar_svg(svg)
    textos = _textos(svg)

    for valor in ("IEUser", "key.exe", "WIN7-PC", "modern.ie"):
        assert valor in textos
    # Los tipos que SOLO aparecen en la banda también tienen su leyenda.
    assert t("graphNode.domain") in textos
    assert t("graphNode.hostname") in textos
    assert t("graphEdge.process_spawn") in textos
    assert t("figure.graph.inventoryBand", count=2) in textos
    # Y el aviso de que es una propuesta del modelo va DENTRO, entero.
    assert t("graph.proposalNotice") in " ".join(textos)


def test_without_a_network_the_band_is_not_drawn_under_an_empty_canvas(castellano) -> None:
    solo_sueltas = [
        SimpleNamespace(finding_id=F1, nodos=[{"tipo": "user", "valor": "IEUser"}], relaciones=[])
    ]
    figura = figura_del_caso(CASO, solo_sueltas)
    assert figura["nodos"] == [] and figura["inventario"]["total"] == 1

    svg = svg_grafo_del_caso(figura, case_name="Caso", compuesta_en=MOMENTO)
    _ancho, alto = validar_svg(svg)
    assert alto < figura["inventario"]["lienzo"]["alto"]
    (disco,) = ET.fromstring(svg).iter(f"{{{SVG_NS}}}circle")
    assert 0 < float(disco.attrib["cy"]) < alto


def test_a_graph_figure_needs_at_least_one_entity() -> None:
    with pytest.raises(ValueError):
        svg_grafo_del_caso(figura_del_caso(CASO, []), case_name="Caso", compuesta_en=MOMENTO)


def test_the_figures_speak_the_language_of_the_report(castellano) -> None:
    textos_es = [x for f in _figuras(_anexo()) for x in _textos(f["svg"])]
    assert "Fuera del eje" in textos_es and "EQ" in textos_es and "RELACIONES" in textos_es

    token = set_current_lang("en")
    try:
        textos_en = [x for f in _figuras(_anexo()) for x in _textos(f["svg"])]
    finally:
        _LANG_ACTUAL.reset(token)
    assert "Outside the axis" in textos_en and "HST" in textos_en and "RELATIONS" in textos_en
    assert "Process creation" in textos_en


# ── el anexo ──────────────────────────────────────────────────────────────────


def test_the_annex_takes_its_number_and_title_from_the_index(castellano) -> None:
    anexo = _anexo()
    assert anexo.seccion["num"] == NUM_ANEXO_FIGURAS == "C"
    assert anexo.seccion["title"] == titulos()["C"]
    assert [f["kind"] for f in _figuras(anexo)] == ["incident_timeline", "case_graph"]


def test_the_same_case_draws_the_same_figures_byte_for_byte(castellano) -> None:
    assert _anexo().seccion == _anexo().seccion


def test_without_events_on_the_axis_the_annex_says_why(castellano) -> None:
    hallazgos = [_hallazgo(1, observed_at=None)]
    anexo = _anexo(hallazgos=hallazgos)
    mensaje = assemble_findings_timeline(hallazgos, {})["message"]
    assert mensaje
    assert {"t": "p", "text": mensaje} in anexo.seccion["blocks"]
    assert [f["kind"] for f in _figuras(anexo)] == ["case_graph"]


def test_without_graphs_the_annex_says_where_they_are_extracted(castellano) -> None:
    anexo = _anexo(grafos=[], finding_ids=[F1])
    assert {"t": "p", "text": t("figure.graph.none")} in anexo.seccion["blocks"]
    assert [f["kind"] for f in _figuras(anexo)] == ["incident_timeline"]


def test_graphs_that_name_no_entity_are_not_mistaken_for_missing_ones(castellano) -> None:
    vacio = [SimpleNamespace(finding_id=F1, nodos=[], relaciones=[])]
    anexo = _anexo(grafos=vacio, finding_ids=[F1])
    assert {"t": "p", "text": t("figure.graph.empty", count=1)} in anexo.seccion["blocks"]


def test_findings_without_a_graph_are_counted_in_the_annex(castellano) -> None:
    anexo = _anexo(finding_ids=[F1, F2, F3])
    assert {
        "t": "p", "text": t("figure.graph.pending", pending=1, total=3)
    } in anexo.seccion["blocks"]


def test_the_audit_summary_names_each_figure_by_the_hash_of_its_drawing(castellano) -> None:
    anexo = _anexo()
    resumen = anexo.resumen_auditable()
    assert [r["kind"] for r in resumen] == ["incident_timeline", "case_graph"]
    for entrada, figura in zip(resumen, _figuras(anexo), strict=True):
        assert entrada["sha256"] == hashlib.sha256(figura["svg"].encode("utf-8")).hexdigest()
        assert entrada["chars"] == len(figura["svg"])


def test_the_annex_of_a_real_case_is_read_from_its_stores_and_printed(
    tmp_path, castellano
) -> None:
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create(name="Murcielago", examiner="ramos", os_profile="windows")
    findings = FindingStore(cases)
    hallazgo = findings.append(case.id, {
        "title": "Ejecucion de key.exe desde el Escritorio de IEUser",
        "summary": "IEUser ejecuta key.exe desde su Escritorio.",
        "severity": "critical", "run_id": str(uuid.uuid4()),
        "artifact_sha256": "a" * 64, "tool_id": "volatility3",
        "observed_at": "2021-03-23T19:08:10Z", "mitre_hints": ["T1055"],
    })
    graphs = GraphStore(cases)
    graphs.save(case.id, hallazgo.id, {
        "nodos": [{"tipo": "user", "valor": "IEUser"}, {"tipo": "file", "valor": "key.exe"}],
        "relaciones": [{"origen": "IEUser", "destino": "key.exe", "tipo": "process_spawn"}],
    })

    # Una flecha en el título, que la transliteración del PDF convierte en «<-».
    findings.append(case.id, {
        "title": "Descarga de payload.bin ← 185.10.10.10 (servidor C2)",
        "summary": "WIN7-PC descarga payload.bin desde 185.10.10.10.",
        "severity": "high", "run_id": str(uuid.uuid4()),
        "artifact_sha256": "b" * 64, "tool_id": "volatility3",
        "observed_at": "2021-03-23T19:10:00Z",
    })

    anexo = figuras_del_caso(
        case.id, cases=cases, findings=findings, graphs=graphs,
        coverage=CoverageStore(cases, findings),
    )
    assert [f["kind"] for f in _figuras(anexo)] == ["incident_timeline", "case_graph"]

    documentos = DocumentStore(cases)
    doc = documentos.create(case.id, {
        "title": "Informe pericial", "type": "pericial", "sections": [anexo.seccion],
    })
    assert documentos.verify(case.id, doc.id)["ok"] is True
    pdf = render_pdf(doc)
    assert pdf[:5] == b"%PDF-"
    assert b"payload.bin <- 185.10.10.10" in b"".join(
        zlib.decompress(m.group(1)) for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", pdf, re.S)
        if m.group(1)[:1] == b"x"
    )
