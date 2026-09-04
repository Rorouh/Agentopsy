"""Render de un ``Document`` a PDF real con fpdf2, siguiendo la lógica del
**informe pericial** de Agentopsy (portada + metadata, índice, secciones
numeradas H2/H3, tablas, hallazgos con severidad, citas y listas, con
cabecera/pie por página). fpdf2 es pure-python (sin libs de sistema).

Usa las fuentes core (latin-1): la tipografía unicode del contenido (— … · → ✓)
se normaliza antes de escribir; los acentos españoles sí están en latin-1.
"""

from __future__ import annotations

from typing import Any

from fpdf import FPDF
from fpdf.fonts import FontFace

from forensia.i18n import t
from forensia.reports.store import Document

_INK = (20, 23, 29)       # #14171d
_BODY = (43, 48, 57)      # #2b3039
_MUTED = (91, 98, 109)    # #5b626d
_FAINT = (144, 150, 160)  # #9096a0
_RULE = (227, 230, 234)   # #e3e6ea
_SURFACE = (247, 248, 250)  # #f7f8fa
_ACCENT = (163, 39, 31)   # #a3271f (rojo pericial)

_SEV_COLOR = {
    "critical": (163, 39, 31), "high": (163, 39, 31),
    "medium": (138, 90, 12), "low": (90, 100, 112),
}
_SEV_LABEL = {"critical": "Critico", "high": "Alto", "medium": "Medio", "low": "Bajo"}

_PUNCT = {
    "—": "-", "–": "-", "…": "...", "·": "-", "•": "-",
    "“": '"', "”": '"', "‘": "'", "’": "'",
    "→": "->", "←": "<-", "↑": "^", "↓": "v",
    "✓": "[ok]", "✗": "[x]", "⚠": "!",
}
_TRANS = str.maketrans(_PUNCT)


def _s(text: Any) -> str:
    return str(text).translate(_TRANS).encode("latin-1", "replace").decode("latin-1")


# ── paginación ───────────────────────────────────────────────────────────────
#
# Un informe pericial se lee en papel, y ahí un salto de página mal puesto no es
# un detalle estético: una fila partida entre dos hojas deja media tabla sin su
# otra mitad, y un rótulo al pie con su cuerpo en la hoja siguiente obliga a
# volver atrás para saber de qué se estaba hablando. Las dos cosas se evitan
# igual, RESERVANDO el sitio antes de escribir.

#: Cuánto se reserva DEBAJO de un rótulo (un H2, el título de un hallazgo) para
#: que no se quede solo al pie. Es el alto de un par de líneas de cuerpo: con
#: menos que eso, lo que sigue al rótulo no se ve en la misma hoja.
_ALTO_CUERPO_MINIMO = 14.0


def _reservar(pdf: "_Report", alto: float) -> None:
    """Salta de página si ``alto`` no cabe en lo que queda de la actual.

    La guarda del margen superior es lo que impide que esto genere una hoja en
    blanco: si ya estamos al principio de una página, lo que no quepa no va a
    caber tampoco en la siguiente, así que se escribe aquí y se deja que el salto
    automático lo parta donde toque.
    """
    if pdf.get_y() > pdf.t_margin and pdf.will_page_break(alto):
        pdf.add_page()


def _alto_de(pdf: "_Report", ancho: float, linea: float, texto: str, **kw: Any) -> float:
    """Lo que va a ocupar un ``multi_cell``, sin escribirlo."""
    return float(
        pdf.multi_cell(
            ancho, linea, texto, dry_run=True, output="HEIGHT",
            new_x="LMARGIN", new_y="NEXT", **kw,
        )
    )


class _Report(FPDF):
    header_left = "Agentopsy - Informe pericial forense"
    header_right = "Confidencial"
    footer_left = ""
    footer_author = ""

    def header(self) -> None:  # noqa: D401 — fpdf2 hook
        self.set_y(9)
        self.set_font("Courier", "", 7.5)
        self.set_text_color(*_FAINT)
        self.cell(self.epw / 2, 4, _s(self.header_left))
        self.cell(self.epw / 2, 4, _s(self.header_right), align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*_RULE)
        self.line(self.l_margin, self.get_y() + 1, self.l_margin + self.epw, self.get_y() + 1)
        self.set_y(self.t_margin)

    def footer(self) -> None:  # noqa: D401 — fpdf2 hook
        self.set_y(-13)
        self.set_draw_color(*_RULE)
        self.line(self.l_margin, self.get_y(), self.l_margin + self.epw, self.get_y())
        self.set_y(-11)
        self.set_font("Courier", "", 7.5)
        self.set_text_color(*_FAINT)
        self.cell(self.epw / 2, 4, _s(self.footer_left))
        self.cell(self.epw / 2, 4, _s(f"{self.footer_author}  -  pag. {self.page_no()}"), align="R")


def render_pdf(doc: Document) -> bytes:
    pdf = _Report(orientation="P", unit="mm", format="A4")
    pdf.set_margins(left=18, top=17, right=18)
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.header_right = _s(f"Confidencial - {doc.case_id}")
    pdf.footer_left = _s(doc.type)
    pdf.footer_author = _s(f"Perito: {doc.author}")
    pdf.add_page()

    _cover(pdf, doc)
    _toc(pdf, doc)
    for sec in doc.sections:
        _section(pdf, sec)
    _signature(pdf, doc)
    return bytes(pdf.output())


# ── portada ──────────────────────────────────────────────────────────────────


def _cover(pdf: _Report, doc: Document) -> None:
    pdf.set_font("Courier", "B", 9)
    pdf.set_text_color(*_ACCENT)
    pdf.cell(0, 6, _s(t("pdf.confidential")), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(*_INK)
    pdf.multi_cell(0, 10, _s(doc.title), new_x="LMARGIN", new_y="NEXT")
    if doc.summary:
        pdf.ln(1)
        pdf.set_font("Helvetica", "", 12)
        pdf.set_text_color(*_BODY)
        pdf.multi_cell(0, 6, _s(doc.summary), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    rows = [
        (t("pdf.examiner"), doc.author),
        (t("pdf.reportType"), doc.type),
        (t("pdf.version"), doc.version),
        (t("pdf.reportDate"), doc.created_at),
        (t("pdf.caseId"), doc.case_id),
        (t("pdf.evidence"), doc.evidence_id or "-"),
        (t("pdf.docHash"), doc.sha256),
    ]
    _meta_table(pdf, rows)


#: Qué parte del ancho se lleva la columna de la CLAVE en las dos tablas de dos
#: columnas del informe (la ficha de la portada y los bloques ``kv``).
_ANCHO_CLAVE = 32

#: Aire dentro de cada celda: arriba, derecha, abajo, izquierda. Reproduce la
#: densidad que tenían las celdas dibujadas a mano (una línea ocupaba 6,4 mm con
#: un interlineado de 4,6).
_AIRE_CELDA = (1, 2, 1, 2)


def _tabla_clave_valor(
    pdf: _Report,
    filas: list[tuple[str, str]],
    *,
    estilo_valor: FontFace,
    interlineado: float,
) -> None:
    """Las dos columnas CLAVE / VALOR, paginadas por fpdf2 y no a mano.

    Antes esto se dibujaba pareja a pareja: se guardaba la ``y`` de partida, se
    escribía la clave y se volvía con ``set_xy`` a esa misma ``y`` para escribir
    el valor al lado. Funcionaba en medio de una página y fallaba justo en el
    borde: si la celda de la clave disparaba el salto automático, la clave se
    pintaba ya en la página siguiente, pero el ``set_xy`` devolvía la ``y`` al
    valor que tenía en la ANTERIOR, cerca del pie, de modo que el valor
    disparaba OTRO salto y se iba a una tercera página. Resultado medido sobre un
    bloque de 70 parejas: dos hojas con una sola columna suelta y su valor a dos
    páginas de distancia. Es el defecto que se ve en un informe generado.

    La tabla de fpdf2 no tiene ese problema porque decide el salto por FILA
    ENTERA: la que no cabe pasa completa a la hoja siguiente. De paso arregla dos
    cosas más que se veían en el mismo sitio: las dos celdas de una fila salen
    con la MISMA altura (antes la clave quedaba corta cuando el valor ocupaba dos
    líneas) y el texto se parte por PALABRAS y no por caracteres, así que se
    acabó el «evidenc / ias» del informe anterior. Un token sin espacios que no
    quepa en su columna, un SHA-256 por ejemplo, lo sigue partiendo fpdf2 por
    donde puede, así que no hay nada que desborde.
    """
    pdf.set_draw_color(*_RULE)
    pdf.set_line_width(0.2)
    estilo_clave = FontFace(
        family="Courier", size_pt=8.5, color=_MUTED, fill_color=_SURFACE
    )
    with pdf.table(
        col_widths=(_ANCHO_CLAVE, 100 - _ANCHO_CLAVE),
        first_row_as_headings=False,
        borders_layout="ALL",
        line_height=interlineado,
        padding=_AIRE_CELDA,
        text_align="LEFT",
        v_align="TOP",
    ) as tabla:
        for clave, valor in filas:
            fila = tabla.row()
            fila.cell(_s(str(clave).upper()), style=estilo_clave)
            fila.cell(_s(valor), style=estilo_valor)


def _meta_table(pdf: _Report, rows: list[tuple[str, str]]) -> None:
    _tabla_clave_valor(
        pdf,
        rows,
        estilo_valor=FontFace(family="Courier", size_pt=9, color=_INK),
        interlineado=5,
    )
    pdf.ln(3)


# ── índice ───────────────────────────────────────────────────────────────────


def _toc(pdf: _Report, doc: Document) -> None:
    if not doc.sections:
        return
    _h2(pdf, t("pdf.toc"), num="")
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(*_BODY)
    for sec in doc.sections:
        num = sec.get("num", "")
        prefix = f"{num}  -  " if num else "-  "
        pdf.multi_cell(0, 6.2, _s(prefix + sec.get("title", "")),
                       new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)


# ── secciones y bloques ──────────────────────────────────────────────────────


def _h2(pdf: _Report, title: str, num: str) -> None:
    pdf.set_font("Helvetica", "B", 15)
    pdf.set_text_color(*_INK)
    label = _s(f"{num} - {title}" if num else title)
    # El rótulo se lleva consigo su raya y un par de líneas de cuerpo. Sin esto,
    # un apartado podía titularse al pie de una hoja y empezar en la siguiente, y
    # la raya llegaba a dibujarse ya dentro del pie de página.
    _reservar(pdf, 4 + _alto_de(pdf, 0, 8, label) + 4 + _ALTO_CUERPO_MINIMO)
    pdf.ln(4)
    pdf.multi_cell(0, 8, label, new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(*_INK)
    pdf.set_line_width(0.5)
    y = pdf.get_y() + 1
    pdf.line(pdf.l_margin, y, pdf.l_margin + pdf.epw, y)
    pdf.set_line_width(0.2)
    pdf.ln(3)


def _section(pdf: _Report, sec: dict[str, Any]) -> None:
    _h2(pdf, sec.get("title", ""), num=sec.get("num", ""))
    for b in sec.get("blocks", []):
        _block(pdf, b)


def _block(pdf: _Report, b: dict[str, Any]) -> None:
    t = b.get("t")
    if t == "p":
        pdf.set_font("Helvetica", "", 10.5)
        pdf.set_text_color(*_BODY)
        pdf.multi_cell(0, 5.6, _s(b.get("text", "")), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1.5)
    elif t == "h3":
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(*_INK)
        texto = _s(b.get("text", ""))
        _reservar(pdf, 2 + _alto_de(pdf, 0, 6, texto) + _ALTO_CUERPO_MINIMO)
        pdf.ln(2)
        pdf.multi_cell(0, 6, texto, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)
    elif t == "quote":
        pdf.set_font("Courier", "", 10)
        pdf.set_text_color(*_ACCENT)
        pdf.set_fill_color(250, 241, 240)
        pdf.multi_cell(0, 5.6, _s(b.get("text", "")), border="L", fill=True,
                       new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)
    elif t == "list":
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*_BODY)
        ordered = bool(b.get("ordered"))
        for i, item in enumerate(b.get("items", []) or [], start=1):
            marker = f"{i}." if ordered else "-"
            pdf.cell(7, 5.4, marker)
            pdf.multi_cell(pdf.epw - 7, 5.4, _s(item), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1.5)
    elif t == "code":
        pdf.set_font("Courier", "", 8.5)
        pdf.set_text_color(*_INK)
        pdf.set_fill_color(*_SURFACE)
        pdf.multi_cell(0, 4.8, _s(b.get("text", "")), border=1, fill=True,
                       new_x="LMARGIN", new_y="NEXT", wrapmode="CHAR")
        pdf.ln(1.5)
    elif t == "kv":
        _kv(pdf, b.get("pairs", []) or [])
    elif t == "table":
        _table(pdf, b.get("headers", []) or [], b.get("rows", []) or [])
    elif t == "finding":
        _finding(pdf, b)


def _kv(pdf: _Report, pairs: list[dict[str, Any]]) -> None:
    if not pairs:
        return
    _tabla_clave_valor(
        pdf,
        [(kv.get("k", ""), kv.get("v", "")) for kv in pairs],
        estilo_valor=FontFace(family="Helvetica", size_pt=9.5, color=_INK),
        interlineado=4.6,
    )
    pdf.ln(2)


def _table(pdf: _Report, headers: list[Any], rows: list[list[Any]]) -> None:
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*_INK)
    pdf.set_draw_color(*_RULE)
    with pdf.table(
        borders_layout="ALL",
        cell_fill_color=_SURFACE,
        cell_fill_mode="ROWS",
        line_height=5,
        headings_style=FontFace(emphasis="BOLD", color=_MUTED, fill_color=(242, 243, 245)),
    ) as table:
        if headers:
            hr = table.row()
            for h in headers:
                hr.cell(_s(h))
        for r in rows:
            row = table.row()
            for c in r:
                row.cell(_s(c))
    pdf.ln(2.5)


def _finding(pdf: _Report, b: dict[str, Any]) -> None:
    sev = b.get("sev", "low")
    color = _SEV_COLOR.get(sev, _MUTED)
    titulo = _s(b.get("title", ""))
    # La cabecera de un hallazgo son tres cosas que solo significan algo juntas:
    # la severidad, el título y el arranque de su descripción. Se reservan de una
    # vez para que no quede una etiqueta «[ ALTO ]» suelta al pie de una hoja.
    pdf.set_font("Helvetica", "B", 10.5)
    _reservar(pdf, 5 + _alto_de(pdf, 0, 5.4, titulo) + _ALTO_CUERPO_MINIMO)
    pdf.set_font("Helvetica", "B", 7.5)
    pdf.set_text_color(*color)
    pdf.cell(0, 5, _s(f"[ {_SEV_LABEL.get(sev, sev).upper()} ]"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "B", 10.5)
    pdf.set_text_color(*_INK)
    pdf.multi_cell(0, 5.4, titulo, new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9.5)
    pdf.set_text_color(*_BODY)
    pdf.multi_cell(0, 5, _s(b.get("text", "")), new_x="LMARGIN", new_y="NEXT")
    meta = b.get("meta")
    if meta:
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(*_FAINT)
        pdf.multi_cell(0, 4.6, _s(str(meta)), new_x="LMARGIN", new_y="NEXT")
    tags = b.get("tags", []) or []
    if tags:
        pdf.set_font("Courier", "", 8)
        pdf.set_text_color(*_FAINT)
        pdf.multi_cell(0, 4.6, _s("  ".join(f"[{tag}]" for tag in tags)),
                       new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)


# ── firma ────────────────────────────────────────────────────────────────────


#: Alto del bloque de firma: la raya, el aire, las dos líneas del pie y el
#: SHA-256 partido en dos. Es lo último del informe y va entero o en la hoja
#: siguiente: una firma separada de su hash no acredita nada.
_ALTO_FIRMA = 34.0


def _signature(pdf: _Report, doc: Document) -> None:
    _reservar(pdf, _ALTO_FIRMA)
    pdf.ln(6)
    pdf.set_draw_color(*_RULE)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.l_margin + pdf.epw, pdf.get_y())
    pdf.ln(3)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*_FAINT)
    status = t("pdf.signedFull") if doc.status == "final" else t("pdf.draftFull")
    pdf.multi_cell(
        0,
        5,
        _s(t("pdf.footer", status=status, date=doc.created_at)),
                   new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Courier", "", 8)
    pdf.multi_cell(0, 5, _s(f"SHA-256 {doc.sha256}"), new_x="LMARGIN", new_y="NEXT",
                   wrapmode="CHAR")
