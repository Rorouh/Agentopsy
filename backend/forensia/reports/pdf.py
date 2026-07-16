"""Render de un ``Document`` a PDF real con fpdf2, siguiendo la lógica del
**informe pericial** de FORENSIA (portada + metadata, índice, secciones
numeradas H2/H3, tablas, hallazgos con severidad, citas y listas, con
cabecera/pie por página). fpdf2 es pure-python (sin libs de sistema).

Usa las fuentes core (latin-1): la tipografía unicode del contenido (— … · → ✓)
se normaliza antes de escribir; los acentos españoles sí están en latin-1.
"""

from __future__ import annotations

from typing import Any

from fpdf import FPDF
from fpdf.fonts import FontFace

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


class _Report(FPDF):
    header_left = "FORENSIA - Informe pericial forense"
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
    pdf.cell(0, 6, _s("DOCUMENTO PERICIAL CONFIDENCIAL"), new_x="LMARGIN", new_y="NEXT")
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
        ("Perito", doc.author),
        ("Tipo de informe", doc.type),
        ("Version", doc.version),
        ("Fecha del informe", doc.created_at),
        ("Identificador del caso", doc.case_id),
        ("Evidencia", doc.evidence_id or "-"),
        ("SHA-256 del documento", doc.sha256),
    ]
    _meta_table(pdf, rows)


def _meta_table(pdf: _Report, rows: list[tuple[str, str]]) -> None:
    kw = pdf.epw * 0.32
    pdf.set_draw_color(*_RULE)
    for k, v in rows:
        y0 = pdf.get_y()
        pdf.set_fill_color(*_SURFACE)
        pdf.set_font("Courier", "", 8.5)
        pdf.set_text_color(*_MUTED)
        pdf.multi_cell(kw, 7, _s(k.upper()), border=1, fill=True, align="L",
                       new_x="RIGHT", new_y="TOP", max_line_height=5)
        pdf.set_font("Courier", "", 9)
        pdf.set_text_color(*_INK)
        pdf.set_xy(pdf.l_margin + kw, y0)
        pdf.multi_cell(pdf.epw - kw, 7, _s(v), border=1, align="L",
                       new_x="LMARGIN", new_y="NEXT", wrapmode="CHAR", max_line_height=5)
    pdf.ln(3)


# ── índice ───────────────────────────────────────────────────────────────────


def _toc(pdf: _Report, doc: Document) -> None:
    if not doc.sections:
        return
    _h2(pdf, "Indice de contenidos", num="")
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
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 15)
    pdf.set_text_color(*_INK)
    label = f"{num} - {title}" if num else title
    pdf.multi_cell(0, 8, _s(label), new_x="LMARGIN", new_y="NEXT")
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
        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(*_INK)
        pdf.multi_cell(0, 6, _s(b.get("text", "")), new_x="LMARGIN", new_y="NEXT")
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
    kw = pdf.epw * 0.32
    pdf.set_draw_color(*_RULE)
    for kv in pairs:
        y0 = pdf.get_y()
        pdf.set_fill_color(*_SURFACE)
        pdf.set_font("Courier", "", 8.5)
        pdf.set_text_color(*_MUTED)
        pdf.multi_cell(kw, 6.4, _s(kv.get("k", "")).upper(), border=1, fill=True,
                       new_x="RIGHT", new_y="TOP", max_line_height=4.6)
        pdf.set_font("Helvetica", "", 9.5)
        pdf.set_text_color(*_INK)
        pdf.set_xy(pdf.l_margin + kw, y0)
        pdf.multi_cell(pdf.epw - kw, 6.4, _s(kv.get("v", "")), border=1,
                       new_x="LMARGIN", new_y="NEXT", wrapmode="CHAR", max_line_height=4.6)
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
    pdf.set_font("Helvetica", "B", 7.5)
    pdf.set_text_color(*color)
    pdf.cell(0, 5, _s(f"[ {_SEV_LABEL.get(sev, sev).upper()} ]"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "B", 10.5)
    pdf.set_text_color(*_INK)
    pdf.multi_cell(0, 5.4, _s(b.get("title", "")), new_x="LMARGIN", new_y="NEXT")
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


def _signature(pdf: _Report, doc: Document) -> None:
    pdf.ln(6)
    pdf.set_draw_color(*_RULE)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.l_margin + pdf.epw, pdf.get_y())
    pdf.ln(3)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*_FAINT)
    status = "FIRMADO - version final" if doc.status == "final" else "BORRADOR - sin firmar"
    pdf.multi_cell(0, 5, _s(f"Generado por FORENSIA - {status} - {doc.created_at}"),
                   new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Courier", "", 8)
    pdf.multi_cell(0, 5, _s(f"SHA-256 {doc.sha256}"), new_x="LMARGIN", new_y="NEXT",
                   wrapmode="CHAR")
