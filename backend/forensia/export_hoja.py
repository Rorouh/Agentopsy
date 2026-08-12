"""La HOJA de un export: cómo Agentopsy escribe la tabla que el perito ABRE en
una hoja de cálculo y adjunta a su informe.

**Por qué no es un CSV.** Lo fue, y no se podía leer. Un `.csv` obliga a negociar
DOS cosas con el programa que lo abre, y en Windows las dos salen mal a la vez:

1. *La codificación.* Excel abre un `.csv` con la página de códigos del sistema
   salvo que encuentre un BOM, así que sin BOM «Exfiltración» se leía
   «ExfiltraciÃ³n».
2. *El separador.* Excel parte por el separador de listas del locale (`;` en un
   Windows español, `,` en uno inglés), así que un fichero correcto en una
   máquina cae entero en la columna A en la otra.

La declaración `sep=;` arregla lo segundo y **rompe lo primero**: medido contra
Excel 16 (es-ES), un fichero con BOM y `sep=;` delante se decodifica como ANSI y
vuelven los caracteres ilegibles. Son excluyentes, no hay CSV que gane las dos.

Un `.xlsx` no negocia ninguna de las dos: el texto viaja en XML UTF-8 dentro del
paquete y las celdas ya vienen separadas, así que se abre igual en Excel,
LibreOffice, Numbers y Google Sheets, en cualquier idioma del sistema. Y de paso
la hoja se puede presentar: cabecera fijada, filtros, anchos de columna y ajuste
de impresión, que es lo que distingue un anexo de un volcado.

Para consumo por MÁQUINA hay canales mejores y no se tocan: la cobertura ATT&CK
sale además como *layer* del Navigator y el timeline como JSON en
``GET /api/cases/{id}/timeline``. Esta hoja es el artefacto para PERSONAS.

**La evidencia es hostil** (SECURITY INVARIANTS). Un `summary` o un `argv` que
salgan de la imagen pueden empezar por ``=``, y una hoja de cálculo interpreta
eso como FÓRMULA: es la inyección de fórmulas de toda la vida, y aquí el texto
que la dispararía viene literalmente del disco del sospechoso.
:func:`build_workbook` escribe TODA celda de texto como texto (nunca como
fórmula), de modo que lo que se ve es el byte que estaba en la evidencia.

Puro (CLAUDE.md RULE 3): sin I/O ni acceso a disco; recibe datos, devuelve bytes.
"""

from __future__ import annotations

import io
import re
import unicodedata
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Any

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

#: Tipo MIME del `.xlsx` (OOXML). Es el que hace que el navegador y el sistema
#: operativo ofrezcan abrirlo con la hoja de cálculo, no con un editor de texto.
MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

#: Extensión del fichero que se descarga.
EXTENSION = "xlsx"

#: Separador de VARIOS valores DENTRO de una celda (identificadores de hallazgo,
#: técnicas de una fila). Se leen de un golpe sin tener que ensanchar la columna.
SUBSEPARADOR = " | "

#: Lo que se escribe donde un campo NO APLICA a esa fila (una fila de hallazgo no
#: tiene código de salida). Igual que en la interfaz, «n/d», nunca un cero ni un
#: guion que se pueda leer como un dato.
NO_APLICA = "n/d"

# Paleta del producto (la misma del informe en PDF): papel, tinta y terracota.
_ACENTO = "A3271F"
_TINTA = "14171D"
_APAGADO = "5B626D"
_LINEA = "E3E6EA"
_CABECERA_FONDO = "F2EDE9"


def iso_utc_ahora() -> str:
    """Marca temporal de la exportación, en UTC explícito y al segundo."""
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


#: Cuántos caracteres del nombre del caso entran en el nombre del fichero. Un
#: nombre de caso puede ser una frase; el fichero no.
MAX_SLUG = 48


def export_basename(case_name: str, kind: str, *, exported_at: str | None = None) -> str:
    """Nombre de fichero de una exportación, sin extensión.

    ``agentopsy-mitre-attack-lonewolf-20260806T130542Z``: la herramienta, QUÉ es,
    de qué caso y CUÁNDO. La marca temporal va dentro a propósito, para que dos
    exportaciones del mismo caso no se pisen en la carpeta de descargas y para que
    la del informe se pueda identificar después.

    Se transcribe a ASCII porque viaja en la cabecera ``Content-Disposition``, que
    no admite otra cosa; un nombre de caso que al transcribirse se queda en nada
    (escrito íntegro en un alfabeto no latino) deja sólo la herramienta, el tipo y
    la fecha, nunca un nombre inventado.
    """
    ascii_name = (
        unicodedata.normalize("NFKD", case_name or "")
        .encode("ascii", "ignore")
        .decode("ascii")
        .lower()
    )
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_name).strip("-")[:MAX_SLUG].strip("-")
    marca = (exported_at or iso_utc_ahora()).replace("-", "").replace(":", "")
    partes = ["agentopsy", kind, slug, marca]
    return "-".join(p for p in partes if p)


def celda(valor: Any) -> str:
    """Un valor como TEXTO: tal cual, y ``""`` para lo ausente. Nunca inventa un
    cero ni un texto de relleno."""
    if valor is None:
        return ""
    if isinstance(valor, bool):  # antes de int: un bool es un int en Python
        return "Sí" if valor else "No"
    return str(valor)


def unir(valores: Iterable[Any]) -> str:
    """Varios valores en una sola celda, legibles y sin entrecomillado."""
    return SUBSEPARADOR.join(celda(v) for v in valores if celda(v))


def _valor_de_celda(valor: Any) -> Any:
    """Lo que se ESCRIBE en la celda, conservando el tipo cuando importa.

    Un entero entra como número para que la columna ordene por valor y no
    alfabéticamente (con texto, la fila 10 va delante de la 9). Todo lo demás
    entra como texto: un identificador, un hash o un código de salida no son
    magnitudes y no deben redondearse ni convertirse a notación científica.
    """
    if valor is None:
        return ""
    if isinstance(valor, bool):
        return "Sí" if valor else "No"
    if isinstance(valor, int):
        return valor
    return str(valor)


#: Ancho mínimo y máximo de una columna, en caracteres. El máximo existe porque un
#: ``argv`` auditado pasa de cien caracteres y, sin tope, una sola columna deja la
#: hoja inservible; el contenido sigue entero en la celda.
_ANCHO_MIN = 10
_ANCHO_MAX = 60


def _ancho(valores: Sequence[Any]) -> float:
    """Ancho de columna a partir de lo más largo que lleva, acotado."""
    largo = max((len(celda(v)) for v in valores), default=0)
    return min(max(largo + 2, _ANCHO_MIN), _ANCHO_MAX)


#: Excel rechaza estos caracteres en el nombre de una pestaña, y la corta a 31.
_NOMBRE_HOJA_PROHIBIDO = re.compile(r"[\[\]:*?/\\]")


def _nombre_de_hoja(titulo: str) -> str:
    limpio = _NOMBRE_HOJA_PROHIBIDO.sub(" ", titulo).strip()
    return limpio[:31] or "Hoja"


def build_workbook(
    *,
    procedencia: Sequence[tuple[str, str]],
    cabecera: Sequence[str],
    filas: Iterable[Sequence[Any]],
    titulo: str,
) -> bytes:
    """La hoja completa: bloque de procedencia, una fila en blanco y la tabla.

    ``procedencia`` son pares (campo, valor) del bloque de cabecera, en el orden en
    que deben leerse. ``filas`` se escribe tal cual: este módulo no ordena, no
    agrupa y no formatea valores, eso es de quien conoce el dominio. ``titulo``
    nombra la pestaña.

    La fila en blanco entre la procedencia y la tabla se conserva del formato
    anterior: es lo que permite leer la hoja con un programa sin adivinar
    (``pandas.read_excel(f, skiprows=len(procedencia) + 1)``), y de paso separa a
    la vista el quién/cuándo del qué.
    """
    filas = [list(f) for f in filas]
    wb = Workbook()
    ws = wb.active
    ws.title = _nombre_de_hoja(titulo)

    negro = Font(name="Calibri", size=10, color=_TINTA)
    campo = Font(name="Calibri", size=10, bold=True, color=_APAGADO)
    titular = Font(name="Calibri", size=13, bold=True, color=_ACENTO)
    cabecera_fuente = Font(name="Calibri", size=10, bold=True, color=_TINTA)
    relleno = PatternFill("solid", fgColor=_CABECERA_FONDO)
    raya = Border(bottom=Side(style="thin", color=_LINEA))
    arriba = Alignment(vertical="top")

    # ── bloque de procedencia ────────────────────────────────────────────────
    for i, (nombre, valor) in enumerate(procedencia):
        fila = i + 1
        a = ws.cell(row=fila, column=1, value=celda(nombre))
        b = ws.cell(row=fila, column=2, value=celda(valor))
        a.font = campo
        b.font = titular if i == 0 else negro
        b.alignment = arriba

    fila_cabecera = len(procedencia) + 2  # +1 por la fila en blanco

    # ── cabecera de la tabla ─────────────────────────────────────────────────
    for col, nombre in enumerate(cabecera, start=1):
        c = ws.cell(row=fila_cabecera, column=col, value=str(nombre))
        c.font = cabecera_fuente
        c.fill = relleno
        c.border = raya
        c.alignment = Alignment(vertical="bottom", wrap_text=True)

    # ── filas ────────────────────────────────────────────────────────────────
    for i, fila_datos in enumerate(filas):
        fila = fila_cabecera + 1 + i
        for col, valor in enumerate(fila_datos, start=1):
            c = ws.cell(row=fila, column=col, value=_valor_de_celda(valor))
            c.font = negro
            c.alignment = arriba
            # La evidencia es hostil: un texto que empiece por «=» lo escribiría
            # openpyxl como FÓRMULA. Se fuerza a texto para que la celda muestre
            # el byte que había en la imagen y no ejecute nada.
            if isinstance(c.value, str):
                c.data_type = "s"

    ultima_col = max(len(cabecera), 2)
    ultima_fila = fila_cabecera + len(filas)

    # Anchos: se calculan con la cabecera y los datos de cada columna. La columna
    # A lleva además los nombres del bloque de procedencia.
    for col in range(1, ultima_col + 1):
        valores: list[Any] = [cabecera[col - 1] if col <= len(cabecera) else ""]
        valores += [f[col - 1] for f in filas if col <= len(f)]
        if col == 1:
            valores += [p[0] for p in procedencia]
        ws.column_dimensions[get_column_letter(col)].width = _ancho(valores)

    # Cabecera siempre a la vista al desplazarse, y filtros para ordenar/filtrar
    # sin tocar el fichero. Con la tabla vacía no se pone filtro: Excel avisa de
    # un rango de filtro sin filas y la hoja se abriría con una advertencia.
    ws.freeze_panes = ws.cell(row=fila_cabecera + 1, column=1)
    if filas:
        ws.auto_filter.ref = (
            f"A{fila_cabecera}:{get_column_letter(ultima_col)}{ultima_fila}"
        )

    # Ajuste de impresión: el anexo de un informe se imprime, y una tabla ancha
    # sin esto sale partida en columnas sueltas por páginas distintas.
    ws.page_setup.orientation = "landscape"
    ws.page_setup.fitToWidth = 1
    ws.page_setup.fitToHeight = 0
    ws.sheet_properties.pageSetUpPr.fitToPage = True
    ws.print_title_rows = f"{fila_cabecera}:{fila_cabecera}"

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


__all__ = [
    "EXTENSION",
    "MAX_SLUG",
    "MEDIA_TYPE",
    "NO_APLICA",
    "SUBSEPARADOR",
    "build_workbook",
    "celda",
    "export_basename",
    "iso_utc_ahora",
    "unir",
]
