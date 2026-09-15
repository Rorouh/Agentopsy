"""El SVG de las figuras del informe pericial.

Cuatro piezas que comparten las dos figuras del anexo C (la línea de tiempo del
incidente y el grafo de relaciones del caso) y el PDF que las imprime:

- la PALETA DE PAPEL (``PAPEL``): los colores del informe impreso. Son los del
  PDF (``reports.pdf`` los toma de aquí) y no siguen el tema de la interfaz: la
  figura de un informe va SIEMPRE sobre fondo blanco, esté la aplicación en
  claro o en oscuro, porque es la del documento y no la de la pantalla;
- la MEDIDA DE TEXTO (``ancho_de_texto``, ``partir_en_lineas``): con las
  métricas de las fuentes base del PDF, no con la tipografía de la máquina.
  SVG no parte líneas solo, así que el ajuste se calcula aquí, y tiene que
  salir igual en el servidor de cualquiera. Son las métricas de Helvetica, que
  es con la que fpdf2 imprime el texto de la figura y con la que Arial comparte
  medidas, así que el PDF encaja exacto y el navegador casi;
- la ESCRITURA (``Figura``): elementos con coordenadas absolutas y texto
  escapado. El texto de una figura sale de la EVIDENCIA (una ruta, el título que
  el agente escribió) y puede venir sembrado por el investigado: viaja siempre
  como nodo de texto XML escapado, nunca como marcado (SECURITY INVARIANT 8);
- la LISTA BLANCA (``validar_svg``): lo único que el almacén de documentos
  acepta en un bloque ``figure`` y lo único que el PDF imprime. Hace falta
  porque un documento también se puede crear por ``POST …/documents`` con el
  cuerpo que se quiera, y fpdf2 resuelve un ``<image href>`` leyendo un fichero
  o una URL: sin la lista, un SVG sembrado haría que el servidor leyera disco o
  saliera a la red al imprimir. La lista admite exactamente el vocabulario que
  dibuja este módulo (rectángulo, círculo, línea, polígono y texto sin hijos,
  todos hijos directos de la raíz y con los atributos que ``Figura`` escribe),
  sin DOCTYPE ni entidades. Lo que llega a fpdf2 ni siquiera es el SVG guardado:
  ``svg_para_imprimir`` lo reescribe desde el árbol ya validado, con el texto
  transliterado y escapado otra vez, y lo vuelve a validar.

Lógica pura (RULE 3): sin disco, sin red.
"""

from __future__ import annotations

import math
import re
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterable
from xml.sax.saxutils import escape, quoteattr

from fpdf.fonts import CORE_FONTS_CHARWIDTHS

SVG_NS = "http://www.w3.org/2000/svg"

#: La paleta del informe en PAPEL. Una sola fuente: el PDF deriva de aquí sus
#: colores, así que la figura y el texto que la rodea no pueden divergir.
PAPEL: dict[str, str] = {
    "fondo": "#ffffff",
    "tinta": "#14171d",
    "cuerpo": "#2b3039",
    "apagado": "#5b626d",
    "tenue": "#9096a0",
    "filete": "#e3e6ea",
    "superficie": "#f7f8fa",
    "acento": "#a3271f",
}

#: Color de cada severidad de hallazgo, el mismo del PDF. Crítica y alta
#: comparten el rojo pericial, como en el cuerpo del informe: la marca lleva
#: además la severidad ESCRITA, así que el color acompaña y no sustituye.
SEVERIDAD_PAPEL: dict[str, str] = {
    "critical": "#a3271f",
    "high": "#a3271f",
    "medium": "#8a5a0c",
    "low": "#5a6470",
}

#: Las dos familias de la figura. Se nombran varias para que el navegador use
#: la que tenga; fpdf2 recorre la lista y se queda con la primera que resuelve a
#: una fuente base (Helvetica y Courier). Sin comillas: dentro de un atributo
#: estorban, y un nombre con espacio sin comillas sigue siendo CSS válido.
SANS = "Helvetica, Arial, sans-serif"
MONO = "Menlo, Consolas, Courier New, monospace"

#: Ancho de un carácter monoespaciado, en em. Menlo y Courier miden 0,60 y
#: Consolas 0,55: se toma el mayor, con un pelo de margen.
_EM_MONO = 0.61

#: Holgura sobre la métrica de Helvetica. En macOS y Windows la sans que pinta el
#: navegador es Helvetica o Arial, con las mismas medidas; en Linux puede caer en
#: una más ancha. Pasarse de ancho solo deja aire; quedarse corto desborda.
_HOLGURA_SANS = 1.08

#: Lo que mide, en milésimas de em, un carácter que las fuentes base no tienen
#: (fuera de latin-1). Un em entero: el lado seguro.
_ANCHO_DESCONOCIDO = 1000

#: Cotas de un SVG de figura. Acotan lo absurdo, no una figura legítima: el
#: grafo de un caso grande ronda los cien kilobytes.
MAX_CARACTERES_SVG = 3_000_000
MAX_ELEMENTOS_SVG = 60_000
#: Lado máximo del lienzo, en unidades del SVG. El grafo de un caso grande no
#: llega a 3000.
MAX_LADO_SVG = 100_000


class SvgNoAdmitido(ValueError):
    """Un SVG que no es una figura de Agentopsy: ni se guarda ni se imprime."""


def rgb(color: str) -> tuple[int, int, int]:
    """``#rrggbb`` como la terna que usa fpdf2."""
    if not re.fullmatch(r"#[0-9a-f]{6}", color):
        raise ValueError(f"color must be #rrggbb in lowercase, got {color!r}")
    return (int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16))


# ── medida de texto ───────────────────────────────────────────────────────────


def ancho_de_texto(
    texto: str, tamano: float, *, mono: bool = False, negrita: bool = False
) -> float:
    """Lo que ocupa ``texto`` a ``tamano`` unidades de fuente, en esas unidades."""
    if mono:
        return len(texto) * _EM_MONO * tamano
    tabla = CORE_FONTS_CHARWIDTHS["helveticaB" if negrita else "helvetica"]
    milesimas = sum(tabla.get(c, _ANCHO_DESCONOCIDO) for c in texto)
    return milesimas * tamano / 1000 * _HOLGURA_SANS


def _cuantos_caben(
    texto: str, ancho_max: float, medir: Callable[[str], float]
) -> int:
    """Cuántos caracteres del principio de ``texto`` caben en ``ancho_max``.
    Al menos uno: una línea que no avanza sería un bucle."""
    caben = 1
    while caben < len(texto) and medir(texto[: caben + 1]) <= ancho_max:
        caben += 1
    return caben


def partir_en_lineas(
    texto: str,
    ancho_max: float,
    tamano: float,
    *,
    mono: bool = False,
    negrita: bool = False,
) -> list[str]:
    """El texto partido por PALABRAS en líneas que caben en ``ancho_max``.

    Una palabra sola más ancha que la línea (una ruta, un hash) se trocea por
    caracteres: partirla es feo, pero cortarla sería perder un dato."""

    def medir(s: str) -> float:
        return ancho_de_texto(s, tamano, mono=mono, negrita=negrita)

    lineas: list[str] = []
    actual = ""
    for palabra in texto.split():
        candidata = f"{actual} {palabra}" if actual else palabra
        if medir(candidata) <= ancho_max:
            actual = candidata
            continue
        if actual:
            lineas.append(actual)
        actual = palabra
        while len(actual) > 1 and medir(actual) > ancho_max:
            corte = _cuantos_caben(actual, ancho_max, medir)
            lineas.append(actual[:corte])
            actual = actual[corte:]
    if actual:
        lineas.append(actual)
    return lineas or [""]


# ── escritura ─────────────────────────────────────────────────────────────────

#: Caracteres que XML 1.0 no admite ni escapados. Un byte de control dentro de
#: una ruta de la evidencia no puede invalidar la figura entera: se sustituye por
#: el carácter de reemplazo, que dice «aquí había algo ilegible».
_NO_XML_RE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")


def _num(valor: float) -> str:
    """Una coordenada con dos decimales como mucho y sin ceros de cola: el mismo
    dato escribe el mismo texto en cualquier máquina."""
    redondeado = round(float(valor), 2)
    texto = f"{redondeado:.2f}".rstrip("0").rstrip(".")
    return "0" if texto in ("-0", "") else texto


def _texto_xml(texto: str) -> str:
    limpio = _NO_XML_RE.sub("\ufffd", str(texto))
    return escape(" ".join(limpio.split()))


class Figura:
    """Un SVG en construcción, con fondo de papel y coordenadas absolutas.

    Solo dibuja lo que ``validar_svg`` admite: si esta clase gana un elemento, la
    lista blanca tiene que ganarlo con ella, y el test que valida las figuras
    reales lo detecta si no."""

    def __init__(self, ancho: float, alto: float) -> None:
        if ancho <= 0 or alto <= 0:
            raise ValueError(f"a figure needs a positive size, got {ancho} x {alto}")
        self.ancho = float(ancho)
        self.alto = float(alto)
        self._elementos: list[str] = []
        self.rect(0, 0, self.ancho, self.alto, fill=PAPEL["fondo"])

    def rect(
        self,
        x: float,
        y: float,
        ancho: float,
        alto: float,
        *,
        fill: str = "none",
        stroke: str | None = None,
        grosor: float | None = None,
        trazo: str | None = None,
    ) -> None:
        attrs = (
            f'x="{_num(x)}" y="{_num(y)}" width="{_num(ancho)}" height="{_num(alto)}" '
            f'fill="{fill}"'
        )
        self._elementos.append(f"<rect {attrs}{_trazo(stroke, grosor, trazo)}/>")

    def linea(
        self,
        x1: float,
        y1: float,
        x2: float,
        y2: float,
        *,
        stroke: str,
        grosor: float,
        trazo: str | None = None,
    ) -> None:
        attrs = f'x1="{_num(x1)}" y1="{_num(y1)}" x2="{_num(x2)}" y2="{_num(y2)}"'
        self._elementos.append(f"<line {attrs}{_trazo(stroke, grosor, trazo)}/>")

    def circulo(self, cx: float, cy: float, r: float, *, fill: str) -> None:
        self._elementos.append(
            f'<circle cx="{_num(cx)}" cy="{_num(cy)}" r="{_num(r)}" fill="{fill}"/>'
        )

    def poligono(self, puntos: Iterable[tuple[float, float]], *, fill: str) -> None:
        pares = " ".join(f"{_num(x)},{_num(y)}" for x, y in puntos)
        self._elementos.append(f'<polygon points="{pares}" fill="{fill}"/>')

    def texto(
        self,
        x: float,
        y: float,
        texto: str,
        *,
        tamano: float,
        color: str,
        mono: bool = False,
        negrita: bool = False,
        ancla: str = "start",
        espaciado: float | None = None,
    ) -> None:
        attrs = [
            f'x="{_num(x)}"',
            f'y="{_num(y)}"',
            f'fill="{color}"',
            f'font-family="{MONO if mono else SANS}"',
            f'font-size="{_num(tamano)}"',
        ]
        if negrita:
            attrs.append('font-weight="bold"')
        if ancla != "start":
            attrs.append(f'text-anchor="{ancla}"')
        if espaciado is not None:
            attrs.append(f'letter-spacing="{_num(espaciado)}"')
        self._elementos.append(f"<text {' '.join(attrs)}>{_texto_xml(texto)}</text>")

    def svg(self) -> str:
        ancho, alto = _num(self.ancho), _num(self.alto)
        return (
            f'<svg xmlns="{SVG_NS}" width="{ancho}" height="{alto}" '
            f'viewBox="0 0 {ancho} {alto}">' + "".join(self._elementos) + "</svg>"
        )


def _trazo(stroke: str | None, grosor: float | None, trazo: str | None) -> str:
    out = ""
    if stroke is not None:
        out += f' stroke="{stroke}"'
    if grosor is not None:
        out += f' stroke-width="{_num(grosor)}"'
    if trazo is not None:
        out += f' stroke-dasharray="{trazo}"'
    return out


# ── lista blanca ──────────────────────────────────────────────────────────────

#: Números en ASCII y acotados: ``\d`` admitiría dígitos de otras escrituras que
#: fpdf2 no sabe leer, y un número de cuatrocientas cifras es infinito.
_NUMERO = r"-?[0-9]{1,7}(?:\.[0-9]{1,6})?"
_NUMERO_RE = re.compile(_NUMERO)
_COLOR_RE = re.compile(r"#[0-9a-f]{6}|none")
_PUNTOS_RE = re.compile(rf"{_NUMERO},{_NUMERO}(?: {_NUMERO},{_NUMERO}){{0,63}}")
_TRAZO_RE = re.compile(r"[0-9]{1,4}(?:\.[0-9]{1,4})?(?: [0-9]{1,4}(?:\.[0-9]{1,4})?){0,7}")
_VIEWBOX_RE = re.compile(rf"0 0 ({_NUMERO}) ({_NUMERO})")

#: Cómo empieza un SVG de Agentopsy, carácter a carácter. fpdf2 reconoce un SVG
#: por ese arranque; uno que empiece distinto lo trataría como imagen rasterizada.
_ARRANQUE = f'<svg xmlns="{SVG_NS}" '


def _es(patron: re.Pattern[str]) -> Callable[[str], bool]:
    return lambda valor: patron.fullmatch(valor) is not None


def _uno_de(*valores: str) -> Callable[[str], bool]:
    return lambda valor: valor in valores


_NUM = _es(_NUMERO_RE)
_COLOR = _es(_COLOR_RE)

#: Elemento a sus atributos admitidos, y cómo se valida el valor de cada uno.
_ATRIBUTOS: dict[str, dict[str, Callable[[str], bool]]] = {
    "svg": {"width": _NUM, "height": _NUM, "viewBox": _es(_VIEWBOX_RE)},
    "rect": {
        "x": _NUM, "y": _NUM, "width": _NUM, "height": _NUM,
        "fill": _COLOR, "stroke": _COLOR, "stroke-width": _NUM,
        "stroke-dasharray": _es(_TRAZO_RE),
    },
    "circle": {"cx": _NUM, "cy": _NUM, "r": _NUM, "fill": _COLOR},
    "line": {
        "x1": _NUM, "y1": _NUM, "x2": _NUM, "y2": _NUM,
        "stroke": _COLOR, "stroke-width": _NUM, "stroke-dasharray": _es(_TRAZO_RE),
    },
    "polygon": {"points": _es(_PUNTOS_RE), "fill": _COLOR},
    "text": {
        "x": _NUM, "y": _NUM, "fill": _COLOR,
        "font-family": _uno_de(SANS, MONO),
        "font-size": _NUM,
        "font-weight": _uno_de("bold"),
        "text-anchor": _uno_de("middle", "end"),
        "letter-spacing": _NUM,
    },
}

#: Los atributos que ``Figura`` escribe SIEMPRE. Un elemento sin ellos no lo ha
#: dibujado Agentopsy, y fpdf2 fallaría al imprimirlo.
_OBLIGATORIOS: dict[str, frozenset[str]] = {
    "svg": frozenset({"width", "height", "viewBox"}),
    "rect": frozenset({"x", "y", "width", "height", "fill"}),
    "circle": frozenset({"cx", "cy", "r", "fill"}),
    "line": frozenset({"x1", "y1", "x2", "y2", "stroke", "stroke-width"}),
    "polygon": frozenset({"points", "fill"}),
    "text": frozenset({"x", "y", "fill", "font-family", "font-size"}),
}


def _vacio(texto: str | None) -> bool:
    return texto is None or not texto.strip()


def _nombre(elemento: ET.Element) -> str:
    prefijo = f"{{{SVG_NS}}}"
    if not elemento.tag.startswith(prefijo):
        raise SvgNoAdmitido(f"figure.svg carries a foreign element {elemento.tag[:80]!r}")
    return elemento.tag[len(prefijo):]


def _validar_elemento(elemento: ET.Element, nombre: str) -> None:
    admitidos = _ATRIBUTOS.get(nombre)
    if admitidos is None:
        raise SvgNoAdmitido(
            f"figure.svg carries a <{nombre[:60]}> element, which is not allowed"
        )
    for clave, valor in elemento.attrib.items():
        validar = admitidos.get(clave)
        if validar is None:
            raise SvgNoAdmitido(
                f"figure.svg: attribute {clave[:60]!r} is not allowed on <{nombre}>"
            )
        if not validar(valor):
            # El valor se cita recortado: puede traer megas y el motivo viaja
            # en un `detail` de HTTP.
            raise SvgNoAdmitido(
                f"figure.svg: attribute {clave!r} of <{nombre}> has a bad value {valor[:60]!r}"
            )
    faltan = _OBLIGATORIOS[nombre] - set(elemento.attrib)
    if faltan:
        raise SvgNoAdmitido(f"figure.svg: <{nombre}> lacks {sorted(faltan)}")
    if not _vacio(elemento.tail):
        raise SvgNoAdmitido("figure.svg carries loose text between elements")


def validar_svg(fuente: object) -> tuple[float, float]:
    """Comprueba que ``fuente`` es un SVG de figura de Agentopsy y devuelve su
    ancho y su alto. ``SvgNoAdmitido`` con el motivo si no lo es.

    Es una LISTA BLANCA, no una lista negra: lo que no está escrito aquí no
    pasa, así que un elemento nuevo del estándar no abre un hueco por sí solo.
    La forma también es la de ``Figura``: una raíz ``<svg>`` y, colgando de
    ella, elementos sin hijos."""
    if not isinstance(fuente, str) or not fuente.strip():
        raise SvgNoAdmitido("figure.svg must be a non-empty string")
    if len(fuente) > MAX_CARACTERES_SVG:
        raise SvgNoAdmitido(
            f"figure.svg has {len(fuente)} characters, the limit is {MAX_CARACTERES_SVG}"
        )
    # Sin DOCTYPE no hay entidades que expandir, y sin instrucciones de
    # proceso, comentarios ni CDATA no hay nada que el parser tenga que
    # interpretar. El texto de la figura va escapado, así que un `<!` literal
    # solo puede venir de un marcado que Agentopsy no escribe.
    if "<!" in fuente or "<?" in fuente:
        raise SvgNoAdmitido("figure.svg must not carry a DOCTYPE, entities, comments or CDATA")
    if not fuente.startswith(_ARRANQUE):
        raise SvgNoAdmitido(f"figure.svg must start with {_ARRANQUE!r}")
    try:
        raiz = ET.fromstring(fuente)
    except ET.ParseError as exc:
        raise SvgNoAdmitido(f"figure.svg is not well-formed XML: {exc}") from exc

    if _nombre(raiz) != "svg":
        raise SvgNoAdmitido("figure.svg must have an <svg> root in the SVG namespace")
    _validar_elemento(raiz, "svg")
    if not _vacio(raiz.text):
        raise SvgNoAdmitido("figure.svg carries loose text between elements")
    if len(raiz) + 1 > MAX_ELEMENTOS_SVG:
        raise SvgNoAdmitido(f"figure.svg has more than {MAX_ELEMENTOS_SVG} elements")

    for elemento in raiz:
        nombre = _nombre(elemento)
        if nombre == "svg":
            raise SvgNoAdmitido("figure.svg must not nest another <svg>")
        _validar_elemento(elemento, nombre)
        if len(elemento):
            raise SvgNoAdmitido(f"figure.svg: <{nombre}> must not have child elements")
        if nombre != "text" and not _vacio(elemento.text):
            raise SvgNoAdmitido(f"figure.svg: <{nombre}> must not carry text")

    ancho = float(raiz.attrib["width"])
    alto = float(raiz.attrib["height"])
    vista = _VIEWBOX_RE.fullmatch(raiz.attrib["viewBox"])
    if not (0 < ancho <= MAX_LADO_SVG and 0 < alto <= MAX_LADO_SVG):
        raise SvgNoAdmitido(
            f"figure.svg must be between 0 and {MAX_LADO_SVG} units on each side"
        )
    if vista is None or (float(vista.group(1)), float(vista.group(2))) != (ancho, alto):
        raise SvgNoAdmitido("figure.svg viewBox must be «0 0 width height»")
    if not (math.isfinite(ancho) and math.isfinite(alto)):
        raise SvgNoAdmitido("figure.svg must have a finite size")
    return ancho, alto


def svg_para_imprimir(
    fuente: object, transliterar: Callable[[str], str]
) -> tuple[str, float, float]:
    """El SVG que se le da a fpdf2: el validado, REESCRITO desde su árbol con el
    texto pasado por ``transliterar`` y escapado otra vez, y validado de nuevo.

    Reescribirlo, y no transliterar la cadena guardada, es lo que impide que la
    transliteración rompa el marcado: la del PDF convierte «←» en «<-», y ese
    «<» dentro de un texto sin escapar dejaría un XML que fpdf2 no puede leer.
    Una referencia numérica (``&#8364;``) llega aquí ya resuelta por el parser,
    así que también pasa por la transliteración. Devuelve el SVG, su ancho y su
    alto."""
    ancho, alto = validar_svg(fuente)
    assert isinstance(fuente, str)
    raiz = ET.fromstring(fuente)

    def atributos(elemento: ET.Element) -> str:
        return " ".join(f"{clave}={quoteattr(valor)}" for clave, valor in elemento.attrib.items())

    partes = [f"{_ARRANQUE}{atributos(raiz)}>"]
    for elemento in raiz:
        nombre = _nombre(elemento)
        if nombre == "text":
            texto = escape(transliterar(elemento.text or ""))
            partes.append(f"<text {atributos(elemento)}>{texto}</text>")
        else:
            partes.append(f"<{nombre} {atributos(elemento)}/>")
    partes.append("</svg>")
    salida = "".join(partes)
    validar_svg(salida)
    return salida, ancho, alto


__all__ = [
    "MAX_CARACTERES_SVG",
    "MAX_ELEMENTOS_SVG",
    "MAX_LADO_SVG",
    "MONO",
    "PAPEL",
    "SANS",
    "SEVERIDAD_PAPEL",
    "SVG_NS",
    "Figura",
    "SvgNoAdmitido",
    "ancho_de_texto",
    "partir_en_lineas",
    "rgb",
    "svg_para_imprimir",
    "validar_svg",
]
