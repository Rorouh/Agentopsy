"""La FIGURA del grafo de relaciones del caso, tal y como va en el informe.

Es la misma figura que la vista Grafos exporta a PNG
(``web/src/pages/graphs/RelationGraph.tsx``, modo ``exportacion``): la cabecera
con el título, el recuento y la píldora de nodos y aristas; el dibujo con la
MISMA geometría (``graph.figura.figura_del_caso``, calculada una vez para las dos
superficies); la banda de las entidades que ningún hallazgo relaciona; la
leyenda; y la procedencia con el aviso de que el grafo es una propuesta del
modelo. Cambian dos cosas, y las dos las pide el papel:

- **Fondo y tinta de papel** (``reports.svg.PAPEL``) y los colores semánticos en
  su variante clara (``graph.vocabulario``), sea cual sea el tema de la
  interfaz: la figura es la del documento, no la de la pantalla.
- **La leyenda enumera todo lo que se pinta**, también los tipos que solo
  aparecen en la banda, y las líneas del pie se parten al ancho de la figura en
  vez de salirse por el borde. La cabecera, la leyenda y el pie van un punto más
  grandes y en tinta más oscura que en la pantalla, porque a lo ancho de un A4
  el cuerpo de la vista queda en cuatro puntos. El DIBUJO no cambia de cuerpo:
  su sitio lo reservó ``graph.layout`` con los tamaños de la vista.

Si el caso no tiene red (ninguna entidad relacionada con otra) pero sí
entidades, la banda sube bajo la cabecera en lugar de dejar encima el lienzo
vacío de una red que no existe.

Los radios, las dos líneas de etiqueta y los cuerpos de letra son los del
cliente y los de ``graph.layout``, que reservó el sitio de cada nodo con ellos:
si divergen, la figura vuelve a solaparse.

Lógica pura (RULE 3): recibe la figura ya colocada y devuelve SVG.
"""

from __future__ import annotations

import math
from typing import Any

from agentopsy.graph.layout import RADIO_NODO, etiqueta_de_nodo
from agentopsy.graph.modelo import TIPOS_NODO
from agentopsy.graph.vocabulario import (
    color_nodo,
    color_relacion,
    rotulo_nodo,
    rotulo_relacion,
)
from agentopsy.i18n import t
from agentopsy.reports.svg import PAPEL, Figura, ancho_de_texto, partir_en_lineas

_MARGEN_X = 30
_CABECERA = 92
#: Pie con UNA línea de nodos, UNA de relaciones y DOS de procedencia. Crece con
#: las que haga falta añadir.
_PIE_BASE = 128
_ALTO_LINEA_PIE = 17

_LINEA_VALOR = RADIO_NODO + 15
_LINEA_TIPO = RADIO_NODO + 27

_LEYENDA_X = _MARGEN_X + 88
_LEYENDA_LINEA = 24
_LEYENDA_AIRE = 26
_MUESTRA_NODO = 15
_MUESTRA_RELACION = 20

#: Cuando no hay red, cuánto aire queda entre la raya de la cabecera y la raya
#: que abre la banda.
_AIRE_BANDA_SIN_RED = 10

#: Cuerpos del DIBUJO: los de la vista y los de la reserva de sitio de
#: ``graph.layout``.
_F_VALOR = 10.5
_F_TIPO = 9
_F_RELACION = 9.5
#: Cuerpos del MARCO (cabecera, leyenda y pie), un punto por encima de la vista.
_F_TITULO = 18
_F_SUBTITULO = 13
_F_RECUENTO = 12
_F_BANDA = 12
_F_RUBRICA = 10
_F_LEYENDA = 12
_F_PIE = 11


def _abreviatura(tipo: str) -> str:
    """El «icono» del nodo, dentro de la forma: una abreviatura en el idioma del
    informe. Un tipo que el vocabulario no declara lleva «?», como en la vista."""
    return t(f"figure.graph.abbr.{tipo}") if tipo in TIPOS_NODO else "?"


def _forma(figura: Figura, tipo: str, x: float, y: float, color: str) -> None:
    """Forma por tipo, redundante con el color para que la figura se lea en
    escala de grises o para quien no distinga dos de los tonos."""
    r = RADIO_NODO
    if tipo == "user":
        figura.circulo(x, y, r, fill=color)
    elif tipo == "domain":
        figura.poligono([(x, y - r), (x + r, y), (x, y + r), (x - r, y)], fill=color)
    elif tipo == "ip":
        figura.poligono(
            [
                (x + r * math.cos(math.pi / 3 * i - math.pi / 6),
                 y + r * math.sin(math.pi / 3 * i - math.pi / 6))
                for i in range(6)
            ],
            fill=color,
        )
    elif tipo == "hostname":
        figura.rect(x - r, y - r * 0.8, r * 2, r * 1.6, fill=color)
    else:  # file, y cualquier tipo que el vocabulario no conozca
        figura.rect(x - r, y - r, r * 2, r * 2, fill=color)


def _dibujo(
    figura: Figura,
    nodos: list[dict[str, Any]],
    relaciones: list[dict[str, Any]],
    dx: float,
    dy: float,
) -> None:
    """Aristas, rótulos de relación y nodos, en ese orden: primero TODAS las
    líneas y luego TODOS los rótulos, para que la línea de una arista posterior no
    tache el rótulo de la anterior."""
    posicion = {str(n["valor"]): n for n in nodos}
    trazos = []
    for r in relaciones:
        a = posicion.get(str(r["origen"]))
        b = posicion.get(str(r["destino"]))
        if a is None or b is None:
            continue
        x1, y1 = a["x"] + dx, a["y"] + dy
        x2, y2 = b["x"] + dx, b["y"] + dy
        trazos.append((r, x1, y1, x2, y2, math.atan2(y2 - y1, x2 - x1)))

    for r, x1, y1, x2, y2, angulo in trazos:
        color = color_relacion(str(r["tipo"]))
        # La línea se acorta en los dos extremos para que la punta de flecha
        # toque el borde del nodo y no su centro.
        ox = math.cos(angulo) * (RADIO_NODO + 2)
        oy = math.sin(angulo) * (RADIO_NODO + 2)
        px, py = x2 - ox, y2 - oy
        figura.linea(x1 + ox, y1 + oy, px, py, stroke=color, grosor=1.4)
        punta = 7
        figura.poligono(
            [
                (px, py),
                (px - punta * math.cos(angulo - 0.4), py - punta * math.sin(angulo - 0.4)),
                (px - punta * math.cos(angulo + 0.4), py - punta * math.sin(angulo + 0.4)),
            ],
            fill=color,
        )

    for r, x1, y1, x2, y2, _angulo in trazos:
        texto = rotulo_relacion(str(r["tipo"]))
        caja = ancho_de_texto(texto, _F_RELACION) + 10
        # A dos tercios hacia el destino: en un concentrador, a mitad de camino
        # todos los rótulos se juntaban sobre el nombre del nodo.
        mx = x1 + (x2 - x1) * 0.62
        my = y1 + (y2 - y1) * 0.62
        figura.rect(
            mx - caja / 2, my - 8, caja, 15,
            fill=PAPEL["fondo"], stroke=PAPEL["filete"], grosor=0.8,
        )
        figura.texto(
            mx, my + 3, texto, tamano=_F_RELACION, color=PAPEL["cuerpo"], ancla="middle"
        )

    for n in nodos:
        tipo = str(n["tipo"])
        x, y = n["x"] + dx, n["y"] + dy
        _forma(figura, tipo, x, y, color_nodo(tipo))
        figura.texto(
            x, y + 4, _abreviatura(tipo),
            tamano=9, color=PAPEL["fondo"], mono=True, negrita=True, ancla="middle",
        )
        figura.texto(
            x, y + _LINEA_VALOR, etiqueta_de_nodo(str(n["valor"])),
            tamano=_F_VALOR, color=PAPEL["tinta"], mono=True, negrita=True, ancla="middle",
        )
        figura.texto(
            x, y + _LINEA_TIPO, rotulo_nodo(tipo),
            tamano=_F_TIPO, color=PAPEL["apagado"], ancla="middle",
        )


def _por_linea(entradas: int, caben: int) -> int:
    """Entradas por línea de leyenda, EQUILIBRADAS: cinco con sitio para cuatro
    se reparten 3 + 2, no 4 + 1."""
    if entradas <= caben:
        return max(1, entradas)
    return math.ceil(entradas / math.ceil(entradas / caben))


def _tipos_presentes(nodos: list[dict[str, Any]]) -> list[str]:
    """Los tipos que la figura PINTA, en el orden de la enum; uno que la enum no
    declare va detrás, por nombre, en vez de quedarse sin leyenda."""
    presentes = {str(n["tipo"]) for n in nodos}
    conocidos = [tipo for tipo in TIPOS_NODO if tipo in presentes]
    return conocidos + sorted(presentes - set(TIPOS_NODO))


def svg_grafo_del_caso(
    figura_caso: dict[str, Any],
    *,
    case_name: str,
    compuesta_en: str,
) -> str:
    """La figura del grafo del caso. ``figura_caso`` es lo que devuelve
    ``graph.figura.figura_del_caso`` y tiene que traer al menos una entidad (en la
    red o en la banda): sin entidades no hay figura, y quien compone el anexo lo
    dice con palabras."""
    red: list[dict[str, Any]] = figura_caso["nodos"]
    relaciones: list[dict[str, Any]] = figura_caso["relaciones"]
    lienzo = figura_caso["lienzo"]
    banda = figura_caso["inventario"] if figura_caso["inventario"] else None
    sueltos: list[dict[str, Any]] = banda["nodos"] if banda else []
    if not red and not sueltos:
        raise ValueError("the case graph figure needs at least one entity")

    ancho = float(lienzo["ancho"]) + 2 * _MARGEN_X
    dx = float(_MARGEN_X)
    dy = float(_CABECERA)

    # Sin red, la banda sube: no se deja el lienzo vacío de una red inexistente.
    if banda and not red:
        subida = float(banda["y"]) - _AIRE_BANDA_SIN_RED
        alto_dibujo = float(banda["lienzo"]["alto"]) - subida
    elif banda:
        subida = 0.0
        alto_dibujo = float(banda["lienzo"]["alto"])
    else:
        subida = 0.0
        alto_dibujo = float(lienzo["alto"])
    sueltos_colocados = [{**n, "y": float(n["y"]) - subida} for n in sueltos]
    todos = red + sueltos_colocados
    total = len(todos)

    tipos = _tipos_presentes(todos)
    tipos_relacion = sorted({str(r["tipo"]) for r in relaciones})
    ancho_columna = (
        max(
            [0.0]
            + [_MUESTRA_NODO + ancho_de_texto(rotulo_nodo(x), _F_LEYENDA) for x in tipos]
            + [
                _MUESTRA_RELACION + ancho_de_texto(rotulo_relacion(x), _F_LEYENDA)
                for x in tipos_relacion
            ]
        )
        + _LEYENDA_AIRE
    )
    caben = max(1, math.floor((ancho - _MARGEN_X - _LEYENDA_X + _LEYENDA_AIRE) / ancho_columna))
    nodos_por_linea = _por_linea(len(tipos), caben)
    relaciones_por_linea = _por_linea(len(tipos_relacion), caben)
    lineas_nodos = max(1, math.ceil(len(tipos) / nodos_por_linea))
    lineas_relaciones = max(1, math.ceil(len(tipos_relacion) / relaciones_por_linea))

    ancho_pie = ancho - 2 * _MARGEN_X
    lineas_pie = [
        (linea, True)
        for linea in partir_en_lineas(
            t(
                "figure.graph.provenance",
                case=case_name,
                date=compuesta_en,
                nodes=total,
                edges=len(relaciones),
            ),
            ancho_pie,
            _F_PIE,
            mono=True,
        )
    ] + [
        (linea, False)
        for linea in partir_en_lineas(t("graph.proposalNotice"), ancho_pie, _F_PIE)
    ]
    pie = (
        _PIE_BASE
        + (lineas_nodos + lineas_relaciones - 2) * _LEYENDA_LINEA
        + (len(lineas_pie) - 2) * _ALTO_LINEA_PIE
    )
    alto = alto_dibujo + _CABECERA + pie

    figura = Figura(ancho, alto)

    # ── cabecera ──
    figura.texto(
        _MARGEN_X, 34, t("figure.graph.title"),
        tamano=_F_TITULO, color=PAPEL["tinta"], negrita=True,
    )
    figura.texto(
        _MARGEN_X, 54,
        t(
            "figure.graph.subtitle",
            nodes=total,
            edges=len(relaciones),
            findings=len(figura_caso["hallazgos"]),
        ),
        tamano=_F_SUBTITULO, color=PAPEL["apagado"],
    )
    recuento = t("figure.graph.counts", nodes=total, edges=len(relaciones))
    pildora = max(156.0, ancho_de_texto(recuento, _F_RECUENTO, mono=True) + 24)
    figura.rect(ancho / 2 - pildora / 2, 22, pildora, 24, stroke=PAPEL["filete"], grosor=1)
    figura.texto(
        ancho / 2, 38, recuento,
        tamano=_F_RECUENTO, color=PAPEL["cuerpo"], mono=True, ancla="middle",
    )
    figura.linea(
        _MARGEN_X, _CABECERA - 20, ancho - _MARGEN_X, _CABECERA - 20,
        stroke=PAPEL["filete"], grosor=1,
    )

    # ── dibujo ──
    _dibujo(figura, todos, relaciones, dx, dy)

    # ── banda de entidades sin relación ──
    if banda:
        y_raya = dy + float(banda["y"]) - subida
        figura.linea(
            _MARGEN_X, y_raya, ancho - _MARGEN_X, y_raya,
            stroke=PAPEL["filete"], grosor=1, trazo="3 3",
        )
        figura.texto(
            _MARGEN_X, y_raya + 24, t("figure.graph.inventoryBand", count=banda["total"]),
            tamano=_F_BANDA, color=PAPEL["cuerpo"],
        )

    # ── leyenda ──
    def y_linea(i: int) -> float:
        return alto - pie + 26 + i * _LEYENDA_LINEA

    def x_columna(c: int) -> float:
        return _LEYENDA_X + c * ancho_columna

    figura.linea(
        _MARGEN_X, alto - pie + 8, ancho - _MARGEN_X, alto - pie + 8,
        stroke=PAPEL["filete"], grosor=1,
    )
    figura.texto(
        _MARGEN_X, y_linea(0) + 4, t("figure.graph.legendNodes"),
        tamano=_F_RUBRICA, color=PAPEL["apagado"], mono=True, espaciado=0.6,
    )
    for i, tipo in enumerate(tipos):
        x = x_columna(i % nodos_por_linea)
        y = y_linea(i // nodos_por_linea)
        figura.rect(x, y - 7, 9, 9, fill=color_nodo(tipo))
        figura.texto(
            x + _MUESTRA_NODO, y + 1, rotulo_nodo(tipo),
            tamano=_F_LEYENDA, color=PAPEL["cuerpo"],
        )
    figura.texto(
        _MARGEN_X, y_linea(lineas_nodos) + 4, t("figure.graph.legendEdges"),
        tamano=_F_RUBRICA, color=PAPEL["apagado"], mono=True, espaciado=0.6,
    )
    for i, tipo in enumerate(tipos_relacion):
        x = x_columna(i % relaciones_por_linea)
        y = y_linea(lineas_nodos + i // relaciones_por_linea)
        figura.linea(x, y - 3, x + 14, y - 3, stroke=color_relacion(tipo), grosor=1.6)
        figura.texto(
            x + _MUESTRA_RELACION, y + 1, rotulo_relacion(tipo),
            tamano=_F_LEYENDA, color=PAPEL["cuerpo"],
        )
    if not tipos_relacion:
        figura.texto(
            _LEYENDA_X, y_linea(lineas_nodos) + 4, t("figure.graph.na"),
            tamano=_F_LEYENDA, color=PAPEL["apagado"],
        )

    # ── procedencia y aviso, DENTRO de la figura ──
    for i, (linea, mono) in enumerate(lineas_pie):
        figura.texto(
            _MARGEN_X, alto - 18 - (len(lineas_pie) - 1 - i) * _ALTO_LINEA_PIE, linea,
            tamano=_F_PIE, color=PAPEL["apagado"], mono=mono,
        )
    return figura.svg()


__all__ = ["svg_grafo_del_caso"]
