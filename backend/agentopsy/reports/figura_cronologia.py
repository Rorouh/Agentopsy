"""La FIGURA de la línea de tiempo del incidente, tal y como va en el informe.

Es la misma figura que la vista Timeline dibuja y exporta
(``web/src/pages/timeline/IncidentRail.tsx``): el mismo raíl, un evento por
hallazgo con su marca del artefacto, su severidad y sus técnicas, el bloque de
procedencia arriba y lo que no se pudo situar declarado abajo. Cambian tres
cosas, y las tres las pide el papel:

- **Fondo y tinta de papel** (``reports.svg.PAPEL``), sea cual sea el tema de la
  interfaz: la figura es la del documento, no la de la pantalla.
- **Ancho de hoja.** La vista mide 1120 unidades; aquí 840, con los mismos
  cuerpos de letra, para que a lo ancho de un A4 el título de un evento se lea a
  unos nueve puntos en vez de a seis. Por la misma razón la severidad va en
  negrita y lo que quedó fuera del eje en tinta de cuerpo y no en gris claro: el
  monoespaciado de las fuentes base es fino, y en papel el gris claro no se lee.
- **Partes que caben en una hoja.** Una línea de tiempo larga partida por el salto
  de página del PDF dejaría eventos cortados, y una sola figura altísima
  reducida a una hoja sería ilegible. Así que se trocea por EVENTOS ENTEROS en
  partes que caben en la hoja del PDF (``pdf.ALTO_UTIL_MM``), cada una con su
  cabecera y su «(1 de 3)», y lo que quedó fuera del eje va al pie de la última.

Los títulos de los eventos son texto que escribió el agente, así que pasan por la
tipografía del informe (``reports.estilo``); el resto del texto es dato (una
marca temporal, un id de técnica) o catálogo.

Lógica pura (RULE 3): recibe la cronología ya ensamblada
(``timeline.hallazgos.assemble_findings_timeline``) y devuelve SVG.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from agentopsy.i18n import t
from agentopsy.reports.estilo import sanear_estilo
from agentopsy.reports.pdf import AIRE_FIGURA_MM, ALTO_UTIL_MM, ANCHO_UTIL_MM
from agentopsy.reports.svg import PAPEL, SEVERIDAD_PAPEL, Figura, partir_en_lineas

# ── métrica, en unidades del SVG ──────────────────────────────────────────────
ANCHO = 840
_PAD = 32
#: La marca temporal completa, `01/04/2021, 15:32:11 (UTC)`, son 26 caracteres.
_ANCHO_HORA = 200
_RAIL_X = _PAD + _ANCHO_HORA + 20
_CONTENIDO_X = _RAIL_X + 24
_CONTENIDO_ANCHO = ANCHO - _PAD - _CONTENIDO_X

_F_CABECERA = 17
_F_TITULO = 15
_F_MONO = 12
_F_SEVERIDAD = 10.5
_F_TECNICA = 12

_H_SEVERIDAD = 17
_H_TITULO = 21
_H_TECNICA = 18
_H_LINEA_MONO = 17
_HUECO_FILA = 22
_RADIO_MARCA = 5

#: De la raya de la cabecera a la primera fila, y de la última fila al borde de
#: una parte que no es la última (el hueco de la fila ya deja aire).
_RAYA_A_FILAS = 36
_CIERRE = 12

#: Lo más alta que puede ser una parte: la hoja útil del PDF menos el aire de la
#: figura, pasada a unidades del SVG a lo ancho útil de la hoja. Sale de las
#: medidas del PDF y no se escribe a mano, para que cambiar un margen no deje
#: partes que ya no caben.
ALTO_MAX_PARTE = math.floor((ALTO_UTIL_MM - 2 * AIRE_FIGURA_MM) * ANCHO / ANCHO_UTIL_MM)


@dataclass(frozen=True)
class LineaDeTiempo:
    """Las partes de la figura, en orden, y cuántos títulos reescribió la
    tipografía del informe (va a la auditoría: se normaliza a la vista)."""

    partes: tuple[str, ...]
    titulos_normalizados: int


@dataclass(frozen=True)
class _Fila:
    evento: dict[str, Any]
    titulo: tuple[str, ...]
    tecnicas: tuple[str, ...]
    alto: float


def marca_utc(ts: str) -> str:
    """``2021-04-01T15:32:11Z`` como ``01/04/2021, 15:32:11 (UTC)``, el formato de
    la vista. La zona va ESCRITA en cada marca: una hora sin zona en una figura
    pericial es una hora que hay que ir a buscar a otra parte."""
    try:
        momento = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return ts
    return momento.strftime("%d/%m/%Y, %H:%M:%S (UTC)")


def _etiqueta_tecnica(tecnica: dict[str, Any]) -> str:
    """``T1041 · Exfiltración``. Sin táctica, la técnica sola: nunca una táctica
    adivinada (RULE 2)."""
    if tecnica.get("tactic"):
        return f"{tecnica['technique_id']} · {tecnica['tactic']}"
    return str(tecnica["technique_id"])


def _cabecera(
    parte: int,
    partes: int,
    case_name: str,
    compuesta_en: str,
    cronologia: dict[str, Any],
) -> tuple[str, list[str]]:
    """El título de la parte y las líneas de procedencia, partidas al ancho."""
    titulo = (
        t("figure.rail.title")
        if partes == 1
        else t("figure.rail.titlePart", part=parte, parts=partes)
    )
    ancho = ANCHO - 2 * _PAD
    lineas = partir_en_lineas(t("figure.rail.case", name=case_name), ancho, _F_MONO, mono=True)
    lineas += partir_en_lineas(
        t(
            "figure.rail.composed",
            date=compuesta_en,
            shown=len(cronologia["eventos"]),
            total=cronologia["total_hallazgos"],
        ),
        ancho,
        _F_MONO,
        mono=True,
    )
    return titulo, lineas


def _alto_cabecera(lineas: list[str]) -> float:
    """``y`` de la primera fila: título, líneas de procedencia, raya y aire."""
    return _y_raya(lineas) + _RAYA_A_FILAS


def _y_raya(lineas: list[str]) -> float:
    return _PAD + 26 + (len(lineas) - 1) * _H_LINEA_MONO + 13


def _fuera_del_eje(cronologia: dict[str, Any]) -> list[str]:
    fuera: list[str] = []
    if cronologia["sin_observed_at"]:
        fuera.append(t("figure.rail.noObservedAt", count=cronologia["sin_observed_at"]))
    if cronologia["no_parseable"]:
        valores = ", ".join(cronologia["no_parseable_valores"])
        fuera.append(
            t("figure.rail.unparseable", count=cronologia["no_parseable"])
            + (f": {valores}" if valores else "")
            + (t("figure.rail.listTrimmed") if cronologia["no_parseable_truncado"] else "")
        )
    if not fuera:
        return [t("figure.rail.allPlaced", count=cronologia["total_hallazgos"])]
    ancho = ANCHO - 2 * _PAD
    return [
        linea
        for texto in fuera
        for linea in partir_en_lineas(texto, ancho, _F_MONO, mono=True)
    ]


def _alto_pie(fuera: list[str]) -> float:
    """Lo que el pie añade bajo la última fila, hasta el borde de la figura."""
    return 56 + len(fuera) * _H_LINEA_MONO


def _partir(filas: list[_Fila], alto_cabecera: float, alto_pie: float) -> list[list[_Fila]]:
    """Las filas agrupadas en partes que caben en ``ALTO_MAX_PARTE``.

    Por EVENTOS ENTEROS: una fila no se parte nunca. La última fila viaja con el
    pie, para que «Fuera del eje» no acabe solo en una parte sin eventos. Una fila
    que por sí sola no cabe va sola en su parte, y el PDF la reduce."""
    partes: list[list[_Fila]] = []
    actual: list[_Fila] = []
    alto = alto_cabecera
    for indice, fila in enumerate(filas):
        cierre = alto_pie if indice == len(filas) - 1 else _CIERRE
        if actual and alto + fila.alto + cierre > ALTO_MAX_PARTE:
            partes.append(actual)
            actual = []
            alto = alto_cabecera
        actual.append(fila)
        alto += fila.alto
    if actual:
        partes.append(actual)
    return partes


def svg_linea_de_tiempo(
    cronologia: dict[str, Any], *, case_name: str, compuesta_en: str
) -> LineaDeTiempo:
    """La figura de la línea de tiempo en partes. Sin eventos en el eje, ninguna
    parte: quien compone el anexo dice entonces por qué (``cronologia["message"]``)."""
    normalizados = 0
    filas: list[_Fila] = []
    for evento in cronologia["eventos"]:
        original = str(evento["title"])
        titulo = sanear_estilo(original)
        if titulo != original:
            normalizados += 1
        lineas_titulo = partir_en_lineas(titulo, _CONTENIDO_ANCHO, _F_TITULO)
        # UNA técnica por línea: encadenadas se leen como una sola cosa.
        tecnicas = [
            linea
            for tecnica in evento["mitre"]
            for linea in partir_en_lineas(
                _etiqueta_tecnica(tecnica), _CONTENIDO_ANCHO, _F_TECNICA, mono=True
            )
        ]
        alto = (
            _H_SEVERIDAD
            + len(lineas_titulo) * _H_TITULO
            + len(tecnicas) * _H_TECNICA
            + _HUECO_FILA
        )
        filas.append(_Fila(evento, tuple(lineas_titulo), tuple(tecnicas), alto))

    if not filas:
        return LineaDeTiempo(partes=(), titulos_normalizados=0)

    fuera = _fuera_del_eje(cronologia)
    # El número de partes no cambia el alto de la cabecera (el «(1 de 3)» cabe en
    # la línea del título), así que se mide con una y se reparte después.
    _, lineas_muestra = _cabecera(1, 1, case_name, compuesta_en, cronologia)
    grupos = _partir(filas, _alto_cabecera(lineas_muestra), _alto_pie(fuera))

    partes: list[str] = []
    for numero, grupo in enumerate(grupos, 1):
        ultima = numero == len(grupos)
        titulo, lineas = _cabecera(numero, len(grupos), case_name, compuesta_en, cronologia)
        partes.append(_dibujar_parte(grupo, titulo, lineas, fuera if ultima else None))
    return LineaDeTiempo(partes=tuple(partes), titulos_normalizados=normalizados)


def _dibujar_parte(
    filas: list[_Fila], titulo: str, lineas: list[str], fuera: list[str] | None
) -> str:
    y_primera = _alto_cabecera(lineas)
    posiciones: list[float] = []
    y = y_primera
    for fila in filas:
        posiciones.append(y)
        y += fila.alto
    abajo = y
    alto = abajo + (_alto_pie(fuera) if fuera is not None else _CIERRE)

    figura = Figura(ANCHO, alto)

    # Procedencia, DENTRO de la imagen.
    figura.texto(_PAD, _PAD + 6, titulo, tamano=_F_CABECERA, color=PAPEL["tinta"], negrita=True)
    for i, linea in enumerate(lineas):
        figura.texto(
            _PAD, _PAD + 26 + i * _H_LINEA_MONO, linea,
            tamano=_F_MONO, color=PAPEL["apagado"], mono=True,
        )
    y_raya = _y_raya(lineas)
    figura.linea(_PAD, y_raya, ANCHO - _PAD, y_raya, stroke=PAPEL["filete"], grosor=1)

    # El raíl muere en la ÚLTIMA MARCA: una línea que la sobrepasa sugiere que la
    # cronología sigue.
    figura.linea(
        _RAIL_X, posiciones[0] + 2, _RAIL_X, posiciones[-1] + 8,
        stroke=PAPEL["filete"], grosor=2,
    )

    for fila, y_fila in zip(filas, posiciones, strict=True):
        evento = fila.evento
        # Una severidad fuera de la tabla (un hallazgo antiguo) se pinta en gris:
        # no se le inventa un color que afirmaría un grado. La etiqueta la dice.
        color = SEVERIDAD_PAPEL.get(evento["severity"], PAPEL["tenue"])
        marca_y = y_fila + 8
        figura.texto(
            _RAIL_X - 20, marca_y + 4, marca_utc(evento["ts"]),
            tamano=_F_MONO, color=PAPEL["cuerpo"], mono=True, ancla="end",
        )
        figura.circulo(_RAIL_X, marca_y, _RADIO_MARCA, fill=color)
        figura.texto(
            _CONTENIDO_X, marca_y + 4, str(evento["severity_label"]).upper(),
            tamano=_F_SEVERIDAD, color=color, mono=True, negrita=True, espaciado=0.84,
        )
        for i, linea in enumerate(fila.titulo):
            figura.texto(
                _CONTENIDO_X, y_fila + _H_SEVERIDAD + 14 + i * _H_TITULO, linea,
                tamano=_F_TITULO, color=PAPEL["tinta"],
            )
        base_tecnicas = y_fila + _H_SEVERIDAD + len(fila.titulo) * _H_TITULO + 12
        for i, linea in enumerate(fila.tecnicas):
            figura.texto(
                _CONTENIDO_X, base_tecnicas + i * _H_TECNICA, linea,
                tamano=_F_TECNICA, color=PAPEL["acento"], mono=True,
            )

    if fuera is not None:
        # Lo que no se pudo situar en el eje: dentro de la imagen, no al lado.
        figura.linea(_PAD, abajo + 20, ANCHO - _PAD, abajo + 20, stroke=PAPEL["filete"], grosor=1)
        figura.texto(
            _PAD, abajo + 40, t("figure.rail.outside"),
            tamano=_F_MONO, color=PAPEL["apagado"], mono=True,
        )
        for i, linea in enumerate(fuera):
            figura.texto(
                _PAD, abajo + 58 + i * _H_LINEA_MONO, linea,
                tamano=_F_MONO, color=PAPEL["cuerpo"], mono=True,
            )
    return figura.svg()


__all__ = ["ALTO_MAX_PARTE", "ANCHO", "LineaDeTiempo", "marca_utc", "svg_linea_de_tiempo"]
