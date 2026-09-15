"""FUNCIÓN «INVENTARIO»: la red de relaciones, separada de las entidades sueltas.

Está en prueba (2026-09-04). Para RETIRARLA basta con borrar este fichero, quitar
su uso de ``graph/figura.py`` (la composición que comparten la vista Grafos y el
anexo C del informe pericial) y el suyo del cliente y de ``reports/figura_grafo.py``.
Nada más depende de ella.

Por qué existe, medido sobre el caso real LoneWolf, 20 hallazgos con grafo:

    grafo del caso           82 nodos, 34 aristas
    nodos con grado 0        46, o sea el 56,1 %
    la red de verdad         36 nodos en 2 componentes (29 y 7)

    con los 46 sueltos       lienzo 2620 x 1850, la etiqueta se ve a 4,0 px
    solo la red              lienzo 1258 x  887, la etiqueta se ve a 8,3 px

Es decir: más de la mitad de la figura son entidades que no participan en NINGUNA
relación, y son ellas las que inflan el lienzo hasta dejar los rótulos en cuatro
píxeles. Un grafo de relaciones estaba dibujando un inventario como si fuera una
red.

Lo que NO es esto. No es un filtro ni una poda: los 46 se enseñan enteros, con su
recuento declarado, en la pantalla como lista y dentro del PNG como una banda
rotulada al pie del dibujo. No se descarta un dato del caso (RULE 2): lo que se
deja de hacer es afirmar con la geometría una relación que nadie ha afirmado,
porque colocar una entidad suelta en el mismo anillo que una conectada sugiere
que pertenece a la red, y no pertenece.

Tampoco es un fallo de la extracción que haya que corregir. La regla 2 del
encargo (``i18n_catalogo``, ``gx.rules``) EXIGE exhaustividad y dice literalmente
que un nodo suelto es un resultado correcto y esperado, que es lo que impide
perder un dominio escrito en el texto. El dato está bien; lo que estaba mal era
la figura.

Solo se aplica al grafo del CASO. El de un hallazgo tiene entre 0 y 15 nodos y su
anillo se lee sin ayuda; ahí la banda sería ceremonia sin ganancia.

Lógica pura (RULE 3): sin HTTP, sin disco, sin modelo.
"""

from __future__ import annotations

import math
from typing import Any

from agentopsy.graph.layout import (
    ALTO_ETIQUETA,
    RADIO_NODO,
    ancho_caja,
)

#: Aire entre el borde inferior del dibujo y la raya que abre la banda.
_AIRE_SOBRE_LA_RAYA = 34.0

#: De la raya al centro de la primera fila de la rejilla: cabe el rótulo de la
#: banda y el semialto del disco.
_RAYA_A_PRIMERA_FILA = 58.0

#: Aire bajo la última fila, antes del borde del lienzo.
_AIRE_BAJO_LA_REJILLA = 26.0

#: Márgenes laterales de la rejilla, los mismos que usa el dibujo.
_MARGEN_X = 40.0

#: Separación entre columnas y entre filas de la rejilla, por encima de la caja
#: de cada nodo. La rejilla se coloca de una vez y no pasa por el relajador de
#: ``layout``: es una tabla, no un grafo, así que el sitio se reserva aquí y se
#: cumple por construcción.
_AIRE_COLUMNA = 16.0
_AIRE_FILA = 14.0

#: Alto de la caja de un nodo con sus dos líneas de etiqueta. Mismo cálculo que
#: ``layout._caja``, del que salen las constantes.
_ALTO_CAJA = 2 * RADIO_NODO + ALTO_ETIQUETA


def partir(
    nodos: list[dict[str, Any]], relaciones: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Separa los nodos que participan en alguna relación de los que no.

    El criterio es el grado, no el tipo ni el valor: una entidad está en la red
    si alguna arista la nombra como origen o como destino, y punto. No se juzga
    si un nodo «parece» relevante, que es justo la clase de criterio que dejaría
    fuera un dato del caso.

    Conserva el orden que traían, que ya es determinista (``fusion`` los ordena
    por grado, tipo y valor).
    """
    con_arista: set[str] = set()
    for r in relaciones:
        con_arista.add(str(r.get("origen") or ""))
        con_arista.add(str(r.get("destino") or ""))
    conectados = [n for n in nodos if str(n.get("valor")) in con_arista]
    sueltos = [n for n in nodos if str(n.get("valor")) not in con_arista]
    return conectados, sueltos


def _rejilla(sueltos: list[dict[str, Any]], ancho_disponible: float) -> tuple[int, float]:
    """Cuántas columnas caben y cuánto mide cada una.

    El paso lo fija la etiqueta MÁS ancha de la banda, igual que la rejilla de la
    leyenda: así ninguna entrada invade a la de al lado y la tabla se lee por
    columnas.
    """
    paso = max((ancho_caja(n) for n in sueltos), default=0.0) + _AIRE_COLUMNA
    if paso <= 0:
        return (1, 0.0)
    columnas = max(1, int((ancho_disponible - 2 * _MARGEN_X + _AIRE_COLUMNA) // paso))
    return (columnas, paso)


def componer(figura: dict[str, Any], sueltos: list[dict[str, Any]]) -> dict[str, Any]:
    """Añade a una figura ya colocada la banda de las entidades sueltas.

    ``figura`` es lo que devuelve ``layout_caso`` sobre los nodos CONECTADOS.
    Devuelve la misma estructura, con el lienzo de la RED intacto y un
    ``inventario`` que describe la banda aparte.

    Que el lienzo de la red NO cambie es la decisión que hace que esto sirva de
    algo, y salió de medirlo. La primera versión metía la banda dentro del mismo
    lienzo, y sobre el caso real ese lienzo pasaba de 1258 x 887 a 1258 x 1531:
    la figura volvía a ajustarse al 46 % y la etiqueta se quedaba en 4,8 px, o
    sea casi los 4,0 px de los que se venía. La banda se comía la ganancia
    entera. Ahora la red se dibuja en SU lienzo (79 % de ajuste, etiqueta a
    8,3 px) y la banda se compone aparte:

    - en PANTALLA el inventario no es una figura, es una LISTA, y se lee mejor
      como texto que como 46 discos de cuatro píxeles; no compite con el grafo
      por la ventana;
    - en el PNG sí se compone dentro de la imagen, bajo el dibujo, porque un PNG
      suelto tiene que llevar el caso entero encima.

    La banda tampoco ENSANCHA nunca la figura: sus columnas se calculan sobre el
    ancho que ya tiene la red, y si no caben crece en filas. Así las coordenadas
    de los nodos de la red son las MISMAS en pantalla y en el PNG, que es lo que
    permite decir que se exporta lo que se está mirando.

    Sin sueltos no toca nada y devuelve ``inventario`` a ``None``.
    """
    if not sueltos:
        return {**figura, "inventario": None}

    ancho = int(figura["lienzo"]["ancho"])
    alto_red = int(figura["lienzo"]["alto"])

    columnas, paso_x = _rejilla(sueltos, float(ancho))
    filas = math.ceil(len(sueltos) / columnas)
    paso_y = _ALTO_CAJA + _AIRE_FILA

    y_raya = alto_red + _AIRE_SOBRE_LA_RAYA
    y_primera = y_raya + _RAYA_A_PRIMERA_FILA
    ancho_rejilla = min(columnas, len(sueltos)) * paso_x - _AIRE_COLUMNA
    x_primera = (ancho - ancho_rejilla) / 2 + (paso_x - _AIRE_COLUMNA) / 2

    colocados = []
    for indice, nodo in enumerate(sueltos):
        fila, columna = divmod(indice, columnas)
        colocados.append({
            **nodo,
            "x": round(x_primera + columna * paso_x, 2),
            "y": round(y_primera + fila * paso_y, 2),
            "centro": False,
            # Lo lee el cliente para no confundirlos con la red: la banda ya los
            # separa, y esto lo hace explícito en el dato.
            "suelto": True,
        })

    alto_con_banda = int(
        math.ceil(y_primera + (filas - 1) * paso_y + _ALTO_CAJA / 2 + _AIRE_BAJO_LA_REJILLA)
    )

    return {
        "nodos": figura["nodos"],
        "lienzo": figura["lienzo"],
        "notas": figura["notas"],
        "inventario": {
            "total": len(sueltos),
            "en_la_red": len(figura["nodos"]),
            "nodos": colocados,
            #: `y` de la raya que abre la banda y lienzo de la figura CON banda,
            #: los dos en las coordenadas de la EXPORTACIÓN.
            "y": round(y_raya, 2),
            "lienzo": {"ancho": ancho, "alto": alto_con_banda},
        },
    }


__all__ = ["componer", "partir"]
