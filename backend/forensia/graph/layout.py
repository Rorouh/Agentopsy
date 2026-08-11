"""La GEOMETRÍA del grafo, determinista y calculada en el servidor.

Por qué no hay simulación de fuerzas. Es lo que hace la referencia (Nexus) y es
lo que no sirve aquí: una simulación con semilla aleatoria dibuja el MISMO grafo
distinto en cada render, y una figura que se adjunta a un informe pericial tiene
que ser reproducible, es decir, el mismo grafo tiene que dar la misma imagen hoy
y dentro de un año. Así que la posición de cada nodo sale de una función pura de
(identificador, tipo, valor): mismo grafo, misma imagen, en cualquier máquina.

Por qué en el backend y no en el navegador. La reproducibilidad no puede depender
de la versión del navegador ni del orden en que React monte los componentes, y la
lógica vive en ``forensia/*`` (RULE 3). El cliente recibe coordenadas y pinta.

Dos figuras distintas, porque dos problemas distintos:

- **Grafo de un hallazgo**: pocos nodos (medido: entre 0 y 15). Estrella. El nodo
  de mayor grado va al centro y el resto a un anillo, que es como se lee
  «IEUser ejecutó estos tres ficheros» de un vistazo. Sin aristas, anillo simple.
- **Grafo del caso**: decenas de nodos (medido: 63). Una estrella se vuelve una
  maraña, así que van ANILLOS CONCÉNTRICOS POR TIPO, con las cuentas y los
  equipos dentro y los ficheros fuera, que es donde se acumulan.

El desfase angular sale de un hash del identificador (``finding_id`` o
``case_id``). No es azar: es una constante distinta por figura para que dos
grafos del mismo caso no salgan calcados, y es estable porque el hash lo es.
"""

from __future__ import annotations

import hashlib
import math
from typing import Any

#: Lienzo de la figura, en unidades de ``viewBox``. El cliente escala; aquí solo
#: existen para que las coordenadas sean absolutas y comparables.
ANCHO = 1000
ALTO = 700

#: Margen para que la etiqueta de un nodo del borde no se salga del lienzo.
_MARGEN = 110

#: Orden de los anillos del grafo del caso, de dentro afuera. Las entidades que
#: más aristas concentran (cuentas, equipos) van dentro para que sus aristas
#: crucen lo menos posible.
ANILLOS: tuple[str, ...] = ("user", "hostname", "ip", "domain", "file")


def _desfase(semilla: str) -> float:
    """Un ángulo en [0, 2pi) derivado del identificador. Estable por definición."""
    h = hashlib.sha256(semilla.encode("utf-8")).hexdigest()[:8]
    return (int(h, 16) % 3600) / 3600 * 2 * math.pi


def _punto(cx: float, cy: float, radio: float, angulo: float) -> dict[str, float]:
    return {
        "x": round(cx + radio * math.cos(angulo), 2),
        "y": round(cy + radio * math.sin(angulo), 2),
    }


def _grados(nodos: list[dict[str, Any]], relaciones: list[dict[str, Any]]) -> dict[str, int]:
    grado = {str(n.get("valor")): 0 for n in nodos}
    for r in relaciones:
        for extremo in (str(r.get("origen")), str(r.get("destino"))):
            if extremo in grado:
                grado[extremo] += 1
    return grado


def layout_hallazgo(
    finding_id: str, nodos: list[dict[str, Any]], relaciones: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Estrella determinista para el grafo de UN hallazgo.

    El centro es el nodo de mayor grado, con desempate por (tipo, valor) para que
    no lo decida el orden en que el modelo los declaró, que no es estable.
    """
    if not nodos:
        return []

    grado = _grados(nodos, relaciones)
    cx, cy = ANCHO / 2, ALTO / 2

    if len(nodos) == 1:
        return [{**nodos[0], **_punto(cx, cy, 0, 0), "centro": True}]

    ordenados = sorted(
        nodos, key=lambda n: (-grado.get(str(n.get("valor")), 0), str(n.get("tipo")), str(n.get("valor")))
    )
    hay_centro = grado.get(str(ordenados[0].get("valor")), 0) >= 2
    centro = ordenados[0] if hay_centro else None
    anillo = ordenados[1:] if hay_centro else ordenados

    radio = min(ANCHO, ALTO) / 2 - _MARGEN
    desfase = _desfase(finding_id)
    out: list[dict[str, Any]] = []
    if centro is not None:
        out.append({**centro, **_punto(cx, cy, 0, 0), "centro": True})
    for i, n in enumerate(anillo):
        angulo = desfase + (2 * math.pi * i / max(len(anillo), 1))
        out.append({**n, **_punto(cx, cy, radio, angulo), "centro": False})
    return out


def layout_caso(
    case_id: str, nodos: list[dict[str, Any]], relaciones: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Anillos concéntricos por tipo para el grafo del CASO."""
    if not nodos:
        return []

    cx, cy = ANCHO / 2, ALTO / 2
    por_tipo: dict[str, list[dict[str, Any]]] = {}
    for n in nodos:
        por_tipo.setdefault(str(n.get("tipo")), []).append(n)

    # Solo se reservan anillos para los tipos PRESENTES: con dos tipos, dos
    # anillos bien separados, no dos pegados y tres vacíos.
    presentes = [t for t in ANILLOS if t in por_tipo]
    presentes += [t for t in sorted(por_tipo) if t not in presentes]

    radio_max = min(ANCHO, ALTO) / 2 - _MARGEN
    desfase = _desfase(case_id)
    out: list[dict[str, Any]] = []
    for indice_anillo, tipo in enumerate(presentes):
        del_tipo = sorted(por_tipo[tipo], key=lambda n: str(n.get("valor")))
        # Un anillo interior con UN solo nodo se planta en el centro. Medido
        # sobre un caso real: con una cuenta y once ficheros, la cuenta es el
        # concentrador de todas las aristas y ponerla en una órbita de radio
        # medio dejaba la figura descentrada y las aristas cruzando el hueco.
        if indice_anillo == 0 and len(del_tipo) == 1 and len(presentes) > 1:
            out.append({**del_tipo[0], **_punto(cx, cy, 0, 0), "centro": True})
            continue
        if len(presentes) == 1:
            radio = radio_max
        else:
            radio = radio_max * (indice_anillo + 1) / len(presentes)
        # Cada anillo gira un poco respecto al anterior para que los nodos no
        # queden alineados en radios y las etiquetas no se pisen.
        giro = desfase + indice_anillo * math.pi / max(len(presentes), 1)
        for i, n in enumerate(del_tipo):
            angulo = giro + (2 * math.pi * i / max(len(del_tipo), 1))
            out.append({**n, **_punto(cx, cy, radio, angulo), "centro": False})
    return out


__all__ = ["ALTO", "ANCHO", "ANILLOS", "layout_caso", "layout_hallazgo"]
