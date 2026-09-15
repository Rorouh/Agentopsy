"""Cómo se LEEN y de qué color se pintan las dos enums cerradas del grafo.

Misma regla que ``agentopsy.timeline.vocabulario``, de donde se reutiliza
:func:`etiqueta`: un valor que no esté en la tabla sale **TAL CUAL**. Aquí esa
regla es aún más estricta que allí, porque las dos enums se validan en el
servidor: un tipo que no esté en la tabla NO puede llegar a un grafo persistido
(``modelo._validar_nodos`` lo habría rechazado antes). La tabla que se queda sin
respaldo es, por tanto, la garantía de que estas etiquetas y las enums no se
desincronizan en silencio: si alguien añade un tipo y olvida su etiqueta, la
leyenda enseña el id ``snake_case``, que es dato, en vez de una traducción
inventada.

Los ids viajan igualmente a la interfaz: son el dato (lo que el modelo propuso y
lo que se persiste), y la etiqueta es solo cómo se lee. Las tablas son de CLAVES
del catálogo (``graphNode.*`` y ``graphEdge.*``), no de texto, porque la figura
del grafo que se congela en el informe pericial (``reports.figura_grafo``) se lee
en el idioma del informe.

Los COLORES son semánticos (dicen de qué tipo es la entidad) y son los de papel:
los mismos que el cliente usa en claro (``web/src/pages/graphs/vocabulario.ts``,
variante ``claro``). Aquí solo hace falta esa variante, porque la figura del
informe va siempre sobre fondo blanco; ``test_figuras_informe`` comprueba que
las dos tablas dicen lo mismo.
"""

from __future__ import annotations

from agentopsy.timeline.vocabulario import etiqueta

#: Tipo de NODO. Los cinco de la enum cerrada (``modelo.TIPOS_NODO``).
NODO_KEY: dict[str, str] = {
    "ip": "graphNode.ip",
    "domain": "graphNode.domain",
    "hostname": "graphNode.hostname",
    "user": "graphNode.user",
    "file": "graphNode.file",
}

#: Tipo de RELACIÓN. Los trece de la enum cerrada (``modelo.TIPOS_RELACION``).
RELACION_KEY: dict[str, str] = {
    "connection": "graphEdge.connection",
    "process_spawn": "graphEdge.process_spawn",
    "network_connection": "graphEdge.network_connection",
    "lateral_move": "graphEdge.lateral_move",
    "malware": "graphEdge.malware",
    "c2": "graphEdge.c2",
    "exfiltration": "graphEdge.exfiltration",
    "beacon": "graphEdge.beacon",
    "persistence": "graphEdge.persistence",
    "priv_esc": "graphEdge.priv_esc",
    "rce": "graphEdge.rce",
    "logon": "graphEdge.logon",
    "file_transfer": "graphEdge.file_transfer",
}

#: Color de papel de cada tipo de nodo.
NODO_COLOR: dict[str, str] = {
    "ip": "#2f7d4f",
    "domain": "#b26206",
    "hostname": "#0f7b8a",
    "user": "#6b4bab",
    "file": "#4a4a52",
}

#: Color de papel de cada tipo de relación.
RELACION_COLOR: dict[str, str] = {
    "connection": "#7a7a84",
    "process_spawn": "#6b4bab",
    "network_connection": "#3d7fb8",
    "lateral_move": "#b26206",
    "malware": "#c4553f",
    "c2": "#a51f3d",
    "exfiltration": "#8c3a2b",
    "beacon": "#0f7b8a",
    "persistence": "#9a7a10",
    "priv_esc": "#7d2b3f",
    "rce": "#a51f3d",
    "logon": "#2f7d4f",
    "file_transfer": "#3d7fb8",
}

#: Un tipo desconocido se pinta con el gris neutro: no se le inventa un color
#: semántico que afirmaría algo sobre él.
COLOR_NEUTRO = "#7a7a84"


def rotulo_nodo(tipo: str) -> str:
    """Cómo se lee un tipo de nodo en el idioma en curso; el id si no se conoce."""
    return etiqueta(NODO_KEY, tipo)


def rotulo_relacion(tipo: str) -> str:
    """Cómo se lee un tipo de relación en el idioma en curso; el id si no se conoce."""
    return etiqueta(RELACION_KEY, tipo)


def color_nodo(tipo: str) -> str:
    return NODO_COLOR.get(tipo, COLOR_NEUTRO)


def color_relacion(tipo: str) -> str:
    return RELACION_COLOR.get(tipo, COLOR_NEUTRO)


__all__ = [
    "COLOR_NEUTRO",
    "NODO_COLOR",
    "NODO_KEY",
    "RELACION_COLOR",
    "RELACION_KEY",
    "color_nodo",
    "color_relacion",
    "etiqueta",
    "rotulo_nodo",
    "rotulo_relacion",
]
