"""Grafos de relaciones: qué se conecta con qué dentro de un hallazgo.

Donde la línea de tiempo del incidente (``forensia.timeline.hallazgos``) responde
«cuándo pasó», el grafo responde «qué se conecta con qué»: qué equipo, qué cuenta,
qué fichero, qué dominio y qué IP intervienen en un hallazgo, y con qué relación.

Es una PROPUESTA del modelo sobre el texto del hallazgo, no un hecho verificado
como lo son un hash o un argv auditado, y así se etiqueta en toda superficie que
lo enseñe. Lo que sí es verificable es su procedencia: cada grafo se persiste con
su SHA-256 y su extracción queda en el log encadenado con el argv literal de la
corrida del ejecutor.

Y el grafo del CASO (``fusion``) funde los de todos los hallazgos por entidad:
el mismo ``IEUser`` que aparece en siete hallazgos es UN nodo, y ahí es donde
aparece la estructura que se lleva a un informe, sin gastar una llamada más al
modelo.
"""

from forensia.graph.extractor import (
    SesionEncadenada,
    build_delta_prompt,
    build_prompt,
    extract_graph,
)
from forensia.graph.fusion import clave_de_nodo, merge_case_graph
from forensia.graph.layout import layout_caso, layout_hallazgo
from forensia.graph.lote import extraer_lote
from forensia.graph.modelo import (
    TIPOS_NODO,
    TIPOS_RELACION,
    GraphExtractError,
    validar_grafo,
)
from forensia.graph.store import Graph, GraphStore, graph_store

__all__ = [
    "TIPOS_NODO",
    "TIPOS_RELACION",
    "Graph",
    "GraphExtractError",
    "GraphStore",
    "SesionEncadenada",
    "build_delta_prompt",
    "build_prompt",
    "clave_de_nodo",
    "extract_graph",
    "extraer_lote",
    "graph_store",
    "layout_caso",
    "layout_hallazgo",
    "merge_case_graph",
    "validar_grafo",
]
