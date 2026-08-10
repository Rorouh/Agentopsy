"""Grafos de relaciones: qué se conecta con qué dentro de un hallazgo.

Donde la línea de tiempo del incidente (``forensia.timeline.hallazgos``) responde
«cuándo pasó», el grafo responde «qué se conecta con qué»: qué equipo, qué cuenta,
qué fichero, qué dominio y qué IP intervienen en un hallazgo, y con qué relación.

Es una PROPUESTA del modelo sobre el texto del hallazgo, no un hecho verificado
como lo son un hash o un argv auditado, y así se etiqueta en toda superficie que
lo enseñe. Lo que sí es verificable es su procedencia: cada grafo se persiste con
su SHA-256 y su extracción queda en el log encadenado con el argv literal de la
corrida del ejecutor.
"""

from forensia.graph.extractor import build_prompt, extract_graph
from forensia.graph.modelo import (
    TIPOS_NODO,
    TIPOS_RELACION,
    GraphExtractError,
    validar_grafo,
)

__all__ = [
    "TIPOS_NODO",
    "TIPOS_RELACION",
    "GraphExtractError",
    "build_prompt",
    "extract_graph",
    "validar_grafo",
]
