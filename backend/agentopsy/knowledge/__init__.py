"""Grafo de conocimiento POR CASO — el lado de escritura del agente.

Lo que el paquete trae en ``agentes/<id>/knowledge/`` es conocimiento GENERAL
(«dónde suele vivir un artefacto en Windows»): estático, idéntico en todos los
casos, de solo lectura y de CONFIANZA (lo escribe el equipo). Este módulo es la
otra mitad: lo que se ha encontrado en ESTE caso, dónde está y qué queda abierto
— escrito por el agente mientras trabaja.

La analogía que lo fija: el paquete es el `FLUJO.md` (la receta, sirve para
cualquier caso) y esto es la `FICHA-<caso>.md` (los datos concretos, no valen
para otro caso).

Por qué existe: el ejecutor es stateless y Agentopsy le reenvía la conversación
entera en cada iteración, con windowing que colapsa los turnos viejos a stubs.
Todo lo que el agente concluye y no persiste, se pierde — y reenviarlo entero
cuesta ``contexto × turnos``. Con el grafo, en el prompt viaja el ÍNDICE (una
línea por nodo) y el contenido se trae bajo demanda con
``consultar_conocimiento(doc_id)``.

Garantías:

- **Append-only con vista consolidada.** Cada escritura añade un bloque al
  registro ``.historial/<doc_id>.jsonl`` — nunca se modifica ni se borra una
  línea anterior — y re-renderiza atómicamente la vista ``<doc_id>.md`` con la
  ÚLTIMA versión de cada sección. Evidencia hostil no puede lograr que el agente
  borre lo que concluyó antes: como mucho añade una versión posterior, y la
  anterior sigue en el registro.
- **El agente emite un ID, nunca una ruta.** ``doc_id`` con juego de caracteres
  cerrado (``[a-z0-9][a-z0-9-]{0,63}``): el traversal no se rechaza, es que no
  es expresable. El backend construye la ruta (SECURITY INVARIANT 5-6).
- **Confinado** al ``knowledge/`` del caso activo, verificado tras resolver.
- **Nunca sobre la evidencia ni sobre los artefactos.** Directorio aparte; ni
  ``evidence/`` ni ``artifacts/`` ni ``audit.jsonl`` se tocan desde aquí.
- **Un nodo NO es un hallazgo.** El grafo es para navegar y no recargar; la
  cadena de custodia sigue siendo ``findings.jsonl`` + el audit encadenado.

Lo que devuelve la lectura de un nodo del CASO viaja al modelo marcado como NO
CONFIABLE (lo envuelve ``agent.py``): el agente cita en sus notas cadenas
derivadas de la evidencia, y releerlas como contexto de confianza sería un canal
de blanqueo de prompt-injection.
"""

from agentopsy.knowledge.store import (
    DOC_ID_PATTERN,
    MAX_BLOCK_CHARS,
    MAX_NODES_PER_CASE,
    MAX_SECTION_CHARS,
    MAX_SECTIONS_PER_NODE,
    KnowledgeBlock,
    KnowledgeNode,
    KnowledgeStore,
    NodeSummary,
    knowledge_store,
)

__all__ = [
    "DOC_ID_PATTERN",
    "MAX_BLOCK_CHARS",
    "MAX_NODES_PER_CASE",
    "MAX_SECTION_CHARS",
    "MAX_SECTIONS_PER_NODE",
    "KnowledgeBlock",
    "KnowledgeNode",
    "KnowledgeStore",
    "NodeSummary",
    "knowledge_store",
]
