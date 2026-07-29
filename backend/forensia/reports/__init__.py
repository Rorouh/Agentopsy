"""Documentos / informes del caso.

Tres ejes: el **almacén** de documentos con su integridad (``store``), la
**síntesis** del informe pericial desde los datos reales del caso
(``generator``) y la **narrativa** que le da hilo conductor (``narrative``,
2026-07-30) — más la **redacción humanizada opcional** a través del ejecutor
seleccionado por el operador (``humanize``). Un documento se persiste por caso
con su SHA-256 real, y las acciones del perito (verificar integridad, firmar
como final, eliminar borrador) operan sobre ficheros reales y quedan en el
audit hash-encadenado.

``build_pericial_report`` ensambla las secciones del informe (resumen ejecutivo
narrativo, metadatos, cadena de custodia, metodología, RELATO de la
investigación, hallazgos, correlación MITRE y conclusiones que cierran el hilo)
desde ``forensia.cases`` / ``custody`` / ``findings`` / ``mitre`` /
``toolkit.usage``; el router lo pasa por ``DocumentStore.create``. No inventa
nada (RULE 2): la narrativa elige orden y tejido conectivo — nunca contenido —
y un caso sin hallazgos produce un informe honesto que lo dice.
"""

from __future__ import annotations

from forensia.reports.generator import (
    AUTO_DRAFT_TITLE,
    build_pericial_report,
    generate_draft_report,
)
from forensia.reports.store import Document, DocumentStore, document_store

__all__ = [
    "AUTO_DRAFT_TITLE",
    "Document",
    "DocumentStore",
    "build_pericial_report",
    "document_store",
    "generate_draft_report",
]
