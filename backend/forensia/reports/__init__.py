"""Documentos / informes del caso.

Dos ejes: el **almacén** de documentos con su integridad (``store``) y la
**síntesis** del informe pericial desde los datos reales del caso (``generator``).
Un documento se persiste por caso con su SHA-256 real, y las acciones del perito
(verificar integridad, firmar como final, eliminar borrador) operan sobre
ficheros reales y quedan en el audit hash-encadenado.

``build_pericial_report`` ensambla las secciones del informe (metadatos, cadena
de custodia, metodología, hallazgos y correlación MITRE) desde ``forensia.cases``
/ ``custody`` / ``findings`` / ``mitre`` / ``toolkit.usage``; el router lo pasa por
``DocumentStore.create``. No inventa nada (RULE 2): un caso sin hallazgos produce
un informe honesto que lo dice.
"""

from __future__ import annotations

from forensia.reports.generator import build_pericial_report
from forensia.reports.store import Document, DocumentStore, document_store

__all__ = [
    "Document",
    "DocumentStore",
    "build_pericial_report",
    "document_store",
]
