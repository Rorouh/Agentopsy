"""Documentos / informes del caso.

El motor de SÍNTESIS del orquestador (que redacta informes a partir de los
hallazgos) sigue sin implementarse — este paquete es sólo el **almacén** de
documentos y su integridad: un documento se persiste por caso con su SHA-256
real, y las acciones del perito (verificar integridad, firmar como final,
eliminar borrador) operan sobre ficheros reales y quedan en el audit
hash-encadenado. Quién CREA los documentos (el agente, en el futuro) es otro eje;
hoy el almacén está listo pero vacío hasta que algo escriba en él.
"""

from __future__ import annotations

from forensia.reports.store import Document, DocumentStore, document_store

__all__ = ["Document", "DocumentStore", "document_store"]
