"""Documentos / informes del caso.

Cuatro piezas. El **almacén** de documentos con su integridad SHA-256
(``store``); el **índice canónico** del informe pericial (``indice``), que es lo
ÚNICO que dos informes tienen en común; el **material** que el caso ha
persistido (``material`` + ``works``), sin una sola frase redactada; y el
**redactor** (``writer``), que entrega ese material al ejecutor seleccionado por
el operador para que escriba el informe de principio a fin y valida lo que
devuelve antes de que llegue al almacén.

**La plantilla determinista se retiró el 2026-07-30** (``generator`` /
``narrative`` / ``humanize``, y con ellos el borrador automático al cerrar un
análisis). Agentopsy ya no rellena huecos de un molde: cada investigación
produce un informe único, con la narrativa y la longitud que ese caso pide, y se
redacta UNA sola vez, al FINALIZAR la investigación
(``POST …/documents/finalize``). Lo que Agentopsy no delega es la custodia: el
índice exacto, el modelo de bloques, los referentes cerrados del material y los
comandos literales del audit son cuatro puertas que se cruzan antes de persistir
nada (ver ``writer``).
"""

from __future__ import annotations

from forensia.reports.material import build_material
from forensia.reports.store import Document, DocumentStore, document_store
from forensia.reports.writer import ReportWriteError, write_report

__all__ = [
    "Document",
    "DocumentStore",
    "ReportWriteError",
    "build_material",
    "document_store",
    "write_report",
]
