"""Las etiquetas en castellano del vocabulario CERRADO del timeline.

Una sola fuente para toda superficie que enseñe un evento a una persona: dos
tablas distintas para el mismo valor serían dos nombres para el mismo hecho en
dos anexos del mismo informe.

La regla que gobierna las tres tablas es la misma: un valor que no esté en la
tabla sale **TAL CUAL**. Es un dato del caso, y traducirlo a lo que se le parezca
sería inventar (CLAUDE.md RULE 2). Por eso :func:`etiqueta` no tiene rama de
respaldo, solo devuelve lo que le llega.
"""

from __future__ import annotations

from typing import Any

#: Tipo de evento que ensambla ``forensia.timeline.builder``.
KIND_LABEL: dict[str, str] = {
    "tool_run": "Ejecución de herramienta",
    "finding": "Hallazgo",
}

#: Estado de una ejecución, tal y como lo escribe el dispatcher en el audit log.
STATUS_LABEL: dict[str, str] = {
    "running": "En curso",
    "finished": "Finalizada",
    "error": "Con error",
}

#: Severidad de un hallazgo (``forensia.findings.store``).
SEVERITY_LABEL: dict[str, str] = {
    "info": "Informativa",
    "low": "Baja",
    "medium": "Media",
    "high": "Alta",
    "critical": "Crítica",
}


def etiqueta(tabla: dict[str, str], valor: Any) -> str:
    """La etiqueta en castellano de un valor de vocabulario cerrado.

    Un valor que no esté en la tabla se devuelve TAL CUAL (RULE 2). ``None`` y el
    vacío dan cadena vacía: quien la pinta decide si eso es un hueco o un ``n/d``.
    """
    texto = str(valor or "").strip()
    return tabla.get(texto, texto)


__all__ = [
    "KIND_LABEL",
    "SEVERITY_LABEL",
    "STATUS_LABEL",
    "etiqueta",
]
