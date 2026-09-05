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

from agentopsy.i18n import t

#: Tipo de evento que ensambla ``agentopsy.timeline.builder``.
KIND_KEY: dict[str, str] = {
    "tool_run": "tlvoc.kind.tool_run",
    "finding": "tlvoc.kind.finding",
}

#: Estado de una ejecución, tal y como lo escribe el dispatcher en el audit log.
STATUS_KEY: dict[str, str] = {
    "running": "tlvoc.status.running",
    "finished": "tlvoc.status.finished",
    "error": "tlvoc.status.error",
}

#: Severidad de un hallazgo (``agentopsy.findings.store``).
SEVERITY_KEY: dict[str, str] = {
    "info": "tlvoc.sev.info",
    "low": "tlvoc.sev.low",
    "medium": "tlvoc.sev.medium",
    "high": "tlvoc.sev.high",
    "critical": "tlvoc.sev.critical",
}


def etiqueta(tabla: dict[str, str], valor: Any) -> str:
    """La etiqueta de un valor de vocabulario cerrado, en el idioma en curso.

    Un valor que no esté en la tabla se devuelve TAL CUAL (RULE 2). ``None`` y el
    vacío dan cadena vacía: quien la pinta decide si eso es un hueco o un ``n/d``.
    """
    texto = str(valor or "").strip()
    clave = tabla.get(texto)
    return t(clave) if clave else texto


__all__ = [
    "KIND_KEY",
    "SEVERITY_KEY",
    "STATUS_KEY",
    "etiqueta",
]
