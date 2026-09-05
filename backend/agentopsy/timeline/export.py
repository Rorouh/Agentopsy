"""Exportación del timeline de investigación como HOJA (CLAUDE.md RULE 3).

El perito se lleva la línea temporal de investigación (ejecuciones de herramienta
del audit log + hallazgos) fuera de Agentopsy para adjuntarla a su informe. Reusa
los eventos que ensambla ``agentopsy.timeline.builder``: no reconstruye nada, no
ejecuta herramientas y no reordena.

El envoltorio es el de ``agentopsy.export_hoja`` (un `.xlsx` real, con su bloque de
procedencia y una línea vacía antes de la tabla), y sobre él hay tres decisiones
de PRESENTACIÓN propias de este dominio:

- **El comando va en la ÚLTIMA columna.** Un ``argv`` auditado ocupa más de cien
  caracteres (lleva la ruta absoluta de la evidencia dentro del maletín) y, puesto
  a la izquierda, empujaba fuera de la pantalla las columnas que se leen. Es el
  dato más valioso y el más ancho: al final, se lee cuando se busca.
- **Cada fila se numera** para poder citarla («fila 14 del anexo») sin depender
  del orden en que la abra quien la reciba.
- **La marca temporal viaja en ISO 8601 con la Z**, exactamente como la escribió
  el log de auditoría. Es la forma que ordena bien como texto en cualquier hoja de
  cálculo y la única que no deja la zona horaria implícita.

Un caso sin actividad da una hoja con su procedencia y la cabecera, sin filas.
Los valores de vocabulario cerrado (tipo de evento, estado de la ejecución,
severidad) se escriben en castellano; un valor que no esté en la tabla de
etiquetas sale TAL CUAL, nunca traducido a lo que se le parezca (RULE 2).
"""

from __future__ import annotations

from typing import Any

from agentopsy.i18n import t
from agentopsy.export_hoja import NO_APLICA, build_workbook, iso_utc_ahora, unir
from agentopsy.timeline.vocabulario import (
    KIND_KEY,
    SEVERITY_KEY,
    STATUS_KEY,
    etiqueta,
)

#: Cabecera de la tabla del timeline. Orden estable, es un contrato que los tests
#: fijan. Cubre los dos tipos de evento (``tool_run`` y ``finding``); cada fila
#: rellena los campos que le aplican y escribe ``n/d`` en los que no.
#: Las CLAVES de la cabecera, en su orden estable. El orden es el contrato que
#: los tests fijan; el rótulo de cada columna lo resuelve `hoja_header()` en el
#: idioma de la hoja.
HOJA_HEADER_KEYS: tuple[str, ...] = (
    "tlSheet.col.n",
    "tlSheet.col.ts",
    "tlSheet.col.kind",
    "tlSheet.col.tool",
    "tlSheet.col.status",
    "tlSheet.col.exit",
    "tlSheet.col.finding",
    "tlSheet.col.severity",
    "tlSheet.col.detail",
    "tlSheet.col.techniques",
    "tlSheet.col.evidence",
    "tlSheet.col.eventId",
    "tlSheet.col.outputs",
    "tlSheet.col.argv",
)


def hoja_header() -> tuple[str, ...]:
    """La cabecera de la tabla, en el idioma de la hoja."""
    return tuple(t(k) for k in HOJA_HEADER_KEYS)

def timeline_to_hoja(
    events: list[dict[str, Any]],
    *,
    case_id: str = "",
    case_name: str = "",
    timezone: str = "UTC",
    exported_at: str | None = None,
) -> bytes:
    """La hoja del timeline de investigación: una fila por evento.

    ``events`` son los eventos de :func:`build_investigation_timeline`, en el orden
    cronológico que ya trae. ``tool_run`` rellena herramienta, estado, código de
    salida, ficheros de salida y comando; ``finding`` rellena hallazgo, severidad,
    detalle y técnicas. Un ``ts`` no parseable llega como celda vacía pero la fila
    NO se descarta (RULE 2: igual que en la vista, nada se oculta).

    ``exported_at`` es inyectable para que los tests fijen la marca temporal.
    """
    ejecuciones = sum(1 for e in events if e.get("kind") == "tool_run")
    hallazgos = sum(1 for e in events if e.get("kind") == "finding")
    fallidas = sum(
        1
        for e in events
        if e.get("kind") == "tool_run" and e.get("exit") not in (0, None)
    )
    primero = next((str(e.get("ts") or "") for e in events if e.get("ts")), "")
    ultimo = next(
        (str(e.get("ts") or "") for e in reversed(events) if e.get("ts")), ""
    )

    procedencia: list[tuple[str, str]] = [
        ("Agentopsy", t("tlSheet.prov.title")),
        (t("tlSheet.prov.case"), case_name),
        (t("tlSheet.prov.caseId"), case_id),
        (t("tlSheet.prov.exported"), exported_at or iso_utc_ahora()),
        (t("tlSheet.prov.timezone"), timezone),
        (t("tlSheet.prov.events"), str(len(events))),
        (
            t("tlSheet.prov.composition"),
            t(
                "tlSheet.prov.compositionValue",
                runs=ejecuciones,
                failed=fallidas,
                findings=hallazgos,
            ),
        ),
        (t("tlSheet.prov.first"), primero),
        (t("tlSheet.prov.last"), ultimo),
        (t("tlSheet.prov.howToRead"), t("tlSheet.prov.howToReadValue")),
    ]

    filas: list[list[Any]] = []
    for n, ev in enumerate(events, start=1):
        kind = str(ev.get("kind") or "")
        es_run = kind == "tool_run"
        argv = ev.get("argv")
        exit_code = ev.get("exit")
        salidas = ev.get("output_files_count")
        filas.append([
            n,
            ev.get("ts") or "",
            etiqueta(KIND_KEY, kind),
            ev.get("tool_id") or "",
            etiqueta(STATUS_KEY, ev.get("status")) if es_run else NO_APLICA,
            NO_APLICA if not es_run else ("" if exit_code is None else exit_code),
            ev.get("title") or (NO_APLICA if es_run else ""),
            etiqueta(SEVERITY_KEY, ev.get("severity")) if not es_run else NO_APLICA,
            ev.get("summary") or (NO_APLICA if es_run else ""),
            unir(ev.get("mitre_hints") or []) if not es_run else NO_APLICA,
            ev.get("evidence_id") or "",
            ev.get("run_id") or ev.get("finding_id") or "",
            NO_APLICA if not es_run else ("" if salidas is None else salidas),
            " ".join(argv) if isinstance(argv, list) and argv else NO_APLICA,
        ])
    return build_workbook(
        procedencia=procedencia,
        cabecera=hoja_header(),
        filas=filas,
        titulo=t("tlSheet.tabTitle"),
    )


__all__ = ["HOJA_HEADER_KEYS", "hoja_header", "timeline_to_hoja"]
