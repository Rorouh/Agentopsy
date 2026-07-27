"""Exportación CSV del timeline de investigación (CLAUDE.md RULE 3: lógica aquí).

El perito se lleva la línea temporal de investigación (ejecuciones de herramienta del
audit log + hallazgos) fuera de Agentopsy como CSV. Reusa los eventos que ensambla
``forensia.timeline.builder`` — no reconstruye nada ni ejecuta herramientas.

Puro: recibe la lista de eventos (``build_investigation_timeline``) y devuelve el
texto CSV. Un caso sin actividad da un CSV con sólo la cabecera (0 filas, honesto).
Las marcas de tiempo ya vienen en UTC explícito (``…Z``); la columna se llama
``ts_utc`` para que la zona nunca quede implícita (hallazgo F).
"""

from __future__ import annotations

import csv
import io
from typing import Any

#: Cabecera del CSV del timeline. Orden estable — contrato que los tests fijan. Cubre
#: los dos tipos de evento (``tool_run`` y ``finding``); cada fila rellena los campos
#: que le aplican y deja el resto vacío.
CSV_HEADER: tuple[str, ...] = (
    "ts_utc",
    "kind",
    "tool_id",
    "argv",
    "exit",
    "status",
    "title",
    "severity",
    "evidence_id",
    "mitre_hints",
)


def timeline_to_csv(events: list[dict[str, Any]]) -> str:
    """Serializa el timeline de investigación a CSV (una fila por evento).

    ``events`` son los eventos de :func:`build_investigation_timeline` (orden
    cronológico ya aplicado). ``tool_run`` rellena ``tool_id`` / ``argv`` / ``exit`` /
    ``status``; ``finding`` rellena ``title`` / ``severity`` / ``mitre_hints``. Un
    ``ts`` no parseable llega como cadena vacía pero la fila NO se descarta (RULE 2:
    igual que la timeline, nada se oculta).
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(CSV_HEADER)
    for ev in events:
        kind = ev.get("kind", "")
        argv = ev.get("argv")
        exit_code = ev.get("exit")
        hints = ev.get("mitre_hints") or []
        writer.writerow([
            ev.get("ts") or "",
            kind,
            ev.get("tool_id") or "",
            " ".join(argv) if isinstance(argv, list) else "",
            "" if exit_code is None else exit_code,
            ev.get("status") or "",
            ev.get("title") or "",
            ev.get("severity") or "",
            ev.get("evidence_id") or "",
            ";".join(str(h) for h in hints),
        ])
    return buf.getvalue()
