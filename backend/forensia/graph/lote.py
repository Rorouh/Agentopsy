"""El LOTE: extraer el grafo de varios hallazgos en una sola pasada.

Dos cosas que este módulo garantiza y que no son negociables:

1. **El lote no muere en el primer rechazo.** Cada hallazgo lleva su propio
   resultado, y al final se dice cuántos salieron, cuáles no y por qué. Un lote
   que aborta a la mitad y no dice dónde es indistinguible de uno que no se
   lanzó, y deja al perito sin saber qué hay que repetir.
2. **La sesión se encadena solo si ``session_guard`` la avala.** El ahorro
   medido es real (0,0141 USD por hallazgo encadenando frente a 0,0353 en frío,
   sobre los 19 hallazgos de un caso real el 2026-08-10), pero se subordina a la
   contabilidad: un turno que el guard no puede verificar se manda con el
   encargo entero y el motivo queda auditado. Nunca al revés.

El lote NO publica coste ni conteo de tokens (retirado el 2026-08-12, con el resto
de la telemetría de coste: el conteo no era fiable y una cifra que no se sostiene
en un informe pericial es peor que ninguna). Lo que sí se conserva es la
procedencia de cada extracción: el bloque ``extraction`` que persiste junto a cada
grafo sigue llevando el usage que informó el ejecutor, igual que el log de
auditoría encadenado.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from forensia.executors.base import ExecutorError, PromptExecutor
from forensia.findings import Finding
from forensia.graph.extractor import SesionEncadenada, extract_graph
from forensia.graph.modelo import GraphExtractError
from forensia.graph.store import GraphStore

def extraer_lote(
    case_id: str,
    findings: list[Finding],
    *,
    executor: PromptExecutor,
    audit: Any,
    store: GraphStore,
    model: str | None = None,
    reasoning_effort: str | None = None,
    emit: Callable[[dict[str, Any]], None] | None = None,
    should_cancel: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Extrae y persiste el grafo de cada hallazgo. Devuelve el parte del lote."""
    sesion = SesionEncadenada() if executor.supports_session_resume else None
    resultados: list[dict[str, Any]] = []

    for indice, f in enumerate(findings):
        if should_cancel is not None and should_cancel():
            break
        if emit is not None:
            emit({
                "type": "graph_finding_start",
                "finding_id": f.id,
                "title": f.title,
                "index": indice,
                "total": len(findings),
            })
        try:
            grafo = extract_graph(
                case_id, f,
                executor=executor, audit=audit, model=model,
                reasoning_effort=reasoning_effort, sesion=sesion,
                on_progress=emit,
            )
        except (GraphExtractError, ExecutorError) as exc:
            # El fallo de UN hallazgo no cancela el lote: se anota con su motivo
            # y se sigue con el siguiente.
            resultados.append({
                "finding_id": f.id,
                "title": f.title,
                "ok": False,
                "error": str(exc),
            })
            if emit is not None:
                emit({
                    "type": "graph_finding_error",
                    "finding_id": f.id,
                    "error": str(exc),
                })
            continue

        guardado = store.save(case_id, f.id, grafo)
        resultados.append({
            "finding_id": f.id,
            "title": f.title,
            "ok": True,
            "revision": guardado.revision,
            "sha256": guardado.sha256,
            "n_nodos": len(guardado.nodos),
            "n_relaciones": len(guardado.relaciones),
        })
        if emit is not None:
            emit({
                "type": "graph_finding_done",
                "finding_id": f.id,
                "revision": guardado.revision,
                "n_nodos": len(guardado.nodos),
                "n_relaciones": len(guardado.relaciones),
            })

    con_grafo = [r for r in resultados if r["ok"]]
    sin_grafo = [r for r in resultados if not r["ok"]]
    return {
        "solicitados": len(findings),
        "con_grafo": len(con_grafo),
        "sin_grafo": len(sin_grafo),
        "resultados": resultados,
        "executor": executor.id,
        "model": model,
    }


__all__ = ["extraer_lote"]
