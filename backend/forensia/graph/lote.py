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

El coste ESTIMADO y el coste REAL viajan en campos distintos y con nombres
distintos, la misma regla que ya siguen los turnos que mueren por timeout: una
medida y una previsión no se mezclan jamás en el mismo número (RULE 2).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from forensia.executors.base import ExecutorError, PromptExecutor
from forensia.findings import Finding
from forensia.graph.extractor import SesionEncadenada, extract_graph
from forensia.graph.modelo import GraphExtractError
from forensia.graph.store import GraphStore

#: Coste estimado de extraer el grafo de UN hallazgo, en USD.
#:
#: BASE DECLARADA: medido el 2026-08-10 sobre los 19 hallazgos del caso
#: TestCase2 con `claude-code` (modelo por defecto del CLI, claude-sonnet-5),
#: encadenando la sesión: 0,268 USD en total, 19 llamadas, 115 s. En frío, sin
#: encadenar, la misma extracción salió a 0,0353 USD de media.
#:
#: Es una PREVISIÓN, y la superficie que la enseñe tiene que decir que lo es y
#: con qué ejecutor se midió: cambiar de ejecutor o de modelo la invalida, y un
#: hallazgo con mucho texto cuesta más que uno de dos líneas.
COSTE_ESTIMADO_POR_HALLAZGO_USD = 0.0141
BASE_DEL_ESTIMADO = (
    "medido el 2026-08-10 sobre 19 hallazgos reales con claude-code encadenando "
    "la sesión (0,268 USD en total). Cambiar de ejecutor o de modelo lo invalida."
)


def estimar_coste(n_hallazgos: int) -> dict[str, Any]:
    """La previsión que se enseña ANTES de lanzar, con su base declarada."""
    n = max(0, int(n_hallazgos))
    return {
        "hallazgos": n,
        "coste_estimado_usd": round(n * COSTE_ESTIMADO_POR_HALLAZGO_USD, 4),
        "estimado_por_hallazgo_usd": COSTE_ESTIMADO_POR_HALLAZGO_USD,
        "base_del_estimado": BASE_DEL_ESTIMADO,
    }


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
    coste_real = 0.0
    coste_informado = False
    tokens_in = tokens_out = 0

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

        extraccion = grafo.get("extraction") or {}
        if extraccion.get("cost_usd") is not None:
            coste_real += float(extraccion["cost_usd"])
            coste_informado = True
        tokens_in += int(extraccion.get("input_tokens") or 0)
        tokens_out += int(extraccion.get("output_tokens") or 0)

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
        # El coste REAL, del audit del ejecutor. `None` cuando ningún envoltorio
        # lo informa (codex no lo hace), para no enseñar un cero que no es cero.
        "coste_usd": round(coste_real, 6) if coste_informado else None,
        "input_tokens": tokens_in,
        "output_tokens": tokens_out,
        "executor": executor.id,
        "model": model,
    }


__all__ = [
    "BASE_DEL_ESTIMADO",
    "COSTE_ESTIMADO_POR_HALLAZGO_USD",
    "estimar_coste",
    "extraer_lote",
]
