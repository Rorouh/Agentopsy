"""El turno como grafo de LangGraph: planificar → investigar → revisar → (fin | investigar).

Los nodos son métodos de `runner.Corrida`; aquí solo está la forma del bucle.
Con `LANGSMITH_TRACING=true` LangGraph traza cada nodo por sí mismo y LangSmith
muestra el turno como grafo, con los pasos, las llamadas al modelo y las
herramientas anidados debajo (ver `trazas.py`).
"""

from __future__ import annotations

from typing import Any, TypedDict

from langgraph.graph import END, StateGraph


class EstadoTurno(TypedDict, total=False):
    ronda: int
    ordenes: list[str]
    informe: str
    respuesta: str
    terminado: bool


def construir(corrida: Any):
    g = StateGraph(EstadoTurno)
    g.add_node("planificar", corrida.nodo_planificar)
    g.add_node("investigar", corrida.nodo_investigar)
    g.add_node("revisar", corrida.nodo_revisar)
    g.set_entry_point("planificar")
    g.add_edge("planificar", "investigar")
    g.add_edge("investigar", "revisar")
    g.add_conditional_edges("revisar", lambda s: END if s.get("terminado") else "investigar",
                            {END: END, "investigar": "investigar"})
    return g.compile()
