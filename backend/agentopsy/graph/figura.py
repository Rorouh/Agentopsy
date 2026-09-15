"""La FIGURA del grafo del caso: fundir, separar la red del inventario y colocar.

Es la composición que comparten dos superficies y que por eso no puede vivir en
ninguna de ellas:

- la vista Grafos (``GET …/graphs/case``), que la pinta y la exporta a PNG;
- el informe pericial, que la congela en su anexo C (``reports.figuras``).

Si cada una fundiera y colocara por su cuenta, el grafo que el perito miró en la
pantalla y el que firmó en el informe podrían dejar de ser el mismo con el primer
cambio en cualquiera de las dos. Aquí se hace una vez.

Lógica pura (RULE 3): recibe los grafos ya leídos del almacén, sin disco ni HTTP.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Protocol

from agentopsy.graph import inventario
from agentopsy.graph.fusion import merge_case_graph
from agentopsy.graph.layout import layout_caso


class _GrafoDeHallazgo(Protocol):
    finding_id: str
    nodos: list[dict[str, Any]]
    relaciones: list[dict[str, Any]]


def figura_del_caso(case_id: str, grafos: Iterable[_GrafoDeHallazgo]) -> dict[str, Any]:
    """El grafo del caso con su geometría.

    Devuelve ``nodos`` (la RED, colocada), ``relaciones`` y ``hallazgos`` (los de
    la fusión), ``lienzo`` y ``notas`` (los de la red) e ``inventario`` (la banda
    de entidades sin relación, o ``None``).

    FUNCIÓN «INVENTARIO»: la figura dibuja la RED, y las entidades que no
    participan en ninguna relación bajan a una banda declarada al pie. No se
    descarta ninguna: se deja de afirmar con la geometría una relación que nadie
    afirmó. Para retirarla: colocar ``fundido["nodos"]`` con ``layout_caso``, dar
    ``inventario`` a ``None`` y borrar ``agentopsy/graph/inventario.py``.
    """
    fundido = merge_case_graph([
        {"finding_id": g.finding_id, "nodos": g.nodos, "relaciones": g.relaciones}
        for g in grafos
    ])
    conectados, sueltos = inventario.partir(fundido["nodos"], fundido["relaciones"])
    figura = layout_caso(case_id, conectados, fundido["relaciones"])
    figura = inventario.componer(figura, sueltos)
    return {
        "nodos": figura["nodos"],
        "relaciones": fundido["relaciones"],
        "hallazgos": fundido["hallazgos"],
        "lienzo": figura["lienzo"],
        "notas": figura["notas"],
        "inventario": figura["inventario"],
    }


__all__ = ["figura_del_caso"]
