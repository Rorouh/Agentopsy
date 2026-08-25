"""Grafo de conocimiento por caso — superficie HTTP.

Adaptador fino sobre ``forensia.knowledge.store`` (RULE 3): sin lógica propia.

Es de **solo lectura desde HTTP a propósito**. El grafo son las notas de trabajo
del AGENTE, escritas con ``anotar_conocimiento`` dentro del loop, donde cada
escritura queda en la cadena de audit con su hash y su iteración. Abrir un
endpoint de escritura crearía una segunda vía sin ese anclaje, y con ella la duda
de quién escribió cada bloque — justo lo que el registro append-only existe para
zanjar. La UI pinta el grafo; no lo edita.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from forensia.i18n import t, traducir_excepcion
from forensia.knowledge import knowledge_store
from forensia.security import require_token

router = APIRouter()


@router.get(
    "/api/cases/{case_id}/knowledge",
    dependencies=[Depends(require_token)],
)
def list_nodes(case_id: str) -> list[dict[str, Any]]:
    """Índice del grafo: un nodo por entrada, con sus secciones. Sin contenido."""
    try:
        return [asdict(n) for n in knowledge_store.index(case_id)]
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=traducir_excepcion(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc


@router.get(
    "/api/cases/{case_id}/knowledge/{doc_id}",
    dependencies=[Depends(require_token)],
)
def read_node(case_id: str, doc_id: str) -> dict[str, Any]:
    """La vista consolidada de un nodo: última versión de cada sección."""
    try:
        node = knowledge_store.read(case_id, doc_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=traducir_excepcion(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc
    if node is None:
        raise HTTPException(
            status_code=404, detail=t("api.noKnowledgeNode", doc_id=repr(doc_id))
        )
    return asdict(node)


@router.get(
    "/api/cases/{case_id}/knowledge/{doc_id}/historial",
    dependencies=[Depends(require_token)],
)
def read_history(case_id: str, doc_id: str) -> list[dict[str, Any]]:
    """El registro append-only íntegro del nodo, en orden de escritura.

    Es lo que permite al perito auditar la EVOLUCIÓN de una nota: qué se concluyó
    primero, qué se corrigió después y cuándo. Nada de esto se borra jamás.
    """
    try:
        return [b.as_dict() for b in knowledge_store.history(case_id, doc_id)]
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=traducir_excepcion(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc
