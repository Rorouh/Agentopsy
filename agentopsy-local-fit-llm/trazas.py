"""Observabilidad con LangSmith: trazas del turno, de cada paso, de cada llamada al
modelo y de cada herramienta.

OPT-IN explícito: solo traza cuando `LANGSMITH_TRACING=true` y hay
`LANGSMITH_API_KEY` (o `LANGSMITH_ENDPOINT` propio). Sin eso, `trazable` es un
decorador que no hace nada y el motor no habla con ningún servicio externo.

Aviso de custodia y privacidad: con las trazas activas, los prompts y las
salidas acotadas de las herramientas (contenido derivado de la evidencia) se
envían al servidor de LangSmith configurado. Es el operador quien lo activa;
para un caso real conviene un LangSmith autoalojado (`LANGSMITH_ENDPOINT`).
"""

from __future__ import annotations

import os
from functools import wraps
from typing import Any, Callable


def activo() -> bool:
    valor = (os.environ.get("LANGSMITH_TRACING") or os.environ.get("LANGCHAIN_TRACING_V2") or "").lower()
    if valor not in {"true", "1", "yes", "on"}:
        return False
    return bool(os.environ.get("LANGSMITH_API_KEY") or os.environ.get("LANGCHAIN_API_KEY")
                or os.environ.get("LANGSMITH_ENDPOINT"))


def _sin_traza(func: Callable) -> Callable:
    @wraps(func)
    def envoltura(*args: Any, **kwargs: Any) -> Any:
        kwargs.pop("langsmith_extra", None)
        return func(*args, **kwargs)

    return envoltura


def trazable(name: str | None = None, run_type: str = "chain", **extra: Any) -> Callable[[Callable], Callable]:
    """`langsmith.traceable` si las trazas están activas; si no, la función tal cual
    (aceptando y descartando `langsmith_extra`)."""
    def decorador(func: Callable) -> Callable:
        if not activo():
            return _sin_traza(func)
        from langsmith import traceable

        return traceable(name=name or func.__name__, run_type=run_type, **extra)(func)

    return decorador


def metadatos(**campos: Any) -> dict[str, Any]:
    """Para pasar como `langsmith_extra={"metadata": ...}` a una función trazable."""
    return {"metadata": {k: v for k, v in campos.items() if v is not None}}


def anotar_run(**campos: Any) -> None:
    """Añade metadatos al run actual (si hay trazas y hay run)."""
    if not activo():
        return
    try:
        from langsmith.run_helpers import get_current_run_tree

        rt = get_current_run_tree()
        if rt is not None:
            rt.add_metadata({k: v for k, v in campos.items() if v is not None})
    except Exception:  # noqa: BLE001 — las trazas nunca rompen el motor
        return


def estado() -> dict[str, Any]:
    return {
        "activo": activo(),
        "proyecto": os.environ.get("LANGSMITH_PROJECT"),
        "endpoint": os.environ.get("LANGSMITH_ENDPOINT") or "https://api.smith.langchain.com",
    }
