"""Execution layer: the four operator-selected executors (2026-07-02 pivot).

``get_executor`` is a closed enum — an unknown id fails loudly with the valid
ids listed (RULE 2: no silent defaults, no substitution). ``executors_status``
feeds ``/api/capabilities`` so the UI can degrade explicitly per executor.
"""

from __future__ import annotations

from forensia.executors.base import (
    DEFAULT_TIMEOUT_S,
    ExecutorAvailability,
    ExecutorError,
    ExecutorResult,
    PromptExecutor,
    resolve_timeout,
)
from forensia.executors.claude_code import ClaudeCodeExecutor
from forensia.executors.codex import CodexExecutor
from forensia.executors.gemini import GeminiExecutor
from forensia.executors.ollama import OllamaExecutor

# Closed enum of executor ids the API accepts. Order = display order in the UI.
EXECUTOR_IDS: tuple[str, ...] = ("claude-code", "codex", "gemini", "ollama")

_FACTORIES = {
    "claude-code": ClaudeCodeExecutor,
    "codex": CodexExecutor,
    "gemini": GeminiExecutor,
    "ollama": OllamaExecutor,
}


def get_executor(executor_id: str) -> PromptExecutor:
    """Instantiate the executor for ``executor_id``. Unknown id → loud failure."""
    factory = _FACTORIES.get(executor_id)
    if factory is None:
        raise ValueError(
            f"ejecutor desconocido {executor_id!r}. Válidos: {', '.join(EXECUTOR_IDS)} "
            "(RULE 2: FORENSIA no sustituye por un default)."
        )
    return factory()


def executor_models(executor_id: str) -> dict[str, object]:
    """Models selectable for ``executor_id``, for the composer's model picker.

    Only ``ollama`` exposes a selectable list (the installed models, which the
    backend actually honours via ``OLLAMA_MODEL``). The cloud CLIs manage their own
    model inside their session; FORENSIA does not override it (RULE 2), so they
    return ``editable=False`` with an actionable note instead of a fake list. If the
    Ollama host is down, the reason travels in ``note`` (empty list) so the UI
    degrades explicitly rather than silently.
    """
    executor = get_executor(executor_id)  # loud on unknown id
    if isinstance(executor, OllamaExecutor):
        try:
            models = executor.list_models()
            return {"executor": executor_id, "editable": True, "models": models, "note": None}
        except ExecutorError as exc:
            return {"executor": executor_id, "editable": True, "models": [], "note": str(exc)}
    return {
        "executor": executor_id,
        "editable": False,
        "models": [],
        "note": (
            f"El modelo lo gestiona el CLI de {executor.name}; FORENSIA no lo "
            "sobrescribe (RULE 2). Cámbialo en la sesión del propio CLI."
        ),
    }


def executors_status() -> dict[str, dict[str, object]]:
    """Availability of the four executors, with the actionable reason when one
    is unavailable. Consumed by ``forensia.capabilities.snapshot``."""
    status: dict[str, dict[str, object]] = {}
    for executor_id in EXECUTOR_IDS:
        executor = get_executor(executor_id)
        availability = executor.is_available()
        status[executor_id] = {
            "name": executor.name,
            "local": executor.is_local,
            "available": availability.available,
            "reason": availability.reason,
        }
    return status


__all__ = [
    "DEFAULT_TIMEOUT_S",
    "EXECUTOR_IDS",
    "ExecutorAvailability",
    "ExecutorError",
    "ExecutorResult",
    "PromptExecutor",
    "ClaudeCodeExecutor",
    "CodexExecutor",
    "GeminiExecutor",
    "OllamaExecutor",
    "get_executor",
    "executor_models",
    "executors_status",
    "resolve_timeout",
]
