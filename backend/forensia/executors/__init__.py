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
    validate_model_id,
)
from forensia.executors.claude_code import ClaudeCodeExecutor
from forensia.executors.codex import CodexExecutor
from forensia.executors.gemini import GeminiExecutor
from forensia.executors.ollama import OllamaExecutor

# Closed enum of executor ids the API accepts. Order = display order in the UI.
EXECUTOR_IDS: tuple[str, ...] = ("claude-code", "codex", "gemini", "ollama")

# Config key that persists the operator-selected model PER executor (so the
# choice survives a reload — "recuerda el último modelo"). Read by the agent
# router into the run context and written by the composer's model picker. RULE 2:
# an unset key means "no operator choice" — Ollama then demands the package's
# model, a cloud CLI uses its own default; Agentopsy never invents one.
MODEL_CONFIG_KEY: dict[str, str] = {
    "claude-code": "CLAUDE_CODE_MODEL",
    "codex": "CODEX_MODEL",
    "gemini": "GEMINI_MODEL",
    "ollama": "OLLAMA_MODEL",
}

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
            "(RULE 2: Agentopsy no sustituye por un default)."
        )
    return factory()


def executor_models(executor_id: str) -> dict[str, object]:
    """Models selectable for ``executor_id``, for the composer's model picker.

    Every executor is ``editable``: the operator chooses the model and Agentopsy
    honours it via ``MODEL_CONFIG_KEY`` (Ollama over HTTP, the cloud CLIs as a
    ``--model`` argv flag). What differs is the list:

    - ``ollama`` returns the REAL installed models (``/api/tags``); if the host
      is down the reason travels in ``note`` (empty list) so the UI degrades
      explicitly.
    - the cloud CLIs return only the documented shortcut aliases as SUGGESTIONS
      (``allow_custom`` is always true — the operator can type any id the CLI
      accepts). Agentopsy cannot ENUMERATE their catalogs: that would need an API
      key (SECURITY INVARIANT 7). Leaving the model empty uses the CLI's own
      default (RULE 2: Agentopsy never invents one).
    """
    executor = get_executor(executor_id)  # loud on unknown id
    if isinstance(executor, OllamaExecutor):
        try:
            models = executor.list_models()
            return {
                "executor": executor_id,
                "editable": True,
                "allow_custom": True,
                "models": models,
                "note": None,
            }
        except ExecutorError as exc:
            return {
                "executor": executor_id,
                "editable": True,
                "allow_custom": True,
                "models": [],
                "note": str(exc),
            }
    return {
        "executor": executor_id,
        "editable": True,
        "allow_custom": True,
        "models": executor.suggested_models(),
        "note": (
            f"Agentopsy no puede enumerar los modelos de {executor.name} sin una API "
            "key (SECURITY INVARIANT 7). Escribe el id que aceptes en su CLI, se "
            "pasa como --model; déjalo vacío para usar el modelo por defecto del CLI."
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
    "MODEL_CONFIG_KEY",
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
    "validate_model_id",
]
