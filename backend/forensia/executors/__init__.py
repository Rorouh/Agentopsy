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
    "executors_status",
    "resolve_timeout",
]
