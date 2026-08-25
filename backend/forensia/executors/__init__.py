"""Execution layer: the four operator-selected executors (2026-07-02 pivot).

``get_executor`` is a closed enum — an unknown id fails loudly with the valid
ids listed (RULE 2: no silent defaults, no substitution). ``executors_status``
feeds ``/api/capabilities`` so the UI can degrade explicitly per executor.
"""

from __future__ import annotations

from forensia.i18n import Mensaje, t, traducir_excepcion
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
from forensia.executors.codex import (
    CodexExecutor,
    read_model_catalog,
    supported_efforts,
    validate_reasoning_effort,
)
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

# Config key that persists the operator-selected REASONING LEVEL — la «potencia»
# del modelo (2026-07-30). Solo Codex: es el único CLI cuyo nivel de
# razonamiento se ha verificado contra el binario real (`-c
# model_reasoning_effort=…`, codex-cli 0.146.0). No se declara una clave para
# los demás «por simetría»: sería exactamente la suposición que prohíbe RULE 2.
# Un ejecutor ausente de este mapa no lleva nivel y su CLI decide.
REASONING_CONFIG_KEY: dict[str, str] = {
    "codex": "CODEX_REASONING_EFFORT",
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
            Mensaje(
                "executor.unknown",
                id=repr(executor_id),
                ids=", ".join(EXECUTOR_IDS),
            )
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
    - ``codex`` returns the REAL catalog too, plus the reasoning levels each
      model admits: the CLI itself caches it in ``CODEX_HOME`` using the
      operator's OAuth session, so enumerating needs no API key (SECURITY
      INVARIANT 7). See ``forensia.executors.codex.read_model_catalog``.
    - the other cloud CLIs return only the documented shortcut aliases as
      SUGGESTIONS (``allow_custom`` is always true — the operator can type any id
      the CLI accepts). Agentopsy cannot ENUMERATE their catalogs: that would
      need an API key. Leaving the model empty uses the CLI's own default
      (RULE 2: Agentopsy never invents one).

    ``model_details`` (rich per-model data) and ``reasoning`` (the level picker)
    are EMPTY/``None`` for the executors that have no verified source for them —
    the UI paints what exists instead of a picker that would guess.
    """
    executor = get_executor(executor_id)  # loud on unknown id
    if isinstance(executor, OllamaExecutor):
        try:
            models = executor.list_models()
            note: str | None = None
        except ExecutorError as exc:
            models, note = [], traducir_excepcion(exc)
        return {
            "executor": executor_id,
            "editable": True,
            "allow_custom": True,
            "models": models,
            "note": note,
            "model_details": [],
            "reasoning": None,
        }
    if isinstance(executor, CodexExecutor):
        catalog, catalog_note = read_model_catalog()
        return {
            "executor": executor_id,
            "editable": True,
            "allow_custom": True,
            "models": [entry.slug for entry in catalog],
            "note": catalog_note,
            "model_details": [entry.as_dict() for entry in catalog],
            "reasoning": {
                "config_key": REASONING_CONFIG_KEY["codex"],
                "note": t("executor.reasoningNote"),
            },
        }
    # `note` queda RESERVADO para diagnósticos: por qué la lista viene vacía o
    # incompleta (p. ej. el catálogo de Codex que no se pudo leer, RULE 2). El
    # texto genérico que ocupaba este hueco explicaba que hay que escribir el id
    # a mano, cosa que el propio campo de la interfaz ya dice con su placeholder;
    # no es un diagnóstico y se retiró.
    return {
        "executor": executor_id,
        "editable": True,
        "allow_custom": True,
        "models": executor.suggested_models(),
        "note": None,
        "model_details": [],
        "reasoning": None,
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
    "REASONING_CONFIG_KEY",
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
    "read_model_catalog",
    "resolve_timeout",
    "supported_efforts",
    "validate_model_id",
    "validate_reasoning_effort",
]
