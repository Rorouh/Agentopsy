"""Cloud backend (OpenAI) implementation.

Used opt-in per case with recorded consent + redaction (THREAT_MODEL §C). The
operator configures ``MODEL_BACKEND=cloud`` + ``OPENAI_API_KEY`` + ``MODEL_NAME``
in ``~/.forensia/config.json`` (RULE 2: no silent defaults).

The agent loop in ``forensia.agent.agent.ForensicAgent.run`` is the only caller.
This module never talks to the network on its own — every request originates
from an explicit ``next_action`` invocation.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from forensia.config import config
from forensia.models.base import Action, FinalAnswer, ModelBackend, ModelCapabilities, ToolCall

logger = logging.getLogger(__name__)

# OpenAI chat-completions context windows (approximate, current as of 2025-06).
_CONTEXT_LIMITS: dict[str, int] = {
    "gpt-4o": 128_000,
    "gpt-4o-mini": 128_000,
    "gpt-4-turbo": 128_000,
    "gpt-4": 8_192,
    "gpt-3.5-turbo": 16_385,
    "o1-preview": 128_000,
    "o1-mini": 128_000,
    "o3-mini": 200_000,
}

DEFAULT_MAX_CONTEXT = 128_000


class CloudBackend(ModelBackend):
    name = "cloud"

    def __init__(self) -> None:
        # Lazy import: do NOT pay the cost when the operator chose local.
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise RuntimeError(
                "OpenAI SDK is not installed. Add `openai>=2.0` to the sidecar "
                "venv (already declared in pyproject [models]); a fresh "
                "release-bundle PyInstaller build ships it baked in."
            ) from exc

        api_key = config.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError(
                "OPENAI_API_KEY is not configured. Set it via Settings > "
                "Modelos / IA or in ~/.forensia/config.json."
            )

        model = config.get("MODEL_NAME")
        if not model:
            raise RuntimeError(
                "MODEL_NAME is not configured. Pick one in Settings > "
                "Modelos / IA (e.g. gpt-4o)."
            )

        self._client = OpenAI(api_key=api_key)
        self._model = str(model)

    @property
    def model_name(self) -> str:
        return self._model

    def capabilities(self) -> ModelCapabilities:
        max_ctx = _CONTEXT_LIMITS.get(self._model, DEFAULT_MAX_CONTEXT)
        return ModelCapabilities(
            supports_native_tools=True,
            json_mode=True,
            max_context=max_ctx,
            is_local=False,
        )

    def next_action(
        self, state: dict[str, Any], tools: list[dict[str, Any]]
    ) -> Action:
        """Single round-trip to OpenAI's chat-completions endpoint.

        ``state["messages"]`` is the running conversation in OpenAI shape.
        ``tools`` is a list of function specs (see ``agent.tool_schemas``).
        """
        messages = state.get("messages")
        if not isinstance(messages, list) or not messages:
            raise ValueError("state['messages'] must be a non-empty list")

        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "temperature": float(state.get("temperature", 0.2)),
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        response = self._client.chat.completions.create(**kwargs)
        choice = response.choices[0]
        msg = choice.message

        tool_calls = getattr(msg, "tool_calls", None) or []
        if tool_calls:
            # FORENSIA processes one tool call per round-trip — keeps the audit
            # log linear and the timeline easy to reason about. The model can
            # request another tool in the next iteration.
            tc = tool_calls[0]
            try:
                params = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError as exc:
                logger.warning("model returned invalid tool JSON: %s", exc)
                params = {}
            assistant_msg = {
                "role": "assistant",
                "content": msg.content or None,
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                ],
            }
            return ToolCall(
                tool_id=tc.function.name,
                params=params if isinstance(params, dict) else {},
                call_id=tc.id,
                assistant_message=assistant_msg,
            )

        # No tool call → FinalAnswer
        return FinalAnswer(text=msg.content or "")
