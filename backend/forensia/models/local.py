"""Local backend (Ollama) — the privacy default.

Tool-calling on local models is fragile; the real implementation will use a degraded path
(structured prompting + strict parser + allowlist validation + retries) instead of trusting
native tool-calling. Skeleton stub.
"""

from __future__ import annotations

from typing import Any

from forensia.models.base import Action, ModelBackend, ModelCapabilities


class LocalOllamaBackend(ModelBackend):
    name = "local"

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            supports_native_tools=False,
            json_mode=True,
            max_context=8192,
            is_local=True,
        )

    def next_action(self, state: dict[str, Any], tools: list[dict[str, Any]]) -> Action:
        raise NotImplementedError("local backend not implemented yet (skeleton)")
