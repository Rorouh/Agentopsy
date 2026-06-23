"""Cloud backend (Anthropic / OpenAI) — OFF by default.

Used during development for reliable tool-use and as one column of the comparison harness.
At runtime it is opt-in per case with recorded consent + redaction (THREAT_MODEL section C).
Skeleton stub.
"""

from __future__ import annotations

from typing import Any

from forensia.models.base import Action, ModelBackend, ModelCapabilities


class CloudBackend(ModelBackend):
    name = "cloud"

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            supports_native_tools=True,
            json_mode=True,
            max_context=200000,
            is_local=False,
        )

    def next_action(self, state: dict[str, Any], tools: list[dict[str, Any]]) -> Action:
        raise NotImplementedError("cloud backend not implemented yet (skeleton)")
