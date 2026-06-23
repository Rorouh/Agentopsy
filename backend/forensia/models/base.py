"""Common model interface.

The interface declares CAPABILITIES, not just methods — so the abstraction does not hide
that a cloud model with robust tool-use differs from a weak local one. The local-vs-cloud
comparison harness (the TFM's scientific contribution) is built on top of this.

`next_action` returns either a tool call (closed-enum id + typed params) or a final answer.
The backend NEVER returns a raw command string.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Literal


@dataclass(frozen=True)
class ModelCapabilities:
    supports_native_tools: bool
    json_mode: bool
    max_context: int
    is_local: bool


@dataclass(frozen=True)
class ToolCall:
    tool_id: str
    params: dict[str, Any]


@dataclass(frozen=True)
class FinalAnswer:
    text: str


Action = ToolCall | FinalAnswer


class ModelBackend(ABC):
    name: str

    @abstractmethod
    def capabilities(self) -> ModelCapabilities: ...

    @abstractmethod
    def next_action(self, state: dict[str, Any], tools: list[dict[str, Any]]) -> Action: ...


def get_backend(name: Literal["local", "cloud"]) -> ModelBackend:
    """No silent default (RULE 2): an unknown name fails loudly."""
    if name == "local":
        from forensia.models.local import LocalOllamaBackend

        return LocalOllamaBackend()
    if name == "cloud":
        from forensia.models.cloud import CloudBackend

        return CloudBackend()
    raise ValueError(f"unknown model backend '{name}' (expected 'local' or 'cloud')")
