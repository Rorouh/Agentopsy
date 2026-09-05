"""Agent-loop action types + the adapter over the execution layer.

The concrete executors live in ``agentopsy.executors`` (operator-selected per
request; no SDK backends, no API keys — 2026-07-02 pivot).
"""

from agentopsy.models.base import (
    Action,
    ExecutorBackend,
    FinalAnswer,
    ModelBackend,
    ModelCapabilities,
    ResponseContractError,
    ToolBatch,
    ToolCall,
)

__all__ = [
    "Action",
    "ExecutorBackend",
    "FinalAnswer",
    "ModelBackend",
    "ModelCapabilities",
    "ResponseContractError",
    "ToolBatch",
    "ToolCall",
]
