"""Chat session storage: append-only JSONL per session under ``<case_dir>/chats/``.

One ``<session_id>.jsonl`` file per chat session. Each line is exactly one JSON
object (one :class:`ChatMessage`). Writes are append-only with line buffering
so concurrent readers see whole lines; a truncated trailing line on read is
tolerated (skipped with a warning) rather than corrupting the session.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from forensia.cases.manager import CaseManager, case_manager

logger = logging.getLogger(__name__)

_ALLOWED_ROLES = frozenset({"user", "assistant", "system", "tool"})
_SESSION_ID_RE = re.compile(r"^([a-fA-F0-9-]{36}|[a-zA-Z0-9_-]{1,64})$")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ChatMessage:
    role: str  # one of {"user", "assistant", "system", "tool"}
    content: str
    ts: str  # ISO-8601 UTC; auto-filled by ChatStore.append if empty
    tool_calls: list[dict] | None = None  # optional; { tool_id, params, run_id }
    # Traza de actividad del turno (eventos tool_call/tool_result/finding/
    # reasoning) para poder RE-PINTAR el bloque colapsable "✓ N pasos" al recargar
    # el chat, como en Claude Code. Sólo presentación; NO se re-inyecta al modelo.
    activity: list[dict] | None = None


class ChatStore:
    """Filesystem-backed JSONL store for chat sessions."""

    def __init__(self, case_manager: CaseManager) -> None:
        self._cases = case_manager

    # ---------- internal helpers ----------

    def _chats_dir(self, case_id: str) -> Path:
        # ``case_dir`` raises KeyError on unknown case_id — propagate.
        return self._cases.case_dir(case_id) / "chats"

    def _session_path(self, case_id: str, session_id: str) -> Path:
        if not isinstance(session_id, str) or not _SESSION_ID_RE.match(session_id):
            raise ValueError(
                f"invalid session_id (expected UUID or slug matching "
                f"^[a-zA-Z0-9_-]{{1,64}}$): {session_id!r}"
            )
        return self._chats_dir(case_id) / f"{session_id}.jsonl"

    @staticmethod
    def _validate_message(message: ChatMessage) -> None:
        if not isinstance(message, ChatMessage):
            raise TypeError(f"expected ChatMessage, got {type(message).__name__}")
        if message.role not in _ALLOWED_ROLES:
            raise ValueError(
                f"invalid role {message.role!r} (expected one of {sorted(_ALLOWED_ROLES)})"
            )
        if not isinstance(message.content, str):
            raise ValueError("ChatMessage.content must be a str")
        if message.tool_calls is not None and not isinstance(message.tool_calls, list):
            raise ValueError("ChatMessage.tool_calls must be a list[dict] or None")
        if message.activity is not None and not isinstance(message.activity, list):
            raise ValueError("ChatMessage.activity must be a list[dict] or None")

    # ---------- public API ----------

    def append(self, case_id: str, session_id: str, message: ChatMessage) -> None:
        """Append one JSON object (one message) to ``chats/<session_id>.jsonl``.

        Auto-fills ``ts`` if ``message.ts`` is empty. Creates the ``chats/``
        directory and the session file on first append.
        """
        self._validate_message(message)
        path = self._session_path(case_id, session_id)
        path.parent.mkdir(parents=True, exist_ok=True)

        payload = asdict(message)
        if not payload.get("ts"):
            payload["ts"] = _now_iso()

        line = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        # Line-buffered append: one json.dumps + '\n' per call, atomic per line
        # on POSIX for sizes well below PIPE_BUF.
        with path.open("a", encoding="utf-8", buffering=1) as fh:
            fh.write(line + "\n")

    def read(self, case_id: str, session_id: str) -> list[ChatMessage]:
        """Return every message in the session, in insertion order.

        A truncated trailing line (e.g. from a crash mid-write) is skipped with
        a warning instead of raising. Raises ``KeyError`` if the session file
        does not exist.
        """
        path = self._session_path(case_id, session_id)
        if not path.exists():
            raise KeyError(f"unknown chat session for case {case_id}: {session_id}")

        messages: list[ChatMessage] = []
        with path.open("r", encoding="utf-8") as fh:
            lines = fh.readlines()
        for idx, raw in enumerate(lines):
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                # Tolerate ONLY a truncated last line — anything else is corruption.
                if idx == len(lines) - 1:
                    logger.warning(
                        "skipping truncated last line in chat session %s/%s",
                        case_id,
                        session_id,
                    )
                    continue
                raise
            messages.append(
                ChatMessage(
                    role=obj["role"],
                    content=obj["content"],
                    ts=obj["ts"],
                    tool_calls=obj.get("tool_calls"),
                    activity=obj.get("activity"),
                )
            )
        return messages

    def list_sessions(self, case_id: str) -> list[str]:
        """Return session ids found in ``chats/`` (filenames stripped of ``.jsonl``)."""
        chats_dir = self._chats_dir(case_id)
        if not chats_dir.exists():
            return []
        return sorted(
            p.stem
            for p in chats_dir.iterdir()
            if p.is_file() and p.suffix == ".jsonl" and _SESSION_ID_RE.match(p.stem)
        )


chat_store = ChatStore(case_manager)
