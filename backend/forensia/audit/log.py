"""Tamper-evident audit log: one JSON object per line, each chained to the previous.

Records the LITERAL action (argv), never the LLM's stated intent. Implemented for real
in the skeleton because it is cheap and central to chain of custody.

**Concurrency**: ``append`` takes an exclusive ``fcntl.flock`` over the log file for the
duration of the read-prev → compute → write critical section. Without the lock, two
concurrent appenders both read the same ``prev_hash`` and the chain branches silently —
only detectable later by ``verify()``. With it, appenders serialise. The lock is held for
microseconds and goes away when the file descriptor closes (process death is safe).

This matters now because the MCP server (``forensia.mcp.toolkit``) may run as a separate
process (``python -m forensia.mcp`` spawned by Claude Desktop) that writes to the SAME
``audit.jsonl`` as the sidecar's dispatcher writes to. The lock is the only thing that
keeps the hash chain coherent across processes.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash_from_fd(self, fh) -> str:
        """Read the chain tail from an OPEN file descriptor (the same one locked by
        ``append``). Avoids the race window between two ``read_text`` + ``open("a")``
        cycles. Empty file → GENESIS.
        """
        fh.seek(0)
        last = GENESIS
        for line in fh:
            stripped = line.strip()
            if not stripped:
                continue
            last = json.loads(stripped)["entry_hash"]
        return last

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = GENESIS
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = json.loads(line)["entry_hash"]
        return last

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        # Open with O_RDWR | O_CREAT | O_APPEND so the same fd can both read the
        # tail and append the new line under a single lock. ``a`` mode would seek
        # to end on every write but reading the tail still needs explicit seek(0).
        flags = os.O_RDWR | os.O_CREAT | os.O_APPEND
        fd = os.open(self.path, flags, 0o644)
        try:
            with os.fdopen(fd, "r+", encoding="utf-8") as fh:
                # Exclusive lock across processes. Released when fd closes.
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                prev = self._last_hash_from_fd(fh)
                body = {
                    "ts_utc": datetime.now(timezone.utc).isoformat(),
                    "prev_hash": prev,
                    **event,
                }
                body["entry_hash"] = hashlib.sha256(_canonical(body)).hexdigest()
                # O_APPEND guarantees writes go to EOF atomically.
                fh.write(json.dumps(body, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
                return body
        except BaseException:
            # If we opened fd but didn't get into the with-block, close it.
            try:
                os.close(fd)
            except OSError:
                pass
            raise

    def verify(self) -> bool:
        prev = GENESIS
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            recorded = entry.pop("entry_hash")
            if entry["prev_hash"] != prev:
                return False
            if hashlib.sha256(_canonical(entry)).hexdigest() != recorded:
                return False
            prev = recorded
        return True
