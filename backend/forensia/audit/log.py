"""Tamper-evident audit log: one JSON object per line, each chained to the previous.

Records the LITERAL action (argv), never the LLM's stated intent. Implemented for real
in the skeleton because it is cheap and central to chain of custody.

**Concurrency**: ``append`` takes an exclusive cross-platform file lock (via the
``filelock`` library, which uses ``fcntl`` on POSIX and ``msvcrt`` on Windows) over a
companion ``audit.jsonl.lock`` file for the duration of the read-prev → compute → write
critical section. Without the lock, two concurrent appenders both read the same
``prev_hash`` and the chain branches silently — only detectable later by ``verify()``.
With it, appenders serialise. The lock is held for microseconds and goes away when the
context manager exits (process death is also safe — the OS releases the lock).

This matters now because the MCP server (``forensia.mcp.toolkit``) may run as a separate
process (``python -m forensia.mcp`` spawned by Claude Desktop) that writes to the SAME
``audit.jsonl`` as the api's dispatcher writes to. The lock is the only thing that
keeps the hash chain coherent across processes — and the propuesta v1.2 requires this to
work on Windows / macOS / Linux uniformly.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from filelock import FileLock

GENESIS = "0" * 64


def _canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Lockfile is a COMPANION FILE of the audit log (not the log itself) so the locking
        # semantics are uniform across POSIX (advisory flock) and Windows (mandatory
        # msvcrt range lock). The audit.jsonl remains pure append-only data.
        self._lock_path = self.path.with_suffix(self.path.suffix + ".lock")

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = GENESIS
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = json.loads(line)["entry_hash"]
        return last

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        # Exclusive cross-process lock on the companion lockfile. The critical section
        # is read-tail → compute hash → append: the read and the write must observe
        # the same ``prev_hash``. Outside the lock, appends to ``audit.jsonl`` would
        # race and the chain would branch silently.
        with FileLock(str(self._lock_path)):
            prev = self._last_hash()
            body = {
                "ts_utc": datetime.now(timezone.utc).isoformat(),
                "prev_hash": prev,
                **event,
            }
            body["entry_hash"] = hashlib.sha256(_canonical(body)).hexdigest()
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(body, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            return body

    def entries(self) -> list[dict[str, Any]]:
        """Parsed entries in append order.

        Read-only view for policy lookups (e.g. the cloud-consent gate in
        ``forensia.consent``). It does NOT re-check the hash chain — call
        ``verify()`` for tamper-evidence. Missing log → empty list.
        """
        if not self.path.exists():
            return []
        out: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

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
