"""Tamper-evident audit log: one JSON object per line, each chained to the previous.

Records the LITERAL action (argv), never the LLM's stated intent. Implemented for real
in the skeleton because it is cheap and central to chain of custody.
"""

from __future__ import annotations

import hashlib
import json
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

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = GENESIS
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = json.loads(line)["entry_hash"]
        return last

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        prev = self._last_hash()
        body = {
            "ts_utc": datetime.now(timezone.utc).isoformat(),
            "prev_hash": prev,
            **event,
        }
        body["entry_hash"] = hashlib.sha256(_canonical(body)).hexdigest()
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(body, sort_keys=True) + "\n")
        return body

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
