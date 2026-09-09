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

This matters now because the MCP server (``agentopsy.mcp.toolkit``) may run as a separate
process (``python -m agentopsy.mcp`` spawned by Claude Desktop) that writes to the SAME
``audit.jsonl`` as the api's dispatcher writes to. The lock is the only thing that
keeps the hash chain coherent across processes, and it has to work on
Windows / macOS / Linux uniformly.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from filelock import FileLock

GENESIS = "0" * 64


@dataclass(frozen=True)
class EstadoCadena:
    """The result of verifying the chain: valid or not, and where it broke.

    ``indice_roto`` is 1-based over the non-empty lines of the log, so it names a
    line the examiner can open. ``motivo`` is a development-facing string: the
    surfaces translate the FACT (the chain does not verify) into their own
    product message, they do not forward this text.
    """

    valida: bool
    entradas: int
    indice_roto: int | None = None
    motivo: str | None = None


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

        Read-only view for policy lookups and cost aggregation. It does NOT
        re-check the hash chain — call ``verify()`` for tamper-evidence.
        Missing log → empty list.
        """
        if not self.path.exists():
            return []
        out: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

    def estado(self) -> "EstadoCadena":
        """Verify the chain and say WHERE it broke, not just whether it did.

        ``verify()`` answers a yes/no question, and a yes/no answer is not enough
        for the consumers that use audited entries as ANCHORS of trust
        (``agentopsy.artifacts.lectura``): they need to refuse an anchor read out
        of a broken chain, and they need to name the entry that broke it so the
        examiner can look at it. A malformed line (truncated write, hand-edited
        JSON) is a break like any other, reported as such instead of raising a
        ``JSONDecodeError`` at the caller.

        A log that does not exist yet is ``valida=True`` with ``entradas=0``:
        there is no chain to break. That is NOT the same as an existing log whose
        chain fails, and the two are never collapsed into the same answer.
        """
        if not self.path.exists():
            return EstadoCadena(valida=True, entradas=0)
        prev = GENESIS
        indice = 0
        try:
            lineas = self.path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            return EstadoCadena(
                valida=False, entradas=0, indice_roto=0, motivo=f"unreadable log: {exc}"
            )
        for linea in lineas:
            if not linea.strip():
                continue
            indice += 1
            try:
                entry = json.loads(linea)
            except json.JSONDecodeError as exc:
                return EstadoCadena(
                    valida=False,
                    entradas=indice,
                    indice_roto=indice,
                    motivo=f"entry {indice} is not valid JSON: {exc}",
                )
            if not isinstance(entry, dict) or "entry_hash" not in entry:
                return EstadoCadena(
                    valida=False,
                    entradas=indice,
                    indice_roto=indice,
                    motivo=f"entry {indice} carries no entry_hash",
                )
            recorded = entry.pop("entry_hash")
            if entry.get("prev_hash") != prev:
                return EstadoCadena(
                    valida=False,
                    entradas=indice,
                    indice_roto=indice,
                    motivo=f"entry {indice} does not chain to the previous one",
                )
            if hashlib.sha256(_canonical(entry)).hexdigest() != recorded:
                return EstadoCadena(
                    valida=False,
                    entradas=indice,
                    indice_roto=indice,
                    motivo=f"entry {indice} does not hash to its recorded entry_hash",
                )
            prev = recorded
        return EstadoCadena(valida=True, entradas=indice)

    def verify(self) -> bool:
        """Whether the whole chain verifies. Thin wrapper over :meth:`estado`.

        It never raises on a corrupt log: a log that cannot be parsed is a log
        that does not verify, which is the honest answer and the one every caller
        already handles.
        """
        return self.estado().valida
