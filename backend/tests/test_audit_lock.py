"""Concurrency test for AuditLog.append + fcntl.flock.

Without the lock, two processes appending concurrently both read the same
prev_hash and the chain branches silently. This test arms two CHILD processes
hammering the same log file in parallel and asserts that AuditLog.verify()
remains True afterwards — i.e. the chain is intact, regardless of who won
each lock.

Uses multiprocessing (real OS processes) because flock is the file-locking
mechanism we care about; a threading test would not exercise that path.
"""

from __future__ import annotations

import multiprocessing as mp
import os
from pathlib import Path

import pytest

from forensia.audit.log import AuditLog


def _hammer(path: str, n: int, label: str) -> None:
    """Child process: append `n` entries with `label` as discriminator."""
    log = AuditLog(Path(path))
    for i in range(n):
        log.append({"action": "concurrency_test", "worker": label, "i": i})


@pytest.mark.parametrize("workers,per_worker", [(2, 100), (4, 50)])
def test_concurrent_appends_keep_chain_intact(tmp_path: Path, workers: int, per_worker: int) -> None:
    log_path = tmp_path / "audit.jsonl"
    processes = []
    for k in range(workers):
        p = mp.Process(target=_hammer, args=(str(log_path), per_worker, f"w{k}"))
        p.start()
        processes.append(p)
    for p in processes:
        p.join(timeout=30)
        assert p.exitcode == 0, f"worker {p.pid} crashed: exitcode={p.exitcode}"

    log = AuditLog(log_path)
    assert log.verify(), "audit chain broke under concurrent appends — flock is not effective"

    # Sanity: we wrote exactly workers * per_worker lines.
    lines = log_path.read_text().splitlines()
    assert len([l for l in lines if l.strip()]) == workers * per_worker


def test_no_fd_leak_on_exception(tmp_path: Path) -> None:
    """If something inside append() raises, we must not leak the file descriptor."""
    log = AuditLog(tmp_path / "audit.jsonl")
    # Cause a downstream JSON-encode failure by passing a non-serialisable value.
    with pytest.raises(TypeError):
        log.append({"oops": object()})
    # The lockfile is the same as the log; if a leak happened, the OS would have
    # an open fd. We can at least confirm subsequent appends still work.
    entry = log.append({"action": "after_exception"})
    assert entry["action"] == "after_exception"
    assert log.verify()
