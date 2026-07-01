#!/usr/bin/env python3
"""Compute the SHA-256 baseline of an evidence file (dev helper).

This is a *development* helper for populating the `SHA-256 baseline` column of
docs/agentes/corpus-windows.md and the ground-truth metadata blocks. It is NOT
the runtime hash gate — inside the app, `forensia.evidence.EvidenceManager` owns
the ingest → baseline hash → set read-only → expose handle sequence (see
CLAUDE.md, FORENSIC INVARIANTS §2). This script only reproduces the same digest
so a human can record it once and re-verify later.

Design constraints (CLAUDE.md):
  * Shell-free: no os.system / os.popen / subprocess. Pure `hashlib`. (gate 4)
  * Streaming: reads in fixed-size blocks so multi-GB images never load into RAM.
  * No fallbacks: a missing/unreadable/non-regular file fails loudly, non-zero,
    with an actionable message — it never guesses or silently skips. (RULE 2)

Usage:
    python scripts/hash-evidence.py <path-to-evidence-file>

Example:
    python scripts/hash-evidence.py evidence-corpus/lonewolf-2018/LoneWolf.E01

Output (one line, stable format):
    sha256 <hexdigest>  size <bytes>  path <path>

Exit codes:
    0  success
    2  usage error (wrong number of arguments)
    1  the path does not exist, is not a regular file, or cannot be read
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

# 1 MiB blocks: large enough to keep syscall overhead low on multi-GB images,
# small enough that memory stays flat regardless of file size.
_BLOCK_SIZE = 1024 * 1024


def sha256_streaming(path: Path, block_size: int = _BLOCK_SIZE) -> tuple[str, int]:
    """Return (hexdigest, size_in_bytes) for *path*, reading in blocks.

    Raises FileNotFoundError / IsADirectoryError / OSError to the caller instead
    of masking them — the surface (``main``) turns them into a loud exit.
    """
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(block_size)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
    return digest.hexdigest(), total


def main(argv: list[str]) -> int:
    # No fallbacks: demand exactly one path. Do not "default to cwd" or "take the
    # first *.raw we can find" — the operator names the file explicitly (RULE 2).
    if len(argv) != 2:
        sys.stderr.write(
            "error: exactly one argument expected (the evidence file path).\n"
            "usage: python scripts/hash-evidence.py <path-to-evidence-file>\n"
        )
        return 2

    path = Path(argv[1])

    if not path.exists():
        sys.stderr.write(f"error: file does not exist: {path}\n")
        return 1
    if not path.is_file():
        sys.stderr.write(f"error: not a regular file (is it a directory?): {path}\n")
        return 1

    try:
        hexdigest, size = sha256_streaming(path)
    except OSError as exc:  # permission denied, I/O error, etc. — fail loud.
        sys.stderr.write(f"error: cannot read {path}: {exc}\n")
        return 1

    sys.stdout.write(f"sha256 {hexdigest}  size {size}  path {path}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
