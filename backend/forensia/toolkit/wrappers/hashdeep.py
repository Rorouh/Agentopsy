"""hashdeep wrapper — recursive, multi-algorithm hashing.

Computes several hashes (MD5 / SHA-1 / SHA-256 / …) of a file or a directory tree in
one pass. On a raw evidence image it yields the image's hashes (integrity cross-check
against the baseline FORENSIA registered); recursively over an extracted tree it produces
the hash set for the report. hashdeep also supports an **audit** mode (`-a -k <known>`)
that filters a tree against a known set (e.g. NSRL) — not exposed here yet.

Output is CSV with a `%%%%` column header; `parse` turns it into per-file hash maps.
"""

from __future__ import annotations

from typing import Any

ALLOWED_FLAGS = frozenset({"-c", "-r", "-l", "-b", "-j", "-e"})

# Algorithms hashdeep understands (via -c). Kept as an allowlist so the argv never
# carries an arbitrary string.
_ALGOS = ("md5", "sha1", "sha256", "sha512", "tiger", "whirlpool")


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for hashdeep.

    params:
        image_path (str, required): file or directory to hash (evidence image or
            an extracted tree). FORENSIA injects the evidence path here.
        algorithms (list[str], optional): subset of md5/sha1/sha256/sha512/tiger/
            whirlpool. Default ["md5", "sha256"].
        recursive (bool, optional): recurse into directories (`-r`). Default False.
    """
    image_path = params.get("image_path")
    if not image_path or not isinstance(image_path, str):
        raise ValueError("hashdeep requires params.image_path: str")

    algorithms = params.get("algorithms") or ["md5", "sha256"]
    if not isinstance(algorithms, list) or not all(isinstance(a, str) for a in algorithms):
        raise ValueError("hashdeep algorithms must be a list[str]")
    for a in algorithms:
        if a not in _ALGOS:
            raise ValueError(f"hashdeep: invalid algorithm {a!r} (allowed: {list(_ALGOS)})")

    argv: list[str] = ["-c", ",".join(algorithms)]
    if params.get("recursive"):
        argv.append("-r")
    argv.append(image_path)
    return argv


def parse(stdout: str) -> dict[str, Any]:
    """Parse hashdeep CSV output into per-file hash maps.

    Format: header lines start with `%%%%` (one carries the column order, e.g.
    ``%%%% size,md5,sha256,filename``) or `##`; data lines are
    ``size,<hash1>,<hash2>,...,filename``.
    """
    columns: list[str] | None = None
    files: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        if not line:
            continue
        if line.startswith("%%%%"):
            body = line[4:].strip()
            if body.lower().startswith("size,"):
                columns = [c.strip() for c in body.split(",")]
            continue
        if line.startswith("#") or line.startswith("%"):
            continue
        parts = line.split(",")
        if len(parts) < 3:
            continue
        size, path = parts[0], parts[-1]
        hash_values = parts[1:-1]
        if columns:
            algo_names = [c for c in columns if c not in ("size", "filename")]
        else:
            algo_names = [f"hash{i}" for i in range(len(hash_values))]
        hashes = dict(zip(algo_names, hash_values))
        files.append({"size": size, "path": path, "hashes": hashes})

    algorithms = [c for c in (columns or []) if c not in ("size", "filename")] or None
    return {
        "files_count": len(files),
        "algorithms": algorithms,
        "files": files[:200],
    }
