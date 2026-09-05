"""Low-level resolution helpers per CLAUDE.md RULE 1.

- `resolve(binary)`: env override (`AGENTOPSY_<BIN>_BIN`) → host PATH, for binaries
  resolvable where the api itself runs (dev / env-override path).
- `container_runtime()`: the OCI client (docker/podman/nerdctl) the api would use to
  reach the maletines.
- `current_host_os()`: still consumed by the dispatcher's legacy execution path.

Per-tool availability against the compose maletines (`toolkit-windows` / `toolkit-unix`)
lives in `agentopsy.toolkit.maletin`, which is what `capabilities` reports. The old
vendored per-OS/arch binaries are gone (pivote 2026-07-02).
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Literal

HostOs = Literal["linux", "mac", "windows"]

_HOST_OS_MAP: dict[str, HostOs] = {
    "linux": "linux",
    "darwin": "mac",
    "win32": "windows",
}


def current_host_os() -> HostOs:
    return _HOST_OS_MAP.get(sys.platform, "linux")


def resolve(binary: str) -> Path | None:
    """Find a binary via env override → host PATH. None if absent."""
    env = os.environ.get(f"AGENTOPSY_{binary.upper().replace('-', '_')}_BIN")
    if env and Path(env).exists():
        return Path(env)

    found = shutil.which(binary)
    return Path(found) if found else None


def container_runtime() -> Path | None:
    """Return the path to a usable OCI runtime, or None.

    Tries docker, podman, nerdctl in that order. Presence on PATH is sufficient
    for `capabilities` reporting; the actual `docker info` health check belongs to the
    executor that runs a containerized tool.
    """
    for binary in ("docker", "podman", "nerdctl"):
        found = shutil.which(binary)
        if found:
            return Path(found)
    return None
