"""Resolve a forensic tool's invocation per CLAUDE.md RULE 1:

    env override → declared delivery in catalog (bundled | container) → host PATH

The catalog entry for each tool declares its delivery per host OS. Bundled tools live
under `vendor/<tool>/<os>-<arch>/<binary>` (or inside the PyInstaller sidecar for Python
tools). Container-delivered tools require docker / podman / nerdctl on the host.

`is_tool_available(tool)` is the per-tool predicate `capabilities` reports — `None`/
`False` here means the UI degrades, never a crude error.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
from pathlib import Path
from typing import Literal

from forensia.toolkit.tool import Tool

HostOs = Literal["linux", "mac", "windows"]

_HOST_OS_MAP: dict[str, HostOs] = {
    "linux": "linux",
    "darwin": "mac",
    "win32": "windows",
}


def current_host_os() -> HostOs:
    return _HOST_OS_MAP.get(sys.platform, "linux")


def platform_key() -> str:
    system = {"darwin": "mac", "win32": "win"}.get(sys.platform, sys.platform)
    arch = {"x86_64": "x64", "amd64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(
        platform.machine().lower(), platform.machine().lower()
    )
    return f"{system}-{arch}"


def bundled_root() -> Path:
    override = os.environ.get("FORENSIA_RESOURCES")
    if override:
        return Path(override)
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent)) / "vendor"
    return Path(__file__).resolve().parents[3] / "vendor"


def resolve(binary: str) -> Path | None:
    """Find a binary via env override → bundled → host PATH. None if absent."""
    env = os.environ.get(f"FORENSIA_{binary.upper().replace('-', '_')}_BIN")
    if env and Path(env).exists():
        return Path(env)

    candidate = bundled_root() / binary / platform_key() / binary
    for path in (candidate, candidate.with_suffix(".exe")):
        if path.exists():
            return path

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


def is_tool_available(tool: Tool) -> bool:
    """Per-tool availability based on its declared delivery for THIS host OS."""
    host = current_host_os()
    mode = tool.delivery_for(host)
    if mode == "bundled":
        return resolve(tool.binary) is not None
    if mode == "container":
        return container_runtime() is not None
    return False
