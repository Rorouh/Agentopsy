"""Resolve a forensic binary in EXACTLY this order (CLAUDE.md RULE 1):

    env override  ->  bundled (resources packaged / vendor in dev)  ->  host PATH

There is NO Docker branch. `None` means the tool is unavailable; the UI degrades via
capabilities, it never errors crudely.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
from pathlib import Path


def platform_key() -> str:
    system = {"darwin": "mac", "windows": "win"}.get(sys.platform, sys.platform)
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
    env = os.environ.get(f"FORENSIA_{binary.upper().replace('-', '_')}_BIN")
    if env and Path(env).exists():
        return Path(env)

    candidate = bundled_root() / binary / platform_key() / binary
    for path in (candidate, candidate.with_suffix(".exe")):
        if path.exists():
            return path

    found = shutil.which(binary)
    return Path(found) if found else None
