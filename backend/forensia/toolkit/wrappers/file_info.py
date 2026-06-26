"""file_info wrapper — characterize the evidence via libmagic (`file`).

POSIX standard. Available on macOS and every modern Linux distro without
extra deps. Used by the agent as the FIRST step of any analysis: knowing
whether the evidence is a disk image, a memory dump, an EVTX, an archive
or just "data" eliminates 2-3 wrong tool invocations.
"""

from __future__ import annotations

import re
from typing import Any

ALLOWED_FLAGS = frozenset({"-b", "-i", "-z", "-L", "--brief", "--mime"})

_HEADER_LINE_RE = re.compile(r"^(?P<head>[^,]+)(?:,\s*(?P<rest>.+))?$")


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for file.

    params:
        image_path (str, required): host path to the evidence.
        also_mime (bool, optional): also emit MIME info; default False.
        follow_symlink (bool, optional): default False (we already reject symlinks).
    """
    image_path = params.get("image_path")
    if not image_path or not isinstance(image_path, str):
        raise ValueError("file_info requires params.image_path: str")

    # Brief output (no filename prefix) — easier to parse.
    argv: list[str] = ["-b"]
    if params.get("also_mime"):
        argv.append("--mime")
    argv.append(image_path)
    return argv


def parse(stdout: str) -> dict[str, Any]:
    """Split the descriptive line into head + traits + raw."""
    raw = stdout.strip()
    if not raw:
        return {"raw": "", "description": None, "traits": []}

    m = _HEADER_LINE_RE.match(raw)
    if not m:
        return {"raw": raw, "description": raw, "traits": []}

    head = m.group("head").strip()
    rest = (m.group("rest") or "").strip()
    traits = [t.strip() for t in rest.split(",") if t.strip()]

    lower = raw.lower()
    hints: list[str] = []
    if "boot sector" in lower or "partition" in lower:
        hints.append("disk_image_with_partition_table")
    if "ewf" in lower or "encase" in lower:
        hints.append("ewf_e01")
    if "vmware" in lower or "vmdk" in lower:
        hints.append("vmdk")
    if "core" in lower and "dump" in lower:
        hints.append("memory_or_core_dump")
    if "elf" in lower or "mach-o" in lower or "pe32" in lower:
        hints.append("executable")
    if "evtx" in lower:
        hints.append("evtx")
    if raw == "data" or raw == "ASCII text":
        hints.append("unstructured_blob")

    return {
        "raw": raw,
        "description": head,
        "traits": traits,
        "format_hints": hints,
    }
