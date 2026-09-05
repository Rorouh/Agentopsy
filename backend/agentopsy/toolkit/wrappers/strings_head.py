"""strings wrapper — extract printable strings ≥ N chars from the evidence.

POSIX (binutils on Linux, baked-in on macOS as `/usr/bin/strings`). Used by
the agent as the second "first look" step after `file_info` and `xxd_head`:
vendor names, format markers, kernel version strings and embedded paths
appear here and immediately disambiguate "data" blobs.

The wrapper bounds the output so the LLM context doesn't blow up: a default
of 200 lines is plenty to spot a memdump signature, a vendor brand or a
kernel banner.
"""

from __future__ import annotations

from typing import Any

ALLOWED_FLAGS = frozenset({"-n", "-a", "-t", "-e"})


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for strings.

    params:
        image_path (str, required).
        min_len (int, optional, default 12): minimum string length (`-n`).
        radix (str, optional): 'd' / 'o' / 'x' for `-t`.
    """
    image_path = params.get("image_path")
    if not image_path or not isinstance(image_path, str):
        raise ValueError("strings_head requires params.image_path: str")

    min_len = params.get("min_len", 12)
    if not isinstance(min_len, int) or min_len < 4 or min_len > 256:
        raise ValueError("strings_head min_len must be 4..256")

    argv: list[str] = ["-n", str(min_len)]
    if (radix := params.get("radix")):
        if radix not in {"d", "o", "x"}:
            raise ValueError("strings_head radix must be 'd', 'o' or 'x'")
        argv += ["-t", str(radix)]
    argv.append(image_path)
    return argv


# How many lines we forward to the LLM. Keeps the message-history bounded.
_LINE_CAP = 200


def parse(stdout: str) -> dict[str, Any]:
    lines = stdout.splitlines()
    head = lines[:_LINE_CAP]
    tail = lines[-50:] if len(lines) > _LINE_CAP else []
    # Tiny heuristics so the LLM can act without parsing every line.
    lower = stdout.lower()
    hints: list[str] = []
    if "linux version" in lower:
        hints.append("linux_kernel_banner")
    if "windows" in lower and ("nt " in lower or "kernel" in lower):
        hints.append("windows_kernel_strings")
    if "vmware" in lower or "vmdk" in lower:
        hints.append("vmware_vmdk")
    if "evtx" in lower:
        hints.append("evtx_signature")
    if "encase" in lower or "ftk" in lower:
        hints.append("ewf_e01_metadata")
    if "memory" in lower and "dump" in lower:
        hints.append("memory_dump_marker")
    if "lime" in lower:
        hints.append("lime_format_marker")
    return {
        "total_lines": len(lines),
        "head": head,
        "tail_50": tail,
        "format_hints": hints,
    }
