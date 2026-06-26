"""xxd wrapper — hex dump of the first bytes of the evidence.

POSIX (`xxd` ships with vim, present on macOS and Linux by default). Used by
the agent right after `file_info` to **see** the magic bytes when `file` returns
nothing diagnostic. The first 16-32 bytes identify almost every forensic
container: EWF, ELF, PE, ZIP, OLE2, MBR, GPT, hibernation files, LiME, etc.
"""

from __future__ import annotations

from typing import Any

ALLOWED_FLAGS = frozenset({"-l", "-s", "-c"})


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for xxd.

    params:
        image_path (str, required).
        bytes (int, optional, default 512): how many bytes to dump (`-l`).
        skip (int, optional, default 0): offset to start (`-s`).
        cols (int, optional, default 16): bytes per row (`-c`).
    """
    image_path = params.get("image_path")
    if not image_path or not isinstance(image_path, str):
        raise ValueError("xxd_head requires params.image_path: str")

    n_bytes = params.get("bytes", 512)
    if not isinstance(n_bytes, int) or n_bytes < 1 or n_bytes > 65536:
        raise ValueError("xxd_head bytes must be 1..65536")
    skip = params.get("skip", 0)
    if not isinstance(skip, int) or skip < 0:
        raise ValueError("xxd_head skip must be a non-negative int")
    cols = params.get("cols", 16)
    if not isinstance(cols, int) or cols < 4 or cols > 64:
        raise ValueError("xxd_head cols must be 4..64")

    return ["-l", str(n_bytes), "-s", str(skip), "-c", str(cols), image_path]


def parse(stdout: str) -> dict[str, Any]:
    """xxd output is already structured; we just summarise."""
    lines = stdout.splitlines()
    # Pull the raw hex column (chars 10-49 typically) and the ASCII tail (49-).
    hex_only = []
    for line in lines:
        # Format: 00000000: 7f45 4c46 0201 0102 0000 0000 0000 0000  .ELF............
        if ":" in line:
            after = line.split(":", 1)[1]
            # The ASCII column is after two spaces between hex and ascii.
            parts = after.rsplit("  ", 1)
            if len(parts) >= 1:
                hex_only.append(parts[0].strip())
    head_hex = " ".join(hex_only[:2])  # first 32 bytes of hex
    return {
        "raw": stdout,
        "lines": len(lines),
        "first_32_hex": head_hex,
    }
