"""TSK `fls` wrapper — list files and directories from a raw image / partition.

Bundled cross-platform. Returns an artifact reference because `-r` can produce
millions of rows on a real image; the agent never sees the full output inline.
"""

from __future__ import annotations

import re
from typing import Any

ALLOWED_FLAGS = frozenset({"-r", "-m", "-d", "-u", "-o", "-f", "-i", "-l"})

_VALID_FS_TYPES = frozenset({"ntfs", "fat", "fat12", "fat16", "fat32", "ext2", "ext3", "ext4", "hfs", "iso9660", "ufs", "yaffs2"})
_VALID_IMG_FORMATS = frozenset({"raw", "ewf", "aff", "vmdk", "vhd"})

_FLS_LINE_RE = re.compile(r"^(?P<type>[rdlcps?-]/[rdlcps?-])\s+(?P<inode>[\d\-]+(?::\d+)?)(?:\s+\(realloc\))?:\s+(?P<name>.+)$")


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for fls.

    params:
        image_path (str, required): host path to the image.
        partition_offset (int, optional): partition offset in sectors (-o).
        filesystem (str, optional): filesystem type hint (-f).
        image_format (str, optional): image format hint (-i).
        body_format (bool, optional): emit body format for mactime (-m).
        recursive (bool, optional): recurse into directories (-r). Default False.
        deleted_only (bool, optional): only deleted entries (-d).
        allocated_only (bool, optional): only allocated entries (-u).
        long_format (bool, optional): long listing with timestamps (-l).
        mount_point (str, optional): mount point prefix for -m body format.
    """
    image_path = params.get("image_path")
    if not image_path or not isinstance(image_path, str):
        raise ValueError("fls requires params.image_path: str")

    argv: list[str] = []
    if (off := params.get("partition_offset")) is not None:
        if not isinstance(off, int) or off < 0:
            raise ValueError("fls partition_offset must be a non-negative int")
        argv += ["-o", str(off)]
    if (fs := params.get("filesystem")):
        if fs not in _VALID_FS_TYPES:
            raise ValueError(f"invalid fls filesystem: {fs!r}")
        argv += ["-f", fs]
    if (fmt := params.get("image_format")):
        if fmt not in _VALID_IMG_FORMATS:
            raise ValueError(f"invalid fls image_format: {fmt!r}")
        argv += ["-i", fmt]
    if params.get("body_format"):
        mount = params.get("mount_point", "/")
        if not isinstance(mount, str):
            raise ValueError("fls mount_point must be a str")
        argv += ["-m", mount]
    if params.get("recursive"):
        argv.append("-r")
    if params.get("deleted_only"):
        argv.append("-d")
    if params.get("allocated_only"):
        argv.append("-u")
    if params.get("long_format"):
        argv.append("-l")
    argv.append(image_path)
    return argv


def parse(stdout: str) -> dict[str, Any]:
    """Parse fls regular-format output. Body-format (`-m`) is handed off as raw."""
    if "|" in stdout.split("\n", 1)[0]:
        return {"format": "body", "raw": stdout, "lines": stdout.count("\n")}

    entries = []
    for line in stdout.splitlines():
        m = _FLS_LINE_RE.match(line.strip())
        if not m:
            continue
        entries.append(
            {
                "type": m["type"],
                "inode": m["inode"],
                "name": m["name"],
            }
        )
    return {"format": "list", "entries_count": len(entries), "entries": entries[:200]}
