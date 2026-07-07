"""TSK `icat` wrapper — extract a file's content by inode, without mounting.

Given the metadata address (inode) of a file located with `tsk_fls`, `icat` streams its
bytes from the raw image (allocated or deleted) to stdout — the surgical extraction step
that follows a listing. Returns the content as an artifact.

Caveat: the exec-agent decodes stdout as text; a purely binary file may come back with
replacement chars. For binary artifacts prefer extracting and inspecting via the artifact
file rather than the parsed preview.
"""

from __future__ import annotations

import re
from typing import Any

ALLOWED_FLAGS = frozenset({"-o", "-f", "-i", "-r", "-s"})

# TSK metadata address: a number, optionally with -type[-id] suffixes (e.g. "13552",
# "12-128-4"). Kept strict so the argv never carries an arbitrary token.
_INODE_RE = re.compile(r"^\d+(?:-\d+){0,2}$")

_VALID_FS_TYPES = frozenset(
    {"ntfs", "fat", "fat12", "fat16", "fat32", "ext2", "ext3", "ext4", "hfs", "iso9660", "ufs", "yaffs2"}
)
_VALID_IMG_FORMATS = frozenset({"raw", "ewf", "aff", "vmdk", "vhd"})


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for icat.

    params:
        image_path (str, required): raw image. Injected by FORENSIA.
        inode (int | str, required): TSK metadata address of the file to extract.
        partition_offset (int, optional): partition offset in sectors (`-o`).
        filesystem (str, optional): filesystem type hint (`-f`).
        image_format (str, optional): image format hint (`-i`).
        recover (bool, optional): recover deleted content best-effort (`-r`).
        slack (bool, optional): include slack space (`-s`).
    """
    image_path = params.get("image_path")
    if not image_path or not isinstance(image_path, str):
        raise ValueError("icat requires params.image_path: str")

    inode = params.get("inode")
    if isinstance(inode, int):
        inode = str(inode)
    if not isinstance(inode, str) or not _INODE_RE.match(inode):
        raise ValueError("icat requires params.inode: a TSK metadata address (e.g. 13552 or 12-128-4)")

    argv: list[str] = []
    if (off := params.get("partition_offset")) is not None:
        if not isinstance(off, int) or off < 0:
            raise ValueError("icat partition_offset must be a non-negative int")
        argv += ["-o", str(off)]
    if (fs := params.get("filesystem")):
        if fs not in _VALID_FS_TYPES:
            raise ValueError(f"invalid icat filesystem: {fs!r}")
        argv += ["-f", fs]
    if (fmt := params.get("image_format")):
        if fmt not in _VALID_IMG_FORMATS:
            raise ValueError(f"invalid icat image_format: {fmt!r}")
        argv += ["-i", fmt]
    if params.get("recover"):
        argv.append("-r")
    if params.get("slack"):
        argv.append("-s")

    argv += [image_path, inode]
    return argv


def parse(stdout: str) -> dict[str, Any]:
    """Summarise the extracted content: length, a text/binary heuristic and a preview."""
    length = len(stdout)
    if length == 0:
        return {"content_length": 0, "is_text": True, "preview": ""}
    sample = stdout[:1000]
    printable = sum(1 for c in sample if c.isprintable() or c in "\n\t\r")
    is_text = printable / len(sample) > 0.85
    return {
        "content_length": length,
        "is_text": is_text,
        "preview": stdout[:500] if is_text else None,
    }
