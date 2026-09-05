"""TSK `mmls` wrapper — list partitions of a raw disk image.

The `Slot` column (parsed as `meta`) carries the row's KIND, and TSK writes a real
partition's slot in two different shapes depending on the partition table. Anything
reading `meta` to tell partitions from table metadata has to accept both.

DOS/MBR table over an NTFS partition — the slot is `table:slot`:

    DOS Partition Table
    Offset Sector: 0
    Units are in 512-byte sectors

         Slot      Start        End          Length       Description
    000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
    001:  -------   0000000000   0000002047   0000002048   Unallocated
    002:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07)

GPT table (a modern Windows 10/11 or Linux disk) — no nested tables, so the slot
is printed ALONE:

    GUID Partition Table (EFI)
    Offset Sector: 0
    Units are in 512-byte sectors

          Slot      Start        End          Length       Description
    000:  Meta      0000000000   0000000000   0000000001   Safety Table
    003:  Meta      0000000002   0000000033   0000000032   Partition Table
    004:  000       0000002048   0001023999   0001021952   Basic data partition
    005:  001       0001024000   0001226751   0000202752   EFI system partition

`Meta` rows are the table's own structures and `-------` is unallocated space:
neither is a filesystem.
"""

from __future__ import annotations

import re
from typing import Any

ALLOWED_FLAGS = frozenset({"-t", "-i", "-o", "-B"})

_VALID_PT_TYPES = frozenset({"dos", "gpt", "mac", "bsd", "sun"})
_VALID_IMG_FORMATS = frozenset({"raw", "ewf", "aff", "vmdk", "vhd"})

_PARTITION_RE = re.compile(
    r"^(?P<slot>\d{3}):\s+(?P<meta>\S+)\s+(?P<start>\d+)\s+(?P<end>\d+)\s+"
    r"(?P<length>\d+)\s+(?P<description>.+)$"
)


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for mmls.

    params:
        image_path (str, required): host path to the image file (a `Handle` from
            EvidenceManager). The Tool resolver supplies the binary; this returns
            ONLY the argv tail (no binary name).
        type (str, optional): partition table type — one of `dos`, `gpt`, `mac`,
            `bsd`, `sun`. mmls auto-detects if absent.
        image_format (str, optional): one of `raw`, `ewf`, `aff`, `vmdk`, `vhd`.
            mmls auto-detects if absent.
    """
    image_path = params.get("image_path")
    if not image_path or not isinstance(image_path, str):
        raise ValueError("mmls requires params.image_path: str")

    argv: list[str] = []
    if t := params.get("type"):
        if t not in _VALID_PT_TYPES:
            raise ValueError(f"invalid mmls type: {t!r}")
        argv += ["-t", t]
    if fmt := params.get("image_format"):
        if fmt not in _VALID_IMG_FORMATS:
            raise ValueError(f"invalid mmls image_format: {fmt!r}")
        argv += ["-i", fmt]
    argv.append(image_path)
    return argv


def parse(stdout: str) -> dict[str, Any]:
    """Extract partitions into a structured dict the agent can reason over."""
    partitions = []
    for line in stdout.splitlines():
        m = _PARTITION_RE.match(line.strip())
        if not m:
            continue
        partitions.append(
            {
                "slot": int(m["slot"]),
                "meta": m["meta"],
                "start_sector": int(m["start"]),
                "end_sector": int(m["end"]),
                "length_sectors": int(m["length"]),
                "description": m["description"].strip(),
            }
        )
    return {"partitions": partitions, "count": len(partitions)}
