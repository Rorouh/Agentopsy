"""TSK `tsk_recover` wrapper — extract a whole DIRECTORY TREE from a raw image.

Where `tsk_icat` extracts ONE file by its metadata address, `tsk_recover` walks a
directory and writes every file under it into an output directory, preserving the tree.
It is the producer the catalog was missing: `hindsight` consumes a browser PROFILE
DIRECTORY, and until this wrapper existed nothing in the catalog could build one from a
disk image (`tsk_icat` yields a single `stdout.bin`), so the tool was exposed with an
input nobody could fill.

Like the rest of the TSK family it reads the image WITHOUT mounting a filesystem
(FORENSIC INVARIANT 3), and the image path is injected by Agentopsy, never chosen by
the model.

Two contract choices worth stating, both of them RULE 2 rather than taste:

- `-d dir_inum` takes a PLAIN metadata address. `tsk_fls` prints a directory as
  `d/d 68-144-6:`, and passing that full form makes tsk_recover report "Files
  Recovered: 0" WITHOUT failing (measured on 2020JimmyWilson.E01, 2026-09-03): a silent
  empty result, which is the worst outcome for a forensic step. The wrapper therefore
  accepts the address in either form and passes only the leading number, so the caller
  can hand over what `tsk_fls` printed and still get the 27 files that are really there.
- The allocation scope is EXPLICIT. `tsk_recover` defaults to allocated-only when
  neither `-a` nor `-e` is given, and "did this listing include deleted files" is a
  question a report has to answer, so the wrapper always emits one of the two flags and
  `scope` has a designed default of `allocated`.
"""

from __future__ import annotations

import re
from typing import Any

ALLOWED_FLAGS = frozenset({"-o", "-f", "-i", "-d", "-a", "-e"})

#: A TSK metadata address as `tsk_fls` prints it: a number, optionally with
#: `-type[-id]` suffixes (`68`, `68-144-6`). Only the leading number reaches argv.
_INODE_RE = re.compile(r"^(?P<inum>\d+)(?:-\d+){0,2}$")

_VALID_FS_TYPES = frozenset(
    {"ntfs", "fat", "fat12", "fat16", "fat32", "ext2", "ext3", "ext4", "hfs", "iso9660", "ufs", "yaffs2"}
)
_VALID_IMG_FORMATS = frozenset({"raw", "ewf", "aff", "vmdk", "vhd"})

#: `-a` recovers allocated files only, `-e` recovers allocated AND deleted ones.
_SCOPES = {"allocated": "-a", "all": "-e"}


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for tsk_recover.

    params:
        image_path (str, required): raw image. Injected by Agentopsy.
        output_dir (str, required): run dir injected by the dispatcher. The tree is
            recovered into `<output_dir>/recovered` so the run's own files (the audit
            side never writes here, but a future one might) never mix with evidence.
        directory_inode (int | str, optional): metadata address of the directory to
            recover, as `tsk_fls` printed it. Omitted, tsk_recover walks the whole
            filesystem, which on a real image is very large: pass it whenever you know
            the subtree you want.
        partition_offset (int, optional): partition offset in sectors (`-o`). Required
            by tsk_recover itself whenever `directory_inode` is used on an image that
            has a volume system.
        scope (str, optional): `allocated` (default, `-a`) or `all` (`-e`, includes
            deleted files).
        filesystem (str, optional): filesystem type hint (`-f`).
        image_format (str, optional): image format hint (`-i`).
    """
    image_path = params.get("image_path")
    if not image_path or not isinstance(image_path, str):
        raise ValueError("tsk_recover requires params.image_path: str")
    output_dir = params.get("output_dir")
    if not output_dir or not isinstance(output_dir, str):
        raise ValueError("tsk_recover requires params.output_dir: str")

    argv: list[str] = []

    if (off := params.get("partition_offset")) is not None:
        if not isinstance(off, int) or isinstance(off, bool) or off < 0:
            raise ValueError("tsk_recover partition_offset must be a non-negative int")
        argv += ["-o", str(off)]

    if (fs := params.get("filesystem")):
        if fs not in _VALID_FS_TYPES:
            raise ValueError(
                f"invalid tsk_recover filesystem: {fs!r} "
                f"(allowed: {sorted(_VALID_FS_TYPES)})"
            )
        argv += ["-f", fs]

    if (fmt := params.get("image_format")):
        if fmt not in _VALID_IMG_FORMATS:
            raise ValueError(
                f"invalid tsk_recover image_format: {fmt!r} "
                f"(allowed: {sorted(_VALID_IMG_FORMATS)})"
            )
        argv += ["-i", fmt]

    scope = params.get("scope", "allocated")
    if scope not in _SCOPES:
        raise ValueError(
            f"tsk_recover scope must be one of {sorted(_SCOPES)}, got {scope!r}"
        )
    argv.append(_SCOPES[scope])

    if (inode := params.get("directory_inode")) is not None:
        if isinstance(inode, bool) or not isinstance(inode, (int, str)):
            raise ValueError("tsk_recover directory_inode must be an int or a str")
        match = _INODE_RE.match(str(inode).strip())
        if match is None:
            raise ValueError(
                f"invalid tsk_recover directory_inode: {inode!r} (expected a TSK "
                f"metadata address such as 68 or 68-144-6)"
            )
        # Only the leading number: the full `68-144-6` form makes tsk_recover recover
        # NOTHING and still exit 0, which would read as "the directory was empty".
        argv += ["-d", match["inum"]]

    argv.append(image_path)
    argv.append(output_dir.rstrip("/") + "/recovered")
    return argv


def parse(stdout: str) -> dict[str, Any]:
    """Read the `Files Recovered: N` line tsk_recover closes with.

    Zero recovered is surfaced as its own flag rather than buried in a count, because
    tsk_recover exits 0 in that case: a wrong `-d`, a wrong `-o` or a genuinely empty
    directory all look identical from the exit code, and a silent empty extraction
    would otherwise flow downstream as if it were a result.
    """
    recovered: int | None = None
    for raw in stdout.splitlines():
        line = raw.strip()
        if line.lower().startswith("files recovered:"):
            _, _, value = line.partition(":")
            try:
                recovered = int(value.strip())
            except ValueError:
                recovered = None
    return {
        "files_recovered": recovered,
        "recovered_nothing": recovered == 0,
        "note": (
            "el arbol recuperado esta en recovered/ del out/ del run; paselo como "
            "{run_id, relpath} a la tool que lo consuma"
        ),
        "tail": [ln for ln in stdout.splitlines() if ln.strip()][-5:],
    }
