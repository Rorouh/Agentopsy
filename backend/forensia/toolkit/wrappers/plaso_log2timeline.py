"""plaso `log2timeline.py` wrapper — build a super-timeline (.plaso storage) from a source.

Runs plaso's parsers over a disk image / partition / directory and writes a `.plaso`
storage file (the artifact) that `plaso_psort` then post-processes. Heavy: on a full disk
it runs dozens of parsers — bound it with `partitions` and/or `parsers` when testing.
"""

from __future__ import annotations

import re
from typing import Any

ALLOWED_FLAGS = frozenset(
    {"--storage_file", "--partitions", "--parsers", "--status_view", "--no_vss", "-z"}
)

# Parser filter expression (plaso preset/parser names, with ! and , and *). Kept as an
# allowlist pattern so the argv never carries an arbitrary token.
_PARSERS_RE = re.compile(r"^[A-Za-z0-9_,!*-]+$")
# Partition selector: "all" or comma/range of numbers (e.g. "1", "1,3", "p1").
_PARTITIONS_RE = re.compile(r"^(all|[0-9p,]+)$")


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for log2timeline.py.

    params:
        image_path (str, required): SOURCE (disk image / partition / dir). Injected.
        output_dir (str, required): run dir injected by the dispatcher; the .plaso goes to
            `<output_dir>/timeline.plaso`.
        partitions (str, optional): partition selector (`all` default, or `1`, `1,3`…).
        parsers (str, optional): plaso parser/preset filter (e.g. `filestat`, `linux`).
        timezone (str, optional): time zone (`-z`).
    """
    image_path = params.get("image_path")
    if not image_path or not isinstance(image_path, str):
        raise ValueError("plaso_log2timeline requires params.image_path: str")
    output_dir = params.get("output_dir")
    if not output_dir or not isinstance(output_dir, str):
        raise ValueError("plaso_log2timeline requires params.output_dir: str")

    partitions = params.get("partitions", "all")
    if not isinstance(partitions, str) or not _PARTITIONS_RE.match(partitions):
        raise ValueError("plaso_log2timeline partitions must be 'all' or a partition selector")

    storage = output_dir.rstrip("/") + "/timeline.plaso"
    argv: list[str] = ["--status_view", "none", "--no_vss", "--partitions", partitions]

    if (parsers := params.get("parsers")):
        if not isinstance(parsers, str) or not _PARSERS_RE.match(parsers):
            raise ValueError("plaso_log2timeline parsers must be a plaso parser filter expression")
        argv += ["--parsers", parsers]
    if (tz := params.get("timezone")):
        if not isinstance(tz, str):
            raise ValueError("plaso_log2timeline timezone must be a str")
        argv += ["-z", tz]

    argv += ["--storage_file", storage, image_path]
    return argv


def parse(stdout: str) -> dict[str, Any]:
    """log2timeline con `--status_view none` imprime poco; el resultado es el `.plaso`
    (artefacto). Extrae cualquier resumen que aparezca y reporta si terminó."""
    lower = stdout.lower()
    completed = "processing completed" in lower or "log2timeline" in lower
    return {
        "completed": completed,
        "note": "el resultado es <output_dir>/timeline.plaso (artefacto); procésalo con plaso_psort",
        "tail": [ln for ln in stdout.splitlines() if ln.strip()][-8:],
    }
