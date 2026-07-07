"""RECmd wrapper — run a RECmd batch against pre-extracted registry hives.

Runs `recmd` (Eric Zimmerman, .NET net9 on the runtime bundled in the maletín
windows) via the exec-agent, in batch mode (`--bn`). The batch is selected by
FILE NAME from the `BatchExamples/` directory the maletín ships inside the
RECmd zip — the model never supplies a free path (closed contract; the name is
validated against a strict pattern and anchored to the shipped directory).
The caller pre-extracts the hive(s) under the read-only `/evidence` mount; the
CSV report lands in `output_dir` (`--csv`).
"""

from __future__ import annotations

import re
from typing import Any

from forensia.toolkit.wrappers._ez_summary import parse_summary

ALLOWED_FLAGS = frozenset({"--bn", "-f", "-d", "--csv"})

# Where the maletín's Dockerfile unzips RECmd (the zip nests RECmd/ inside).
# The wrapper and the image ship together; if upstream re-layouts the zip the
# run fails loud and the pin gets fixed alongside this constant.
_BATCH_DIR = "/opt/eztools/RECmd/RECmd/BatchExamples"

# Batch file names: no separators, no traversal — a bare `<name>.reb`.
_BATCH_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+\.reb$")


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for RECmd (batch mode).

    params:
        hive_path (str, required): path to a pre-extracted registry hive (or a
            directory of hives, with `is_directory=true`), under the maletín's
            read-only `/evidence` mount.
        output_dir (str, required): directory for the CSV report (`--csv`).
        batch (str, required): batch file NAME from the shipped
            `BatchExamples/` (e.g. `Kroll_Batch.reb`). Validated, never a path.
        is_directory (bool, optional, default False): treat `hive_path` as a
            directory of hives (`-d`) instead of a single hive (`-f`).
    """
    hive_path = params.get("hive_path")
    if not hive_path or not isinstance(hive_path, str):
        raise ValueError("recmd requires params.hive_path: str")
    output_dir = params.get("output_dir")
    if not output_dir or not isinstance(output_dir, str):
        raise ValueError("recmd requires params.output_dir: str")
    batch = params.get("batch")
    if not batch or not isinstance(batch, str) or not _BATCH_NAME_RE.match(batch):
        raise ValueError(
            "recmd requires params.batch: a batch file name like 'Kroll_Batch.reb' "
            f"(shipped in the maletín under {_BATCH_DIR}; no paths, no separators)"
        )
    is_directory = params.get("is_directory", False)
    if not isinstance(is_directory, bool):
        raise ValueError("recmd params.is_directory must be a bool")

    source_flag = "-d" if is_directory else "-f"
    return [
        "--bn", f"{_BATCH_DIR}/{batch}",
        source_flag, hive_path,
        "--csv", output_dir,
    ]


def parse(stdout: str) -> dict[str, Any]:
    """RECmd closes with `Processed …` + `Key: value` lines (shared EZ shape)."""
    return parse_summary(stdout)
