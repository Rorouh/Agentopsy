"""RECmd wrapper — run a RECmd batch against pre-extracted registry hives.

Runs `recmd` (Eric Zimmerman, .NET net9 on the runtime bundled in the maletín
windows) via the exec-agent, in batch mode (`--bn`). The batch is selected by
closed identifier ``Kroll_Batch.reb``. The dispatcher maps it to the single exact
allowlisted path in the maletín before this thin wrapper builds argv.
The caller pre-extracts the hive(s) under the read-only `/evidence` mount; the
CSV report lands in `output_dir` (`--csv`).
"""

from __future__ import annotations

from typing import Any

from forensia.toolkit.wrappers._ez_summary import parse_summary

ALLOWED_FLAGS = frozenset({"--bn", "-f", "-d", "--csv"})

# Where the maletín's Dockerfile unzips RECmd (the zip nests RECmd/ inside).
# The wrapper and the image ship together; if upstream re-layouts the zip the
# run fails loud and the pin gets fixed alongside this constant.
def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for RECmd (batch mode).

    params:
        hive_path (str, required): path to a pre-extracted registry hive (or a
            directory of hives, with `is_directory=true`), under the maletín's
            read-only `/evidence` mount.
        output_dir (str, required): directory for the CSV report (`--csv`).
        batch (str, required): exact maletín path mapped by the dispatcher from the
            closed id `Kroll_Batch.reb`.
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
    if not batch or not isinstance(batch, str):
        raise ValueError(
            "recmd requires params.batch: a dispatcher-mapped bundled ruleset path"
        )
    is_directory = params.get("is_directory", False)
    if not isinstance(is_directory, bool):
        raise ValueError("recmd params.is_directory must be a bool")

    source_flag = "-d" if is_directory else "-f"
    return [
        "--bn", batch,
        source_flag, hive_path,
        "--csv", output_dir,
    ]


def parse(stdout: str) -> dict[str, Any]:
    """RECmd closes with `Processed …` + `Key: value` lines (shared EZ shape)."""
    return parse_summary(stdout)
