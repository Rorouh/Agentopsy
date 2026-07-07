"""JLECmd wrapper — parse pre-extracted Windows Jump Lists.

Runs `jlecmd` (Eric Zimmerman, .NET net9 on the runtime bundled in the maletín
windows) via the exec-agent. The caller pre-extracts the Jump List file(s)
(`*.automaticDestinations-ms` / `*.customDestinations-ms`, typically under the
user's `Recent/` folder) under the read-only `/evidence` mount and passes a
single file or a directory; the CSV reports land in `output_dir` (`--csv`).
"""

from __future__ import annotations

from typing import Any

from forensia.toolkit.wrappers._ez_summary import parse_summary

ALLOWED_FLAGS = frozenset({"-f", "-d", "--csv"})


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for JLECmd.

    params:
        target_path (str, required): path to a single `*Destinations-ms` file OR
            a directory containing Jump Lists, under the maletín's read-only
            `/evidence` mount. The wrapper picks `-f` vs `-d` by extension.
        output_dir (str, required): directory for the CSV reports (`--csv`).
    """
    target_path = params.get("target_path")
    if not target_path or not isinstance(target_path, str):
        raise ValueError("jlecmd requires params.target_path: str")
    output_dir = params.get("output_dir")
    if not output_dir or not isinstance(output_dir, str):
        raise ValueError("jlecmd requires params.output_dir: str")

    source_flag = "-f" if target_path.lower().endswith("destinations-ms") else "-d"
    return [source_flag, target_path, "--csv", output_dir]


def parse(stdout: str) -> dict[str, Any]:
    """JLECmd closes with `Processed …` + `Key: value` lines (shared EZ shape)."""
    return parse_summary(stdout)
