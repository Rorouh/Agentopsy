"""LECmd wrapper — parse pre-extracted Windows shortcut (`.lnk`) files.

Runs `lecmd` (Eric Zimmerman, .NET net9 on the runtime bundled in the maletín
windows) via the exec-agent. The caller pre-extracts the shortcut(s) under the
read-only `/evidence` mount and passes either a single `.lnk` file or a
directory of them; the CSV report lands in `output_dir` (`--csv`).
"""

from __future__ import annotations

from typing import Any

from forensia.toolkit.wrappers._ez_summary import parse_summary

ALLOWED_FLAGS = frozenset({"-f", "-d", "--csv"})


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for LECmd.

    params:
        target_path (str, required): path to a single `.lnk` file OR a directory
            of them, under the maletín's read-only `/evidence` mount. The wrapper
            picks `-f` vs `-d` based on the file extension.
        output_dir (str, required): directory for the CSV report (`--csv`).
    """
    target_path = params.get("target_path")
    if not target_path or not isinstance(target_path, str):
        raise ValueError("lecmd requires params.target_path: str")
    output_dir = params.get("output_dir")
    if not output_dir or not isinstance(output_dir, str):
        raise ValueError("lecmd requires params.output_dir: str")

    source_flag = "-f" if target_path.lower().endswith(".lnk") else "-d"
    return [source_flag, target_path, "--csv", output_dir]


def parse(stdout: str) -> dict[str, Any]:
    """LECmd closes with `Processed …` + `Key: value` lines (shared EZ shape)."""
    return parse_summary(stdout)
