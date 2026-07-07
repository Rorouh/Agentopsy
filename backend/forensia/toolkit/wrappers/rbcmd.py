"""RBCmd wrapper — parse Recycle Bin `$I` metadata files.

Runs `rbcmd` (Eric Zimmerman, .NET net9 on the runtime bundled in the maletín
windows) via the exec-agent. The caller pre-extracts the `$Recycle.Bin` tree
(or a single `$I` file) under the read-only `/evidence` mount; the CSV report
(original path, size and deletion timestamp of each recycled file) lands in
`output_dir` (`--csv`).
"""

from __future__ import annotations

from typing import Any

from forensia.toolkit.wrappers._ez_summary import parse_summary

ALLOWED_FLAGS = frozenset({"-f", "-d", "--csv"})


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for RBCmd.

    params:
        target_path (str, required): `$Recycle.Bin` directory (default) or a
            single `$I` file, under the maletín's read-only `/evidence` mount.
        output_dir (str, required): directory for the CSV report (`--csv`).
        is_file (bool, optional, default False): treat `target_path` as a single
            `$I` file (`-f`) instead of a directory (`-d`).
    """
    target_path = params.get("target_path")
    if not target_path or not isinstance(target_path, str):
        raise ValueError("rbcmd requires params.target_path: str")
    output_dir = params.get("output_dir")
    if not output_dir or not isinstance(output_dir, str):
        raise ValueError("rbcmd requires params.output_dir: str")
    is_file = params.get("is_file", False)
    if not isinstance(is_file, bool):
        raise ValueError("rbcmd params.is_file must be a bool")

    source_flag = "-f" if is_file else "-d"
    return [source_flag, target_path, "--csv", output_dir]


def parse(stdout: str) -> dict[str, Any]:
    """RBCmd prints `Processed N out of M files …` + `Key: value` (EZ shape)."""
    return parse_summary(stdout)
