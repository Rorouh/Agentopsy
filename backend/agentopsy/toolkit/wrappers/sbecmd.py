"""SBECmd wrapper — parse ShellBags from user registry hives.

Runs `sbecmd` (Eric Zimmerman, .NET net9 on the runtime bundled in the maletín
windows) via the exec-agent. The caller pre-extracts the user hives
(`UsrClass.dat` / `NTUSER.DAT`) under the read-only `/evidence` mount and
passes the DIRECTORY that contains them (SBECmd only takes `-d`); the CSV
report (folders the user browsed, even if since deleted) lands in
`output_dir` (`--csv`).
"""

from __future__ import annotations

from typing import Any

from agentopsy.toolkit.wrappers._ez_summary import parse_summary

ALLOWED_FLAGS = frozenset({"-d", "--csv"})


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for SBECmd.

    params:
        target_path (str, required): directory containing `UsrClass.dat` /
            `NTUSER.DAT` hives, under the maletín's read-only `/evidence` mount.
        output_dir (str, required): directory for the CSV report (`--csv`).
    """
    target_path = params.get("target_path")
    if not target_path or not isinstance(target_path, str):
        raise ValueError("sbecmd requires params.target_path: str (a directory)")
    output_dir = params.get("output_dir")
    if not output_dir or not isinstance(output_dir, str):
        raise ValueError("sbecmd requires params.output_dir: str")

    return ["-d", target_path, "--csv", output_dir]


def parse(stdout: str) -> dict[str, Any]:
    """SBECmd prints `Total ShellBags found: N` + `Processed …` (EZ shape)."""
    return parse_summary(stdout)
