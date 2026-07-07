"""WxTCmd wrapper — parse a pre-extracted Windows Timeline database.

Runs `wxtcmd` (Eric Zimmerman, .NET net9 on the runtime bundled in the maletín
windows) via the exec-agent. The caller pre-extracts `ActivitiesCache.db`
(`Users/<user>/AppData/Local/ConnectedDevicesPlatform/<id>/ActivitiesCache.db`,
Windows 10 1803+ — does not exist on Win7) under the read-only `/evidence`
mount; the CSV report lands in `output_dir` (`--csv`).
"""

from __future__ import annotations

from typing import Any

from forensia.toolkit.wrappers._ez_summary import parse_summary

ALLOWED_FLAGS = frozenset({"-f", "--csv"})


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for WxTCmd.

    params:
        target_path (str, required): path to the pre-extracted
            `ActivitiesCache.db`, under the maletín's read-only `/evidence` mount.
        output_dir (str, required): directory for the CSV report (`--csv`).
    """
    target_path = params.get("target_path")
    if not target_path or not isinstance(target_path, str):
        raise ValueError("wxtcmd requires params.target_path: str")
    output_dir = params.get("output_dir")
    if not output_dir or not isinstance(output_dir, str):
        raise ValueError("wxtcmd requires params.output_dir: str")

    return ["-f", target_path, "--csv", output_dir]


def parse(stdout: str) -> dict[str, Any]:
    """WxTCmd closes with `Processed …` + `Key: value` lines (EZ shape)."""
    return parse_summary(stdout)
