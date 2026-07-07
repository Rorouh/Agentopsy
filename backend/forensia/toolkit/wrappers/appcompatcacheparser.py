"""AppCompatCacheParser wrapper — parse the ShimCache from a `SYSTEM` hive.

Runs `appcompatcacheparser` (Eric Zimmerman, .NET net9 on the runtime bundled
in the maletín windows) via the exec-agent. The caller pre-extracts the
`SYSTEM` hive (`Windows/System32/config/SYSTEM`) under the read-only
`/evidence` mount; the CSV report (AppCompatCache / ShimCache entries — paths
of executables with evidence of presence) lands in `output_dir` (`--csv`).
"""

from __future__ import annotations

from typing import Any

from forensia.toolkit.wrappers._ez_summary import parse_summary

ALLOWED_FLAGS = frozenset({"-f", "--csv"})


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for AppCompatCacheParser.

    params:
        hive_path (str, required): path to the pre-extracted `SYSTEM` hive,
            under the maletín's read-only `/evidence` mount.
        output_dir (str, required): directory for the CSV report (`--csv`).
    """
    hive_path = params.get("hive_path")
    if not hive_path or not isinstance(hive_path, str):
        raise ValueError("appcompatcacheparser requires params.hive_path: str")
    output_dir = params.get("output_dir")
    if not output_dir or not isinstance(output_dir, str):
        raise ValueError("appcompatcacheparser requires params.output_dir: str")

    return ["-f", hive_path, "--csv", output_dir]


def parse(stdout: str) -> dict[str, Any]:
    """ACCP prints `Found N cache entries …` + `Key: value` lines (EZ shape)."""
    return parse_summary(stdout)
