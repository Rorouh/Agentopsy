"""AmcacheParser wrapper — parse a pre-extracted `Amcache.hve`.

Runs `amcacheparser` (Eric Zimmerman, .NET net9 on the runtime bundled in the
maletín windows) via the exec-agent. The caller pre-extracts `Amcache.hve`
(`Windows/AppCompat/Programs/Amcache.hve`) under the read-only `/evidence`
mount; the CSV reports (program entries, file entries, drivers…) land in
`output_dir` (`--csv`).
"""

from __future__ import annotations

from typing import Any

from forensia.toolkit.wrappers._ez_summary import parse_summary

ALLOWED_FLAGS = frozenset({"-f", "--csv", "-i"})


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for AmcacheParser.

    params:
        hive_path (str, required): path to the pre-extracted `Amcache.hve`,
            under the maletín's read-only `/evidence` mount.
        output_dir (str, required): directory for the CSV reports (`--csv`).
        include_linked (bool, optional, default False): also emit file entries
            linked to program entries (`-i`).
    """
    hive_path = params.get("hive_path")
    if not hive_path or not isinstance(hive_path, str):
        raise ValueError("amcacheparser requires params.hive_path: str")
    output_dir = params.get("output_dir")
    if not output_dir or not isinstance(output_dir, str):
        raise ValueError("amcacheparser requires params.output_dir: str")
    include_linked = params.get("include_linked", False)
    if not isinstance(include_linked, bool):
        raise ValueError("amcacheparser params.include_linked must be a bool")

    argv = ["-f", hive_path, "--csv", output_dir]
    if include_linked:
        argv.append("-i")
    return argv


def parse(stdout: str) -> dict[str, Any]:
    """AmcacheParser closes with `Key: value` totals (shared EZ shape)."""
    return parse_summary(stdout)
