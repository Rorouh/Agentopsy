"""YARA wrapper — match a rules file against a path on disk.

Bundled cross-platform. The wrapper composes the argv tail (the resolver supplies
the `yara` binary). YARA's standard match line is `<rule_name> <target_path>`; with
`-s` it additionally prints the offending strings, which we surface as part of the
raw output but never as executable content.
"""

from __future__ import annotations

import re
from typing import Any

ALLOWED_FLAGS = frozenset({"-r", "-s", "-w", "-N", "-p"})

_MATCH_RE = re.compile(r"^(?P<rule>[A-Za-z_][A-Za-z0-9_]*)\s+(?P<path>.+)$")


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for yara.

    params:
        rules_path (str, required): host path to the compiled or source YARA rules.
        target_path (str, required): host path (file or directory) to scan.
        recursive (bool, optional): recurse into directories (-r).
        print_strings (bool, optional): print matching strings (-s).
        disable_warnings (bool, optional): suppress warnings (-w).
    """
    rules_path = params.get("rules_path")
    if not rules_path or not isinstance(rules_path, str):
        raise ValueError("yara requires params.rules_path: str")
    target_path = params.get("target_path")
    if not target_path or not isinstance(target_path, str):
        raise ValueError("yara requires params.target_path: str")

    argv: list[str] = []
    if params.get("recursive"):
        argv.append("-r")
    if params.get("print_strings"):
        argv.append("-s")
    if params.get("disable_warnings"):
        argv.append("-w")
    argv += [rules_path, target_path]
    return argv


def parse(stdout: str) -> dict[str, Any]:
    """Each YARA hit is a line `rule_name target_path`; -s appends string lines
    that begin with whitespace, which we ignore for the structured summary.
    """
    matches: list[dict[str, str]] = []
    for line in stdout.splitlines():
        if not line or line.startswith((" ", "\t")):
            continue
        m = _MATCH_RE.match(line.strip())
        if not m:
            continue
        matches.append({"rule": m["rule"], "target": m["path"].strip()})
    return {"matches": matches[:200], "count": len(matches)}
