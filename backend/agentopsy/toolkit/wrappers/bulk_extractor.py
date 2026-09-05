"""bulk_extractor wrapper — parallel scanner for emails, URLs, IPs, credit cards…

Returns an artifact (the report directory). Parse summarises feature counts found
in `report.xml` if present, otherwise from stdout.
"""

from __future__ import annotations

import re
from typing import Any

ALLOWED_FLAGS = frozenset({"-o", "-e", "-x", "-E", "-S", "-Z"})

_SCANNER_NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")
_FEATURE_COUNT_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9_\.]+):\s+(?P<count>\d+)\s+features\b", re.MULTILINE
)


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for bulk_extractor.

    params:
        image_path (str, required).
        output_dir (str, required): writable directory that does NOT exist yet.
        enable_scanners (list[str], optional): only run these (-E + -e).
        disable_scanners (list[str], optional): skip these (-x).
    """
    image_path = params.get("image_path")
    if not image_path or not isinstance(image_path, str):
        raise ValueError("bulk_extractor requires params.image_path: str")
    output_dir = params.get("output_dir")
    if not output_dir or not isinstance(output_dir, str):
        raise ValueError("bulk_extractor requires params.output_dir: str")

    argv = ["-o", output_dir]

    enable = params.get("enable_scanners") or []
    if enable:
        if not isinstance(enable, list) or not all(isinstance(s, str) for s in enable):
            raise ValueError("enable_scanners must be list[str]")
        for s in enable:
            if not _SCANNER_NAME_RE.match(s):
                raise ValueError(f"invalid scanner name: {s!r}")
        argv += ["-E", enable[0]]
        for s in enable[1:]:
            argv += ["-e", s]

    disable = params.get("disable_scanners") or []
    if disable:
        if not isinstance(disable, list) or not all(isinstance(s, str) for s in disable):
            raise ValueError("disable_scanners must be list[str]")
        for s in disable:
            if not _SCANNER_NAME_RE.match(s):
                raise ValueError(f"invalid scanner name: {s!r}")
            argv += ["-x", s]

    argv.append(image_path)
    return argv


def parse(stdout: str) -> dict[str, Any]:
    """Extract per-scanner feature counts from the BE summary printed on stdout."""
    counts: dict[str, int] = {}
    for m in _FEATURE_COUNT_RE.finditer(stdout):
        counts[m.group("name")] = int(m.group("count"))
    return {
        "feature_counts": counts,
        "scanners_with_hits": sorted(k for k, v in counts.items() if v > 0),
        "total_features": sum(counts.values()),
    }
