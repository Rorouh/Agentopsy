"""Hayabusa wrapper — run Sigma-based detections over a directory of EVTX files.

Bundled cross-platform Rust binary. The wrapper produces a CSV timeline as the
artifact; stdout is summarised (it contains aggregate counts like
`Total detections: N`). The EVTX files must already be exported to the host
(e.g. via TSK `icat`) — Hayabusa does not read raw images.
"""

from __future__ import annotations

import re
from typing import Any

ALLOWED_FLAGS = frozenset({"csv-timeline", "-d", "-o", "--min-level", "--no-color"})

_VALID_LEVELS = frozenset({"info", "low", "medium", "high", "critical"})
_SUMMARY_RE = re.compile(r"^\s*(?P<key>[A-Za-z][A-Za-z0-9 _\-/]+?)\s*:\s*(?P<value>\S.*)$")


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for Hayabusa.

    params:
        evtx_dir (str, required): host directory of pre-extracted .evtx files.
        output_csv (str, required): host path to write the CSV timeline to.
        min_level (str, optional): one of `info`, `low`, `medium`, `high`,
            `critical`. Passed via `--min-level`.
    """
    evtx_dir = params.get("evtx_dir")
    if not evtx_dir or not isinstance(evtx_dir, str):
        raise ValueError("hayabusa requires params.evtx_dir: str")
    output_csv = params.get("output_csv")
    if not output_csv or not isinstance(output_csv, str):
        raise ValueError("hayabusa requires params.output_csv: str")

    argv: list[str] = [
        "csv-timeline",
        "-d", evtx_dir,
        "-o", output_csv,
        "--no-color",
    ]
    if (level := params.get("min_level")) is not None:
        if not isinstance(level, str) or level not in _VALID_LEVELS:
            raise ValueError(f"invalid hayabusa min_level: {level!r}")
        argv += ["--min-level", level]
    return argv


def parse(stdout: str) -> dict[str, Any]:
    """Pull the `Key: value` summary lines Hayabusa prints after the run."""
    summary: dict[str, str] = {}
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line or "|" in line:
            continue
        m = _SUMMARY_RE.match(line)
        if not m:
            continue
        key = m.group("key").strip().lower().replace(" ", "_").replace("-", "_")
        summary[key] = m.group("value").strip()
    return {"summary": summary, "summary_count": len(summary)}
