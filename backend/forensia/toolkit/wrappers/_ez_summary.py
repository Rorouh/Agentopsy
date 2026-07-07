"""Shared stdout summariser for the Eric Zimmerman .NET tool wrappers.

Every EZ tool closes its run with a `Processed …` line plus a short block of
`Key: value` lines. The per-tool wrappers delegate here so all of them surface
the same structured shape: ``{"summary": {…}, "summary_count": N}`` (the shape
`evtxecmd`/`mftecmd` established).
"""

from __future__ import annotations

from typing import Any


def parse_summary(stdout: str) -> dict[str, Any]:
    summary: dict[str, str] = {}
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.lower().startswith("processed "):
            summary["processed"] = line
            continue
        if ":" in line and not line.endswith(":"):
            key, _, value = line.partition(":")
            key = key.strip().lower().replace(" ", "_").replace("-", "_")
            value = value.strip()
            if key and value and len(key) <= 64:
                summary[key] = value
    return {"summary": summary, "summary_count": len(summary)}
