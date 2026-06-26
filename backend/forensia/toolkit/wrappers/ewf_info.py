"""libewf `ewfinfo` wrapper — read case metadata from an E01 image."""

from __future__ import annotations

import re
from typing import Any

ALLOWED_FLAGS = frozenset({"-d", "-e", "-i", "-m", "-v"})

_KV_RE = re.compile(r"^\s*([A-Za-z][A-Za-z _\-/]+?):\s*(.+)$")


def build_argv(params: dict[str, Any]) -> list[str]:
    """params: {image_path: str}"""
    image_path = params.get("image_path")
    if not image_path or not isinstance(image_path, str):
        raise ValueError("ewfinfo requires params.image_path: str")
    return [image_path]


def parse(stdout: str) -> dict[str, Any]:
    """Flatten ewfinfo's key/value sections into a single dict."""
    fields: dict[str, str] = {}
    current_section = "general"
    for raw in stdout.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        stripped = line.lstrip()
        if line == stripped and line.endswith(":") and ":" not in line[:-1]:
            current_section = stripped.rstrip(":").strip().lower().replace(" ", "_")
            continue
        m = _KV_RE.match(line)
        if not m:
            continue
        key = m.group(1).strip().lower().replace(" ", "_").replace("-", "_")
        fields[f"{current_section}.{key}"] = m.group(2).strip()
    return {"fields": fields, "count": len(fields)}
