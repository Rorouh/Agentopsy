"""Volatility 3 wrapper — run a plugin against a memory dump.

Bundled cross-platform via the PyInstaller sidecar (Volatility 3 is a Python
package, shipped as a dependency of the backend per RULE 1). The resolver
supplies the entry point; this wrapper composes the argv tail only.

We always request the JSON renderer (`-r json --quiet`) so the agent gets
structured rows instead of human-formatted columns.
"""

from __future__ import annotations

import json
import re
from typing import Any

ALLOWED_FLAGS = frozenset({"-f", "-r", "-o", "--quiet", "--plugin-dirs"})

_PLUGIN_RE = re.compile(r"^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)+$")
_ARG_KEY_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_\-]*$")


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for Volatility 3.

    params:
        dump_path (str, required): host path to the memory image.
        plugin (str, required): fully-qualified plugin name, e.g.
            `windows.pslist.PsList`.
        plugin_args (dict[str, str], optional): extra plugin-specific args; each
            entry becomes `--<key> <value>` after the plugin name. Keys are
            validated against `[a-zA-Z][a-zA-Z0-9_-]*`, values must be `str`.
    """
    dump_path = params.get("dump_path")
    if not dump_path or not isinstance(dump_path, str):
        raise ValueError("volatility3 requires params.dump_path: str")
    plugin = params.get("plugin")
    if not plugin or not isinstance(plugin, str):
        raise ValueError("volatility3 requires params.plugin: str")
    if not _PLUGIN_RE.match(plugin):
        raise ValueError(f"invalid volatility3 plugin name: {plugin!r}")

    argv: list[str] = ["-f", dump_path, "-r", "json", "--quiet", plugin]

    plugin_args = params.get("plugin_args")
    if plugin_args is not None:
        if not isinstance(plugin_args, dict):
            raise ValueError("volatility3 plugin_args must be dict[str, str]")
        for key, value in plugin_args.items():
            if not isinstance(key, str) or not _ARG_KEY_RE.match(key):
                raise ValueError(f"invalid volatility3 plugin_arg key: {key!r}")
            if not isinstance(value, str):
                raise ValueError(
                    f"invalid volatility3 plugin_arg value for {key!r}: must be str"
                )
            argv += [f"--{key}", value]

    return argv


def parse(stdout: str) -> dict[str, Any]:
    """Volatility 3 with `-r json` emits a JSON array of row dicts."""
    try:
        rows = json.loads(stdout)
    except (ValueError, json.JSONDecodeError):
        return {"raw": stdout, "lines": stdout.count("\n")}
    row_count = len(rows) if isinstance(rows, list) else 0
    return {"rows": rows, "row_count": row_count}
