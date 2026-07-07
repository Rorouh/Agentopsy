"""Volatility 3 wrapper — run a plugin against a memory dump.

Bundled cross-platform as a Python dependency of the backend (RULE 1: it ships
inside the api image built by the compose). The resolver supplies the entry
point; this wrapper composes the argv tail only.

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


# How many rows of the parsed array reach the LLM context (Bug 008). The FULL
# array (pslist/netscan/filescan can be hundreds→tens of thousands of rows) is
# always preserved on disk as the run's hash-chained stdout.txt (custody); this
# cap only bounds what gets re-sent to the model every iteration. Filter the
# full array with `jq` against the artifact, never by pulling `rows` inline.
_MAX_SAMPLE_ROWS = 20


def parse(stdout: str) -> dict[str, Any]:
    """Volatility 3 with `-r json` emits a JSON array of row dicts.

    Returns a BOUNDED summary — ``row_count``, the column names, and a capped
    ``sample`` — not the whole array. The uncapped array was the token inflator
    behind Bug 008: it went straight to the executor's context (re-sent on every
    stateless iteration). The complete rows live in the run's ``stdout.txt``
    artifact (SHA-256 in the audit chain), so nothing is lost for custody.
    """
    try:
        rows = json.loads(stdout)
    except (ValueError, json.JSONDecodeError):
        return {"raw": stdout, "lines": stdout.count("\n")}
    if not isinstance(rows, list):
        # Volatility -r json normally emits an array; anything else is unexpected
        # and stays on disk. Keep the context payload tiny.
        return {"row_count": 0, "columns": [], "sample": [], "note": "non-array JSON"}
    row_count = len(rows)
    columns = sorted(rows[0].keys()) if rows and isinstance(rows[0], dict) else []
    sample = rows[:_MAX_SAMPLE_ROWS]
    return {
        "row_count": row_count,
        "columns": columns,
        "sample": sample,
        "sample_truncated": row_count > len(sample),
    }
