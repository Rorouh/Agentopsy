"""jq wrapper — run a filter over a JSON file.

Bundled cross-platform helper used to pluck fields from artifacts produced by other
tools (Volatility 3 json renderer, Chainsaw `--json`, …). The filter is a free-form
string but is passed as an argv element (`shell=False`), so it cannot turn into a
shell injection. We still cap its length and reject empty strings.
"""

from __future__ import annotations

import json
from typing import Any

ALLOWED_FLAGS = frozenset({"-r", "-c", "-s", "-e", "-a", "-S"})

_FILTER_MAX = 4096


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for jq.

    params:
        filter (str, required): jq filter expression (e.g. `.[] | .name`).
        input_path (str, required): host path to the JSON file.
        raw_output (bool, optional): emit raw strings instead of JSON-encoded (-r).
        compact (bool, optional): compact output (-c).
        slurp (bool, optional): read whole input into one array (-s).
        sort_keys (bool, optional): sort object keys (-S).
    """
    flt = params.get("filter")
    if not flt or not isinstance(flt, str):
        raise ValueError("jq requires params.filter: str")
    if len(flt) > _FILTER_MAX:
        raise ValueError(f"jq filter too long (>{_FILTER_MAX} chars)")
    input_path = params.get("input_path")
    if not input_path or not isinstance(input_path, str):
        raise ValueError("jq requires params.input_path: str")

    argv: list[str] = []
    if params.get("raw_output"):
        argv.append("-r")
    if params.get("compact"):
        argv.append("-c")
    if params.get("slurp"):
        argv.append("-s")
    if params.get("sort_keys"):
        argv.append("-S")
    argv += [flt, input_path]
    return argv


def parse(stdout: str) -> dict[str, Any]:
    """Try to parse stdout as JSON; fall back to raw text with a line count."""
    try:
        return {"json": json.loads(stdout)}
    except (ValueError, json.JSONDecodeError):
        lines = stdout.splitlines()
        return {"raw": stdout, "lines": len(lines)}
