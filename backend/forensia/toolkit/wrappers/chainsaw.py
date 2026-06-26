"""Chainsaw wrapper — hunt Sigma / Chainsaw rules over EVTX or JSON event files.

Bundled cross-platform Rust binary. The wrapper composes a `hunt` invocation;
the target directory holds the pre-extracted artifacts (no raw image access).
At least one rule source — `sigma_dir` or `rules_dir` — must be provided.
"""

from __future__ import annotations

from typing import Any

ALLOWED_FLAGS = frozenset({"hunt", "-s", "-r", "--csv", "--json", "--output"})

_VALID_FORMATS = frozenset({"csv", "json"})


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for Chainsaw.

    params:
        target_dir (str, required): host directory of EVTX / JSON event files.
        sigma_dir (str, optional): host directory with Sigma rule YAMLs (-s).
        rules_dir (str, optional): host directory with Chainsaw rule YAMLs (-r).
        output_format (str, required): `csv` or `json`.
        output_path (str, required): host path for the written report.

    At least one of `sigma_dir` / `rules_dir` is required.
    """
    target_dir = params.get("target_dir")
    if not target_dir or not isinstance(target_dir, str):
        raise ValueError("chainsaw requires params.target_dir: str")

    sigma_dir = params.get("sigma_dir")
    rules_dir = params.get("rules_dir")
    if sigma_dir is not None and not isinstance(sigma_dir, str):
        raise ValueError("chainsaw sigma_dir must be a str")
    if rules_dir is not None and not isinstance(rules_dir, str):
        raise ValueError("chainsaw rules_dir must be a str")
    if not sigma_dir and not rules_dir:
        raise ValueError("chainsaw requires at least one of sigma_dir / rules_dir")

    output_format = params.get("output_format")
    if not output_format or not isinstance(output_format, str):
        raise ValueError("chainsaw requires params.output_format: str")
    if output_format not in _VALID_FORMATS:
        raise ValueError(f"invalid chainsaw output_format: {output_format!r}")
    output_path = params.get("output_path")
    if not output_path or not isinstance(output_path, str):
        raise ValueError("chainsaw requires params.output_path: str")

    argv: list[str] = ["hunt", target_dir]
    if sigma_dir:
        argv += ["-s", sigma_dir]
    if rules_dir:
        argv += ["-r", rules_dir]
    argv += [f"--{output_format}", "--output", output_path]
    return argv


def parse(stdout: str) -> dict[str, Any]:
    """Count Chainsaw's detection lines (it prefixes findings with `[+]`)."""
    detections = 0
    for line in stdout.splitlines():
        s = line.lstrip()
        if s.startswith("[+]"):
            detections += 1
    return {"detections": detections, "lines": stdout.count("\n")}
