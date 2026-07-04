"""Chainsaw wrapper — hunt Sigma / Chainsaw rules over EVTX or JSON event files.

Bundled cross-platform Rust binary. The wrapper composes a `hunt` invocation;
the target directory holds the pre-extracted artifacts (no raw image access).
At least one rule source — `sigma_dir` or `rules_dir` — must be provided.
"""

from __future__ import annotations

import re
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


_DETECTIONS_RE = re.compile(r"(?P<n>\d+)\s+Detections?\s+found", re.IGNORECASE)
_CREATED_RE = re.compile(r"\bCreated\s+(?P<name>[\w .()\-]+?\.csv)\b")


def parse(stdout: str, stderr: str = "") -> dict[str, Any]:
    """Summarise a Chainsaw hunt.

    Bug 007: Chainsaw prints its banner, progress and the ``[+] N Detections found``
    summary to **stderr** (with ``--output`` the per-rule tables go to CSV files, so
    stdout is empty). The dispatcher passes ``stderr`` to wrappers whose ``parse``
    accepts it; we read the count from there, falling back to stdout for safety.
    """
    stream = "\n".join(s for s in (stdout, stderr) if s)

    detections: int | None = None
    if m := _DETECTIONS_RE.search(stream):
        detections = int(m.group("n"))

    categories = [m.group("name").strip() for m in _CREATED_RE.finditer(stream)]

    # Legacy fallback: count `[+]`-prefixed lines if the summary line is absent.
    if detections is None:
        detections = sum(1 for ln in stream.splitlines() if ln.lstrip().startswith("[+]"))

    return {"detections": detections, "categories": categories}
