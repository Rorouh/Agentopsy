"""FTK Imager CLI wrapper — convert the disk-image evidence between formats.

Runs `ftkimager` (AccessData, 3.1.1 ubuntu64 — the last CLI published for
Linux; in the `base` stage of BOTH maletines) via the exec-agent. The source
is the evidence itself (ftkimager reads raw/E01/SMART natively, so the tool
declares NO `image_param`: it must not go through the dispatcher's ewfmount
rewrite — it wants the container, not an exposed raw view). The converted
image lands inside the run's `output_dir` as `imagen.<ext>` (ftkimager
appends the extension: `.E01`, `.s01` or `.001` for raw) plus a `.txt`
acquisition report; `--verify` re-hashes the destination (MD5+SHA1).
"""

from __future__ import annotations

import re
from typing import Any

ALLOWED_FLAGS = frozenset({"--e01", "--s01", "--compress", "--verify", "--quiet"})

# Output format → CLI flag (raw/dd is ftkimager's default: no flag).
_FORMATS: dict[str, str | None] = {"raw": None, "e01": "--e01", "s01": "--s01"}

_SECTION_RE = re.compile(r"^\[(\w+)\]$")


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for ftkimager (`source dest_base [options]`).

    params:
        image_path (str, required): the source image (raw/E01/SMART — read
            natively), under the maletín's read-only `/evidence` mount.
        output_dir (str, required): run output directory; the destination base
            becomes `<output_dir>/imagen` and ftkimager appends the extension.
        format (str, optional, default "raw"): output format — raw | e01 | s01.
        compress (int 0..9, optional): compression level, only for e01/s01.
        verify (bool, optional, default True): hash/verify the destination
            image after writing (MD5+SHA1).
    """
    image_path = params.get("image_path")
    if not image_path or not isinstance(image_path, str):
        raise ValueError("ftkimager requires params.image_path: str")
    output_dir = params.get("output_dir")
    if not output_dir or not isinstance(output_dir, str):
        raise ValueError("ftkimager requires params.output_dir: str")
    fmt = params.get("format", "raw")
    if fmt not in _FORMATS:
        raise ValueError(
            f"ftkimager params.format must be one of {sorted(_FORMATS)} — got {fmt!r}"
        )
    verify = params.get("verify", True)
    if not isinstance(verify, bool):
        raise ValueError("ftkimager params.verify must be a bool")

    # --quiet suppresses the \r progress spam only; hashes/report still print.
    argv = [image_path, f"{output_dir.rstrip('/')}/imagen", "--quiet"]
    format_flag = _FORMATS[fmt]
    if format_flag:
        argv.append(format_flag)

    compress = params.get("compress")
    if compress is not None:
        if format_flag is None:
            raise ValueError(
                "ftkimager params.compress only applies to e01/s01 (raw is never compressed)"
            )
        if not isinstance(compress, int) or isinstance(compress, bool) or not 0 <= compress <= 9:
            raise ValueError("ftkimager params.compress must be an int in 0..9")
        argv += ["--compress", str(compress)]

    if verify:
        argv.append("--verify")
    return argv


def parse(stdout: str) -> dict[str, Any]:
    """ftkimager closes with per-algorithm blocks (`[MD5]`/`[SHA1]`) of
    `Key: value` lines; keys get prefixed by their section so both hashes
    survive, and every `Verify result` is surfaced as a list."""
    summary: dict[str, str] = {}
    verify_results: list[str] = []
    section = ""
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        section_match = _SECTION_RE.match(line)
        if section_match:
            section = section_match.group(1).lower()
            continue
        if ":" in line and not line.endswith(":"):
            key, _, value = line.partition(":")
            key = key.strip().lower().replace(" ", "_").replace("-", "_")
            value = value.strip()
            if not key or not value or len(key) > 64:
                continue
            if section:
                key = f"{section}_{key}"
            summary[key] = value
            if key.endswith("verify_result"):
                verify_results.append(value)
    return {
        "summary": summary,
        "verify_results": verify_results,
        "summary_count": len(summary),
    }
