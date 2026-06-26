"""MFTECmd wrapper — parse a pre-extracted NTFS `$MFT` file.

Container-only delivery (`forensia/mftecmd:latest`). FORENSIC_SOUNDNESS §5 forbids
mounting the raw image inside the container, so the caller must pre-extract the
`$MFT` on the host (TSK `icat -o <offset> <image> 0`) and pass the resulting file.
The wrapper mounts it read-only at `/in/mft` and a writable scratch directory at
`/out` for the CSV report.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

ALLOWED_FLAGS = frozenset({"-f", "--csv", "--csvf"})


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for MFTECmd as it runs INSIDE the container.

    params:
        mft_path (str, required): host path to the pre-extracted `$MFT` file.
        output_dir (str, required): host scratch directory for the CSV report.
    """
    mft_path = params.get("mft_path")
    if not mft_path or not isinstance(mft_path, str):
        raise ValueError("mftecmd requires params.mft_path: str")
    output_dir = params.get("output_dir")
    if not output_dir or not isinstance(output_dir, str):
        raise ValueError("mftecmd requires params.output_dir: str")

    return ["-f", "/in/mft", "--csv", "/out", "--csvf", "mft.csv"]


def parse(stdout: str) -> dict[str, Any]:
    """MFTECmd prints a `Processed X MFT records` summary line plus K/V tails."""
    summary: dict[str, str] = {}
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith("processed "):
            summary["processed"] = line
            continue
        if ":" in line and not line.endswith(":"):
            key, _, value = line.partition(":")
            key = key.strip().lower().replace(" ", "_").replace("-", "_")
            value = value.strip()
            if key and value and len(key) <= 64:
                summary[key] = value
    return {"summary": summary, "summary_count": len(summary)}


def host_mounts(params: dict[str, Any]) -> tuple[dict[Path, str], dict[Path, str]]:
    """ro: $MFT file at /in/mft ; rw: scratch output dir at /out."""
    mft = Path(params["mft_path"]).resolve()
    out = Path(params["output_dir"]).resolve()
    return ({mft: "/in/mft"}, {out: "/out"})
