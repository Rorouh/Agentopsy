"""MFTECmd wrapper — parse a pre-extracted NTFS `$MFT` file.

Runs `MFTECmd` (Eric Zimmerman, .NET net9 on the runtime bundled in the maletín) via
the exec-agent. FORENSIC_SOUNDNESS §5 forbids mounting the raw image inside the
container, so the caller pre-extracts the `$MFT` (TSK `icat -o <offset> <image> 0`)
under the read-only `/evidence` mount and passes the resulting file; the argv references
that real path. The CSV report lands in `output_dir` (`--csv`).
"""

from __future__ import annotations

from typing import Any

ALLOWED_FLAGS = frozenset({"-f", "--csv", "--csvf"})


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for MFTECmd.

    params:
        mft_path (str, required): path to the pre-extracted `$MFT` file, under the
            maletín's read-only `/evidence` mount.
        output_dir (str, required): directory for the CSV report (`--csv`).
    """
    mft_path = params.get("mft_path")
    if not mft_path or not isinstance(mft_path, str):
        raise ValueError("mftecmd requires params.mft_path: str")
    output_dir = params.get("output_dir")
    if not output_dir or not isinstance(output_dir, str):
        raise ValueError("mftecmd requires params.output_dir: str")

    return ["-f", mft_path, "--csv", output_dir, "--csvf", "mft.csv"]


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
