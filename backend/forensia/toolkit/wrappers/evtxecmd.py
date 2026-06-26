"""EvtxECmd wrapper — parse a pre-extracted `.evtx` file (or a directory of them).

Container-only delivery (`forensia/evtxecmd:latest`). FORENSIC_SOUNDNESS §5 forbids
mounting the raw image inside the container, so the caller must pre-extract the
event log(s) on the host (TSK `icat` or similar) and pass either a single file or
a directory. The wrapper mounts that read-only at `/in/evtx` and a writable scratch
directory at `/out` for the CSV report.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

ALLOWED_FLAGS = frozenset({"-d", "--csv", "--csvf", "-f"})


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for EvtxECmd as it runs INSIDE the container.

    params:
        evtx_path (str, required): host path to a single `.evtx` file OR a directory
            containing multiple `.evtx` files. The wrapper picks `-f` vs `-d` based
            on the file extension.
        output_dir (str, required): host scratch directory for the CSV report.
    """
    evtx_path = params.get("evtx_path")
    if not evtx_path or not isinstance(evtx_path, str):
        raise ValueError("evtxecmd requires params.evtx_path: str")
    output_dir = params.get("output_dir")
    if not output_dir or not isinstance(output_dir, str):
        raise ValueError("evtxecmd requires params.output_dir: str")

    single_file = evtx_path.lower().endswith(".evtx")
    source_flag = "-f" if single_file else "-d"
    return [source_flag, "/in/evtx", "--csv", "/out", "--csvf", "evtx.csv"]


def parse(stdout: str) -> dict[str, Any]:
    """EvtxECmd prints a `Processed X events from Y file(s)` summary line.

    We surface that and a few other `Key: value` lines from the closing block.
    """
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
    """ro: evtx path at /in/evtx ; rw: scratch output dir at /out."""
    evtx = Path(params["evtx_path"]).resolve()
    out = Path(params["output_dir"]).resolve()
    return ({evtx: "/in/evtx"}, {out: "/out"})
