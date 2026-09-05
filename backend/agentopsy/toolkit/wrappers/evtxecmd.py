"""EvtxECmd wrapper — parse a pre-extracted `.evtx` file (or a directory of them).

Runs `EvtxECmd` (Eric Zimmerman, .NET net9 on the runtime bundled in the maletín) via
the exec-agent. FORENSIC_SOUNDNESS §5 forbids mounting the raw image inside the
container, so the caller pre-extracts the event log(s) (TSK `icat` or similar) under the
read-only `/evidence` mount and passes either a single file or a directory; the argv
references those real paths. The CSV report lands in `output_dir` (`--csv`).
"""

from __future__ import annotations

from typing import Any

ALLOWED_FLAGS = frozenset({"-d", "--csv", "--csvf", "-f"})


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for EvtxECmd.

    params:
        evtx_path (str, required): path to a single `.evtx` file OR a directory of
            them, under the maletín's read-only `/evidence` mount. The wrapper picks
            `-f` vs `-d` based on the file extension.
        output_dir (str, required): directory for the CSV report (`--csv`).
    """
    evtx_path = params.get("evtx_path")
    if not evtx_path or not isinstance(evtx_path, str):
        raise ValueError("evtxecmd requires params.evtx_path: str")
    output_dir = params.get("output_dir")
    if not output_dir or not isinstance(output_dir, str):
        raise ValueError("evtxecmd requires params.output_dir: str")

    single_file = evtx_path.lower().endswith(".evtx")
    source_flag = "-f" if single_file else "-d"
    return [source_flag, evtx_path, "--csv", output_dir, "--csvf", "evtx.csv"]


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
