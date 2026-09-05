"""plaso `psort.py` wrapper — post-process a .plaso storage into a timeline.

Reads the `.plaso` produced by `plaso_log2timeline`, applies output format (and optional
filters) and writes the timeline (CSV by default). The `.plaso` is NOT the evidence — the
caller passes `plaso_path` (an artifact from the previous step), like `tsk_mactime` takes a
bodyfile.
"""

from __future__ import annotations

from typing import Any

ALLOWED_FLAGS = frozenset({"-o", "-w", "--output_time_zone"})

_FORMATS = frozenset(
    {"l2tcsv", "dynamic", "json", "json_line", "l2ttln", "tln", "kml", "xlsx", "null"}
)

# CSV-ish formats keep a .csv extension; the rest use the format name.
_CSV_FORMATS = frozenset({"l2tcsv", "dynamic"})


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for psort.py.

    params:
        plaso_path (str, required): the `.plaso` storage from log2timeline.
        output_dir (str, required): run dir injected by the dispatcher; the timeline goes to
            `<output_dir>/timeline.<ext>`.
        output_format (str, optional): l2tcsv (default) / dynamic / json / json_line / …
        timezone (str, optional): output time zone (`--output_time_zone`).
    """
    plaso_path = params.get("plaso_path")
    if not plaso_path or not isinstance(plaso_path, str):
        raise ValueError("plaso_psort requires params.plaso_path: str")
    output_dir = params.get("output_dir")
    if not output_dir or not isinstance(output_dir, str):
        raise ValueError("plaso_psort requires params.output_dir: str")

    fmt = params.get("output_format", "l2tcsv")
    if fmt not in _FORMATS:
        raise ValueError(f"plaso_psort output_format must be one of {sorted(_FORMATS)}")

    ext = "csv" if fmt in _CSV_FORMATS else fmt
    out = output_dir.rstrip("/") + f"/timeline.{ext}"

    argv: list[str] = ["-o", fmt, "-w", out]
    if (tz := params.get("timezone")):
        if not isinstance(tz, str):
            raise ValueError("plaso_psort timezone must be a str")
        argv += ["--output_time_zone", tz]
    argv.append(plaso_path)
    return argv


def parse(stdout: str) -> dict[str, Any]:
    """psort imprime un resumen (eventos escritos/filtrados). Lo captura; el CSV completo
    es el artefacto."""
    events = None
    for line in stdout.splitlines():
        low = line.lower()
        if "events" in low and any(c.isdigit() for c in line):
            events = line.strip()
            break
    return {
        "summary": events,
        "note": "el timeline completo es <output_dir>/timeline.csv (artefacto)",
        "tail": [ln for ln in stdout.splitlines() if ln.strip()][-8:],
    }
