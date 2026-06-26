"""TSK `mactime` wrapper — build a timeline from a body file produced by `fls -m`.

Output is CSV (we request `-d`); for big timelines we only summarise the first / last
events plus per-day counts. Full CSV is treated as an artifact.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

ALLOWED_FLAGS = frozenset({"-b", "-d", "-y", "-z", "-p", "-g"})


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for mactime.

    params:
        bodyfile_path (str, required): body file from `fls -m`.
        date_range (str, optional): like `2024-01-01..2024-12-31`.
        iso_dates (bool, optional): use ISO dates with `-y`. Default True.
        timezone (str, optional): timezone label (`-z`, e.g. `EST5EDT`).
    """
    bodyfile = params.get("bodyfile_path")
    if not bodyfile or not isinstance(bodyfile, str):
        raise ValueError("mactime requires params.bodyfile_path: str")

    argv: list[str] = ["-b", bodyfile, "-d"]
    if params.get("iso_dates", True):
        argv.append("-y")
    if (tz := params.get("timezone")):
        if not isinstance(tz, str):
            raise ValueError("mactime timezone must be a str")
        argv += ["-z", tz]
    if (dr := params.get("date_range")):
        if not isinstance(dr, str):
            raise ValueError("mactime date_range must be a str")
        argv.append(dr)
    return argv


def parse(stdout: str) -> dict[str, Any]:
    """Summarise mactime CSV: row count, day histogram, first / last events."""
    rows = [ln for ln in stdout.splitlines() if ln and not ln.startswith("Date,")]
    days = Counter()
    first = last = None
    for line in rows:
        parts = line.split(",", 1)
        if not parts or not parts[0]:
            continue
        day = parts[0].split(" ", 1)[0]
        days[day] += 1
        if first is None:
            first = line
        last = line
    return {
        "rows": len(rows),
        "days_count": len(days),
        "top_days": days.most_common(10),
        "first_event": first,
        "last_event": last,
    }
