"""windowsprefetch `prefetch.py` wrapper — parse ONE Windows Prefetch (`.pf`) file.

Prefetch is the record of PROGRAM EXECUTION on Windows: for each executable it keeps
the run count, the last run times (up to eight on Win8+) and the list of files and
directories the program touched while starting. It answers "was this run, when, and
how many times", which is one of the first questions of almost any case.

It closes a promise the maletín had been making without keeping. `PECmd`, Eric
Zimmerman's Prefetch parser, is excluded from the image because it aborts on Linux
(it needs the Windows-native Xpress decompression in ntdll), and the Dockerfile's own
comment says "Prefetch -> prefetch.py". But `prefetch.py` was never in the catalog
either, so program execution by Prefetch was in fact uncovered while a comment claimed
otherwise.

ONE FILE PER RUN, and that is the tool's own shape, not a restriction added here:
`prefetch.py` takes `-f FILE` and has no directory mode (verified against
windowsprefetch 4.0.3 in the maletín). A Prefetch directory holds one `.pf` per
executable, so answering "what ran on this machine" means one run per file, each with
its own audited argv and its own hash.

**The file must still be NAMED `.pf`, and that is measured, not assumed.** Given two
byte-identical copies of a real Prefetch file, `prefetch.py` parses the one called
`DLLHOST.EXE-766398D2.pf` and, for the one called `stdout.bin`, prints NOTHING and
exits 0. A silent empty result with a success code is the worst outcome a forensic
step can produce: it reads exactly like "this program never ran". So the wrapper
refuses a name it knows the tool will silently ignore, and says what to do instead.

That refusal has a consequence worth stating: `tsk_icat` cannot feed this tool,
because it always writes its extraction as `out/stdout.bin` and the `.pf` name does
not survive. The producer is `tsk_recover`, which preserves the real file names
(verified: recovering the Prefetch directory of 2020JimmyWilson.E01 yields
`DLLHOST.EXE-766398D2.pf` and nine siblings), so the chain is
`tsk_fls` to locate the folder, `tsk_recover` to extract it whole, and then one
`prefetch` run per `.pf` inside it. A standalone `.pf` registered as evidence works
too, since that path keeps its name.
"""

from __future__ import annotations

import re
from typing import Any

ALLOWED_FLAGS = frozenset({"-f", "-c"})

#: `prefetch.py` decides whether to parse by the file NAME, not by the `SCCA` magic:
#: the same bytes under a name that does not end in `.pf` produce no output and exit 0
#: (measured). The check is on the suffix alone, so a carved or renamed-but-still-.pf
#: file is accepted and the tool itself validates the signature.
_PF_SUFFIX = ".pf"

#: `Executable Name: DLLHOST.EXE`, `Run count: 81`, `Last Executed: 2014-...`, and the
#: indented `Volume Name:` / `Creation Date:` / `Serial Number:` of the volume block.
_KV_RE = re.compile(r"^(?P<key>[A-Za-z][A-Za-z /()]*?):\s*(?P<value>.+?)\s*$")

#: The report closes with TWO numbered lists in the same shape, `  12: \DEVICE\...`:
#: `Directory Strings` (the directories the program touched while starting) and
#: `Resources Loaded` (the DLLs and files it actually opened). They answer different
#: questions, so they are kept apart instead of merged into one "resources" bag.
_NUMBERED_RE = re.compile(r"^\s*\d+:\s+(?P<path>\S.*?)\s*$")

#: Every `Directory Strings` entry comes out with a trailing NUL: it is the UTF-16
#: padding of the `.pf` leaking through prefetch.py's own output (measured, 21 of them
#: in a single real file). It is stripped here rather than carried, because these paths
#: travel to the model and end up quoted in a finding, and a path with a NUL glued to
#: its end is corrupt text presented as evidence.
_PADDING = "\x00"

_DIRECTORIES_HEADER = "directory strings:"
_RESOURCES_HEADER = "resources loaded:"

#: How many entries of each list travel to the model. A single `.pf` references
#: hundreds of files, and the full lists are in the artifact anyway.
_LIST_PREVIEW = 100


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for prefetch.py.

    params:
        prefetch_path (str, required): ONE `.pf` file, normally the artifact a previous
            `tsk_icat` run extracted. There is no directory mode.
        csv (bool, optional): emit CSV instead of the readable report (`-c`).
    """
    prefetch_path = params.get("prefetch_path")
    if not prefetch_path or not isinstance(prefetch_path, str):
        raise ValueError("prefetch requires params.prefetch_path: str")
    if not prefetch_path.lower().endswith(_PF_SUFFIX):
        raise ValueError(
            f"prefetch needs a file NAMED *.pf, got {prefetch_path!r}: with any other "
            f"name prefetch.py prints nothing and exits 0, which would read as 'this "
            f"program never ran'. tsk_icat cannot feed it (it always writes "
            f"out/stdout.bin); use tsk_recover on the Prefetch DIRECTORY, which "
            f"preserves the real names, and then run this once per .pf inside it."
        )
    argv: list[str] = []
    if (csv := params.get("csv")) is not None:
        if not isinstance(csv, bool):
            raise ValueError("prefetch csv must be a bool")
        if csv:
            argv.append("-c")
    argv += ["-f", prefetch_path]
    return argv


def parse(stdout: str) -> dict[str, Any]:
    """Read prefetch.py's report (verified against windowsprefetch 4.0.3 output).

    The readable mode prints `Key: value` lines and then two numbered lists;
    CSV mode prints a header and one row. The execution facts are surfaced by name
    because they are what a finding cites: which executable, how many times it ran,
    and WHEN. `Last Executed` can repeat, since Win8 and later keep up to eight run
    times, so the times are collected into a list rather than overwriting each other:
    keeping only the last one would silently discard seven executions.
    """
    lines = [ln.rstrip() for ln in stdout.splitlines() if ln.strip()]
    if not lines:
        return {
            "format": "empty",
            "fields": {},
            "last_executed": [],
            "directories": [],
            "resources": [],
        }

    # CSV mode: a header row and one data row. The real header is
    # `Timestamp,Executable Name,MFT Seq Number,MFT Entry Number,Prefetch Hash,Run Count`.
    if lines[0].count(",") >= 3 and ":" not in lines[0]:
        header = [h.strip() for h in lines[0].split(",")]
        row = [c.strip() for c in lines[1].split(",")] if len(lines) > 1 else []
        fields = dict(zip(header, row))
        return {
            "format": "csv",
            "fields": fields,
            "executable": fields.get("Executable Name"),
            "run_count": fields.get("Run Count"),
            "last_executed": [fields["Timestamp"]] if fields.get("Timestamp") else [],
            "directories": [],
            "resources": [],
            "directories_count": 0,
            "resources_count": 0,
        }

    fields: dict[str, str] = {}
    last_executed: list[str] = []
    directories: list[str] = []
    resources: list[str] = []
    current: list[str] | None = None

    for line in lines:
        stripped = line.strip()
        lowered = stripped.lower()
        if lowered == _DIRECTORIES_HEADER:
            current = directories
            continue
        if lowered == _RESOURCES_HEADER:
            current = resources
            continue

        if (numbered := _NUMBERED_RE.match(line)) is not None:
            if current is not None:
                current.append(numbered["path"].replace(_PADDING, "").rstrip())
            continue

        match = _KV_RE.match(stripped)
        if match is None or len(match["key"]) > 48:
            continue
        key, value = match["key"].strip(), match["value"].strip()
        if key.lower() == "last executed":
            last_executed.append(value)
            continue
        fields[key] = value

    return {
        "format": "report",
        "fields": fields,
        # Named explicitly: these are the execution facts a finding cites.
        "executable": fields.get("Executable Name"),
        "run_count": fields.get("Run count") or fields.get("Run Count"),
        "last_executed": last_executed,
        "directories": directories[:_LIST_PREVIEW],
        "directories_count": len(directories),
        "resources": resources[:_LIST_PREVIEW],
        "resources_count": len(resources),
        "note": (
            "prefetch.py procesa UN fichero .pf por corrida (no tiene modo directorio): "
            "para cubrir la carpeta Prefetch entera, una corrida por fichero. "
            "`last_executed` puede traer hasta ocho marcas en Win8 y posteriores"
        ),
    }
