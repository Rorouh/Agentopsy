"""hindsight wrapper — browser forensics over a pre-extracted Chromium/Firefox profile.

`hindsight.py` (pyhindsight, in the windows maletín) parses the profile directory of a
Chromium-family browser (Chrome, Edge, Brave, Vivaldi; also Firefox and Tor) and emits
history, downloads, cookies, autofill, bookmarks, local/session storage and the results
of its own plugins as ONE dataset. It is the only browser-artifact tool in the catalog:
before it, "what did the user browse between these two dates" had no tool at all.

Input custody. hindsight consumes a DIRECTORY, and Agentopsy never hands it a free path:
`profile_dir` is DERIVED_INPUT only (`ArtifactRef` of a previous run, typically the
`tsk_icat`/`tsk_recover` extraction of `.../User Data/Default`), which the dispatcher
resolves and RE-HASHES before this wrapper composes an argv (FORENSIC INVARIANTS 1-2).

Three flags are pinned by the wrapper rather than exposed, all three measured against
hindsight 2026.06 inside the maletín on 2026-09-03:

- `-l` (log). Left alone it writes `hindsight.log` NEXT TO ITS OWN SCRIPT
  (`/usr/local/bin/hindsight.log`, verified): outside the case, outside the audit, and
  in a path the artifact store never hashes. It is pinned into `output_dir`.
- `--temp_dir`. Same defect, same place (`/usr/local/bin/hindsight-temp`). It matters
  more than the log: hindsight COPIES the profile before opening it, so that directory
  holds the bytes actually parsed. Pinned into `output_dir` so everything a run reads
  and writes stays inside the run.
- `--nocopy` is NOT offered. It is the flag that turns that protective copy off, and
  opening a Chromium SQLite database in place can replay its WAL and WRITE to the file:
  on a derived artifact that would break the hash the dispatcher just verified.

Two more stay out on purpose: `-d/--decrypt`, whose own help calls both its modes buggy
and which only makes sense when running on the very machine the data came from (never a
post-mortem container); and `-t/--timezone`, which only shifts the DISPLAY timestamps of
the xlsx output. Findings carry `observed_at` in UTC with an explicit offset, so letting
the model pick a display timezone here would invite a wrong conversion with no way to
tell from the artifact.
"""

from __future__ import annotations

import re
from typing import Any

ALLOWED_FLAGS = frozenset({"-i", "-o", "-f", "-l", "-b", "--temp_dir"})

#: `-f`. sqlite is the default, and the reason is measured, not stylistic: on the real
#: Firefox profile of 2020JimmyWilson.E01 the jsonl writer emitted 123 rows and NOT ONE
#: of them was history, while sqlite carried all 16 visited URLs with their timestamps
#: in its `timeline` table. jsonl would have made the tool look like it worked and
#: quietly dropped the very thing it exists to produce. xlsx is for an annex.
_FORMATS = frozenset({"sqlite", "jsonl", "xlsx"})

#: `-b`. hindsight matches these case-insensitively and maps Chromium onto Chrome.
#: Omitting it is hindsight's own auto-detection per profile, not an Agentopsy default.
_BROWSERS = frozenset({"Chrome", "Edge", "Brave", "Vivaldi", "Firefox", "Tor"})

#: `<label>  <value>`, right-aligned label, two or more spaces between the two.
_FIELD_RE = re.compile(r"^\s*(?P<label>\S[^\n]*?\S)\s{2,}(?P<value>\S.*?)\s*$")
#: `Google Searches (v20160912):   - 0 searches parsed -`
_PLUGIN_RE = re.compile(r"^\s*(?P<name>.+?)\s+\(v(?P<version>\d+)\):\s+-\s+(?P<result>.+?)\s+-\s*$")

#: Labels of the closing report worth surfacing to the agent, mapped to a stable key.
#: `Output path` is deliberately NOT here. It is the one field guaranteed to wrap (it
#: points inside the case, so it is long), and a wrapped value read as a whole one is a
#: truncated path presented as if it were complete. Agentopsy already holds the exact
#: path in the run's `output_files`, which is the authoritative source anyway.
_FIELDS = {
    "Profiles found": "profiles_found",
    "Detected": "detected",
    "Browser type": "browser_type",
    "Format": "format",
    "Total items": "total_items",
    "Elapsed time": "elapsed",
}


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for hindsight.py.

    params:
        profile_dir (str, required): the browser profile directory, resolved by the
            dispatcher from an ArtifactRef of a previous run. Point it at the profile
            itself (typically `Default`); given a higher directory hindsight recurses
            and reports every profile it finds.
        output_dir (str, required): run dir injected by the dispatcher. The dataset
            lands in `<output_dir>/navegacion.<ext>`, the log in
            `<output_dir>/hindsight.log`, hindsight's working copy of the profile in
            `<output_dir>/hindsight-temp`.
        output_format (str, optional): sqlite (default) / jsonl / xlsx. See _FORMATS:
            jsonl was measured to drop the browsing history.
        browser_type (str, optional): force the browser instead of auto-detecting it.
    """
    profile_dir = params.get("profile_dir")
    if not profile_dir or not isinstance(profile_dir, str):
        raise ValueError("hindsight requires params.profile_dir: str")
    output_dir = params.get("output_dir")
    if not output_dir or not isinstance(output_dir, str):
        raise ValueError("hindsight requires params.output_dir: str")

    fmt = params.get("output_format", "sqlite")
    if fmt not in _FORMATS:
        raise ValueError(
            f"hindsight output_format must be one of {sorted(_FORMATS)}, got {fmt!r}"
        )

    out = output_dir.rstrip("/")
    argv: list[str] = [
        "-i", profile_dir,
        # `-o` takes the basename WITHOUT extension: hindsight appends the one that
        # matches `-f` (verified: `-o …/navegacion -f jsonl` writes navegacion.jsonl).
        "-o", f"{out}/navegacion",
        "-f", fmt,
        "-l", f"{out}/hindsight.log",
        "--temp_dir", f"{out}/hindsight-temp",
    ]

    if (browser := params.get("browser_type")) is not None:
        if not isinstance(browser, str):
            raise ValueError("hindsight browser_type must be a str")
        if browser not in _BROWSERS:
            raise ValueError(
                f"hindsight browser_type must be one of {sorted(_BROWSERS)}, "
                f"got {browser!r}. Omit it to let hindsight detect each profile."
            )
        argv += ["-b", browser]

    return argv


def parse(stdout: str) -> dict[str, Any]:
    """Summarise hindsight's report.

    The dataset itself is the artifact; stdout carries the closing report and one line
    per plugin. Two shapes of the real output drive this parser, both observed on the
    2026.06 build inside the maletín:

    - The counts are grouped in SECTIONS (`User Activity`, `Website Storage`, `Browser
      Extensions`, `Configuration & Supporting Data`), and a section header is a row
      whose value is the literal `Count`. Without that rule the headers themselves land
      in the counts as artifacts named "Count", which is what the model would then read.
    - The panel WRAPS a long value over further lines. Agentopsy's own paths are long
      (a run's `out/` inside the case), so the profile path arrives split across three
      lines and a naive read reports `Path:` with nothing after it.

    An artifact whose count reads `[ Failed ]` is reported as FAILED rather than as
    zero: that is hindsight saying the database matched no schema version it knows,
    which is a very different fact from "the user browsed nothing".
    """
    summary: dict[str, str] = {}
    artifacts: dict[str, str] = {}
    sections: dict[str, list[str]] = {}
    failed: list[str] = []
    plugins: list[dict[str, str]] = []
    panel: list[str] = []

    section: str | None = None
    for raw in stdout.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue

        if (plugin := _PLUGIN_RE.match(line)) is not None:
            plugins.append(
                {
                    "name": plugin["name"].strip(),
                    "version": plugin["version"],
                    "result": plugin["result"].strip(),
                }
            )
            section = None
            continue

        # The profile panel is drawn in a box (border U+2502, not an ASCII pipe). A row
        # without `Key:` continues the previous one, so it is appended rather than kept
        # as an entry of its own.
        if "\u2502" in line:
            inner = line.strip().strip("\u2502").strip()
            if not inner:
                continue
            if ":" in inner and not inner.startswith(("http", "/")):
                panel.append(inner)
            elif panel:
                panel[-1] = panel[-1].rstrip() + inner
            continue

        field = _FIELD_RE.match(line)
        if field is None:
            continue
        label, value = field["label"].strip(), field["value"].strip()

        if value == "Count":
            section = label
            sections.setdefault(section, [])
            continue
        if label in _FIELDS:
            summary[_FIELDS[label]] = value
            section = None
            continue
        if section is not None:
            count = value.strip("[] ")
            artifacts[label] = count
            sections[section].append(label)
            if count.lower() == "failed":
                failed.append(label)

    return {
        "summary": summary,
        "profiles": panel,
        "artifacts": artifacts,
        "artifacts_by_section": sections,
        "artifacts_failed": failed,
        "plugins": plugins,
        "note": (
            "el conjunto completo esta en el artefacto navegacion.* del out/ del run; "
            "las URLs visitadas viven en la tabla `timeline` del sqlite. stdout solo "
            "trae el parte de cierre"
        ),
    }
