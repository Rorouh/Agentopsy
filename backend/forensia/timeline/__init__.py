"""Forensic timeline of a case — three deterministic layers.

1. **Investigation timeline** (always available): every tool run recorded in the
   case's append-only, hash-chained audit log plus every finding the agent
   recorded, merged and ordered chronologically by their UTC timestamp. Built
   from what ALREADY exists in the case — it runs no new tool.

2. **Filesystem super-timeline** (on demand): the ``tsk_fls -m`` forensic step over
   the selected evidence (shell-free, argv-array, run through the dispatcher /
   maletín — never a re-implemented subprocess), whose TSK *bodyfile* is expanded
   into MACB filesystem events. Because it can take minutes on a real image, it
   runs as an asynchronous job (``forensia.agent.jobs``). The completed result is
   materialized under the case so it survives reloads/restarts.

3. **Relevant events** (``forensia.timeline.relevance``): the filesystem layer filtered
   to the forensically important MACB events — credentials, SSH material, shell history,
   persistence, logs, temp executables, web artifacts, system binaries created/modified —
   each tagged with a category / reason / weight. A deterministic triage over ALL events,
   sorted by importance and capped (overflow reported).

All timestamps are UTC and normalized to an explicit ``…Z`` ISO-8601 string, so the
surface can label the timezone unambiguously (never a silent local-time render).

Pure logic lives here (CLAUDE.md RULE 3); ``forensia.routers.timeline`` is a thin
adapter over it.
"""

from __future__ import annotations

from forensia.timeline.builder import (
    TIMEZONE,
    assemble_investigation_timeline,
    bodyfile_to_fs_events,
    build_investigation_timeline,
    load_filesystem_timeline,
    query_filesystem_timeline,
    run_filesystem_timeline,
)

__all__ = [
    "TIMEZONE",
    "assemble_investigation_timeline",
    "bodyfile_to_fs_events",
    "build_investigation_timeline",
    "load_filesystem_timeline",
    "query_filesystem_timeline",
    "run_filesystem_timeline",
]
