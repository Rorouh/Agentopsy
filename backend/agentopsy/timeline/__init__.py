"""Forensic timeline of a case — four deterministic layers.

0. **Incident timeline** (``agentopsy.timeline.hallazgos``, the DEFAULT layer): what
   happened on the INVESTIGATED DEVICE, one event per finding that carries an
   ``observed_at`` (the artifact's own timestamp), in ascending order. It is the line
   a third party reads first and the one that becomes section 3 of the report. A
   finding without ``observed_at`` does not enter it, and is counted and declared
   rather than dropped (RULE 2). Distinct from layer 1 in object, not in shape: this
   one is the chronology of the INCIDENT, that one of the INVESTIGATION.

1. **Investigation timeline** (always available): every tool run recorded in the
   case's append-only, hash-chained audit log plus every finding the agent
   recorded, merged and ordered chronologically by their UTC timestamp. Built
   from what ALREADY exists in the case — it runs no new tool.

2. **Filesystem super-timeline** (on demand): the ``tsk_fls -m`` forensic step over
   the selected evidence (shell-free, argv-array, run through the dispatcher /
   maletín — never a re-implemented subprocess), whose TSK *bodyfile* is expanded
   into MACB filesystem events. Because it can take minutes on a real image, it
   runs as an asynchronous job (``agentopsy.agent.jobs``). The completed result is
   materialized under the case so it survives reloads/restarts.

3. **Relevant events** (``agentopsy.timeline.relevance``): the filesystem layer filtered
   to the forensically important MACB events — credentials, SSH material, shell history,
   persistence, logs, temp executables, web artifacts, system binaries created/modified —
   each tagged with a category / reason / weight. A deterministic triage over ALL events,
   sorted by importance and capped (overflow reported).

All timestamps are UTC and normalized to an explicit ``…Z`` ISO-8601 string, so the
surface can label the timezone unambiguously (never a silent local-time render).

Las capas 1 a 3 se LEEN como lista y se exportan como hoja
(``agentopsy.timeline.export``). La capa 0 se lee como FIGURA y se exporta como imagen:
la dibuja el navegador en SVG y su procedencia (nombre del caso, instante y nombre de
fichero por ``export_hoja.export_basename``) la resuelve ``build_findings_timeline``.

Pure logic lives here (CLAUDE.md RULE 3); ``agentopsy.routers.timeline`` is a thin
adapter over it.
"""

from __future__ import annotations

from agentopsy.timeline.builder import (
    TIMEZONE,
    assemble_investigation_timeline,
    bodyfile_to_fs_events,
    build_investigation_timeline,
    load_filesystem_timeline,
    query_filesystem_timeline,
    run_filesystem_timeline,
)
from agentopsy.timeline.hallazgos import (
    assemble_findings_timeline,
    build_findings_timeline,
)

__all__ = [
    "TIMEZONE",
    "assemble_findings_timeline",
    "assemble_investigation_timeline",
    "bodyfile_to_fs_events",
    "build_findings_timeline",
    "build_investigation_timeline",
    "load_filesystem_timeline",
    "query_filesystem_timeline",
    "run_filesystem_timeline",
]
