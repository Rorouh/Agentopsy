"""Provider-agnostic context-window management for the agent loop (Bug 008).

The executor is stateless: FORENSIA re-sends the whole conversation on every
iteration, so an append-only transcript grows O(N) and the total wire cost of a
run grows O(N^2). Prompt caching can't be relied on uniformly across the four
executors (Claude Code / Codex / Gemini / Ollama), so the only uniform lever is
to **send less**. This module projects the canonical ``messages`` list to a
bounded OUTBOUND copy.

Contract (mirrors ``redaction.redact_messages``): pure function, no I/O, never
mutates the input. The loop keeps the canonical ``messages`` raw for
replay/audit/custody; only the copy that crosses the wire is trimmed here.

The trim is conservative: the system prompt, the task, the assistant reasoning
turns and the most recent K tool results survive verbatim; older tool results —
the heavy artifacts — collapse to a one-line stub that still names the run, so
the model can fetch the detail from the artifact with ``jq`` if it needs it.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Sequence
from typing import Any

# The playbook (the largest static block in the system prompt — ~22 KB on
# windows) is re-sent verbatim on EVERY iteration. Only ONE of its two primary
# branches applies to a given piece of evidence, yet both travel every turn
# (Bug 008). Split at level-2 headers and drop the branch that doesn't match the
# triage `detected_kind`. Common sections (routing, cost discipline, best
# practices, per-tool annex) and the intro always stay.
_H2_RE = re.compile(r"^## .*$", re.MULTILINE)
_H3_RE = re.compile(r"^### .*$", re.MULTILINE)
_DISK_KINDS = frozenset({"disk", "container_disk"})

# Per-tool annex sub-headings (### …) worth branch-trimming. The annex ships in
# EVERY iteration as a "common" ## section, but ~6 KB of it are disk-only tool
# docs that are dead weight on a memory dump (Bug 008 §2 Nivel 1). Keyword sets are
# CONSERVATIVE: a sub-heading that matches neither stays (fails safe — RULE 2:
# never hide guidance we're unsure about).
_ANNEX_DISK_KEYS = ("particiones", "sistema de ficheros", "artefactos windows", "ez tools")
_ANNEX_MEMORY_KEYS = ("memoria volátil", "memoria volatil")


def keep_last_tool_results_default() -> int:
    """How many of the most recent tool-result messages stay verbatim on the wire.

    Older ones are stubbed. Default 4; per-deployment override via
    ``FORENSIA_CONTEXT_KEEP_TOOL_RESULTS``. Minimum 1 (the model always sees at
    least the latest result in full)."""
    try:
        return max(1, int(os.environ.get("FORENSIA_CONTEXT_KEEP_TOOL_RESULTS", "4")))
    except ValueError:
        return 4


def _embedded_json(text: str) -> Any:
    """Best-effort: parse the outermost ``{...}`` object embedded in ``text`` (a tool
    result wrapped in NO-trust spotlighting delimiters). ``None`` if none parses."""
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except (ValueError, json.JSONDecodeError):
        return None


def _stub_for(content: Any) -> str:
    """One-line replacement for an elided tool-result body. Best-effort extracts
    ``tool_id`` / ``exit_code`` / ``run_id`` from the JSON so the stub still points
    the model at the run artifact."""
    tool_id: Any = None
    exit_code: Any = None
    run_id: Any = None
    if isinstance(content, str):
        try:
            body = json.loads(content)
        except (ValueError, json.JSONDecodeError):
            # A real tool result is wrapped in NO-trust spotlighting delimiters
            # (agent._UNTRUSTED_OPEN/CLOSE around the JSON). Recover the embedded
            # object so the stub can still name tool_id/exit_code/run_id.
            body = _embedded_json(content)
        if isinstance(body, dict):
            tool_id = body.get("tool_id")
            exit_code = body.get("exit_code")
            run_id = body.get("run_id")
            if not run_id and isinstance(body.get("artifact_run"), dict):
                run_id = body["artifact_run"].get("run_id")
    meta = ", ".join(
        part
        for part in (
            f"tool={tool_id}" if tool_id else "",
            f"exit={exit_code}" if exit_code is not None else "",
            # Full run_id, never a prefix — it is the agent's recovery key for the run's
            # artifacts ({run_id, relpath}); a truncated id is rejected by the ArtifactStore.
            f"run={run_id}" if run_id else "",
        )
        if part
    )
    return (
        "[resultado de tool elidido para acotar el contexto"
        + (f" ({meta})" if meta else "")
        + "; el detalle sigue en el artefacto del run — recupéralo con `jq` si lo necesitas]"
    )


def window_messages(
    messages: Sequence[dict[str, Any]],
    keep_last_tool_results: int | None = None,
) -> list[dict[str, Any]]:
    """Return a COPY of ``messages`` with all but the most recent
    ``keep_last_tool_results`` tool-result messages collapsed to a stub.

    Only ``role == "tool"`` messages are ever touched; system / user / assistant
    turns pass through verbatim so the reasoning chain stays coherent. The input
    list and its dicts are never mutated.
    """
    keep = (
        keep_last_tool_results
        if keep_last_tool_results is not None
        else keep_last_tool_results_default()
    )
    tool_indices = [i for i, m in enumerate(messages) if m.get("role") == "tool"]
    if len(tool_indices) <= keep:
        return [dict(m) for m in messages]

    stub_targets = set(tool_indices[:-keep])
    out: list[dict[str, Any]] = []
    for i, msg in enumerate(messages):
        copy = dict(msg)
        if i in stub_targets:
            copy["content"] = _stub_for(copy.get("content"))
        out.append(copy)
    return out


def _section_branch(heading: str) -> str:
    """Classify a level-2 playbook section by its heading: ``disk`` | ``memory`` |
    ``common``. Both trained packages use the ``## A. Imagen de disco …`` /
    ``## B. Volcado de memoria RAM …`` convention."""
    h = heading.lower()
    if "imagen de disco" in h:
        return "disk"
    if "volcado de memoria" in h or "memoria ram" in h:
        return "memory"
    return "common"


def _annex_subsection_branch(heading: str) -> str:
    """Classify a per-tool annex ``### …`` sub-heading. Conservative: unknown → common."""
    h = heading.lower()
    if any(k in h for k in _ANNEX_DISK_KEYS):
        return "disk"
    if any(k in h for k in _ANNEX_MEMORY_KEYS):
        return "memory"
    return "common"


def _trim_annex_subsections(section: str, *, keep_disk: bool, keep_memory: bool) -> str:
    """Drop the disk/memory ``### …`` sub-blocks of the annex that don't apply.

    Everything before the first ``###`` (the annex intro) and every ``common``
    sub-block stays. No ``###`` headers → unchanged.
    """
    subs = list(_H3_RE.finditer(section))
    if not subs:
        return section
    kept = [section[: subs[0].start()]]
    for i, match in enumerate(subs):
        start = match.start()
        end = subs[i + 1].start() if i + 1 < len(subs) else len(section)
        branch = _annex_subsection_branch(section[match.start() : match.end()])
        if branch == "disk" and not keep_disk:
            continue
        if branch == "memory" and not keep_memory:
            continue
        kept.append(section[start:end])
    return "".join(kept)


def select_playbook_section(playbook: str, detected_kind: str) -> str:
    """Return the playbook with the primary branch that does NOT match
    ``detected_kind`` removed, keeping the intro and every common section.

    - ``memory`` → drop the disk branch.
    - ``disk`` / ``container_disk`` → drop the memory branch.
    - ``unknown`` (or any unexpected value) → keep everything. RULE 2: never hide
      a branch the operator might still need — the routing block already anchors
      the choice when the triage is confident, and an ``unknown`` fingerprint
      means both branches stay on the table for the single diagnostic probe.
    """
    if not playbook or not playbook.strip():
        return playbook

    matches = list(_H2_RE.finditer(playbook))
    if not matches:
        return playbook

    keep_disk = detected_kind in _DISK_KINDS
    keep_memory = detected_kind == "memory"
    if not keep_disk and not keep_memory:
        # unknown / unexpected → keep both branches (no silent trimming).
        keep_disk = keep_memory = True

    intro = playbook[: matches[0].start()]
    kept: list[str] = [intro]
    for i, match in enumerate(matches):
        start = match.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(playbook)
        heading = playbook[match.start() : match.end()]
        branch = _section_branch(heading)
        if branch == "disk" and not keep_disk:
            continue
        if branch == "memory" and not keep_memory:
            continue
        section = playbook[start:end]
        # The per-tool annex is a "common" section, but its disk/memory tool docs
        # can still be branch-trimmed (Bug 008 §2 Nivel 1). Only when we're actually
        # dropping a branch (not the unknown "keep both" case).
        if "anexo" in heading.lower() and not (keep_disk and keep_memory):
            section = _trim_annex_subsections(
                section, keep_disk=keep_disk, keep_memory=keep_memory
            )
        kept.append(section)
    return "".join(kept).rstrip() + "\n"


__all__ = [
    "window_messages",
    "keep_last_tool_results_default",
    "select_playbook_section",
]
