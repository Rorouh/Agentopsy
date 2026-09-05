"""Per-case tool-usage stats, aggregated from the append-only audit log.

Read-only view for the UI ("Tools" panel): how many times each tool ran in a case
and how it fared (``ok`` = exit 0, ``failed`` = exit != 0). Source of truth is
``case_dir/audit.jsonl`` — ``tool_run_start`` carries ``tool_id`` + ``run_id``, and the
paired ``tool_run_finish`` carries ``run_id`` + ``exit_code`` (FORENSIC INVARIANT 4). The
count is cumulative across every chat session of the case, like the findings ledger.
"""

from __future__ import annotations

import json
from typing import Any

from agentopsy.cases.manager import case_manager


def tool_usage(case_id: str) -> list[dict[str, Any]]:
    """Return ``[{tool_id, total, ok, failed}]`` sorted by most-used first.

    Raises ``ValueError`` for a malformed ``case_id`` (surfaced as 422 by the router);
    a case with no audit log yet returns an empty list.
    """
    case_dir = case_manager.case_dir(case_id)
    audit = case_dir / "audit.jsonl"
    if not audit.is_file():
        return []

    run_tool: dict[str, str] = {}  # run_id → tool_id (to pair finish with its tool)
    stats: dict[str, dict[str, Any]] = {}
    for raw in audit.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            continue
        action = event.get("action")
        if action == "tool_run_start":
            tool_id = event.get("tool_id")
            if not isinstance(tool_id, str) or not tool_id:
                continue
            entry = stats.setdefault(tool_id, {"tool_id": tool_id, "total": 0, "ok": 0, "failed": 0})
            entry["total"] += 1
            run_id = event.get("run_id")
            if isinstance(run_id, str):
                run_tool[run_id] = tool_id
        elif action == "tool_run_finish":
            run_id = event.get("run_id")
            tool_id = run_tool.get(run_id) if isinstance(run_id, str) else None
            if tool_id and tool_id in stats:
                if event.get("exit_code") == 0:
                    stats[tool_id]["ok"] += 1
                else:
                    stats[tool_id]["failed"] += 1

    return sorted(stats.values(), key=lambda s: (-s["total"], s["tool_id"]))
