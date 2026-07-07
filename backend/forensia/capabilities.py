"""Capability contract: the UI never assumes a platform — it asks here and degrades.

Reports the maletín truth (CLAUDE.md RULE 1): every forensic tool lives in one or both
compose maletín images (`toolkit-windows` / `toolkit-unix`), and the api reaches it
there — it bundles none itself. `forensia.toolkit.maletin` probes each maletín through
its exec-agent (reachable? binary present?) and this snapshot surfaces, per tool,
`{available, toolkits, reason}` plus a per-maletín `toolkits` section, so the UI degrades
per capability with an actionable reason (RULE 2: never substitute one maletín for
another). `container_runtime` says whether the api has any channel to consult the
maletines at all (at least one exec-agent URL configured; §B, no host Docker socket).
"""

from __future__ import annotations

import platform
import sys
from typing import Any

from forensia.agent.registry import agent_registry
from forensia.executors import executors_status
from forensia.toolkit import maletin
from forensia.toolkit.catalog import CATALOG


def snapshot() -> dict[str, Any]:
    maletines = maletin.snapshot(CATALOG)
    return {
        "platform": sys.platform,
        "os": platform.system().lower(),
        "arch": platform.machine().lower(),
        "python": platform.python_version(),
        # Whether the api has a channel to the maletines at all (at least one exec-agent
        # URL configured; §B). Without it every tool reports its actionable reason.
        "container_runtime": maletines["client"],
        # Per-maletín service status (running? / why not) — answers "capabilities does
        # not report the maletines".
        "toolkits": maletines["services"],
        # Per-tool availability: {tool_id: {available, toolkits, via, reason, detail}}.
        "tools": maletines["tools"],
        # The four executors of the 2026-07-02 pivot. Each entry carries available + the
        # ACTIONABLE reason when it is not (binary missing, credentials not mounted,
        # Ollama unreachable) so the UI degrades explicitly per executor (RULE 2).
        "executors": executors_status(),
        "agents": {
            "root": str(agent_registry.root),
            "loaded": [pkg.summary() for pkg in agent_registry.list()],
        },
    }
