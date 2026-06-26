"""Capability contract: the UI never assumes a platform — it asks here and degrades.

Reports per-tool availability based on the catalog's declared delivery mode for this
host OS (bundled or container — see CLAUDE.md RULE 1). The `container_runtime` field
indicates whether docker / podman / nerdctl is present on PATH; container-delivered
tools require it.
"""

from __future__ import annotations

import platform
import sys
from typing import Any

from forensia.config import config
from forensia.toolkit.catalog import CATALOG
from forensia.toolkit.resolver import container_runtime, is_tool_available


def snapshot() -> dict[str, Any]:
    return {
        "platform": sys.platform,
        "os": platform.system().lower(),
        "arch": platform.machine().lower(),
        "python": platform.python_version(),
        "packaged": getattr(sys, "frozen", False),
        "container_runtime": container_runtime() is not None,
        "tools": {tool.id: is_tool_available(tool) for tool in CATALOG},
        "models": {
            "local_default": True,
            "ollama": config.get("OLLAMA_HOST") is not None,
            "anthropic": config.get("ANTHROPIC_API_KEY") is not None,
            "openai": config.get("OPENAI_API_KEY") is not None,
        },
    }
