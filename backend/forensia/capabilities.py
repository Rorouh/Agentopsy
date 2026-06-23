"""Capability contract: the UI never assumes a platform — it asks here and degrades.

There is intentionally NO `docker` key: FORENSIA does not use Docker (CLAUDE.md RULE 1).
A tool is reported available when the bundled or env copy resolves, so the packaged app
enables a feature even when the host PATH lacks it.
"""

from __future__ import annotations

import platform
import sys
from typing import Any

from forensia.config import config
from forensia.toolkit.catalog import CATALOG
from forensia.toolkit.resolver import resolve


def snapshot() -> dict[str, Any]:
    return {
        "platform": sys.platform,
        "os": platform.system().lower(),
        "arch": platform.machine().lower(),
        "python": platform.python_version(),
        "packaged": getattr(sys, "frozen", False),
        "tools": {tool.id: resolve(tool.binary) is not None for tool in CATALOG},
        "models": {
            "local_default": True,
            "ollama": config.get("OLLAMA_HOST") is not None,
            "anthropic": config.get("ANTHROPIC_API_KEY") is not None,
            "openai": config.get("OPENAI_API_KEY") is not None,
        },
    }
