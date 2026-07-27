"""Configuration: ~/.forensia/config.json with environment-variable override.

RULE 2 (no silent defaults): `require()` fails loudly when a needed value is absent.
There is no fallback that substitutes a provider/key the operator did not set.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

CONFIG_DIR = Path(os.environ.get("FORENSIA_HOME", Path.home() / ".forensia"))
CONFIG_FILE = CONFIG_DIR / "config.json"


class Config:
    def __init__(self) -> None:
        self._data: dict[str, Any] = {}
        if CONFIG_FILE.exists():
            self._data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))

    def get(self, key: str) -> Any | None:
        env = os.environ.get(key.upper())
        if env is not None:
            return env
        return self._data.get(key)

    def require(self, key: str) -> Any:
        value = self.get(key)
        if value is None or value == "":
            raise KeyError(
                f"Required config '{key}' is not set. "
                f"Set env {key.upper()} or add it to {CONFIG_FILE}. "
                f"Agentopsy does not fall back to a default (see CLAUDE.md RULE 2)."
            )
        return value


config = Config()
