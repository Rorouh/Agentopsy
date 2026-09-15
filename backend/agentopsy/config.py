"""Configuration: the operator's `config.json` layered over the deployment's environment.

`Config` is the store of the keys the operator edits from Settings (executor,
models, reasoning level, Ollama host, run timeout) and nothing else: every other
environment variable of the stack (`AGENTOPSY_HOME`, `AGENTOPSY_EVIDENCE_DIR`,
the maletin URLs) is read straight from `os.environ` by the module that owns it.

Precedence: `config.json` FIRST, environment second. The environment carries the
deployment's baseline (the compose sets `OLLAMA_HOST` to its bundled service);
`config.json` carries an explicit act of the operator in Settings. Reading them
the other way round meant that saving a value in the web UI changed nothing and
said nothing, which is exactly the silent behaviour RULE 2 exists to prevent:
the operator points Agentopsy at the Ollama running on their own machine, the
compose variable keeps winning, and the only symptom is a model that is never
used. `source()` reports which layer answered so the surface can show it.

An empty value in `config.json` is not a value: clearing a key in Settings
removes it (`routers/config._unset_key`), so the environment baseline answers
again. Nothing here invents a value that neither layer holds.

RULE 2 (no silent defaults): `require()` fails loudly when a needed value is absent.
There is no fallback that substitutes a provider/key the operator did not set.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

CONFIG_DIR = Path(os.environ.get("AGENTOPSY_HOME", Path.home() / ".agentopsy"))
CONFIG_FILE = CONFIG_DIR / "config.json"


class Config:
    def __init__(self) -> None:
        self._data: dict[str, Any] = {}
        if CONFIG_FILE.exists():
            self._data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))

    def get(self, key: str) -> Any | None:
        saved = self._data.get(key)
        if saved is not None and saved != "":
            return saved
        return os.environ.get(key.upper())

    def source(self, key: str) -> str | None:
        """Which layer `get(key)` took its value from.

        ``"config"`` (the operator saved it in Settings), ``"env"`` (the
        deployment set it, e.g. the compose) or ``None`` when neither holds it.
        """
        saved = self._data.get(key)
        if saved is not None and saved != "":
            return "config"
        env = os.environ.get(key.upper())
        if env is not None and env != "":
            return "env"
        return None

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
