"""Operator config read/write surface.

Reads and writes ``~/.forensia/config.json`` for a closed allowlist of keys
(model backend, Ollama host, cloud API keys). RULE 2 (no silent defaults):
the API never invents values; the operator must set them explicitly.

Secrets never round-trip through the wire as cleartext: GET returns whether a
key is set plus a masked preview (first 4 chars + length), never the raw value.
POST validates per-key invariants and writes atomically.
"""

from __future__ import annotations

import json
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from forensia.config import CONFIG_DIR, CONFIG_FILE, config
from forensia.security import require_token

router = APIRouter()


_EDITABLE_KEYS = (
    "MODEL_BACKEND",
    "MODEL_NAME",
    "OLLAMA_HOST",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
)
_SECRET_KEYS = frozenset({"ANTHROPIC_API_KEY", "OPENAI_API_KEY"})

# Modelos seleccionables vía Settings. Hardcodeado en vez de pull live a /v1/models
# para que la lista sea reproducible en aire-gapped (RULE 1 espíritu).
_OPENAI_MODELS = (
    "gpt-4o",
    "gpt-4o-mini",
    "gpt-4-turbo",
    "gpt-4",
    "gpt-3.5-turbo",
    "o1-preview",
    "o1-mini",
    "o3-mini",
)

_HTTP_URL_RE = re.compile(r"^https?://[^\s]+$")
_VALID_BACKENDS = frozenset({"local", "cloud"})


class SetConfigRequest(BaseModel):
    key: str
    value: str


def _mask(value: str) -> str:
    """Show the first 4 chars + length so operators can recognise WHICH key is set
    without exposing it. Empty / very short values are reported as fully redacted.
    """
    if not value or len(value) < 8:
        return "(set)"
    return f"{value[:4]}…(len={len(value)})"


@router.get("/api/config", dependencies=[Depends(require_token)])
def get_config() -> dict[str, Any]:
    """Return the status of each editable key. Never the raw values."""
    out: dict[str, dict[str, Any]] = {}
    for key in _EDITABLE_KEYS:
        raw = config.get(key)
        if raw is None or raw == "":
            out[key] = {"set": False, "preview": None}
            continue
        if key in _SECRET_KEYS:
            out[key] = {"set": True, "preview": _mask(str(raw))}
        else:
            # Non-secrets (MODEL_BACKEND, OLLAMA_HOST) are safe to show verbatim.
            out[key] = {"set": True, "preview": str(raw)}
    return {"keys": out, "config_file": str(CONFIG_FILE)}


@router.post("/api/config", dependencies=[Depends(require_token)])
def set_config(req: SetConfigRequest) -> dict[str, Any]:
    key = req.key
    if key not in _EDITABLE_KEYS:
        raise HTTPException(
            status_code=422,
            detail=f"key {key!r} is not editable. Allowed: {list(_EDITABLE_KEYS)}",
        )
    value = req.value.strip()
    if not value:
        raise HTTPException(status_code=422, detail=f"value for {key!r} is empty")

    if key == "MODEL_BACKEND":
        if value not in _VALID_BACKENDS:
            raise HTTPException(
                status_code=422,
                detail=f"MODEL_BACKEND must be one of {sorted(_VALID_BACKENDS)}",
            )
    elif key == "MODEL_NAME":
        # Acepta cualquier string no vacío (Ollama tiene modelos como llama3.1:8b,
        # OpenAI tiene gpt-4o, claude-3-5-sonnet, etc.). Validación blanda.
        if len(value) > 128:
            raise HTTPException(status_code=422, detail="MODEL_NAME too long")
    elif key == "OLLAMA_HOST":
        if not _HTTP_URL_RE.match(value):
            raise HTTPException(
                status_code=422,
                detail="OLLAMA_HOST must be an http(s):// URL",
            )
    elif key in _SECRET_KEYS:
        if len(value) < 16:
            raise HTTPException(
                status_code=422,
                detail=f"{key} value is too short to be a credible API key",
            )

    # Read current file (or start empty), set the key, write atomically.
    existing: dict[str, str] = {}
    if CONFIG_FILE.exists():
        try:
            existing = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            if not isinstance(existing, dict):
                existing = {}
        except json.JSONDecodeError:
            existing = {}
    existing[key] = value

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(existing, sort_keys=True, indent=2), encoding="utf-8")
    tmp.replace(CONFIG_FILE)

    # Reflect the new value in the Config singleton so subsequent /api/capabilities
    # calls see it without a sidecar restart.
    config._data[key] = value  # noqa: SLF001 — module-private mutator for live update

    if key in _SECRET_KEYS:
        return {"key": key, "set": True, "preview": _mask(value)}
    return {"key": key, "set": True, "preview": value}


@router.get("/api/config/models", dependencies=[Depends(require_token)])
def list_models() -> dict[str, Any]:
    """Hardcoded short list of OpenAI models the UI can offer in the dropdown.

    No live ``/v1/models`` lookup — that requires network egress, and FORENSIA
    is supposed to work air-gapped. New models are added to this list with
    each release.
    """
    return {"openai": list(_OPENAI_MODELS)}
