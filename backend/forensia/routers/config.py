"""Operator config read/write surface.

Reads and writes ``config.json`` under ``FORENSIA_HOME`` for a closed allowlist
of keys. RULE 2 (no silent defaults): the API never invents values; the operator
must set them explicitly.

Since the 2026-07-02 pivot there are NO secrets here: the project holds no API
keys (SECURITY INVARIANT 7 — the CLI executors authenticate with the session in
the ``forensia-cli-auth`` volume, seeded once from the host or created by
logging in inside the container). Editable keys:

- ``DEFAULT_EXECUTOR`` — optional. Setting it is an EXPLICIT act of the user in
  Settings (that is operator agency); code inventing it would violate RULE 2.
- ``OLLAMA_HOST`` — http(s) URL of the Ollama service (the compose injects
  ``http://ollama:11434`` via environment; this key covers standalone runs).
- ``OLLAMA_MODEL`` — model name for the ``ollama`` executor (e.g. llama3.1:8b).
- ``FORENSIA_EXECUTOR_TIMEOUT`` — seconds one executor run may take before it
  is aborted (and audited) as a timeout; see ``forensia.executors.base``.
"""

from __future__ import annotations

import json
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from forensia.config import CONFIG_DIR, CONFIG_FILE, config
from forensia.executors import EXECUTOR_IDS, executor_models
from forensia.security import require_token

router = APIRouter()


_EDITABLE_KEYS = (
    "DEFAULT_EXECUTOR",
    "OLLAMA_HOST",
    "OLLAMA_MODEL",
    "FORENSIA_EXECUTOR_TIMEOUT",
)

_HTTP_URL_RE = re.compile(r"^https?://[^\s]+$")


class SetConfigRequest(BaseModel):
    key: str
    value: str


@router.get("/api/config", dependencies=[Depends(require_token)])
def get_config() -> dict[str, Any]:
    """Return the status of each editable key. None of them is a secret, so the
    value is shown verbatim."""
    out: dict[str, dict[str, Any]] = {}
    for key in _EDITABLE_KEYS:
        raw = config.get(key)
        if raw is None or raw == "":
            out[key] = {"set": False, "preview": None}
        else:
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

    if key == "DEFAULT_EXECUTOR":
        if value not in EXECUTOR_IDS:
            raise HTTPException(
                status_code=422,
                detail=f"DEFAULT_EXECUTOR must be one of {list(EXECUTOR_IDS)}",
            )
    elif key == "OLLAMA_HOST":
        if not _HTTP_URL_RE.match(value):
            raise HTTPException(
                status_code=422,
                detail="OLLAMA_HOST must be an http(s):// URL",
            )
    elif key == "OLLAMA_MODEL":
        # Cualquier tag válido de Ollama (llama3.1:8b, mistral, …). Validación blanda.
        if len(value) > 128:
            raise HTTPException(status_code=422, detail="OLLAMA_MODEL too long")
    elif key == "FORENSIA_EXECUTOR_TIMEOUT":
        # Se valida aquí Y en resolve_timeout (un valor corrupto en config.json
        # o en el entorno también falla alto — RULE 2).
        if not value.isdigit() or int(value) <= 0:
            raise HTTPException(
                status_code=422,
                detail="FORENSIA_EXECUTOR_TIMEOUT debe ser un entero de segundos > 0",
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
    # calls see it without restarting the api service.
    config._data[key] = value  # noqa: SLF001 — module-private mutator for live update

    return {"key": key, "set": True, "preview": value}


@router.get("/api/config/executors", dependencies=[Depends(require_token)])
def list_executors() -> dict[str, Any]:
    """Closed enum of executor ids for the Settings dropdown. Availability (with
    the actionable reason when one is down) lives in ``/api/capabilities``."""
    return {"executors": list(EXECUTOR_IDS)}


@router.get("/api/executors/{executor_id}/models", dependencies=[Depends(require_token)])
def list_models(executor_id: str) -> dict[str, Any]:
    """Models the composer's model picker offers for ``executor_id``. Ollama returns
    its installed models (editable); the cloud CLIs return a note (their CLI owns the
    model — RULE 2). Unknown id → 400 with the valid ids."""
    try:
        return executor_models(executor_id)
    except ValueError as exc:  # unknown executor id
        raise HTTPException(status_code=400, detail=str(exc)) from exc
