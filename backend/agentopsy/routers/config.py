"""Operator config read/write surface.

Reads and writes ``config.json`` under ``AGENTOPSY_HOME`` for a closed allowlist
of keys. RULE 2 (no silent defaults): the API never invents values; the operator
must set them explicitly.

Since the 2026-07-02 pivot there are NO secrets here: the project holds no API
keys (SECURITY INVARIANT 7 — the CLI executors authenticate with the session in
the ``agentopsy-cli-auth`` volume, seeded once from the host or created by
logging in inside the container). Editable keys:

- ``DEFAULT_EXECUTOR`` — optional. Setting it is an EXPLICIT act of the user in
  Settings (that is operator agency); code inventing it would violate RULE 2.
- ``OLLAMA_HOST`` — http(s) URL of the Ollama the operator wants to use. The
  compose injects ``http://ollama:11434`` (its own bundled service) as the
  deployment BASELINE and this key overrides it (``agentopsy.config``: saved
  value first, environment second), which is what lets the examiner point
  Agentopsy at the Ollama running on their own machine by writing
  ``http://localhost:11434`` here. Inside the container that loopback is
  resolved to the host machine, visibly, by
  ``agentopsy.executors.ollama.resolve_host``.
- ``OLLAMA_MODEL`` — model name for the ``ollama`` executor (e.g. llama3.1:8b).
- ``CLAUDE_CODE_MODEL`` / ``CODEX_MODEL`` / ``GEMINI_MODEL`` — model the operator
  chose for each cloud CLI, passed as ``--model``. Optional: unset (empty) means
  the CLI's own default (RULE 2 — Agentopsy never invents one). Validated with the
  same id gate as the executor layer (SECURITY INVARIANT 5).
- ``CODEX_REASONING_EFFORT`` — reasoning level («potencia») for the Codex CLI,
  passed as ``-c model_reasoning_effort``. Optional: unset means the level the
  CLI has configured. Validated for FORM always, and against the catalog the CLI
  itself cached when that catalog is readable — never against a list written
  here (RULE 2).
- ``AGENTOPSY_EXECUTOR_TIMEOUT`` — seconds one executor run may take before it
  is aborted (and audited) as a timeout; see ``agentopsy.executors.base``.
"""

from __future__ import annotations

import json
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from agentopsy.i18n import t, traducir_excepcion
from agentopsy.config import CONFIG_DIR, CONFIG_FILE, config
from agentopsy.executors import (
    EXECUTOR_IDS,
    REASONING_CONFIG_KEY,
    ExecutorError,
    executor_models,
    read_model_catalog,
    validate_model_id,
    validate_reasoning_effort,
)
from agentopsy.security import require_token

router = APIRouter()


# Per-cloud-CLI model keys — validated strictly (they become a --model argv flag).
_CLOUD_MODEL_KEYS = ("CLAUDE_CODE_MODEL", "CODEX_MODEL", "GEMINI_MODEL")

# Reasoning-level keys — same treatment as the model keys (they become argv too).
_REASONING_KEYS = tuple(REASONING_CONFIG_KEY.values())

_EDITABLE_KEYS = (
    "DEFAULT_EXECUTOR",
    "OLLAMA_HOST",
    "OLLAMA_MODEL",
    *_CLOUD_MODEL_KEYS,
    *_REASONING_KEYS,
    "AGENTOPSY_EXECUTOR_TIMEOUT",
)

# Keys the operator may CLEAR (empty value = unset). The model keys are optional:
# clearing a cloud model reverts to the CLI's own default; clearing OLLAMA_MODEL
# reverts to the agent package's declared model; clearing a reasoning level
# reverts to the one the CLI has configured (RULE 2 — no invented value).
_UNSETTABLE_KEYS = ("OLLAMA_MODEL", *_CLOUD_MODEL_KEYS, *_REASONING_KEYS)

_HTTP_URL_RE = re.compile(r"^https?://[^\s]+$")


class SetConfigRequest(BaseModel):
    key: str
    value: str


@router.get("/api/config", dependencies=[Depends(require_token)])
def get_config() -> dict[str, Any]:
    """Return the status of each editable key. None of them is a secret, so the
    value is shown verbatim.

    ``source`` says WHICH layer the value came from, ``"config"`` (saved from
    Settings) or ``"env"`` (the deployment, e.g. the compose). Without it a key
    the compose sets looks identical to one the operator chose, and the two
    behave differently when the operator edits it.
    """
    out: dict[str, dict[str, Any]] = {}
    for key in _EDITABLE_KEYS:
        raw = config.get(key)
        if raw is None or raw == "":
            out[key] = {"set": False, "preview": None, "source": None}
        else:
            out[key] = {"set": True, "preview": str(raw), "source": config.source(key)}
    return {"keys": out, "config_file": str(CONFIG_FILE)}


@router.post("/api/config", dependencies=[Depends(require_token)])
def set_config(req: SetConfigRequest) -> dict[str, Any]:
    key = req.key
    if key not in _EDITABLE_KEYS:
        raise HTTPException(
            status_code=422,
            detail=t("api.keyNotEditable", key=repr(key), allowed=list(_EDITABLE_KEYS)),
        )
    value = req.value.strip()
    if not value:
        if key in _UNSETTABLE_KEYS:
            return _unset_key(key)
        raise HTTPException(status_code=422, detail=t("api.valueEmpty", key=repr(key)))

    if key == "DEFAULT_EXECUTOR":
        if value not in EXECUTOR_IDS:
            raise HTTPException(
                status_code=422,
                detail=t("api.defaultExecutorEnum", ids=list(EXECUTOR_IDS)),
            )
    elif key == "OLLAMA_HOST":
        if not _HTTP_URL_RE.match(value):
            raise HTTPException(
                status_code=422,
                detail=t("api.ollamaHostUrl"),
            )
    elif key == "OLLAMA_MODEL":
        # Cualquier tag válido de Ollama (llama3.1:8b, mistral, …). Validación blanda.
        if len(value) > 128:
            raise HTTPException(status_code=422, detail=t("api.ollamaModelLong"))
    elif key in _CLOUD_MODEL_KEYS:
        # Becomes a --model argv flag: reject anything that could masquerade as a
        # CLI flag (SECURITY INVARIANT 5) — same gate as the executor layer.
        try:
            validate_model_id(value)
        except ExecutorError as exc:
            raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc
    elif key in _REASONING_KEYS:
        # Form first (it becomes an argv token), then the catalog the CLI itself
        # cached — the only list Agentopsy trusts. An unreadable catalog does NOT
        # block the operator: the run gate and the CLI still speak (RULE 2 — the
        # answer to "I can't enumerate" is never a hand-written enum).
        try:
            validate_reasoning_effort(value)
        except ExecutorError as exc:
            raise HTTPException(status_code=422, detail=traducir_excepcion(exc)) from exc
        catalog, _note = read_model_catalog()
        known = {eff for entry in catalog for eff, _desc in entry.efforts}
        if known and value not in known:
            raise HTTPException(
                status_code=422,
                detail=(
                    t(
                        "api.reasoningUnknown",
                        value=repr(value),
                        known=", ".join(sorted(known)),
                    )
                ),
            )
    elif key == "AGENTOPSY_EXECUTOR_TIMEOUT":
        # Se valida aquí Y en resolve_timeout (un valor corrupto en config.json
        # o en el entorno también falla alto — RULE 2).
        if not value.isdigit() or int(value) <= 0:
            raise HTTPException(
                status_code=422,
                detail=t("api.timeoutInteger"),
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

    return {"key": key, "set": True, "preview": value, "source": "config"}


def _unset_key(key: str) -> dict[str, Any]:
    """Remove ``key`` from ``config.json`` and the live singleton (used when the
    operator clears an optional model). Idempotent: absent key is a no-op."""
    existing: dict[str, str] = {}
    if CONFIG_FILE.exists():
        try:
            loaded = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                existing = loaded
        except json.JSONDecodeError:
            existing = {}
    existing.pop(key, None)

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(existing, sort_keys=True, indent=2), encoding="utf-8")
    tmp.replace(CONFIG_FILE)

    config._data.pop(key, None)  # noqa: SLF001 — module-private mutator for live update
    # Clearing the saved value uncovers the deployment's baseline again (if the
    # environment holds one), so the source is recomputed rather than assumed.
    return {"key": key, "set": False, "preview": None, "source": config.source(key)}


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
        raise HTTPException(status_code=400, detail=traducir_excepcion(exc)) from exc
