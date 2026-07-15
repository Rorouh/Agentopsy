"""Gemini CLI executor — ``gemini -p <prompt> --output-format json``.

Flags verified against the official docs
(google-gemini.github.io/gemini-cli/docs/cli/headless.html, 2026-07-02):
- ``-p`` / ``--prompt`` takes the prompt and enables headless (non-interactive)
  operation.
- ``--output-format json`` returns one JSON object: the answer in ``response``,
  usage metrics in ``stats``, and an ``error`` object (type/message/code) only
  when something failed.

Auth: the OAuth session (``~/.gemini/oauth_creds.json``) lives in the
``forensia-cli-auth`` volume — seeded from the host (Gemini CLI caches "Login
with Google" in files on every OS, so the seeding path usually works) or
created by logging in inside the container. Gemini CLI has NO non-interactive
auth-status command and its official headless auth alternatives are API keys —
forbidden here (SECURITY INVARIANT 7); checked at
google-gemini.github.io/gemini-cli/docs/get-started/authentication.html
(2026-07-03). The availability check therefore validates the cached OAuth
file's structure: a ``refresh_token`` (the CLI renews the access token itself —
the volume is writable) or a still-valid ``access_token``/``expiry_date`` pair.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from forensia.executors.base import (
    CliPromptExecutor,
    ExecutorAvailability,
    ExecutorError,
    Usage,
    _as_int,
    _find_key,
)

_LOGIN_HINT = (
    "Inicia sesión con tu cuenta de Google: en el HOST, ejecuta `gemini` y "
    "autentícate ANTES del primer `docker compose up` (el arranque seedea "
    "`~/.gemini` al volumen forensia-cli-auth); o dentro del contenedor, "
    "`docker compose exec -it -e NO_BROWSER=true api gemini` — imprime una "
    "URL para abrir en el navegador del host y pide pegar el código de vuelta. "
    "La sesión se revoca con `docker compose down -v`."
)


class GeminiExecutor(CliPromptExecutor):
    id = "gemini"
    name = "Gemini CLI"
    is_local = False
    binary = "gemini"

    def _check_auth(self) -> ExecutorAvailability:
        creds = Path.home() / ".gemini" / "oauth_creds.json"
        if not creds.is_file():
            return ExecutorAvailability(
                available=False,
                reason=(
                    "Gemini CLI no tiene sesión iniciada: no existe "
                    f"`~/.gemini/oauth_creds.json`. {_LOGIN_HINT}"
                ),
            )
        try:
            data = json.loads(creds.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = None
        if not isinstance(data, dict):
            return ExecutorAvailability(
                available=False,
                reason=(
                    "La sesión de Gemini CLI está corrupta: "
                    "`~/.gemini/oauth_creds.json` no es el JSON esperado. "
                    f"Vuelve a autenticarte. {_LOGIN_HINT}"
                ),
            )
        refresh_token = data.get("refresh_token")
        if isinstance(refresh_token, str) and refresh_token:
            # El CLI renueva el access token con el refresh_token; el volumen
            # forensia-cli-auth es escribible, así que el refresh persiste.
            return ExecutorAvailability(available=True)
        access_token = data.get("access_token")
        try:
            expiry_ms = int(data.get("expiry_date") or 0)
        except (TypeError, ValueError):
            expiry_ms = 0
        if isinstance(access_token, str) and access_token and expiry_ms > time.time() * 1000:
            return ExecutorAvailability(available=True)
        return ExecutorAvailability(
            available=False,
            reason=(
                "La sesión de Gemini CLI ha caducado (sin refresh_token y con el "
                f"access_token expirado). Vuelve a autenticarte. {_LOGIN_HINT}"
            ),
        )

    def _build_argv(self, prompt: str, model: str | None) -> list[str]:
        argv = ["gemini", "-p", prompt]
        if model:
            # `-m/--model` — verified in `gemini --help`. Uses the OAuth session,
            # no API key (SECURITY INVARIANT 7).
            argv += ["--model", model]
        argv += ["--output-format", "json"]
        return argv

    def _extract_text(self, stdout: str) -> str:
        try:
            envelope = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise ExecutorError(
                "Gemini CLI no devolvió el JSON esperado con --output-format json. "
                f"stdout (muestra): {stdout.strip()[:500]!r}"
            ) from exc
        if not isinstance(envelope, dict):
            raise ExecutorError(
                f"Gemini CLI devolvió {type(envelope).__name__} en vez de un objeto JSON"
            )
        error = envelope.get("error")
        if error:
            raise ExecutorError(f"Gemini CLI reportó un error: {json.dumps(error)[:500]}")
        response = envelope.get("response")
        if not isinstance(response, str):
            raise ExecutorError(
                "la respuesta JSON de Gemini CLI no contiene el campo 'response' de texto"
            )
        return response

    def _extract_usage(self, raw: str) -> Usage | None:
        # The exact shape of Gemini CLI's `stats` block is version-dependent, so
        # instead of guessing a path we search it for the CANONICAL GenAI
        # usageMetadata field names (stable across the API). Not found → None,
        # never a wrong number (Bug 008 Nivel 0, RULE 2).
        try:
            envelope = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(envelope, dict):
            return None
        stats = envelope.get("stats")
        scope = stats if isinstance(stats, dict) else envelope
        prompt = _find_key(scope, "promptTokenCount")
        candidates = _find_key(scope, "candidatesTokenCount")
        if prompt is None and candidates is None:
            return None
        u = Usage(
            input_tokens=_as_int(prompt),
            output_tokens=_as_int(candidates),
            source="gemini.stats",
        )
        return u if (u.input_tokens or u.output_tokens) is not None else None
