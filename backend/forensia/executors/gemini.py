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

from forensia.i18n import Mensaje, t
from forensia.executors.base import (
    CliPromptExecutor,
    ExecutorAvailability,
    ExecutorError,
    Usage,
    _as_int,
    _find_key,
)

def _login_hint() -> str:
    """El comando de login, en el idioma en curso (clave `gemini.loginHint`)."""
    return t("gemini.loginHint")


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
                reason=t("gemini.noSession", hint=_login_hint()),
            )
        try:
            data = json.loads(creds.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = None
        if not isinstance(data, dict):
            return ExecutorAvailability(
                available=False,
                reason=t("gemini.corruptSession", hint=_login_hint()),
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
            reason=t("gemini.expiredSession", hint=_login_hint()),
        )

    def _build_argv(
        self, prompt: str, model: str | None, session_id: str | None = None
    ) -> list[str]:
        # `session_id` is always None here: this executor leaves
        # `supports_session_resume` at False, so `CliPromptExecutor.run` refuses a
        # session id before it ever reaches this method. Gemini CLI's
        # checkpointing has not been verified against the real binary, and
        # Agentopsy does not send deltas into a session it cannot account for —
        # see plan.md Fase 5.
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
                Mensaje("gemini.noJson", sample=repr(stdout.strip()[:500]))
            ) from exc
        if not isinstance(envelope, dict):
            raise ExecutorError(
                Mensaje("gemini.notAnObject", kind=type(envelope).__name__)
            )
        error = envelope.get("error")
        if error:
            raise ExecutorError(
                Mensaje("gemini.reportedError", detail=json.dumps(error)[:500])
            )
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
        # No cache fields ON PURPOSE (2026-07-29). In the GenAI usageMetadata
        # contract `promptTokenCount` is the FULL prompt and `cachedContentTokenCount`
        # is a subset of it — the opposite convention to Anthropic's, where
        # `input_tokens` excludes the cached bytes and they are separate addends.
        # Mapping the cached count onto `Usage.cache_*` would therefore make
        # `total_input_tokens` double-count. Left None so `total_input_tokens`
        # resolves to `promptTokenCount`, the correct total here.
        u = Usage(
            input_tokens=_as_int(prompt),
            output_tokens=_as_int(candidates),
            source="gemini.stats",
        )
        return u if (u.input_tokens or u.output_tokens) is not None else None
