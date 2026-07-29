"""Codex CLI executor — ``codex exec <prompt>`` in non-interactive mode.

Flags verified against the official docs (developers.openai.com/codex/cli/reference,
2026-07-02):
- ``codex exec "<prompt>"`` runs one non-interactive turn; the prompt is the
  final positional argument.
- ``--skip-git-repo-check`` allows running outside a Git repository (the api
  container's workdir is not a repo).
- ``--sandbox read-only`` pins the strictest sandbox: Agentopsy uses the CLI as a
  pure LLM — its own agentic writes are unwanted.
- ``--output-last-message <path>`` writes the assistant's FINAL message to a
  file. This is the documented stable way to capture the answer; ``--json``
  emits an experimental JSONL event stream we deliberately do not depend on.

Auth: the session (``~/.codex/auth.json``) lives in the ``forensia-cli-auth``
volume — seeded from the host or created with ``codex login --device-auth``
inside the container ("Use OAuth device code flow instead of launching a
browser window", developers.openai.com/codex/cli/reference, verified
2026-07-03). The availability check runs ``codex login status``: "Print the
active authentication mode and exit with 0 when logged in" (same reference).
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any

from forensia.executors.base import (
    CliPromptExecutor,
    ExecutorAvailability,
    ExecutorError,
    ExecutorResult,
    Usage,
    _as_int,
    _find_key,
)

_LOGIN_HINT = (
    "Inicia sesión UNA VEZ dentro del contenedor: "
    "`docker compose exec -it api codex login --device-auth` (flujo device-code "
    "para entornos sin navegador; si el CLI lo rechaza, actívalo en los ajustes "
    "de seguridad de tu cuenta ChatGPT). La sesión persiste en el volumen "
    "forensia-cli-auth; se revoca con `docker compose down -v`. Si ejecutas el "
    "backend fuera del compose, ejecuta `codex login` en esa máquina."
)


class CodexExecutor(CliPromptExecutor):
    id = "codex"
    name = "Codex CLI"
    is_local = False
    binary = "codex"

    def _check_auth(self) -> ExecutorAvailability:
        logged_in, detail = self._probe_auth_command(["codex", "login", "status"])
        if logged_in:
            return ExecutorAvailability(available=True)
        reason = f"Codex CLI no tiene sesión iniciada. {_LOGIN_HINT}"
        if detail:
            reason += f" (detalle de `codex login status`: {detail})"
        return ExecutorAvailability(available=False, reason=reason)

    def __init__(self) -> None:
        self._last_message_path: str | None = None

    def _build_argv(
        self, prompt: str, model: str | None, session_id: str | None = None
    ) -> list[str]:
        # `session_id` is always None here: this executor leaves
        # `supports_session_resume` at False, so `CliPromptExecutor.run` refuses a
        # session id before it ever reaches this method. Codex does document a
        # `codex exec resume`, but its behaviour (id stability, whether the CLI
        # appends turns of its own, whether it compacts) has NOT been verified
        # against the real binary, and Agentopsy does not send deltas into a
        # session it cannot account for — see plan.md Fase 5.
        # self._last_message_path is set per-run in run() below.
        # `--json` and `--output-last-message` are ORTHOGONAL: the final text still
        # goes to the file (text extraction unchanged); `--json` only turns stdout
        # into a JSONL event stream, which is where Codex reports token usage
        # (Bug 008 Nivel 0). If a Codex version ever stopped honouring the file
        # under --json, `_extract_text` fails loud (RULE 2), never silently wrong.
        argv = [
            "codex",
            "exec",
            "--json",
            "--skip-git-repo-check",
            "--sandbox",
            "read-only",
            "--output-last-message",
            str(self._last_message_path),
        ]
        if model:
            # `-m/--model` — verified in `codex exec --help`. Uses the OAuth
            # session, no API key (SECURITY INVARIANT 7).
            argv += ["--model", model]
        argv.append(prompt)
        return argv

    def _extract_text(self, stdout: str) -> str:
        path = self._last_message_path
        if path is None or not os.path.exists(path):
            raise ExecutorError(
                "Codex CLI no escribió el fichero de --output-last-message; "
                f"stdout (muestra): {stdout.strip()[:500]!r}"
            )
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()

    def _extract_error(self, stdout: str, stderr: str) -> str | None:
        # A failed Codex turn is reported as a JSONL event on STDOUT:
        # {"type":"error","message":"…"} (usage limit, auth, sandbox denial, …). The
        # stderr only carries "Reading additional input from stdin..." — an
        # informational note from stdin=DEVNULL, NOT the cause (Bug 3: verified in vivo
        # 2026-07-17, codex-cli 0.142.5). Surface the LAST error message found so the
        # operator sees the real, actionable reason instead of the stdin red herring.
        message: str | None = None
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict) and event.get("type") == "error":
                candidate = event.get("message")
                if isinstance(candidate, str) and candidate.strip():
                    message = candidate.strip()
        return message

    def _extract_usage(self, raw: str) -> Usage | None:
        # stdout is a JSONL event stream (`--json`). Token counts appear in one or
        # more events; the LAST occurrence is the cumulative final. Defensive: each
        # line parsed in isolation, canonical keys searched at any depth, anything
        # unrecognised → None (never a number scraped from free text — RULE 2).
        input_tok: int | None = None
        output_tok: int | None = None
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            found_in = _find_key(event, "input_tokens")
            found_out = _find_key(event, "output_tokens")
            if found_in is not None:
                input_tok = _as_int(found_in) if _as_int(found_in) is not None else input_tok
            if found_out is not None:
                output_tok = _as_int(found_out) if _as_int(found_out) is not None else output_tok
        if input_tok is None and output_tok is None:
            return None
        # No cache fields ON PURPOSE (2026-07-29). Codex reports a prompt total in
        # `input_tokens`, with any cached portion a SUBSET of it — unlike Anthropic's
        # API, where `input_tokens` is only the uncached remainder and the cached
        # bytes are separate addends. Feeding a cached count into `Usage.cache_*`
        # here would make `total_input_tokens` double-count the prompt. Leaving them
        # None keeps `total_input_tokens == input_tokens`, which is the CORRECT total
        # for this executor. See `Usage.total_input_tokens`.
        return Usage(input_tokens=input_tok, output_tokens=output_tok, source="codex.json")

    def run(self, prompt: str, context: dict[str, Any] | None = None) -> ExecutorResult:
        # Private temp file for the final message; the literal argv recorded in
        # the audit log includes this exact path.
        fd, path = tempfile.mkstemp(prefix="forensia-codex-", suffix=".md")
        os.close(fd)
        self._last_message_path = path
        try:
            return super().run(prompt, context)
        finally:
            self._last_message_path = None
            try:
                os.unlink(path)
            except OSError:
                pass
