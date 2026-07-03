"""Codex CLI executor — ``codex exec <prompt>`` in non-interactive mode.

Flags verified against the official docs (developers.openai.com/codex/cli/reference,
2026-07-02):
- ``codex exec "<prompt>"`` runs one non-interactive turn; the prompt is the
  final positional argument.
- ``--skip-git-repo-check`` allows running outside a Git repository (the api
  container's workdir is not a repo).
- ``--sandbox read-only`` pins the strictest sandbox: FORENSIA uses the CLI as a
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

import os
import tempfile
from typing import Any

from forensia.executors.base import (
    CliPromptExecutor,
    ExecutorAvailability,
    ExecutorError,
    ExecutorResult,
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

    def _build_argv(self, prompt: str) -> list[str]:
        # self._last_message_path is set per-run in run() below.
        return [
            "codex",
            "exec",
            "--skip-git-repo-check",
            "--sandbox",
            "read-only",
            "--output-last-message",
            str(self._last_message_path),
            prompt,
        ]

    def _extract_text(self, stdout: str) -> str:
        path = self._last_message_path
        if path is None or not os.path.exists(path):
            raise ExecutorError(
                "Codex CLI no escribió el fichero de --output-last-message; "
                f"stdout (muestra): {stdout.strip()[:500]!r}"
            )
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()

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
