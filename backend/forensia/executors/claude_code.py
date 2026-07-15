"""Claude Code executor — ``claude -p <prompt> --output-format json``.

Flags verified against the official docs (code.claude.com/docs/en/headless,
2026-07-02):
- ``-p`` / ``--print`` runs non-interactively; the prompt is the positional arg.
- ``--output-format json`` returns one JSON object with the text in ``result``
  plus session metadata (``session_id``, ``is_error``, ``total_cost_usd``).
- ``--bare`` is deliberately NOT used: bare mode skips the OAuth reads and
  demands an Anthropic API key via environment — exactly what this project
  forbids (SECURITY INVARIANT 7).

Auth: the session lives in the ``forensia-cli-auth`` volume (the container's
HOME) — seeded from the host or created with ``claude auth login`` inside the
container. The availability check runs ``claude auth status``, documented at
code.claude.com/docs/en/cli-reference (verified 2026-07-03): "Show
authentication status as JSON. Exits with code 0 if logged in, 1 if not". On
macOS hosts there is nothing useful to seed (the OAuth token lives in the
Keychain), so in-container login is the documented path.
"""

from __future__ import annotations

import json

from forensia.executors.base import (
    CliPromptExecutor,
    ExecutorAvailability,
    ExecutorError,
    Usage,
    _as_float,
    _as_int,
)

_LOGIN_HINT = (
    "Inicia sesión UNA VEZ dentro del contenedor: "
    "`docker compose exec -it api claude auth login` (la sesión persiste en el "
    "volumen forensia-cli-auth; se revoca con `docker compose down -v`). Si "
    "ejecutas el backend fuera del compose, ejecuta `claude auth login` en esa "
    "máquina."
)


class ClaudeCodeExecutor(CliPromptExecutor):
    id = "claude-code"
    name = "Claude Code"
    is_local = False
    binary = "claude"

    def _check_auth(self) -> ExecutorAvailability:
        logged_in, detail = self._probe_auth_command(["claude", "auth", "status"])
        if logged_in:
            return ExecutorAvailability(available=True)
        reason = f"Claude Code no tiene sesión iniciada. {_LOGIN_HINT}"
        if detail:
            reason += f" (detalle de `claude auth status`: {detail})"
        return ExecutorAvailability(available=False, reason=reason)

    def _build_argv(self, prompt: str) -> list[str]:
        return ["claude", "-p", prompt, "--output-format", "json"]

    def _extract_text(self, stdout: str) -> str:
        try:
            envelope = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise ExecutorError(
                "Claude Code no devolvió el JSON esperado con --output-format json. "
                f"stdout (muestra): {stdout.strip()[:500]!r}"
            ) from exc
        if not isinstance(envelope, dict):
            raise ExecutorError(
                f"Claude Code devolvió {type(envelope).__name__} en vez de un objeto JSON"
            )
        if envelope.get("is_error"):
            raise ExecutorError(
                f"Claude Code reportó is_error=true: {str(envelope.get('result'))[:500]}"
            )
        result = envelope.get("result")
        if not isinstance(result, str):
            raise ExecutorError(
                "la respuesta JSON de Claude Code no contiene el campo 'result' de texto"
            )
        return result

    def _extract_usage(self, raw: str) -> Usage | None:
        # `claude -p --output-format json` carries `usage.{input_tokens,
        # output_tokens}` and `total_cost_usd`. Defensive: any missing/renamed
        # field degrades to None rather than a wrong number (Bug 008 Nivel 0).
        try:
            envelope = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(envelope, dict):
            return None
        usage = envelope.get("usage")
        usage = usage if isinstance(usage, dict) else {}
        cost = envelope.get("total_cost_usd")
        u = Usage(
            input_tokens=_as_int(usage.get("input_tokens")),
            output_tokens=_as_int(usage.get("output_tokens")),
            cost_usd=_as_float(cost),
            source="claude_code.usage",
        )
        return u if (u.input_tokens or u.output_tokens or u.cost_usd) is not None else None
