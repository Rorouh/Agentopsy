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
    # Verified against the real CLI on 2026-07-29, not inferred from `--help`:
    # `--resume <id>` continues the conversation, returns the SAME session id, and
    # keeps the cached prefix (see `_build_argv`). The guard that decides whether a
    # given session may actually receive a delta lives in
    # `forensia.executors.session_guard` — this flag only says the mechanism exists.
    supports_session_resume = True

    def _check_auth(self) -> ExecutorAvailability:
        logged_in, detail = self._probe_auth_command(["claude", "auth", "status"])
        if logged_in:
            return ExecutorAvailability(available=True)
        reason = f"Claude Code no tiene sesión iniciada. {_LOGIN_HINT}"
        if detail:
            reason += f" (detalle de `claude auth status`: {detail})"
        return ExecutorAvailability(available=False, reason=reason)

    def _build_argv(
        self, prompt: str, model: str | None, session_id: str | None = None
    ) -> list[str]:
        argv = ["claude", "-p", prompt]
        if model:
            # `--model` accepts an alias ('opus', 'sonnet', 'haiku', 'fable') or a
            # full name ('claude-fable-5') — verified in `claude --help`. It does
            # NOT introduce an API key (the session stays OAuth in the volume), so
            # SECURITY INVARIANT 7 holds.
            argv += ["--model", model]
        if session_id:
            # Continue the CLI's own conversation instead of re-sending the whole
            # transcript. Verified 2026-07-29 (`claude` 2.1.220): the session keeps
            # the SAME id across resumes, the CLI does not re-send its system
            # prompt, and `cache_read` grows turn after turn while
            # `cache_creation` collapses to the delta. Uses the same OAuth session
            # in the auth volume — no API key is involved (SECURITY INVARIANT 7).
            argv += ["--resume", session_id]
        argv += ["--output-format", "json"]
        return argv

    def suggested_models(self) -> list[str]:
        # Aliases `claude --help` documents (stable); the operator may also type a
        # full name. Not a live catalog — that would need an API key (SECURITY 7).
        return ["opus", "sonnet", "haiku"]

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
        # output_tokens, cache_creation_input_tokens, cache_read_input_tokens}`
        # and `total_cost_usd`. The two cache fields are what make the real
        # prompt size visible: `input_tokens` alone is only the UNCACHED
        # remainder (see `Usage.total_input_tokens`). Defensive: any
        # missing/renamed field degrades to None rather than a wrong number
        # (Bug 008 Nivel 0).
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
            cache_creation_input_tokens=_as_int(usage.get("cache_creation_input_tokens")),
            cache_read_input_tokens=_as_int(usage.get("cache_read_input_tokens")),
            cost_usd=_as_float(cost),
            source="claude_code.usage",
        )
        reported = (
            u.total_input_tokens is not None
            or u.output_tokens is not None
            or u.cost_usd is not None
        )
        return u if reported else None

    def _extract_session_id(self, raw: str) -> str | None:
        """The CLI's own conversation id from the JSON envelope, or ``None``.

        Verified 2026-07-29 against `claude` 2.1.220: the id is STABLE across
        ``--resume`` (the same session keeps the same id turn after turn), which
        is what lets ``ExecutorBackend`` carry it forward. Never raises: an
        unparseable envelope simply means "no session to reuse", and the caller
        then sends full context (RULE 2 — a fallback of CONTENT, never a delta
        into a session we cannot name).
        """
        try:
            envelope = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(envelope, dict):
            return None
        sid = envelope.get("session_id")
        return sid if isinstance(sid, str) and sid.strip() else None

    def _extract_turn_count(self, raw: str) -> int | None:
        """``num_turns`` from the envelope — how many turns the CLI actually put
        into the session for this ONE call, or ``None`` if not reported.

        Agentopsy authors exactly one turn per call. A value > 1 means the CLI
        appended turns of its own (verified 2026-07-29: with a tool enabled the
        session gained ``tool_use``/``tool_result`` pairs Agentopsy never wrote),
        so the session no longer matches Agentopsy's canonical message list and a
        delta must not be sent into it — see ``forensia.executors.session_guard``.
        """
        try:
            envelope = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(envelope, dict):
            return None
        return _as_int(envelope.get("num_turns"))
