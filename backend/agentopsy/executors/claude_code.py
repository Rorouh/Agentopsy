"""Claude Code executor — ``claude -p <prompt> --output-format json``.

Flags verified against the official docs (code.claude.com/docs/en/headless,
2026-07-02):
- ``-p`` / ``--print`` runs non-interactively; the prompt is the positional arg.
- ``--output-format json`` returns one JSON object with the text in ``result``
  plus session metadata (``session_id``, ``is_error``, ``total_cost_usd``).
- ``--bare`` is deliberately NOT used: bare mode skips the OAuth reads and
  demands an Anthropic API key via environment — exactly what this project
  forbids (SECURITY INVARIANT 7).

Auth: the session lives in the ``agentopsy-cli-auth`` volume (the container's
HOME) — seeded from the host or created with ``claude auth login`` inside the
container. The availability check runs ``claude auth status``, documented at
code.claude.com/docs/en/cli-reference (verified 2026-07-03): "Show
authentication status as JSON. Exits with code 0 if logged in, 1 if not". On
macOS hosts there is nothing useful to seed (the OAuth token lives in the
Keychain), so in-container login is the documented path.

Fase 4 (2026-07-30) — the CLI's own harness is stripped: Agentopsy is not a
coding session, so the Claude Code default system prompt (6.602 tokens
measured) and the built-in tool schemas (7.114 tokens) are pure noise that
also CONTRADICTS the strict JSON contract the prompt carries. Every call now
passes ``--tools ""`` (no built-in tools: the schemas leave the harness and the
CLI can no longer append ``tool_use`` turns Agentopsy never wrote — the
``session_guard`` divergence measured on 2026-07-29 becomes structurally
impossible), ``--setting-sources ""`` (no user/project settings: a CLAUDE.md or
skill in the volume's ``~/.claude`` can never leak into the model's context),
and ``--system-prompt`` with Agentopsy's own minimal identity (the behavioral
contract keeps travelling in the prompt itself — ``agentes/agent.md`` stays the
ONE behavioral file). Verified against ``claude`` 2.1.220 on 2026-07-30: a
call that carried ~13.900 harness tokens enters with 202 input tokens, the
flags are compatible with ``--resume`` (same ``session_id``, ``num_turns=1``)
and the on-disk transcript holds only authored prompts + assistant text.
"""

from __future__ import annotations

import json

from agentopsy.i18n import Mensaje, t
from agentopsy.executors.base import (
    CliPromptExecutor,
    ExecutorAvailability,
    ExecutorError,
    Usage,
    _as_float,
    _as_int,
)

# El system prompt MÍNIMO que sustituye al arnés de Claude Code (Fase 4). La
# conducta real del agente viaja en el prompt (bloque SISTEMA, renderizado de
# `agentes/agent.md` — el ÚNICO fichero de conducta); esto solo fija la
# identidad y remite al contrato. Estable a propósito: cambia el prefijo de
# caché de TODAS las sesiones si se toca.
def _system_prompt() -> str:
    """La identidad mínima con la que Agentopsy sustituye el prompt del CLI.

    Va en el idioma del agente: es lo primero que el modelo lee y contradecirlo
    con una lengua distinta a la del resto del prompt no ayuda a nadie.
    """
    return t("claude.systemPrompt")

def _login_hint() -> str:
    """El comando de login, en el idioma en curso (clave `claude.loginHint`)."""
    return t("claude.loginHint")

#: Marcas de un fallo de AUTENTICACIÓN en el mensaje que devuelve el propio CLI.
#: Se usan junto al `api_error_status`, no en su lugar: el estado HTTP es la señal
#: fuerte y el texto cubre los casos en que el envoltorio no lo trae.
_AUTH_ERROR_MARKERS = (
    "oauth",
    "authenticate",
    "authentication",
    "unauthorized",
    "expired",
    "invalid api key",
)

def _expired_session_hint() -> str:
    return t("claude.expiredHint", hint=_login_hint())


def _is_auth_failure(message: str, status: int | None) -> bool:
    """¿El fallo que reporta el CLI es de autenticación? El 401/403 manda; si el
    envoltorio no trae estado, se mira el texto del propio CLI."""
    if status in (401, 403):
        return True
    low = message.lower()
    return any(marker in low for marker in _AUTH_ERROR_MARKERS)


class ClaudeCodeExecutor(CliPromptExecutor):
    id = "claude-code"
    name = "Claude Code"
    is_local = False
    binary = "claude"
    # Verified against the real CLI on 2026-07-29, not inferred from `--help`:
    # `--resume <id>` continues the conversation, returns the SAME session id, and
    # keeps the cached prefix (see `_build_argv`). The guard that decides whether a
    # given session may actually receive a delta lives in
    # `agentopsy.executors.session_guard` — this flag only says the mechanism exists.
    supports_session_resume = True

    def _check_auth(self) -> ExecutorAvailability:
        logged_in, detail = self._probe_auth_command(["claude", "auth", "status"])
        if logged_in:
            return ExecutorAvailability(available=True)
        reason = t("claude.noSession", hint=_login_hint())
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
        # Fase 4 — sin arnés de Claude Code (ver el docstring del módulo). Los
        # tres flags van TAMBIÉN en los `--resume` (verificado 2026-07-30: mismo
        # session_id, num_turns=1); el string idéntico en cada llamada mantiene
        # el prefijo cacheable estable.
        argv += [
            "--tools", "",
            "--setting-sources", "",
            "--system-prompt", _system_prompt(),
        ]
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
                Mensaje("claude.noJson", sample=repr(stdout.strip()[:500]))
            ) from exc
        if not isinstance(envelope, dict):
            raise ExecutorError(
                Mensaje("claude.notAnObject", kind=type(envelope).__name__)
            )
        if envelope.get("is_error"):
            detail = self._envelope_error(envelope)
            raise ExecutorError(
                Mensaje(
                    "claude.isError",
                    detail=detail or str(envelope.get("result"))[:500],
                )
            )
        result = envelope.get("result")
        if not isinstance(result, str):
            raise ExecutorError(
                "la respuesta JSON de Claude Code no contiene el campo 'result' de texto"
            )
        return result

    def _envelope_error(self, envelope: dict) -> str | None:
        """Causa legible a partir del envoltorio JSON, con el comando de login
        cuando el fallo es de autenticación. Devuelve ``None`` si el envoltorio no
        dice nada aprovechable (nunca inventa un motivo, RULE 2)."""
        result = envelope.get("result")
        message = result.strip() if isinstance(result, str) and result.strip() else ""
        status = _as_int(envelope.get("api_error_status"))
        if not message and status is None:
            return None
        if not message:
            message = t("claude.apiStatus", status=status)
        elif status is not None:
            message = f"{message} (api_error_status={status})"
        if _is_auth_failure(message, status):
            return f"{message[:800]} {_expired_session_hint()}"
        return message[:1200]

    def _extract_error(self, stdout: str, stderr: str) -> str | None:
        """Motivo ACCIONABLE cuando el CLI sale con código distinto de cero.

        Medido en vivo el 2026-08-05 (`claude` 2.1.187): con la sesión OAuth
        caducada la corrida falla dejando la causa en STDOUT
        (``{"is_error":true,"api_error_status":401,"result":"Failed to
        authenticate. API Error: 401 OAuth access token has expired…"}``) y el
        stderr VACÍO. Sin este hook el perito solo veía ``stderr: (vacío)``, que
        no dice qué arreglar. Y no basta con mirar la disponibilidad antes de
        lanzar: `claude auth status` devuelve exit 0 y ``loggedIn: true`` con el
        token ya muerto, así que la corrida es donde aparece la verdad y es ahí
        donde hay que nombrar el comando de login (RULE 2: fallar alto con la
        causa REAL, no con un arenque rojo).
        """
        try:
            envelope = json.loads(stdout)
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(envelope, dict):
            return None
        return self._envelope_error(envelope)

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
        delta must not be sent into it — see ``agentopsy.executors.session_guard``.
        """
        try:
            envelope = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(envelope, dict):
            return None
        return _as_int(envelope.get("num_turns"))
