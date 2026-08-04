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

Model and reasoning level (2026-07-30): both are the OPERATOR's choice and both
are read from the CLI's OWN catalog — see ``read_model_catalog``.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from forensia.executors.base import (
    CliPromptExecutor,
    ExecutorAvailability,
    ExecutorError,
    ExecutorResult,
    Usage,
    _as_int,
    _find_key,
    validate_model_id,
)

# --- Catálogo de modelos y niveles de razonamiento (2026-07-30) --------------
# El CLI cachea en ``CODEX_HOME/models_cache.json`` el catálogo que descarga CON
# LA SESIÓN OAuth del operador — sin API key (SECURITY INVARIANT 7). Es la ÚNICA
# fuente que usa Agentopsy: una lista escrita a mano quedaría obsoleta en cuanto
# OpenAI publicara un modelo, y ofrecer un id que el CLI no acepta es
# exactamente el tipo de valor inventado que prohíbe RULE 2. Si el fichero no
# está (el CLI aún no ha corrido ningún turno) o cambia de forma, el catálogo
# queda VACÍO con la razón viajando en ``note`` — nunca se sustituye por una
# lista de respaldo — y el operador siempre puede escribir el id a mano.
_MODELS_CACHE = "models_cache.json"

# ``visibility`` del propio catálogo: "list" = elegible por el usuario. El CLI
# marca "hide" los modelos internos (p. ej. ``codex-auto-review``), que no se
# ofrecen porque no son para conversar.
_VISIBILITY_LISTED = "list"

# El nivel de razonamiento («potencia») NO tiene flag propio en `codex exec`: se
# pasa como override de configuración `-c clave=valor`. Verificado contra
# codex-cli 0.146.0 (la cabecera del run imprime `reasoning effort: ultra`).
_REASONING_KEY = "model_reasoning_effort"

# El valor acaba DENTRO de un único elemento de argv (`model_reasoning_effort="x"`)
# que el CLI parsea como TOML. Charset cerrado a minúsculas para que no pueda
# cerrar la cadena ni colar otra clave de configuración (SECURITY INVARIANT 5).
_EFFORT_RE = re.compile(r"^[a-z]{1,16}$")

_LOGIN_HINT = (
    "Inicia sesión UNA VEZ dentro del contenedor: "
    "`docker compose exec -it api codex login --device-auth` (flujo device-code "
    "para entornos sin navegador; si el CLI lo rechaza, actívalo en los ajustes "
    "de seguridad de tu cuenta ChatGPT). La sesión persiste en el volumen "
    "forensia-cli-auth; se revoca con `docker compose down -v`. Si ejecutas el "
    "backend fuera del compose, ejecuta `codex login` en esa máquina."
)


@dataclass(frozen=True)
class CodexModel:
    """Un modelo del catálogo del CLI, con los niveles de razonamiento que ese
    modelo admite (no todos admiten los mismos: ``ultra`` solo existe en la
    generación 5.6, y pedirlo a un modelo que no lo soporta es un 400 del
    servidor de OpenAI — verificado en vivo 2026-07-30)."""

    slug: str
    label: str
    description: str
    default_effort: str | None
    efforts: tuple[tuple[str, str], ...]  # (nivel, descripción del catálogo)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.slug,
            "label": self.label,
            "description": self.description,
            "default_effort": self.default_effort,
            "efforts": [{"id": eff, "description": desc} for eff, desc in self.efforts],
        }


def codex_home() -> Path:
    """``CODEX_HOME`` real del CLI (en el compose, el volumen forensia-cli-auth)."""
    raw = os.environ.get("CODEX_HOME", "").strip()
    return Path(raw) if raw else Path.home() / ".codex"


def read_model_catalog() -> tuple[list[CodexModel], str | None]:
    """``(modelos, razón)`` leídos del caché del PROPIO CLI. Nunca lanza.

    Una lista vacía SIEMPRE viaja con la razón concreta (fichero ausente,
    ilegible o con otra forma) para que la superficie degrade explicándolo en
    vez de mostrar un desplegable vacío sin explicación (RULE 2).
    """
    path = codex_home() / _MODELS_CACHE
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [], (
            f"El CLI de Codex todavía no ha cacheado su catálogo en {path}: lo "
            "descarga con la sesión del operador al ejecutar su primer turno. "
            "Lanza una consulta con Codex y vuelve a abrir este selector."
        )
    except (OSError, json.JSONDecodeError) as exc:
        return [], f"No se pudo leer el catálogo de modelos de Codex ({path}): {exc}"

    entries = raw.get("models") if isinstance(raw, dict) else None
    if not isinstance(entries, list):
        return [], (
            f"{path} no tiene la forma esperada (falta la lista 'models'): el CLI "
            "puede haber cambiado el formato de su caché. Escribe el id del modelo "
            "a mano; Agentopsy no sustituye el catálogo por una lista propia."
        )

    models: list[CodexModel] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        slug = entry.get("slug")
        if not isinstance(slug, str) or not slug.strip():
            continue
        if entry.get("visibility") != _VISIBILITY_LISTED:
            continue
        try:
            # El id acabará siendo un elemento de argv: si no pasa la misma
            # puerta que un id escrito a mano, no se ofrece (SECURITY 5).
            validate_model_id(slug)
        except ExecutorError:
            continue
        efforts: list[tuple[str, str]] = []
        for level in entry.get("supported_reasoning_levels") or []:
            if not isinstance(level, dict):
                continue
            effort = level.get("effort")
            if isinstance(effort, str) and _EFFORT_RE.match(effort):
                efforts.append((effort, str(level.get("description") or "")))
        default_effort = entry.get("default_reasoning_level")
        models.append(
            CodexModel(
                slug=slug,
                label=str(entry.get("display_name") or slug),
                description=str(entry.get("description") or ""),
                default_effort=(
                    default_effort if isinstance(default_effort, str) else None
                ),
                efforts=tuple(efforts),
            )
        )

    if not models:
        return [], (
            f"{path} no lista ningún modelo elegible. Escribe el id a mano; "
            "Agentopsy no inventa un catálogo (RULE 2)."
        )
    return models, None


def validate_reasoning_effort(effort: str) -> str:
    """Devuelve ``effort`` si es un nivel con forma válida, o lanza.

    Puerta de FORMA (SECURITY INVARIANT 5), no de catálogo: qué niveles admite
    cada modelo lo dice ``read_model_catalog`` y lo comprueba el ejecutor justo
    antes de lanzar el proceso.
    """
    if not isinstance(effort, str) or not _EFFORT_RE.match(effort):
        raise ExecutorError(
            f"nivel de razonamiento inválido {effort!r}: solo minúsculas "
            "(low, medium, high, xhigh, max, ultra…), máximo 16 caracteres."
        )
    return effort


def supported_efforts(model: str | None) -> tuple[list[str], str | None]:
    """``(niveles, default)`` que el catálogo declara para ``model``.

    Modelo desconocido o catálogo ilegible → ``([], None)``: no se sabe, así que
    nadie decide por el operador (la llamada al CLI dirá la verdad).
    """
    if not model:
        return [], None
    catalog, _ = read_model_catalog()
    for entry in catalog:
        if entry.slug == model:
            return [eff for eff, _desc in entry.efforts], entry.default_effort
    return [], None


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
        # Nivel de razonamiento del turno en curso. Mismo patrón que
        # `_last_message_path`: lo fija `run()` y lo lee `_build_argv`, que es
        # un hook de firma fija compartido por los tres CLIs.
        self._reasoning_effort: str | None = None

    def suggested_models(self) -> list[str]:
        """Los modelos REALES que el CLI declara en su caché — no atajos.

        A diferencia de los otros CLIs cloud, aquí no hace falta una API key
        para enumerar: el propio ``codex`` descarga el catálogo con la sesión
        OAuth del operador y lo deja en ``CODEX_HOME`` (SECURITY INVARIANT 7).
        """
        catalog, _ = read_model_catalog()
        return [entry.slug for entry in catalog]

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
        if self._reasoning_effort:
            # La «potencia» del modelo. No hay flag dedicado: se sobreescribe la
            # clave de configuración, y el valor va ENTRECOMILLADO porque el CLI
            # parsea esa porción como TOML (`codex exec --help`). Sin este
            # override manda lo que diga el config.toml del volumen — que es el
            # default del CLI, no una decisión de Agentopsy (RULE 2).
            argv += ["-c", f'{_REASONING_KEY}="{self._reasoning_effort}"']
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
        ctx = context or {}
        # Nivel de razonamiento elegido por el operador (opcional). Ausente → el
        # que tenga configurado el CLI; Agentopsy no lo inventa (RULE 2).
        effort = ctx.get("reasoning_effort")
        if isinstance(effort, str):
            effort = effort.strip() or None
        elif effort is not None:
            raise ExecutorError(
                "'reasoning_effort' del contexto debe ser str o None, no "
                f"{type(effort).__name__}"
            )
        if effort is not None:
            validate_reasoning_effort(effort)
            self._reject_unsupported_effort(ctx.get("model"), effort)

        # Private temp file for the final message; the literal argv recorded in
        # the audit log includes this exact path.
        fd, path = tempfile.mkstemp(prefix="forensia-codex-", suffix=".md")
        os.close(fd)
        self._last_message_path = path
        self._reasoning_effort = effort
        try:
            return super().run(prompt, context)
        finally:
            self._last_message_path = None
            self._reasoning_effort = None
            try:
                os.unlink(path)
            except OSError:
                pass

    def _reject_unsupported_effort(self, model: Any, effort: str) -> None:
        """Corta ANTES de lanzar el proceso un par (modelo, nivel) que el
        catálogo declara imposible.

        Sin esta puerta el turno sale, viaja el prompt entero y vuelve un 400
        ``unsupported_value`` del servidor (verificado en vivo 2026-07-30 con
        ``gpt-5.5`` + ``ultra``): se paga el turno para nada. Cuando el modelo no
        está fijado, o el catálogo no se puede leer, NO se decide aquí — la
        llamada al CLI dirá la verdad (RULE 2: no se adivina).
        """
        if not isinstance(model, str) or not model.strip():
            return
        allowed, _default = supported_efforts(model.strip())
        if not allowed or effort in allowed:
            return
        raise ExecutorError(
            f"el modelo {model.strip()!r} no admite el nivel de razonamiento "
            f"{effort!r}. Admite: {', '.join(allowed)}. Cámbialo en "
            "Configuración → Ejecutores/IA (Agentopsy no lo degrada solo)."
        )
