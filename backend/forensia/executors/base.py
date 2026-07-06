"""Execution layer contract: ``PromptExecutor``.

The 2026-07-02 pivot replaces the SDK-based model layer (``forensia.models.cloud``,
API keys) with four operator-selected executors — Claude Code (``claude -p``),
Codex CLI (``codex exec``), Gemini CLI (``gemini -p``) and Ollama (HTTP to the
compose service). The CLIs consume the USER's own subscription via the session
stored in the ``forensia-cli-auth`` volume (the ``api`` container's HOME):
seeded once from the host's credentials by the compose entrypoint, or created
by logging in inside the container. Token refresh happens in the volume, never
in the host's files; the project holds no API keys (SECURITY INVARIANT 7).

Contract:
- ``is_available()`` never raises: it returns an ``ExecutorAvailability`` whose
  ``reason`` is an ACTIONABLE Spanish sentence when unavailable (missing binary,
  no session — with the CONCRETE login command —, Ollama unreachable). It is a
  REAL check per CLI (auth-status command or credential-file validation), not a
  directory-existence guess: the E2E verification of 2026-07-02 proved the old
  check reported available executors that could not authenticate.
  ``/api/capabilities`` surfaces it and the UI degrades explicitly (RULE 2:
  never substitute). ``run()`` re-checks it and aborts fast before launching.
- ``run(prompt, context)`` executes ONE prompt and returns an ``ExecutorResult``.
  CLI executors run ``subprocess.run(argv, shell=False)`` — argv arrays only
  (SECURITY INVARIANT 4). When ``context`` carries an ``audit`` log, the run is
  recorded with the LITERAL argv (FORENSIC INVARIANT 4), never a paraphrase.
- Failures raise ``ExecutorError`` with the exact stderr — fail loud, no retries
  against another executor (RULE 2).
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from forensia.config import config

# Designed parameter default (allowed by RULE 2): one prompt round-trip on a
# healthy executor answers in seconds; a hung CLI must not block the operator
# for minutes (the 2026-07-02 E2E saw Gemini hang the old 600 s default).
# Override per request (``context['timeout']``) or per deployment with
# FORENSIA_EXECUTOR_TIMEOUT (env or Settings) — see ``resolve_timeout``.
DEFAULT_TIMEOUT_S = 120

# Budget for the NON-INTERACTIVE auth-status probes in ``is_available()``
# (`claude auth status` / `codex login status` spawn a CLI process).
AUTH_PROBE_TIMEOUT_S = 15


class ExecutorError(RuntimeError):
    """The executor could not produce a response (missing binary, non-zero exit,
    unparseable envelope, unreachable Ollama). The message carries the literal
    stderr / cause so the caller can surface it without guessing."""


@dataclass(frozen=True)
class ExecutorAvailability:
    available: bool
    reason: str | None = None  # actionable, Spanish, only when not available


@dataclass(frozen=True)
class ExecutorResult:
    executor: str                  # executor id ("claude-code" | "codex" | "gemini" | "ollama")
    text: str                      # the assistant's final text
    argv: tuple[str, ...] | None   # literal argv for CLI executors; None for HTTP (Ollama)
    exit_code: int | None          # CLI exit code; None for HTTP
    duration_ms: int
    raw: str                       # raw stdout / HTTP body the text was extracted from


class PromptExecutor(ABC):
    """One prompt in, one structured result out. Selected explicitly by the
    operator per request (RULE 2: there is no default executor)."""

    id: str            # closed-enum id the API accepts
    name: str          # human-readable label for the UI
    is_local: bool     # True only for Ollama — the 100% local option

    @abstractmethod
    def is_available(self) -> ExecutorAvailability: ...

    @abstractmethod
    def run(self, prompt: str, context: dict[str, Any] | None = None) -> ExecutorResult:
        """Execute ``prompt`` and return the structured result.

        ``context`` (optional, designed defaults) may carry:
        - ``audit``: an ``AuditLog`` — the run is recorded start/finish with the
          literal argv (or the HTTP request for Ollama).
        - ``case_id``: case the audit entries belong to.
        - ``timeout``: seconds (else FORENSIA_EXECUTOR_TIMEOUT, else
          ``DEFAULT_TIMEOUT_S`` — see ``resolve_timeout``).
        - ``model`` / ``temperature``: Ollama only (see ``OllamaExecutor``).
        """


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def resolve_timeout(context: dict[str, Any]) -> int:
    """Timeout in seconds for one executor run.

    Resolution order — every step operator-explicit, then the designed default
    (allowed by RULE 2): ``context['timeout']`` (caller) → FORENSIA_EXECUTOR_TIMEOUT
    (env / Settings via ``forensia.config``) → ``DEFAULT_TIMEOUT_S``.

    An UNPARSEABLE value fails loudly instead of silently reverting to the
    default (RULE 2: a typo in Settings must surface, not vanish).
    """
    raw = context.get("timeout")
    source = "context['timeout']"
    if raw is None:
        raw = config.get("FORENSIA_EXECUTOR_TIMEOUT")
        source = "FORENSIA_EXECUTOR_TIMEOUT"
    if raw is None:
        return DEFAULT_TIMEOUT_S
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = 0
    if value <= 0:
        raise ExecutorError(
            f"timeout de ejecutor inválido en {source}: {raw!r}. Debe ser un "
            "entero de segundos > 0 — FORENSIA no lo sustituye por el default "
            "(RULE 2)."
        )
    return value


class CliPromptExecutor(PromptExecutor):
    """Shared plumbing for the three CLI executors.

    Subclasses declare the binary, a REAL auth check (``_check_auth``) and how
    to build/parse the concrete invocation.
    """

    binary: str            # executable looked up on PATH (never a shell string)

    def is_available(self) -> ExecutorAvailability:
        if shutil.which(self.binary) is None:
            return ExecutorAvailability(
                available=False,
                reason=(
                    f"El CLI `{self.binary}` no está en el PATH del servicio api. "
                    "Reconstruye la imagen (`docker compose build api`): los tres "
                    "CLIs se instalan fijados por versión en docker/api/Dockerfile."
                ),
            )
        return self._check_auth()

    def _probe_auth_command(self, argv: list[str]) -> tuple[bool, str]:
        """Run the CLI's NON-INTERACTIVE auth-status command.

        Returns ``(logged_in, detail)`` and never raises: any failure mode
        (non-zero exit, timeout, unlaunchable binary) reads as "no session"
        with the CLI's own message as detail for the actionable reason.
        """
        try:
            proc = subprocess.run(  # noqa: S603 — argv array, shell=False by design
                argv,
                shell=False,
                capture_output=True,
                text=True,
                timeout=AUTH_PROBE_TIMEOUT_S,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            return False, f"`{' '.join(argv)}` no respondió en {AUTH_PROBE_TIMEOUT_S}s"
        except OSError as exc:
            return False, f"no se pudo ejecutar `{argv[0]}`: {exc}"
        if proc.returncode == 0:
            return True, ""
        detail = (proc.stderr or proc.stdout or "").strip()[:300]
        return False, detail or f"`{' '.join(argv)}` devolvió exit code {proc.returncode}"

    # ---- subclass hooks -----------------------------------------------------

    @abstractmethod
    def _check_auth(self) -> ExecutorAvailability:
        """REAL authentication check for this CLI (status command or credential
        file validation — see each subclass and the official doc it cites). The
        reason on failure names the CONCRETE login command."""

    @abstractmethod
    def _build_argv(self, prompt: str) -> list[str]:
        """Literal argv for one non-interactive run (verified against the
        official CLI docs — see each subclass)."""

    @abstractmethod
    def _extract_text(self, stdout: str) -> str:
        """Pull the assistant's final text out of the CLI's stdout envelope."""

    # ---- shared run ----------------------------------------------------------

    def run(self, prompt: str, context: dict[str, Any] | None = None) -> ExecutorResult:
        ctx = context or {}
        # Abort FAST with the actionable reason before launching anything: a
        # CLI without a session must not burn the run timeout hanging (the
        # 2026-07-02 E2E saw exactly that with Gemini + EROFS credentials).
        availability = self.is_available()
        if not availability.available:
            raise ExecutorError(availability.reason or f"{self.id} is not available")

        argv = self._build_argv(prompt)
        timeout = resolve_timeout(ctx)
        audit = ctx.get("audit")
        case_id = ctx.get("case_id")

        if audit is not None:
            # FORENSIC INVARIANT 4: the LITERAL argv (prompt included — it is
            # case-derived content and the audit log lives inside the case dir),
            # never the LLM's or the caller's paraphrase.
            audit.append(
                {
                    "action": "executor_run_start",
                    "executor": self.id,
                    "local": self.is_local,
                    "case_id": case_id,
                    "argv": argv,
                    "prompt_sha256": sha256_text(prompt),
                    "prompt_chars": len(prompt),
                }
            )

        started = time.monotonic()
        try:
            proc = subprocess.run(  # noqa: S603 — argv array, shell=False by design
                argv,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired as exc:
            self._audit_finish(audit, case_id, exit_code=None, duration_ms=_ms(started),
                               error=f"timeout tras {timeout}s")
            raise ExecutorError(
                f"{self.name} superó el timeout de {timeout}s sin responder"
            ) from exc
        except OSError as exc:
            self._audit_finish(audit, case_id, exit_code=None, duration_ms=_ms(started),
                               error=str(exc))
            raise ExecutorError(f"no se pudo ejecutar `{self.binary}`: {exc}") from exc

        duration_ms = _ms(started)

        if proc.returncode != 0:
            self._audit_finish(audit, case_id, exit_code=proc.returncode,
                               duration_ms=duration_ms, error=(proc.stderr or "")[:2000])
            raise ExecutorError(
                f"{self.name} terminó con exit code {proc.returncode}. "
                f"stderr: {(proc.stderr or '').strip()[:2000] or '(vacío)'}"
            )

        try:
            text = self._extract_text(proc.stdout or "")
        except ExecutorError:
            self._audit_finish(audit, case_id, exit_code=proc.returncode,
                               duration_ms=duration_ms, error="unparseable envelope")
            raise

        self._audit_finish(
            audit, case_id, exit_code=proc.returncode, duration_ms=duration_ms,
            response_sha256=sha256_text(text), response_chars=len(text),
        )
        return ExecutorResult(
            executor=self.id,
            text=text,
            argv=tuple(argv),
            exit_code=proc.returncode,
            duration_ms=duration_ms,
            raw=proc.stdout or "",
        )

    def _audit_finish(
        self,
        audit: Any,
        case_id: str | None,
        *,
        exit_code: int | None,
        duration_ms: int,
        response_sha256: str | None = None,
        response_chars: int | None = None,
        error: str | None = None,
    ) -> None:
        if audit is None:
            return
        event: dict[str, Any] = {
            "action": "executor_run_finish",
            "executor": self.id,
            "case_id": case_id,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
        }
        if response_sha256 is not None:
            event["response_sha256"] = response_sha256
            event["response_chars"] = response_chars
        if error is not None:
            event["error"] = error
        audit.append(event)


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
