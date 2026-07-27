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
import re
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

# A model id reaches a CLI as a separate ``--model`` argv element. The argv is
# shell-free (SECURITY INVARIANT 4), so a value can never spawn a subshell — but
# a value that STARTS WITH ``-`` would be read by the CLI as another FLAG
# (argv/flag injection: e.g. ``--dangerously-skip-permissions``). Restrict to a
# conservative charset that MUST start with an alphanumeric so such values are
# rejected before they ever reach the CLI (SECURITY INVARIANT 5). ``/`` is
# allowed for namespaced tags (Ollama: ``hf.co/user/model:tag``).
_MODEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


def validate_model_id(model: str) -> str:
    """Return ``model`` unchanged if it is a safe id, else raise ``ExecutorError``.

    The operator picks the model explicitly; Agentopsy passes it verbatim as a
    ``--model`` argv element. This gate stops a value from masquerading as a CLI
    flag (SECURITY INVARIANT 5) — it is NOT a catalog check (Agentopsy cannot
    enumerate a cloud CLI's models without an API key — SECURITY INVARIANT 7).
    """
    if not isinstance(model, str) or not _MODEL_ID_RE.match(model):
        raise ExecutorError(
            f"id de modelo inválido {model!r}: debe empezar por un carácter "
            "alfanumérico y usar solo [A-Za-z0-9 . _ : / -] (máx. 128). Agentopsy lo "
            "rechaza para que no pueda colarse como un flag del CLI (SECURITY "
            "INVARIANT 5)."
        )
    return model


class ExecutorError(RuntimeError):
    """The executor could not produce a response (missing binary, non-zero exit,
    unparseable envelope, unreachable Ollama). The message carries the literal
    stderr / cause so the caller can surface it without guessing."""


@dataclass(frozen=True)
class ExecutorAvailability:
    available: bool
    reason: str | None = None  # actionable, Spanish, only when not available


@dataclass(frozen=True)
class Usage:
    """Token/cost accounting for ONE executor run, parsed from the envelope the
    executor already returns (Bug 008 / §2 «Coste de tokens», Nivel 0).

    Every field is optional: an executor whose envelope does not carry a datum
    reports ``None`` for it — never a fabricated or estimated value (RULE 2). The
    audit event only persists the fields that are actually present.
    """
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None
    #: How the numbers were obtained (e.g. "claude_code.usage", "ollama.eval_count").
    #: Lets a reviewer tell a real 0 from "the executor didn't report it".
    source: str | None = None

    def as_audit_fields(self) -> dict[str, Any]:
        """The subset actually present — flat keys for the audit event."""
        out: dict[str, Any] = {}
        if self.input_tokens is not None:
            out["input_tokens"] = self.input_tokens
        if self.output_tokens is not None:
            out["output_tokens"] = self.output_tokens
        if self.cost_usd is not None:
            out["cost_usd"] = self.cost_usd
        if out and self.source:
            out["usage_source"] = self.source
        return out


@dataclass(frozen=True)
class ExecutorResult:
    executor: str                  # executor id ("claude-code" | "codex" | "gemini" | "ollama")
    text: str                      # the assistant's final text
    argv: tuple[str, ...] | None   # literal argv for CLI executors; None for HTTP (Ollama)
    exit_code: int | None          # CLI exit code; None for HTTP
    duration_ms: int
    raw: str                       # raw stdout / HTTP body the text was extracted from
    usage: Usage | None = None     # token/cost accounting when the envelope carries it


class PromptExecutor(ABC):
    """One prompt in, one structured result out. Selected explicitly by the
    operator per request (RULE 2: there is no default executor)."""

    id: str            # closed-enum id the API accepts
    name: str          # human-readable label for the UI
    is_local: bool     # True only for Ollama — the 100% local option

    @abstractmethod
    def is_available(self) -> ExecutorAvailability: ...

    def _extract_usage(self, raw: str) -> Usage | None:
        """Best-effort token/cost accounting from the executor's own envelope.

        Runs IN PARALLEL to ``_extract_text`` and never affects it: a subclass
        that can't parse usage returns ``None`` (usage unavailable), so a changed
        envelope shape degrades to "not reported" instead of a wrong number or a
        crash (RULE 2). Default: nothing reported.
        """
        return None

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


def _as_int(value: Any) -> int | None:
    """A non-negative int from an envelope field, or None. Never raises."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float) and value.is_integer() and value >= 0:
        return int(value)
    return None


def _as_float(value: Any) -> float | None:
    """A non-negative float from an envelope field, or None. Never raises."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value) if value >= 0 else None
    return None


def _find_key(obj: Any, key: str, _depth: int = 0) -> Any:
    """First value for ``key`` anywhere in a nested dict/list, or None.

    Depth-bounded (≤ 6) so a pathological envelope can't blow the stack. Used to
    locate token counts under version-dependent envelope shapes without hard-coding
    a fragile path.
    """
    if _depth > 6:
        return None
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            found = _find_key(v, key, _depth + 1)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = _find_key(v, key, _depth + 1)
            if found is not None:
                return found
    return None


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
            "entero de segundos > 0 — Agentopsy no lo sustituye por el default "
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
    def _build_argv(self, prompt: str, model: str | None) -> list[str]:
        """Literal argv for one non-interactive run (verified against the
        official CLI docs — see each subclass).

        ``model`` is the operator-selected model id (already validated by
        ``run``): when set, the subclass appends the CLI's model flag; when
        ``None`` it appends nothing, so the CLI uses its own configured model —
        Agentopsy never invents one (RULE 2)."""

    def suggested_models(self) -> list[str]:
        """Model-id shortcuts the composer's picker offers for this CLI.

        A curated hint list (the aliases the CLI itself documents), never a live
        catalog — enumerating a cloud CLI's models would need an API key
        (SECURITY INVARIANT 7). Empty by default; the operator can always type
        any id the CLI accepts. Ollama does not use this (it lists real installed
        models via HTTP)."""
        return []

    @abstractmethod
    def _extract_text(self, stdout: str) -> str:
        """Pull the assistant's final text out of the CLI's stdout envelope."""

    def _extract_error(self, stdout: str, stderr: str) -> str | None:
        """Hook: pull a MORE ACTIONABLE failure reason than raw stderr from the CLI's
        output when the run exits non-zero. Some CLIs report the real cause (usage
        limit, auth, sandbox denial) as a structured event on STDOUT while stderr
        carries only noise (Codex: an informational "Reading additional input from
        stdin..." from ``stdin=DEVNULL``). Default: none → the run falls back to stderr."""
        return None

    # ---- shared run ----------------------------------------------------------

    def run(self, prompt: str, context: dict[str, Any] | None = None) -> ExecutorResult:
        ctx = context or {}
        # Abort FAST with the actionable reason before launching anything: a
        # CLI without a session must not burn the run timeout hanging (the
        # 2026-07-02 E2E saw exactly that with Gemini + EROFS credentials).
        availability = self.is_available()
        if not availability.available:
            raise ExecutorError(availability.reason or f"{self.id} is not available")

        # Operator-selected model (optional). Absent → the CLI's own default
        # (RULE 2: Agentopsy does not invent one). Present → validated so it can
        # never masquerade as a CLI flag before it reaches argv (SECURITY 5).
        model = ctx.get("model")
        if isinstance(model, str):
            model = model.strip() or None
        elif model is not None:
            raise ExecutorError(
                f"'model' del contexto debe ser str o None, no {type(model).__name__}"
            )
        if model is not None:
            validate_model_id(model)

        argv = self._build_argv(prompt, model)
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
            # Prefer the executor's actionable reason (e.g. Codex's stdout error event)
            # over raw stderr, which for some CLIs is only noise (RULE 2: fail loud with
            # the REAL cause, not a red herring).
            detail = self._extract_error(proc.stdout or "", proc.stderr or "")
            reason = (
                detail.strip()
                if detail and detail.strip()
                else f"stderr: {(proc.stderr or '').strip()[:2000] or '(vacío)'}"
            )
            self._audit_finish(audit, case_id, exit_code=proc.returncode,
                               duration_ms=duration_ms, error=reason[:2000])
            raise ExecutorError(
                f"{self.name} terminó con exit code {proc.returncode}. {reason[:2000]}"
            )

        try:
            text = self._extract_text(proc.stdout or "")
        except ExecutorError:
            self._audit_finish(audit, case_id, exit_code=proc.returncode,
                               duration_ms=duration_ms, error="unparseable envelope")
            raise

        # Best-effort usage from the same stdout the text came from. Never lets a
        # parsing problem sink a successful run — the text is already in hand.
        try:
            usage = self._extract_usage(proc.stdout or "")
        except Exception:  # noqa: BLE001 — telemetry must not break the run
            usage = None

        self._audit_finish(
            audit, case_id, exit_code=proc.returncode, duration_ms=duration_ms,
            response_sha256=sha256_text(text), response_chars=len(text), usage=usage,
        )
        return ExecutorResult(
            executor=self.id,
            text=text,
            argv=tuple(argv),
            exit_code=proc.returncode,
            duration_ms=duration_ms,
            raw=proc.stdout or "",
            usage=usage,
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
        usage: Usage | None = None,
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
        if usage is not None:
            event.update(usage.as_audit_fields())
        if error is not None:
            event["error"] = error
        audit.append(event)


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
