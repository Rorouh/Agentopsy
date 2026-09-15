"""Execution layer contract: ``PromptExecutor``.

The 2026-07-02 pivot replaces the SDK-based model layer (``agentopsy.models.cloud``,
API keys) with four operator-selected executors — Claude Code (``claude -p``),
Codex CLI (``codex exec``), Gemini CLI (``gemini -p``) and Ollama (HTTP to the
compose service). The CLIs consume the USER's own subscription via the session
stored in the ``agentopsy-cli-auth`` volume (the ``api`` container's HOME):
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

from agentopsy.i18n import Mensaje, t
from agentopsy.config import CONFIG_DIR, config

# Designed parameter default (allowed by RULE 2). 300 s, recalibrated against a
# MEASURED run: with the old
# 120 s, 11 of 21 productive turns ran over 85 s, one real turn took 162 s, and
# the run's very first turn DIED at the limit — losing the whole ~35 K-token
# prefix with no cost trace. A `tool_batch` of 6-8 herramientas legitimately
# needs minutes; a hung CLI is still bounded (the 2026-07-02 E2E saw Gemini hang
# the old 600 s default, which is why this is not higher). Override per request
# (``context['timeout']``) or per deployment with AGENTOPSY_EXECUTOR_TIMEOUT
# (env or Settings) — see ``resolve_timeout``.
DEFAULT_TIMEOUT_S = 300

# Chars-per-token divisor for the ESTIMATED cost of a turn that died before the
# executor could report usage (timeout / unlaunchable binary). Explicitly an
# estimate, labeled as such in the audit event (``estimate_basis``) — never mixed
# with reported token fields (RULE 2: a real number and a guess are not the same
# field). Without it a lost turn records zero cost and the run's bill cannot be
# reconstructed from the audit (fase-turnos.md §5).
_ESTIMATE_CHARS_PER_TOKEN = 4

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
        raise ExecutorError(Mensaje("executor.badModelId", model=repr(model)))
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

    **``input_tokens`` is NOT the size of the prompt.** On a cache-aware API it
    is only the UNCACHED REMAINDER; the bytes served from cache are billed
    separately under ``cache_read_input_tokens`` (0.1× base) and the bytes
    written into the cache under ``cache_creation_input_tokens`` (1.25× at the
    5-minute TTL, **2× at the 1-hour TTL** — the one Claude Code uses, verified
    2026-07-29: the envelope reports ``cache_creation.ephemeral_1h_input_tokens``).
    The real prompt is ``total_input_tokens``. Reading ``input_tokens`` as "what
    the prompt cost" understated Agentopsy's real input by ~15× and was the bug
    behind an earlier wrong pre-flight estimate.
    """
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None
    #: How the numbers were obtained (e.g. "claude_code.usage", "ollama.eval_count").
    #: Lets a reviewer tell a real 0 from "the executor didn't report it".
    source: str | None = None
    #: Prompt bytes WRITTEN into the prompt cache this turn (billed above base rate).
    cache_creation_input_tokens: int | None = None
    #: Prompt bytes SERVED from the prompt cache this turn (billed at ~0.1× base).
    #: A value that does not grow turn after turn on a reused session means the
    #: cache is not being hit — see ``agentopsy.executors.cache_health``.
    cache_read_input_tokens: int | None = None

    @property
    def total_input_tokens(self) -> int | None:
        """The REAL prompt size: uncached remainder + cache writes + cache reads.

        ``None`` when the executor reported no input-side datum at all, so a
        caller can still tell "not reported" from a real zero (RULE 2). An
        executor that reports only ``input_tokens`` (no cache accounting) yields
        exactly ``input_tokens`` — the pre-cache behaviour, unchanged.
        """
        parts = [
            self.input_tokens,
            self.cache_creation_input_tokens,
            self.cache_read_input_tokens,
        ]
        if all(p is None for p in parts):
            return None
        return sum(p for p in parts if p is not None)

    def as_audit_fields(self) -> dict[str, Any]:
        """The subset actually present — flat keys for the audit event.

        Purely ADDITIVE with respect to the pre-2026-07-29 event shape: the
        existing keys keep their meaning and position, the cache keys join them
        (FORENSIC INVARIANT 4 — this change never removes what is audited).
        """
        out: dict[str, Any] = {}
        if self.input_tokens is not None:
            out["input_tokens"] = self.input_tokens
        if self.output_tokens is not None:
            out["output_tokens"] = self.output_tokens
        if self.cache_creation_input_tokens is not None:
            out["cache_creation_input_tokens"] = self.cache_creation_input_tokens
        if self.cache_read_input_tokens is not None:
            out["cache_read_input_tokens"] = self.cache_read_input_tokens
        total = self.total_input_tokens
        if total is not None:
            out["total_input_tokens"] = total
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
    #: The executor's own conversation id, when it keeps one and reports it.
    #: ``None`` means "no session to reuse" and the caller must send full context.
    session_id: str | None = None
    #: Turns the executor put into its session for THIS call. Agentopsy authors
    #: exactly one; anything else means the session holds turns Agentopsy did not
    #: write (see ``agentopsy.executors.session_guard``).
    num_turns: int | None = None


class PromptExecutor(ABC):
    """One prompt in, one structured result out. Selected explicitly by the
    operator per request (RULE 2: there is no default executor)."""

    id: str            # closed-enum id the API accepts
    name: str          # human-readable label for the UI
    is_local: bool     # True only for Ollama — the 100% local option

    #: Whether this executor can CONTINUE a previous conversation instead of
    #: re-sending the whole transcript. Opt-in per executor and verified against
    #: the real CLI before being set — never assumed from the presence of a flag
    #: in ``--help``. An executor that leaves this False always runs full-context,
    #: which is correct but costlier; ``/api/capabilities`` surfaces the
    #: difference with an actionable reason instead of letting the operator
    #: discover it in the bill (RULE 2: no silent degradation).
    supports_session_resume: bool = False

    #: Whether ONE run of this executor is bounded by a wall-clock limit.
    #: Declared per executor, never inferred from the context (RULE 2).
    #:
    #: True for the three cloud CLIs: the turn leaves the machine, the vendor
    #: bills it, and a hung CLI must not hold the analysis forever (the
    #: 2026-07-02 E2E watched Gemini hang the whole 600 s of the old default).
    #: False for Ollama, the 100 % local option: nothing leaves the machine,
    #: nothing is billed per second, and the examiner's own model on the
    #: examiner's own hardware legitimately takes far longer than a limit
    #: calibrated against a cloud CLI. A 32B model writing a full pericial
    #: report is minutes of GPU, not seconds; killing it at 300 s threw away the
    #: entire draft and bought nothing back. See ``timeout_for``.
    enforces_timeout: bool = True

    @abstractmethod
    def is_available(self) -> ExecutorAvailability: ...

    def timeout_for(self, context: dict[str, Any]) -> int | None:
        """Seconds one run may take, or ``None`` when this executor is unbounded.

        The single place the two axes meet. WHETHER a limit applies is the
        executor's, declared in ``enforces_timeout``; HOW LONG it is, when one
        does, is the operator's (``resolve_timeout``: caller → Settings/env →
        designed default). An unbounded executor never reads the configured
        value, so a corrupt AGENTOPSY_EXECUTOR_TIMEOUT cannot abort a run it
        does not govern; it still fails loud the moment a bounded executor is
        selected, which is where it actually acts (RULE 2).
        """
        if not self.enforces_timeout:
            return None
        return resolve_timeout(context)

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
        - ``timeout``: seconds (else AGENTOPSY_EXECUTOR_TIMEOUT, else
          ``DEFAULT_TIMEOUT_S`` — see ``resolve_timeout``). Read only by an
          executor that declares ``enforces_timeout``; Ollama runs unbounded
          and ignores it (see ``timeout_for``).
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


def neutral_cwd() -> str:
    """Working directory for CLI executor subprocesses: a dedicated EMPTY dir.

    ``subprocess.run`` inherits Agentopsy's own cwd, and the three CLIs load
    project-context files from wherever they run (``CLAUDE.md`` / ``AGENTS.md`` /
    ``GEMINI.md``, walking up the tree). Measured: launching the backend from the
    repo injected Agentopsy's own ``CLAUDE.md`` into EVERY executor call — 8.870
    tokens/turn the analysis never asked for — and contradicted the contract that
    ``agentes/agent.md`` is the ONE behavioural file the agent reads.
    Running under ``CONFIG_DIR`` keeps the parents
    (``~/.agentopsy``, ``$HOME``) free of such files too. Created on demand and
    kept empty by construction; the literal cwd is audited with the argv."""
    cwd = CONFIG_DIR / "executor-cwd"
    cwd.mkdir(parents=True, exist_ok=True)
    return str(cwd)


def resolve_timeout(context: dict[str, Any]) -> int:
    """How LONG a bounded run may take, in seconds.

    Resolution order — every step operator-explicit, then the designed default
    (allowed by RULE 2): ``context['timeout']`` (caller) → AGENTOPSY_EXECUTOR_TIMEOUT
    (env / Settings via ``agentopsy.config``) → ``DEFAULT_TIMEOUT_S``.

    An UNPARSEABLE value fails loudly instead of silently reverting to the
    default (RULE 2: a typo in Settings must surface, not vanish).

    It does NOT decide whether a limit applies at all: that is the executor's
    declared ``enforces_timeout``, and ``PromptExecutor.timeout_for`` is the
    entry point every run goes through.
    """
    raw = context.get("timeout")
    source = "context['timeout']"
    if raw is None:
        raw = config.get("AGENTOPSY_EXECUTOR_TIMEOUT")
        source = "AGENTOPSY_EXECUTOR_TIMEOUT"
    if raw is None:
        return DEFAULT_TIMEOUT_S
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = 0
    if value <= 0:
        raise ExecutorError(
            Mensaje("executor.badTimeout", source=source, raw=repr(raw))
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
                reason=t("executor.notOnPath", binary=self.binary),
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
            return False, t(
                "executor.probeTimeout",
                argv=" ".join(argv),
                seconds=AUTH_PROBE_TIMEOUT_S,
            )
        except OSError as exc:
            return False, f"no se pudo ejecutar `{argv[0]}`: {exc}"
        if proc.returncode == 0:
            return True, ""
        detail = (proc.stderr or proc.stdout or "").strip()[:300]
        return False, detail or t(
            "executor.probeExit", argv=" ".join(argv), code=proc.returncode
        )

    # ---- subclass hooks -----------------------------------------------------

    @abstractmethod
    def _check_auth(self) -> ExecutorAvailability:
        """REAL authentication check for this CLI (status command or credential
        file validation — see each subclass and the official doc it cites). The
        reason on failure names the CONCRETE login command."""

    @abstractmethod
    def _build_argv(
        self, prompt: str, model: str | None, session_id: str | None = None
    ) -> list[str]:
        """Literal argv for one non-interactive run (verified against the
        official CLI docs — see each subclass).

        ``model`` is the operator-selected model id (already validated by
        ``run``): when set, the subclass appends the CLI's model flag; when
        ``None`` it appends nothing, so the CLI uses its own configured model —
        Agentopsy never invents one (RULE 2).

        ``session_id`` is only ever non-None for an executor that declares
        ``supports_session_resume``; it asks the CLI to CONTINUE that
        conversation so the prompt can carry just the delta."""

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

    def _extract_session_id(self, stdout: str) -> str | None:
        """Hook: the CLI's own conversation id, when its envelope reports one.
        Default: none — the executor is treated as stateless and every run sends
        full context."""
        return None

    def _extract_turn_count(self, stdout: str) -> int | None:
        """Hook: how many turns the CLI recorded for this ONE call. Default: not
        reported, which ``session_guard`` treats as unverifiable (→ full context)."""
        return None

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

        # Session continuation (optional). Only honoured by an executor that
        # declares it: passing a session id to a CLI whose resume behaviour we
        # have not verified would be exactly the kind of guess RULE 2 forbids.
        session_id = ctx.get("session_id")
        if isinstance(session_id, str):
            session_id = session_id.strip() or None
        elif session_id is not None:
            raise ExecutorError(
                f"'session_id' del contexto debe ser str o None, no {type(session_id).__name__}"
            )
        if session_id is not None and not self.supports_session_resume:
            raise ExecutorError(Mensaje("executor.noResume", name=self.name))
        if session_id is not None:
            # The id reaches the CLI as its own argv element, so it can never spawn
            # a subshell — but a value starting with `-` would be read as a FLAG.
            # Same gate as the model id (SECURITY INVARIANT 5).
            validate_model_id(session_id)

        argv = self._build_argv(prompt, model, session_id)
        # ``None`` = unbounded, which ``subprocess.run`` reads as "no limit".
        # The three CLIs declare a bound; the branch keeps the contract honest
        # for any executor that ever declares otherwise.
        timeout = self.timeout_for(ctx)
        cwd = neutral_cwd()
        audit = ctx.get("audit")
        case_id = ctx.get("case_id")

        if audit is not None:
            # FORENSIC INVARIANT 4: the LITERAL argv (prompt included — it is
            # case-derived content and the audit log lives inside the case dir),
            # never the LLM's or the caller's paraphrase.
            event: dict[str, Any] = {
                "action": "executor_run_start",
                "executor": self.id,
                "local": self.is_local,
                "case_id": case_id,
                "argv": argv,
                "prompt_sha256": sha256_text(prompt),
                "prompt_chars": len(prompt),
                # The literal working directory of the subprocess — a neutral
                # empty dir, so no host CLAUDE.md/AGENTS.md/GEMINI.md can leak
                # into the model's context (agentes/agent.md is the ONE
                # behavioural file). Audited so the isolation is verifiable.
                "cwd": cwd,
                # The wall-clock bound this run was launched under, or null when
                # the executor runs unbounded. A turn that ended at a limit and a
                # turn that could never end at one are different facts about the
                # run, and the audit is where a third party reads them.
                "timeout_s": timeout,
                # Whether this turn continued a session (prompt = delta) or opened
                # one (prompt = full context). Without it the audited argv alone
                # could not tell a short prompt that is a delta from a short prompt
                # that is the whole conversation — this ADDS traceability.
                "resume": session_id is not None,
            }
            if session_id is not None:
                event["resumed_session_id"] = session_id
            # Why full context was sent when a session existed (divergence,
            # compaction, unverifiable transcript). Set by the caller.
            reopen_reason = ctx.get("reopen_reason")
            if isinstance(reopen_reason, str) and reopen_reason.strip():
                event["reopen_reason"] = reopen_reason.strip()[:2000]
            audit.append(event)

        started = time.monotonic()
        try:
            proc = subprocess.run(  # noqa: S603 — argv array, shell=False by design
                argv,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
                cwd=cwd,
            )
        except subprocess.TimeoutExpired as exc:
            # A lost turn still COSTS the whole prompt: without an estimate the
            # audit records it as zero and the run's bill cannot be reconstructed
            # (fase-turnos.md §5). Labeled as an estimate, never as reported usage.
            self._audit_finish(
                audit, case_id, exit_code=None, duration_ms=_ms(started),
                error=f"timeout tras {timeout}s",
                prompt_chars=len(prompt),
                estimated_input_tokens=len(prompt) // _ESTIMATE_CHARS_PER_TOKEN,
            )
            raise ExecutorError(
                Mensaje("executor.timedOut", name=self.name, seconds=timeout)
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
                else str(
                    Mensaje(
                        "executor.stderrEmpty",
                        detail=(proc.stderr or "").strip()[:2000]
                        or str(Mensaje("executor.emptyMark")),
                    )
                )
            )
            self._audit_finish(audit, case_id, exit_code=proc.returncode,
                               duration_ms=duration_ms, error=reason[:2000])
            raise ExecutorError(
                Mensaje(
                    "executor.nonZeroExit",
                    name=self.name,
                    code=proc.returncode,
                    reason=reason[:2000],
                )
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
        try:
            returned_session = self._extract_session_id(proc.stdout or "")
        except Exception:  # noqa: BLE001 — same rule: never sink a good run
            returned_session = None
        try:
            num_turns = self._extract_turn_count(proc.stdout or "")
        except Exception:  # noqa: BLE001
            num_turns = None

        self._audit_finish(
            audit, case_id, exit_code=proc.returncode, duration_ms=duration_ms,
            response_sha256=sha256_text(text), response_chars=len(text), usage=usage,
            session_id=returned_session, num_turns=num_turns,
        )
        return ExecutorResult(
            executor=self.id,
            text=text,
            argv=tuple(argv),
            exit_code=proc.returncode,
            duration_ms=duration_ms,
            raw=proc.stdout or "",
            usage=usage,
            session_id=returned_session,
            num_turns=num_turns,
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
        session_id: str | None = None,
        num_turns: int | None = None,
        error: str | None = None,
        prompt_chars: int | None = None,
        estimated_input_tokens: int | None = None,
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
        if estimated_input_tokens is not None:
            # A turn that died before the executor reported usage. The estimate
            # lives in its OWN clearly-labeled fields — never in the reported
            # token fields (RULE 2: a measurement and a guess don't share a key).
            event["prompt_chars"] = prompt_chars
            event["estimated_input_tokens"] = estimated_input_tokens
            event["estimate_basis"] = f"prompt_chars/{_ESTIMATE_CHARS_PER_TOKEN}"
        if response_sha256 is not None:
            event["response_sha256"] = response_sha256
            event["response_chars"] = response_chars
        if usage is not None:
            event.update(usage.as_audit_fields())
        if session_id is not None:
            event["session_id"] = session_id
        if num_turns is not None:
            event["num_turns"] = num_turns
        if error is not None:
            event["error"] = error
        audit.append(event)


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
