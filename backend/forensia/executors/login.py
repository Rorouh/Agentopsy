"""Web-driven CLI login for the cloud executors (2026-07-15).

The four executors authenticate with the USER's own session in the
``forensia-cli-auth`` volume (SECURITY INVARIANT 7 — no API keys). Until now that
session could only be created from a terminal (``docker compose exec -it api …``).
This module relays the CLI's own device / OAuth login flow so the operator can
connect an executor FROM THE WEB: it launches the login process shell-free (argv
fixed per closed-enum id — NEVER built from user input, SECURITY INVARIANT 4),
reads its output until the ``{url, code}`` appears, and keeps the process alive
until the flow completes.

Per-CLI behaviour, captured live inside the api container (2026-07-15):

- **Codex** (``codex login --device-auth``, codex-cli 0.142.5): prints to stdout a
  STATIC device URL (``https://auth.openai.com/codex/device``) plus a one-time code
  (``XXXX-XXXXX``, "expires in 15 minutes"). The operator enters the code in the
  browser — the CLI polls in the background and EXITS 0 on success. It does NOT read
  a code back from stdin (``needs_code_input=False``).
- **Claude** (``claude auth login``, Claude Code 2.1.187): prints to stdout an
  authorize URL (``https://claude.com/cai/oauth/authorize?…`` with PKCE + state) and
  then blocks on ``Paste code here if prompted >`` — the operator authorises in the
  browser, copies the callback code and pastes it BACK (``needs_code_input=True``,
  relayed to the process stdin by ``submit_code``). Exits 0 once the code validates.
- **Gemini** (``gemini`` interactive, gemini-cli 0.49.0): the free-tier "Login with
  Google" flow is now REJECTED server-side (``IneligibleTierError: UNSUPPORTED_CLIENT``
  — "migrate to the Antigravity suite") BEFORE any URL is printed, so there is nothing
  to relay. ``relay_supported=False``: the UI degrades to the exact manual command +
  a re-check button (RULE 2: never a spinner that never ends).

Contract (RULE 2 — no silent defaults, actionable failures):
- ``start_login`` refuses an already-authenticated executor, an unknown / non-cloud
  id, and an executor whose login cannot be relayed — each with an actionable error.
- ``login_status`` reflects ``waiting | logged_in | error | expired`` from the live
  process + the REAL availability check (the same one ``/api/capabilities`` uses).
- The one-time code and any token are NEVER written to a log or the audit trail; the
  code is sensitive and lives only in the ``/login`` response and the operator's
  browser memory (RULE 3: this logic module never ``print()``s either).
"""

from __future__ import annotations

import atexit
import os
import re
import subprocess  # noqa: S404 — argv arrays only, shell=False (SECURITY INVARIANT 4)
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from forensia.i18n import Mensaje, t
from forensia.executors.base import ExecutorAvailability

# Cloud executors that own a login flow. Ollama is 100% local (no login) and is
# deliberately excluded — asking to "connect" it is a caller bug, not a default.
CLOUD_EXECUTOR_IDS: tuple[str, ...] = ("claude-code", "codex", "gemini")

# The one-time code expires in ~15 min (Codex says so explicitly); give the whole
# flow a little more and then declare it expired and reap the process.
MAX_LOGIN_SECONDS = 16 * 60
# How long ``start_login`` waits for the CLI to emit its url (+ code). A healthy
# device flow prints within a second or two; a hung/erroring CLI must not block
# the request.
START_TIMEOUT_S = 30

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


class LoginError(RuntimeError):
    """A login could not start or progress (already authenticated, CLI absent,
    output not parseable, non-zero exit). The message is actionable (RULE 2)."""


class LoginRelayUnsupported(LoginError):
    """This CLI's login cannot be relayed from the web (see ``GeminiExecutor``).

    Carries the exact manual command so the surface can degrade explicitly
    instead of hanging on a flow that will never emit a url (RULE 2)."""

    def __init__(self, message: str, manual_command: str) -> None:
        super().__init__(message)
        self.manual_command = manual_command


@dataclass(frozen=True)
class LoginSpec:
    executor_id: str
    # Fixed argv — NEVER built from user input (SECURITY INVARIANT 4/5).
    argv: tuple[str, ...]
    env: dict[str, str]
    emits_code: bool          # the CLI prints a code we must show (Codex)
    needs_code_input: bool    # the CLI reads a code back from stdin (Claude)
    relay_supported: bool
    manual_command: str
    # Compiled once; ``code_re`` is None when the CLI does not print a code.
    code_re: re.Pattern[str] | None
    reason: str | None = None  # why relay is unsupported (Gemini)


LOGIN_SPECS: dict[str, LoginSpec] = {
    "codex": LoginSpec(
        executor_id="codex",
        argv=("codex", "login", "--device-auth"),
        env={},
        emits_code=True,
        needs_code_input=False,
        relay_supported=True,
        manual_command="docker compose exec -it api codex login --device-auth",
        # e.g. 7RV0-TAHW5 — uppercase alnum blocks joined by a hyphen.
        code_re=re.compile(r"\b([A-Z0-9]{4,8}-[A-Z0-9]{4,8})\b"),
    ),
    "claude-code": LoginSpec(
        executor_id="claude-code",
        argv=("claude", "auth", "login"),
        env={},
        emits_code=False,
        needs_code_input=True,
        relay_supported=True,
        manual_command="docker compose exec -it api claude auth login",
        code_re=None,
    ),
    "gemini": LoginSpec(
        executor_id="gemini",
        argv=("gemini",),
        env={"NO_BROWSER": "true"},
        emits_code=False,
        needs_code_input=True,
        relay_supported=False,
        manual_command="docker compose exec -it -e NO_BROWSER=true api gemini",
        code_re=None,
        reason=t("login.geminiIneligible"),
    ),
}


def _availability(executor_id: str) -> ExecutorAvailability:
    """REAL availability check for ``executor_id`` — the SAME one
    ``/api/capabilities`` uses. Lazy import breaks the executors-package cycle and
    keeps a single source of truth (tests monkeypatch THIS function)."""
    from forensia.executors import get_executor

    return get_executor(executor_id).is_available()


@dataclass
class _LoginSession:
    executor_id: str
    spec: LoginSpec
    proc: subprocess.Popen[str]
    started_at: float
    url: str | None = None
    code: str | None = None
    code_submitted: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _emitted: threading.Event = field(default_factory=threading.Event)
    _reader_done: threading.Event = field(default_factory=threading.Event)
    _lines: deque[str] = field(default_factory=lambda: deque(maxlen=200))

    def start_reader(self) -> None:
        t = threading.Thread(target=self._read_stdout, name=f"login-{self.executor_id}", daemon=True)
        t.start()

    def _read_stdout(self) -> None:
        stream = self.proc.stdout
        if stream is None:  # pragma: no cover — we always create a pipe
            self._reader_done.set()
            return
        for raw in iter(stream.readline, ""):
            line = _strip_ansi(raw).rstrip("\n")
            with self._lock:
                self._lines.append(line)
                if self.url is None:
                    m = _URL_RE.search(line)
                    if m:
                        self.url = m.group(0)
                if (
                    self.spec.emits_code
                    and self.code is None
                    and "http" not in line
                    and self.spec.code_re is not None
                ):
                    cm = self.spec.code_re.search(line)
                    if cm:
                        self.code = cm.group(1)
                if self.url is not None and (self.code is not None or not self.spec.emits_code):
                    self._emitted.set()
        self._reader_done.set()

    def wait_for_emit(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._emitted.wait(0.1):
                return True
            if self._reader_done.is_set():
                break
        return self._emitted.is_set()

    def is_in_flight(self) -> bool:
        """The process is alive AND has already emitted its url/code."""
        return self.proc.poll() is None and self._emitted.is_set()

    def emit_payload(self) -> dict[str, object]:
        with self._lock:
            return {
                "executor": self.executor_id,
                "state": "waiting",
                "url": self.url,
                "code": self.code,
                "needs_code_input": self.spec.needs_code_input,
            }

    def tail(self, redact: str | None = None) -> str:
        with self._lock:
            text = "\n".join(list(self._lines)[-6:]).strip()
        # NEVER surface the one-time code even on an error path.
        if redact:
            text = text.replace(redact, t("login.codeMask"))
        if self.code:
            text = text.replace(self.code, t("login.codeMask"))
        return text[:400]

    def submit_code(self, code: str) -> None:
        stdin = self.proc.stdin
        if stdin is None:  # pragma: no cover — we always create a pipe
            raise LoginError(Mensaje("login.noStdin"))
        try:
            stdin.write(code + "\n")
            stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise LoginError(
                Mensaje("login.stdinClosed")
            ) from exc
        with self._lock:
            self.code_submitted = True

    def terminate(self) -> None:
        proc = self.proc
        if proc.poll() is None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
            except OSError:
                pass
        for pipe in (proc.stdin, proc.stdout):
            try:
                if pipe is not None:
                    pipe.close()
            except OSError:
                pass


_ACTIVE: dict[str, _LoginSession] = {}
_REGISTRY_LOCK = threading.Lock()


def _reap_all() -> None:
    with _REGISTRY_LOCK:
        sessions = list(_ACTIVE.values())
        _ACTIVE.clear()
    for session in sessions:
        session.terminate()


atexit.register(_reap_all)


def _require_cloud_id(executor_id: str) -> LoginSpec:
    spec = LOGIN_SPECS.get(executor_id)
    if spec is None:
        raise ValueError(
            Mensaje(
                "login.notWebCapable",
                id=repr(executor_id),
                ids=", ".join(CLOUD_EXECUTOR_IDS),
            )
        )
    return spec


def login_info(executor_id: str) -> dict[str, object]:
    """Static relay capability of ``executor_id`` — lets the UI choose UP FRONT
    between the "Conectar" flow and the manual-command degrade."""
    spec = _require_cloud_id(executor_id)
    return {
        "executor": executor_id,
        "relay_supported": spec.relay_supported,
        "needs_code_input": spec.needs_code_input,
        "manual_command": spec.manual_command,
        "reason": spec.reason,
    }


def login_capabilities() -> dict[str, dict[str, object]]:
    """Relay capability of every cloud executor (batch, for the Settings page)."""
    return {eid: login_info(eid) for eid in CLOUD_EXECUTOR_IDS}


def start_login(executor_id: str, *, force: bool = False) -> dict[str, object]:
    """Launch (or resume) ``executor_id``'s login and return ``{url, code,
    needs_code_input, state}``.

    ``force`` RENUEVA una sesión que el sondeo da por buena. Existe porque el
    sondeo puede MENTIR: medido el 2026-08-05, `claude auth status` devuelve
    exit 0 y ``loggedIn: true`` con el token OAuth ya caducado, y la corrida
    muere con un 401 «Re-authenticate to continue». Sin esta puerta, el perito
    quedaba encerrado: la aplicación se negaba a reconectar («ya tiene sesión
    iniciada») y la ÚNICA salida era la terminal, o borrar el volumen entero con
    ``docker compose down -v`` (que además se lleva por delante las sesiones de
    los otros ejecutores y los modelos de Ollama).

    No es un fallback ni un default silencioso (RULE 2): solo lo activa una
    petición EXPLÍCITA del operador desde «Renovar sesión». Sin ``force``, pedir
    conectar un ejecutor sano sigue devolviendo el mismo rechazo informativo.

    RULE 2: unknown / non-cloud id → ValueError; relay-unsupported →
    LoginRelayUnsupported; already authenticated (sin ``force``) o salida
    ilegible → LoginError.
    """
    spec = _require_cloud_id(executor_id)

    if not spec.relay_supported:
        raise LoginRelayUnsupported(
            f"El login de este ejecutor no puede iniciarse desde la web. "
            f"{spec.reason or ''} Comando: {spec.manual_command}".strip(),
            manual_command=spec.manual_command,
        )

    if not force:
        availability = _availability(executor_id)
        if availability.available:
            raise LoginError(
                Mensaje("login.alreadyLoggedIn", id=executor_id)
            )

    with _REGISTRY_LOCK:
        existing = _ACTIVE.get(executor_id)
        if existing is not None:
            if existing.is_in_flight():
                # A login is already in flight (double click / reopened modal):
                # return its current url/code instead of spawning a duplicate.
                return existing.emit_payload()
            _ACTIVE.pop(executor_id, None)
            existing.terminate()

    try:
        proc = subprocess.Popen(  # noqa: S603 — fixed argv, shell=False by design
            list(spec.argv),
            shell=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=str(Path.home()),
            env=_child_env(spec),
        )
    except OSError as exc:
        raise LoginError(
            f"no se pudo lanzar `{spec.argv[0]}`: {exc}. Reconstruye la imagen "
            "(`docker compose build api`)."
        ) from exc

    session = _LoginSession(
        executor_id=executor_id, spec=spec, proc=proc, started_at=time.monotonic()
    )
    session.start_reader()

    if not session.wait_for_emit(START_TIMEOUT_S):
        session.terminate()
        exit_code = proc.poll()
        detail = session.tail()
        if exit_code is not None and exit_code != 0:
            raise LoginError(
                Mensaje(
                    "login.endedNoUrl",
                    id=executor_id,
                    code=exit_code,
                    detail=detail or str(Mensaje("login.emptyOutput")),
                )
            )
        raise LoginError(
            Mensaje(
                "login.noUrlInTime",
                id=executor_id,
                seconds=START_TIMEOUT_S,
                detail=detail or str(Mensaje("login.emptyOutput")),
            )
        )

    with _REGISTRY_LOCK:
        _ACTIVE[executor_id] = session
    return session.emit_payload()


def _child_env(spec: LoginSpec) -> dict[str, str] | None:
    if not spec.env:
        return None
    env = os.environ.copy()
    env.update(spec.env)
    return env


def login_status(executor_id: str) -> dict[str, object]:
    """Current state of ``executor_id``'s login: ``waiting | logged_in | error |
    expired``, plus the REAL availability + actionable reason at terminal states."""
    spec = _require_cloud_id(executor_id)

    with _REGISTRY_LOCK:
        session = _ACTIVE.get(executor_id)

    if session is None:
        availability = _availability(executor_id)
        if availability.available:
            return _status(executor_id, "logged_in", True, None, spec)
        return _status(
            executor_id,
            "error",
            False,
            t("login.noneRunning"),
            spec,
        )

    poll = session.proc.poll()

    if poll is None:
        if time.monotonic() - session.started_at > MAX_LOGIN_SECONDS:
            _drop(executor_id, session)
            return _status(
                executor_id,
                "expired",
                False,
                t("login.codeExpired"),
                spec,
            )
        return _status(executor_id, "waiting", False, None, spec, session=session)

    _drop(executor_id, session)
    if poll == 0:
        availability = _availability(executor_id)
        if availability.available:
            return _status(executor_id, "logged_in", True, None, spec)
        # The CLI reported success but the session is not usable — surface the
        # REAL reason, never claim availability we cannot confirm (RULE 2).
        return _status(executor_id, "error", False, availability.reason, spec)
    return _status(
        executor_id,
        "error",
        False,
        t(
            "login.endedWithExit",
            id=executor_id,
            code=poll,
            detail=session.tail() or t("login.emptyOutput"),
        ),
        spec,
    )


def submit_code(executor_id: str, code: str) -> dict[str, object]:
    """Relay the browser callback code to the CLI's stdin (Claude / Gemini)."""
    spec = _require_cloud_id(executor_id)
    if not spec.needs_code_input:
        raise LoginError(
            Mensaje("login.noCodeStep", id=executor_id)
        )
    code = (code or "").strip()
    if not code:
        raise LoginError(Mensaje("login.codeEmpty"))

    with _REGISTRY_LOCK:
        session = _ACTIVE.get(executor_id)
    if session is None or session.proc.poll() is not None:
        raise LoginError(
            Mensaje("login.noneWaiting")
        )
    session.submit_code(code)
    return {"ok": True, "executor": executor_id}


def cancel_login(executor_id: str) -> dict[str, object]:
    """Kill any in-flight login for ``executor_id``. Idempotent."""
    _require_cloud_id(executor_id)
    with _REGISTRY_LOCK:
        session = _ACTIVE.pop(executor_id, None)
    if session is not None:
        session.terminate()
    return {"ok": True, "executor": executor_id}


def _drop(executor_id: str, session: _LoginSession) -> None:
    with _REGISTRY_LOCK:
        if _ACTIVE.get(executor_id) is session:
            _ACTIVE.pop(executor_id, None)
    session.terminate()


def _status(
    executor_id: str,
    state: str,
    available: bool,
    reason: str | None,
    spec: LoginSpec,
    *,
    session: _LoginSession | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "executor": executor_id,
        "state": state,
        "available": available,
        "reason": reason,
        "needs_code_input": spec.needs_code_input,
    }
    if session is not None:
        payload["code_submitted"] = session.code_submitted
    return payload
