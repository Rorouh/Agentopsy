"""Execution-layer tests (2026-07-02 pivot; auth real del 2026-07-03).

Covers:
- Closed enum: `get_executor` fails loud on unknown ids (RULE 2).
- `is_available()` is a REAL check with ACTIONABLE reasons: binary missing,
  no session — the reason names the CONCRETE login command (`claude auth
  login`, `codex login --device-auth`, flujo NO_BROWSER de gemini) —, Ollama
  host not configured / unreachable. The old directory-existence check gave a
  false positive in the 2026-07-02 E2E verification.
- `run()` aborts FAST with the actionable reason when the auth check fails —
  it never launches the prompt (no more hanging until the run timeout).
- Timeout: `resolve_timeout` honours context > FORENSIA_EXECUTOR_TIMEOUT >
  designed default, and fails loud on unparseable values (RULE 2).
- HTTP surface: `/api/agent/query` demands an operator-selected executor —
  4xx actionable, never a default; selected-but-unusable executor → 503 with
  the missing dependency named.
- Regression: the strings ANTHROPIC_API_KEY / OPENAI_API_KEY are gone from the
  backend source tree (SECURITY INVARIANT 7).
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from forensia.config import config
from forensia.executors import (
    DEFAULT_TIMEOUT_S,
    EXECUTOR_IDS,
    ClaudeCodeExecutor,
    CodexExecutor,
    ExecutorAvailability,
    ExecutorError,
    GeminiExecutor,
    OllamaExecutor,
    executor_models,
    get_executor,
    resolve_timeout,
)
from forensia.executors import base as executors_base
from forensia.server import create_app

PORT = 50997
BACKEND_DIR = Path(__file__).resolve().parents[1]


@pytest.fixture
def client() -> TestClient:
    app = create_app(PORT)
    return TestClient(app, base_url=f"http://127.0.0.1:{PORT}")


@pytest.fixture
def clean_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neutralise the dev machine's env/config.json so RULE 2 paths are exercised."""
    for key in ("DEFAULT_EXECUTOR", "OLLAMA_HOST", "OLLAMA_MODEL", "FORENSIA_EXECUTOR_TIMEOUT"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(config, "_data", {})


def _fake_status(returncode: int, stderr: str = "") -> object:
    """Monkeypatch-able stand-in for the auth-status subprocess (never runs the
    dev machine's real CLIs from the test suite)."""

    def runner(argv, **kwargs):  # noqa: ANN001, ANN003
        return subprocess.CompletedProcess(argv, returncode, stdout="", stderr=stderr)

    return runner


# ---- closed enum ------------------------------------------------------------


def test_executor_enum_is_the_four_of_the_pivot() -> None:
    assert EXECUTOR_IDS == ("claude-code", "codex", "gemini", "ollama")


def test_get_executor_unknown_id_fails_loud() -> None:
    with pytest.raises(ValueError) as exc:
        get_executor("gpt-4o")
    # El error es accionable: nombra los ids válidos, no sustituye (RULE 2).
    for valid in EXECUTOR_IDS:
        assert valid in str(exc.value)


# ---- is_available: razones accionables ---------------------------------------


def test_cli_unavailable_when_binary_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _cmd: None)
    availability = ClaudeCodeExecutor().is_available()
    assert availability.available is False
    assert "claude" in availability.reason
    assert "docker compose build api" in availability.reason


def test_claude_available_when_auth_status_exits_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # `claude auth status` sale con 0 si hay sesión (cli-reference oficial).
    monkeypatch.setattr(shutil, "which", lambda _cmd: "/usr/local/bin/claude")
    monkeypatch.setattr(executors_base.subprocess, "run", _fake_status(0))
    assert ClaudeCodeExecutor().is_available().available is True


def test_claude_unavailable_without_session_names_login_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _cmd: "/usr/local/bin/claude")
    monkeypatch.setattr(executors_base.subprocess, "run", _fake_status(1, "Not logged in"))
    availability = ClaudeCodeExecutor().is_available()
    assert availability.available is False
    # Razón accionable: el comando de login CONCRETO, dentro del contenedor.
    assert "claude auth login" in availability.reason
    assert "docker compose exec" in availability.reason
    assert "Not logged in" in availability.reason


def test_claude_unavailable_when_status_probe_hangs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def hang(argv, **kwargs):  # noqa: ANN001, ANN003
        raise subprocess.TimeoutExpired(argv, executors_base.AUTH_PROBE_TIMEOUT_S)

    monkeypatch.setattr(shutil, "which", lambda _cmd: "/usr/local/bin/claude")
    monkeypatch.setattr(executors_base.subprocess, "run", hang)
    availability = ClaudeCodeExecutor().is_available()
    assert availability.available is False
    assert "no respondió" in availability.reason


def test_codex_unavailable_without_session_names_device_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _cmd: "/usr/local/bin/codex")
    monkeypatch.setattr(executors_base.subprocess, "run", _fake_status(1))
    availability = CodexExecutor().is_available()
    assert availability.available is False
    # El flujo device-code es el documentado para entornos sin navegador.
    assert "codex login --device-auth" in availability.reason


def _gemini_with_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> GeminiExecutor:
    monkeypatch.setattr(shutil, "which", lambda _cmd: "/usr/local/bin/gemini")
    monkeypatch.setattr(pathlib.Path, "home", classmethod(lambda _cls: tmp_path))
    return GeminiExecutor()


def test_gemini_unavailable_without_oauth_creds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    availability = _gemini_with_home(monkeypatch, tmp_path).is_available()
    assert availability.available is False
    assert "oauth_creds.json" in availability.reason
    assert "NO_BROWSER" in availability.reason


def test_gemini_available_with_refresh_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    creds = tmp_path / ".gemini" / "oauth_creds.json"
    creds.parent.mkdir()
    creds.write_text(json.dumps({"access_token": "x", "refresh_token": "y"}), encoding="utf-8")
    assert _gemini_with_home(monkeypatch, tmp_path).is_available().available is True


def test_gemini_unavailable_when_session_expired_without_refresh(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    creds = tmp_path / ".gemini" / "oauth_creds.json"
    creds.parent.mkdir()
    expired_ms = int(time.time() * 1000) - 60_000
    creds.write_text(
        json.dumps({"access_token": "x", "expiry_date": expired_ms}), encoding="utf-8"
    )
    availability = _gemini_with_home(monkeypatch, tmp_path).is_available()
    assert availability.available is False
    assert "caducado" in availability.reason


def test_gemini_unavailable_when_creds_file_corrupt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    creds = tmp_path / ".gemini" / "oauth_creds.json"
    creds.parent.mkdir()
    creds.write_text("esto no es JSON", encoding="utf-8")
    availability = _gemini_with_home(monkeypatch, tmp_path).is_available()
    assert availability.available is False
    assert "corrupta" in availability.reason


def test_run_aborts_fast_without_session(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sin sesión, run() falla con la razón accionable ANTES de lanzar el
    prompt — nunca cuelga hasta el timeout de ejecución (E2E 2026-07-02)."""

    def status_only(argv, **kwargs):  # noqa: ANN001, ANN003
        assert list(argv[:3]) == ["claude", "auth", "status"], (
            f"run() lanzó {argv!r} sin sesión válida"
        )
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="Not logged in")

    monkeypatch.setattr(shutil, "which", lambda _cmd: "/usr/local/bin/claude")
    monkeypatch.setattr(executors_base.subprocess, "run", status_only)
    with pytest.raises(ExecutorError) as exc:
        ClaudeCodeExecutor().run("analiza", {})
    assert "claude auth login" in str(exc.value)


# ---- claude -p: salida real vs contrato de parseo (aislamiento E2E 2026-07-06)

# Salida REAL capturada en el contenedor api (claude 2.1.187, sin sesión):
#   $ claude -p "Responde con la palabra: hola" --output-format json
#   exit code 1; stdout vacío; stderr:
_CLAUDE_NOT_LOGGED_IN = "Not logged in · Please run /login"


def test_claude_run_exit_nonzero_surfaces_literal_stderr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Si la sesión cae ENTRE el probe de auth y el run (probe OK, `claude -p`
    exit 1), el error lleva el exit code y el stderr LITERAL del CLI — sin
    reintentos ni sustitución (RULE 2)."""
    monkeypatch.setattr(
        ClaudeCodeExecutor,
        "is_available",
        lambda self: ExecutorAvailability(available=True),
    )

    def run_fails(argv, **kwargs):  # noqa: ANN001, ANN003
        return subprocess.CompletedProcess(
            argv, 1, stdout="", stderr=_CLAUDE_NOT_LOGGED_IN
        )

    monkeypatch.setattr(executors_base.subprocess, "run", run_fails)
    with pytest.raises(ExecutorError) as exc:
        ClaudeCodeExecutor().run("Responde con la palabra: hola", {})
    msg = str(exc.value)
    assert "exit code 1" in msg
    assert _CLAUDE_NOT_LOGGED_IN in msg


def test_claude_extract_text_non_json_names_the_contract() -> None:
    """Capa executor↔parser: un stdout que no es el envelope de
    `--output-format json` produce un error que NOMBRA el contrato y muestra la
    salida real — accionable, nunca críptico."""
    with pytest.raises(ExecutorError) as exc:
        ClaudeCodeExecutor()._extract_text(_CLAUDE_NOT_LOGGED_IN)
    msg = str(exc.value)
    assert "--output-format json" in msg
    assert "Not logged in" in msg


def test_claude_extract_text_happy_envelope_returns_result() -> None:
    """Envelope de éxito de `--output-format json` (campos documentados:
    `result` + `is_error` + metadata de sesión): se extrae `result` tal cual —
    es el texto que ExecutorBackend._parse_action parsea después."""
    inner = '{"action": "final", "text": "hola"}'
    envelope = json.dumps(
        {
            "type": "result",
            "subtype": "success",
            "is_error": False,
            "result": inner,
            "session_id": "sess-0001",
            "total_cost_usd": 0.0007,
        }
    )
    assert ClaudeCodeExecutor()._extract_text(envelope) == inner


def test_claude_extract_text_is_error_envelope_fails_loud() -> None:
    envelope = json.dumps({"is_error": True, "result": "API Error: overloaded"})
    with pytest.raises(ExecutorError) as exc:
        ClaudeCodeExecutor()._extract_text(envelope)
    msg = str(exc.value)
    assert "is_error" in msg
    assert "overloaded" in msg


def test_ollama_unavailable_without_host(clean_config: None) -> None:
    availability = OllamaExecutor().is_available()
    assert availability.available is False
    assert "OLLAMA_HOST" in availability.reason


def test_ollama_unavailable_when_unreachable(
    clean_config: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Puerto 1 en loopback: nada escucha; el probe debe fallar rápido y la
    # razón debe nombrar el host que se intentó.
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:1")
    availability = OllamaExecutor().is_available()
    assert availability.available is False
    assert "http://127.0.0.1:1" in availability.reason


def test_ollama_run_demands_model(clean_config: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:1")
    with pytest.raises(ExecutorError) as exc:
        OllamaExecutor().run("hola", {})
    assert "OLLAMA_MODEL" in str(exc.value)


# ---- timeout configurable ------------------------------------------------------


def test_resolve_timeout_designed_default(clean_config: None) -> None:
    assert resolve_timeout({}) == DEFAULT_TIMEOUT_S
    assert DEFAULT_TIMEOUT_S == 120


def test_resolve_timeout_from_env(clean_config: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORENSIA_EXECUTOR_TIMEOUT", "45")
    assert resolve_timeout({}) == 45


def test_resolve_timeout_context_wins_over_env(
    clean_config: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FORENSIA_EXECUTOR_TIMEOUT", "45")
    assert resolve_timeout({"timeout": 7}) == 7


def test_resolve_timeout_invalid_env_fails_loud(
    clean_config: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    # RULE 2: un valor corrupto NO se sustituye en silencio por el default.
    monkeypatch.setenv("FORENSIA_EXECUTOR_TIMEOUT", "muchos")
    with pytest.raises(ExecutorError) as exc:
        resolve_timeout({})
    assert "FORENSIA_EXECUTOR_TIMEOUT" in str(exc.value)


def test_resolve_timeout_nonpositive_context_fails_loud(clean_config: None) -> None:
    with pytest.raises(ExecutorError) as exc:
        resolve_timeout({"timeout": 0})
    assert "context['timeout']" in str(exc.value)


# ---- HTTP surface: selección de ejecutor obligatoria (RULE 2) -----------------


def _query(client: TestClient, payload: dict) -> object:
    token = client.app.state.token
    base = {"prompt": "analiza", "os_profile": "unix", "case_id": "c1", "evidence_id": "e1"}
    return client.post(
        "/api/agent/query",
        headers={"X-Forensia-Token": token},
        json={**base, **payload},
    )


def test_query_without_executor_is_actionable_422(
    client: TestClient, clean_config: None
) -> None:
    r = _query(client, {})
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert "executor" in detail
    for valid in EXECUTOR_IDS:
        assert valid in detail


def test_query_with_unknown_executor_is_422(client: TestClient, clean_config: None) -> None:
    r = _query(client, {"executor": "gpt-4o"})
    assert r.status_code == 422
    assert "gpt-4o" in r.json()["detail"]


def test_query_with_unavailable_executor_is_503_with_reason(
    client: TestClient, clean_config: None
) -> None:
    # ollama sin OLLAMA_HOST: seleccionado pero inutilizable → 503 nombrando la
    # dependencia que falta, jamás un sustituto (RULE 2).
    r = _query(client, {"executor": "ollama"})
    assert r.status_code == 503
    assert "OLLAMA_HOST" in r.json()["detail"]


# ---- regresión: sin API keys en el código fuente ------------------------------

_SKIP_DIRS = {".venv", "__pycache__", "tests", "build", "dist", ".pytest_cache", ".ruff_cache"}


def test_no_api_key_strings_anywhere_in_backend() -> None:
    # Construidas por concatenación para que ESTE fichero no se auto-delate si
    # algún día se escanease también tests/.
    needles = ("ANTHROPIC" + "_API_KEY", "OPENAI" + "_API_KEY")
    offenders: list[str] = []
    for path in BACKEND_DIR.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS or part.endswith(".egg-info") for part in path.parts):
            continue
        if path.suffix not in {".py", ".toml", ".cfg", ".ini", ".txt", ".md", ".json", ".yaml"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for needle in needles:
            if needle in text:
                offenders.append(f"{path}: {needle}")
    assert not offenders, "API keys reintroducidas (SECURITY INVARIANT 7): " + "; ".join(offenders)


# --------------------------------------------------------------------------- #
# executor_models — selector de modelos del composer (por proveedor)
# --------------------------------------------------------------------------- #
def test_executor_models_cloud_is_not_editable_and_notes_cli() -> None:
    """Los CLIs cloud gestionan su modelo; FORENSIA no lo sobrescribe (RULE 2)."""
    for cid in ("claude-code", "codex", "gemini"):
        res = executor_models(cid)
        assert res["editable"] is False
        assert res["models"] == []
        assert isinstance(res["note"], str) and res["note"]


def test_executor_models_ollama_lists_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(OllamaExecutor, "list_models", lambda self: ["a:8b", "b:7b"])
    res = executor_models("ollama")
    assert res["editable"] is True
    assert res["models"] == ["a:8b", "b:7b"]
    assert res["note"] is None


def test_executor_models_ollama_degrades_on_host_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Host caído → lista vacía + la razón accionable en note (no un fallo mudo)."""
    def boom(self: OllamaExecutor) -> list[str]:
        raise ExecutorError("Ollama no responde en http://x")

    monkeypatch.setattr(OllamaExecutor, "list_models", boom)
    res = executor_models("ollama")
    assert res["editable"] is True
    assert res["models"] == []
    assert "Ollama no responde" in str(res["note"])


def test_executor_models_unknown_id_fails_loud() -> None:
    with pytest.raises(ValueError, match="desconocido"):
        executor_models("gpt5")


def test_models_endpoint_ollama(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(OllamaExecutor, "list_models", lambda self: ["qwen2.5:7b-instruct"])
    r = client.get(
        "/api/executors/ollama/models",
        headers={"X-Forensia-Token": client.app.state.token},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["executor"] == "ollama"
    assert body["editable"] is True
    assert body["models"] == ["qwen2.5:7b-instruct"]


def test_models_endpoint_unknown_id_is_400(client: TestClient) -> None:
    r = client.get(
        "/api/executors/nope/models",
        headers={"X-Forensia-Token": client.app.state.token},
    )
    assert r.status_code == 400
    assert "desconocido" in r.json()["detail"]


def test_stream_endpoint_requires_executor_like_query(
    client: TestClient, clean_config: None
) -> None:
    """/query/stream aplica la MISMA validación RULE-2 que /query (no se puede
    saltar los checks de ejecutor/consentimiento por la vía de streaming)."""
    token = client.app.state.token
    r = client.post(
        "/api/agent/query/stream",
        headers={"X-Forensia-Token": token},
        json={"prompt": "analiza", "os_profile": "unix", "case_id": "c1", "evidence_id": "e1"},
    )
    assert r.status_code == 422
    assert "executor" in r.json()["detail"]
