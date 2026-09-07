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
- Timeout: `resolve_timeout` honours context > AGENTOPSY_EXECUTOR_TIMEOUT >
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

from agentopsy.i18n import codigo_de, t
from agentopsy.config import config
from agentopsy.executors import (
    DEFAULT_TIMEOUT_S,
    EXECUTOR_IDS,
    MODEL_CONFIG_KEY,
    REASONING_CONFIG_KEY,
    ClaudeCodeExecutor,
    CodexExecutor,
    ExecutorAvailability,
    ExecutorError,
    GeminiExecutor,
    OllamaExecutor,
    executor_models,
    get_executor,
    resolve_timeout,
    validate_model_id,
    validate_reasoning_effort,
)
from agentopsy.executors import base as executors_base
from agentopsy.server import create_app


def _gemini_hint() -> str:
    """La pista de login que el ejecutor concatena a su motivo."""
    return t("gemini.loginHint")


PORT = 50997
BACKEND_DIR = Path(__file__).resolve().parents[1]


@pytest.fixture
def client() -> TestClient:
    app = create_app(PORT)
    return TestClient(app, base_url=f"http://127.0.0.1:{PORT}")


@pytest.fixture
def clean_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neutralise the dev machine's env/config.json so RULE 2 paths are exercised."""
    for key in (
        "DEFAULT_EXECUTOR",
        "OLLAMA_HOST",
        "OLLAMA_MODEL",
        "CLAUDE_CODE_MODEL",
        "CODEX_MODEL",
        "CODEX_REASONING_EFFORT",
        "GEMINI_MODEL",
        "AGENTOPSY_EXECUTOR_TIMEOUT",
    ):
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
    # El motivo lo compone el sondeo en el idioma en curso; lo que el test fija
    # es que dice que el CLI no respondió, no la frase concreta.
    assert t("executor.probeTimeout", None, argv="claude auth status", seconds=15) in (
        availability.reason
    )


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
    assert availability.reason == t("gemini.expiredSession", None, hint=_gemini_hint())


def test_gemini_unavailable_when_creds_file_corrupt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    creds = tmp_path / ".gemini" / "oauth_creds.json"
    creds.parent.mkdir()
    creds.write_text("esto no es JSON", encoding="utf-8")
    availability = _gemini_with_home(monkeypatch, tmp_path).is_available()
    assert availability.available is False
    assert availability.reason == t("gemini.corruptSession", None, hint=_gemini_hint())


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


# Bug 3 (repro en vivo 2026-07-17, codex-cli 0.142.5): un turno fallido de Codex se
# reporta como evento JSONL en STDOUT; el stderr solo trae la nota informativa de
# stdin=DEVNULL, que NO es la causa.
_CODEX_STDIN_NOTE = "Reading additional input from stdin..."
_CODEX_USAGE_LIMIT_STDOUT = "\n".join(
    [
        '{"type":"thread.started","thread_id":"t-1"}',
        '{"type":"turn.started"}',
        '{"type":"error","message":"You\'ve hit your usage limit. Upgrade to Plus, '
        'or try again at Jul 19th, 2026 10:33 PM."}',
    ]
)


def test_codex_run_exit_nonzero_surfaces_stdout_error_not_stdin_noise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """El error surfaceado lleva la causa REAL del stdout JSONL (límite de uso), no la
    nota de stdin del stderr — RULE 2: fallar fuerte con lo accionable, no un red herring."""
    monkeypatch.setattr(
        CodexExecutor, "is_available", lambda self: ExecutorAvailability(available=True)
    )

    def run_fails(argv, **kwargs):  # noqa: ANN001, ANN003
        return subprocess.CompletedProcess(
            argv, 1, stdout=_CODEX_USAGE_LIMIT_STDOUT, stderr=_CODEX_STDIN_NOTE
        )

    monkeypatch.setattr(executors_base.subprocess, "run", run_fails)
    with pytest.raises(ExecutorError) as exc:
        CodexExecutor().run("responde: hola", {})
    msg = str(exc.value)
    assert "exit code 1" in msg
    assert "usage limit" in msg
    assert "Reading additional input from stdin" not in msg


def test_codex_extract_error_parses_jsonl_error_event() -> None:
    detail = CodexExecutor()._extract_error(_CODEX_USAGE_LIMIT_STDOUT, _CODEX_STDIN_NOTE)
    assert detail is not None and "usage limit" in detail


def test_codex_extract_error_none_when_no_error_event() -> None:
    """Sin evento `error` en el stdout, el hook devuelve None → el run cae al stderr."""
    clean = '{"type":"thread.started"}\n{"type":"turn.completed"}'
    assert CodexExecutor()._extract_error(clean, "") is None


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
    # 300 s, recalibrado contra la corrida medida (fase-turnos.md §5): con 120 s
    # el primer turno real murió en el límite y 11 de 21 rozaron los 85-162 s.
    assert DEFAULT_TIMEOUT_S == 300


def test_resolve_timeout_from_env(clean_config: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTOPSY_EXECUTOR_TIMEOUT", "45")
    assert resolve_timeout({}) == 45


def test_resolve_timeout_context_wins_over_env(
    clean_config: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTOPSY_EXECUTOR_TIMEOUT", "45")
    assert resolve_timeout({"timeout": 7}) == 7


def test_resolve_timeout_invalid_env_fails_loud(
    clean_config: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    # RULE 2: un valor corrupto NO se sustituye en silencio por el default.
    monkeypatch.setenv("AGENTOPSY_EXECUTOR_TIMEOUT", "muchos")
    with pytest.raises(ExecutorError) as exc:
        resolve_timeout({})
    assert "AGENTOPSY_EXECUTOR_TIMEOUT" in str(exc.value)


# ---- cwd neutro + coste del turno perdido (2026-07-30) -------------------------


class _ListAudit(list):
    def append(self, event: dict) -> None:  # type: ignore[override]
        super().append(dict(event))


def test_run_uses_neutral_cwd_and_audits_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """El subproceso del CLI corre en un directorio neutro VACÍO — ningún
    CLAUDE.md/AGENTS.md/GEMINI.md del host puede colarse en el contexto del
    modelo (medido: 8.870 tokens/turno del propio CLAUDE.md de Agentopsy;
    agentes/agent.md es el ÚNICO fichero de comportamiento) — y el cwd literal
    queda en el audit del run."""
    monkeypatch.setattr(executors_base, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(
        ClaudeCodeExecutor,
        "is_available",
        lambda self: ExecutorAvailability(available=True),
    )
    seen: dict = {}
    envelope = json.dumps({"result": "ok", "session_id": "s1", "num_turns": 1})

    def fake_run(argv, **kwargs):  # noqa: ANN001, ANN003
        seen["cwd"] = kwargs.get("cwd")
        return subprocess.CompletedProcess(argv, 0, stdout=envelope, stderr="")

    monkeypatch.setattr(executors_base.subprocess, "run", fake_run)
    audit = _ListAudit()

    ClaudeCodeExecutor().run("analiza", {"audit": audit, "case_id": "c1"})

    expected = str(tmp_path / "executor-cwd")
    assert seen["cwd"] == expected
    assert Path(expected).is_dir()
    assert not any(Path(expected).iterdir())  # neutro = VACÍO por construcción
    start = next(e for e in audit if e["action"] == "executor_run_start")
    assert start["cwd"] == expected


def test_timeout_audits_estimated_cost(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Un turno perdido por timeout cuesta el prompt entero: el audit registra
    el gasto ESTIMADO en campos propios y etiquetados — nunca mezclado con los
    tokens reportados (fase-turnos.md §5; RULE 2)."""
    monkeypatch.setattr(executors_base, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(
        ClaudeCodeExecutor,
        "is_available",
        lambda self: ExecutorAvailability(available=True),
    )

    def hang(argv, **kwargs):  # noqa: ANN001, ANN003
        raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 0))

    monkeypatch.setattr(executors_base.subprocess, "run", hang)
    audit = _ListAudit()

    with pytest.raises(ExecutorError, match="timeout"):
        ClaudeCodeExecutor().run("x" * 400, {"audit": audit, "case_id": "c1"})

    finish = next(e for e in audit if e["action"] == "executor_run_finish")
    assert finish["error"].startswith("timeout")
    assert finish["prompt_chars"] == 400
    assert finish["estimated_input_tokens"] == 100
    assert finish["estimate_basis"] == "prompt_chars/4"
    assert "input_tokens" not in finish  # el estimado nunca usurpa lo reportado


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
        headers={"X-Agentopsy-Token": token},
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
def test_executor_models_cloud_is_editable_with_suggestions_and_custom() -> None:
    """El operador elige el modelo del CLI cloud (--model); para Claude y Gemini
    Agentopsy no puede ENUMERAR el catálogo sin API key (SECURITY 7), así que
    ofrece atajos + texto libre. Codex NO entra aquí: su propio CLI cachea el
    catálogo con la sesión OAuth (ver más abajo)."""
    for cid in ("claude-code", "gemini"):
        res = executor_models(cid)
        assert res["editable"] is True
        assert res["allow_custom"] is True
        assert isinstance(res["models"], list)
        # `note` es un DIAGNÓSTICO, no una explicación de uso: sólo viaja cuando
        # la lista vino vacía o incompleta y hay que decir por qué. Aquí la lista
        # se construye sin consultar nada, así que no hay nada que diagnosticar.
        assert res["note"] is None
        # Sin fuente real de datos ricos no se inventa ninguna (RULE 2).
        assert res["model_details"] == []
        assert res["reasoning"] is None
    # Claude documenta alias estables; se ofrecen como sugerencias.
    assert "opus" in executor_models("claude-code")["models"]


def test_executor_models_codex_lists_the_cli_catalog(tmp_path: Path, monkeypatch) -> None:
    """Codex enumera de verdad: el catálogo sale del caché que el PROPIO CLI
    escribe en CODEX_HOME con la sesión del operador (sin API key). Se filtran
    los modelos internos (`visibility != list`) y viajan los niveles de
    razonamiento que cada modelo declara."""
    (tmp_path / "models_cache.json").write_text(
        json.dumps({
            "models": [
                {
                    "slug": "gpt-5.6-sol",
                    "display_name": "GPT-5.6-Sol",
                    "description": "Frontier",
                    "visibility": "list",
                    "default_reasoning_level": "low",
                    "supported_reasoning_levels": [
                        {"effort": "low", "description": "rápido"},
                        {"effort": "ultra", "description": "máximo"},
                    ],
                },
                {  # interno: el CLI lo esconde, Agentopsy tampoco lo ofrece
                    "slug": "codex-auto-review",
                    "visibility": "hide",
                    "supported_reasoning_levels": [{"effort": "high", "description": ""}],
                },
            ]
        }),
        encoding="utf-8",
    )
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))

    res = executor_models("codex")
    assert res["models"] == ["gpt-5.6-sol"]
    assert res["note"] is None
    assert res["allow_custom"] is True  # el operador siempre puede escribirlo
    assert res["model_details"] == [{
        "id": "gpt-5.6-sol",
        "label": "GPT-5.6-Sol",
        "description": "Frontier",
        "default_effort": "low",
        "efforts": [
            {"id": "low", "description": "rápido"},
            {"id": "ultra", "description": "máximo"},
        ],
    }]
    assert res["reasoning"] == {
        "config_key": REASONING_CONFIG_KEY["codex"],
        "note": res["reasoning"]["note"],
    }


def test_executor_models_codex_degrades_without_catalog(tmp_path: Path, monkeypatch) -> None:
    """Sin caché no hay lista, y la razón viaja en `note`: nunca una lista de
    respaldo escrita a mano (RULE 2)."""
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "vacio"))
    res = executor_models("codex")
    assert res["models"] == []
    assert res["model_details"] == []
    assert str(res["note"]).startswith(t("codex.noCacheYet", None, path="")[:24])
    # El selector de potencia sigue existiendo: el ejecutor SÍ soporta nivel.
    assert res["reasoning"] is not None


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
    with pytest.raises(ValueError) as exc_unknown:
        executor_models("gpt5")
    assert codigo_de(exc_unknown.value) == "executor.unknown"


# --------------------------------------------------------------------------- #
# model selection — --model threading + flag-injection gate (SECURITY 5)
# --------------------------------------------------------------------------- #
def test_model_config_key_covers_every_executor() -> None:
    assert set(MODEL_CONFIG_KEY) == set(EXECUTOR_IDS)


@pytest.mark.parametrize("bad", ["--dangerously-skip-permissions", "-m", "a b", "a;b", "", "/x"])
def test_validate_model_id_rejects_flag_injection(bad: str) -> None:
    with pytest.raises(ExecutorError) as exc_model:
        validate_model_id(bad)
    assert codigo_de(exc_model.value) == "executor.badModelId"


@pytest.mark.parametrize("ok", ["opus", "claude-fable-5", "gpt-5.5", "llama3.1:8b", "hf.co/u/m:Q4"])
def test_validate_model_id_accepts_real_ids(ok: str) -> None:
    assert validate_model_id(ok) == ok


def test_cloud_build_argv_includes_model_when_set() -> None:
    assert ClaudeCodeExecutor()._build_argv("hi", "opus")[:5] == [
        "claude", "-p", "hi", "--model", "opus",
    ]
    assert "--model" in GeminiExecutor()._build_argv("hi", "gemini-2.5-pro")
    codex = CodexExecutor()
    codex._last_message_path = "/tmp/x.md"
    argv = codex._build_argv("hi", "gpt-5.5")
    assert argv[-3:] == ["--model", "gpt-5.5", "hi"]


def test_cloud_build_argv_omits_model_when_none() -> None:
    """Sin modelo elegido no se pasa --model: manda el default del CLI (RULE 2)."""
    assert "--model" not in ClaudeCodeExecutor()._build_argv("hi", None)
    assert "--model" not in GeminiExecutor()._build_argv("hi", None)
    codex = CodexExecutor()
    codex._last_message_path = "/tmp/x.md"
    assert "--model" not in codex._build_argv("hi", None)


@pytest.mark.parametrize("bad", ["ULTRA", "ultra high", "-c", "x\"", "", "a" * 17])
def test_validate_reasoning_effort_rejects_malformed_levels(bad: str) -> None:
    """El nivel acaba dentro de un elemento de argv que el CLI parsea como TOML:
    solo minúsculas, para que no pueda cerrar la cadena ni colar otra clave
    (SECURITY INVARIANT 5)."""
    with pytest.raises(ExecutorError, match="nivel de razonamiento inválido"):
        validate_reasoning_effort(bad)


def test_codex_argv_carries_the_reasoning_effort() -> None:
    """La «potencia» no tiene flag propio: viaja como override de configuración
    con el valor ENTRECOMILLADO (verificado contra codex-cli 0.146.0, que
    imprime `reasoning effort: ultra` en la cabecera del run)."""
    codex = CodexExecutor()
    codex._last_message_path = "/tmp/x.md"
    codex._reasoning_effort = "ultra"
    argv = codex._build_argv("hi", "gpt-5.6-sol")
    assert argv[argv.index("-c") + 1] == 'model_reasoning_effort="ultra"'
    assert argv[-1] == "hi"
    # Sin nivel elegido no se sobreescribe nada: manda el CLI (RULE 2).
    codex._reasoning_effort = None
    assert "-c" not in codex._build_argv("hi", "gpt-5.6-sol")


def test_codex_rejects_an_effort_the_model_cannot_take(tmp_path: Path, monkeypatch) -> None:
    """Un par (modelo, nivel) que el catálogo declara imposible se corta ANTES de
    lanzar el proceso: si no, sale el turno, viaja el prompt entero y vuelve un
    400 `unsupported_value` (verificado en vivo con gpt-5.5 + ultra)."""
    (tmp_path / "models_cache.json").write_text(
        json.dumps({"models": [{
            "slug": "gpt-5.5",
            "visibility": "list",
            "supported_reasoning_levels": [
                {"effort": "high", "description": ""},
                {"effort": "xhigh", "description": ""},
            ],
        }]}),
        encoding="utf-8",
    )
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))
    codex = CodexExecutor()
    with pytest.raises(ExecutorError) as exc_effort:
        codex.run("hola", {"model": "gpt-5.5", "reasoning_effort": "ultra"})
    assert codigo_de(exc_effort.value) == "codex.effortNotAllowed"
    # Modelo fuera del catálogo: no se sabe, así que no se decide aquí. Llega a
    # la puerta de disponibilidad (el CLI no está instalado en el test).
    # El motivo sale en el idioma en curso: se fija por las dos entradas del
    # catálogo que pueden explicar que no se pueda ejecutar.
    with pytest.raises(ExecutorError) as exc_path:
        codex.run("hola", {"model": "modelo-que-no-esta", "reasoning_effort": "ultra"})
    assert str(exc_path.value) in (
        t("executor.notOnPath", None, binary="codex"),
        t("codex.noSession", None, hint=t("codex.loginHint")),
    )


def test_claude_argv_strips_the_cli_harness() -> None:
    """Fase 4 — el arnés de Claude Code no viaja: sin tools nativas (el CLI no
    puede fabricar turnos `tool_use`), sin settings de usuario/proyecto (ningún
    CLAUDE.md puede colarse) y con el system prompt mínimo de Agentopsy en vez
    del de un asistente de programación. En TODAS las llamadas, `--resume`
    incluido (verificado contra `claude` 2.1.220: mismo session_id, num_turns=1)."""
    ex = ClaudeCodeExecutor()
    for argv in (ex._build_argv("hi", None), ex._build_argv("hi", None, "sid-1")):
        assert argv[argv.index("--tools") + 1] == ""
        assert argv[argv.index("--setting-sources") + 1] == ""
        system = argv[argv.index("--system-prompt") + 1]
        # La identidad va en el idioma del agente: se compara con la entrada
        # del catálogo, no con una palabra castellana.
        assert system == t("claude.systemPrompt")
    assert "--resume" in ex._build_argv("hi", None, "sid-1")


def test_claude_surfaces_the_expired_session_instead_of_an_empty_stderr() -> None:
    """Sesión OAuth caducada: la causa viaja en STDOUT y el stderr va VACÍO.

    Medido en vivo el 2026-08-05 (`claude` 2.1.187) sobre un caso real: las seis
    corridas del audit log murieron con `exit_code 1` y `error: "stderr:
    (vacío)"`, que no dice qué arreglar, porque `ClaudeCodeExecutor` no
    implementaba `_extract_error` y el envoltorio JSON con el 401 se tiraba. El
    motivo tiene que nombrar el comando de login (RULE 2).
    """
    envelope = json.dumps(
        {
            "type": "result",
            "subtype": "success",
            "is_error": True,
            "api_error_status": 401,
            "result": (
                "Failed to authenticate. API Error: 401 OAuth access token has "
                "expired. Re-authenticate to continue."
            ),
            "session_id": "ba5b465f-f457-4af8-af49-d753b0d1e996",
        }
    )
    detail = ClaudeCodeExecutor()._extract_error(envelope, "")
    assert detail is not None, "el envoltorio traía la causa y se ha perdido"
    assert "OAuth access token has expired" in detail
    assert "claude auth login" in detail, "el motivo no nombra el comando que lo arregla"
    assert "agentopsy-cli-auth" in detail


def test_claude_extract_error_stays_quiet_when_the_envelope_says_nothing() -> None:
    """No inventa un motivo: sin envoltorio aprovechable devuelve None y la
    corrida cae al stderr de siempre (RULE 2, nada de causas fabricadas)."""
    ex = ClaudeCodeExecutor()
    assert ex._extract_error("not json", "") is None
    assert ex._extract_error(json.dumps(["lista"]), "") is None
    assert ex._extract_error(json.dumps({"type": "result"}), "") is None


def test_models_endpoint_ollama(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(OllamaExecutor, "list_models", lambda self: ["qwen2.5:7b-instruct"])
    r = client.get(
        "/api/executors/ollama/models",
        headers={"X-Agentopsy-Token": client.app.state.token},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["executor"] == "ollama"
    assert body["editable"] is True
    assert body["models"] == ["qwen2.5:7b-instruct"]


def _set_config(client: TestClient, key: str, value: str) -> object:
    return client.post(
        "/api/config",
        headers={"X-Agentopsy-Token": client.app.state.token},
        json={"key": key, "value": value},
    )


def test_cloud_model_key_set_and_unset(client: TestClient, clean_config: None) -> None:
    r = _set_config(client, "CLAUDE_CODE_MODEL", "opus")
    assert r.status_code == 200 and r.json() == {
        "key": "CLAUDE_CODE_MODEL", "set": True, "preview": "opus", "source": "config",
    }
    assert config.get("CLAUDE_CODE_MODEL") == "opus"
    # Empty clears it back to the CLI default (RULE 2), not a 422.
    r = _set_config(client, "CLAUDE_CODE_MODEL", "")
    assert r.status_code == 200 and r.json()["set"] is False
    assert config.get("CLAUDE_CODE_MODEL") is None


def test_cloud_model_key_rejects_flag_injection(client: TestClient, clean_config: None) -> None:
    r = _set_config(client, "CODEX_MODEL", "--dangerously-skip-permissions")
    assert r.status_code == 422
    assert r.json()["detail"] == t(
        "executor.badModelId", "en", model=repr("--dangerously-skip-permissions")
    )


def test_reasoning_effort_key_set_unset_and_validated(
    client: TestClient, clean_config: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """La potencia se persiste como una clave más, se limpia con vacío (vuelve al
    nivel del CLI) y se valida contra el catálogo QUE CACHEÓ EL CLI, no contra
    una lista escrita en Agentopsy (RULE 2)."""
    (tmp_path / "models_cache.json").write_text(
        json.dumps({"models": [{
            "slug": "gpt-5.6-sol",
            "visibility": "list",
            "supported_reasoning_levels": [
                {"effort": "low", "description": ""},
                {"effort": "ultra", "description": ""},
            ],
        }]}),
        encoding="utf-8",
    )
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))

    r = _set_config(client, "CODEX_REASONING_EFFORT", "ultra")
    assert r.status_code == 200 and r.json()["preview"] == "ultra"
    assert config.get("CODEX_REASONING_EFFORT") == "ultra"

    # Forma inválida: cortada por la puerta de argv (SECURITY 5).
    assert _set_config(client, "CODEX_REASONING_EFFORT", "-c").status_code == 422
    # Forma válida pero ausente del catálogo del CLI: 422 nombrando los reales.
    r = _set_config(client, "CODEX_REASONING_EFFORT", "turbo")
    assert r.status_code == 422 and "low, ultra" in r.json()["detail"]

    r = _set_config(client, "CODEX_REASONING_EFFORT", "")
    assert r.status_code == 200 and r.json()["set"] is False
    assert config.get("CODEX_REASONING_EFFORT") is None


def test_models_endpoint_unknown_id_is_400(client: TestClient) -> None:
    r = client.get(
        "/api/executors/nope/models",
        headers={"X-Agentopsy-Token": client.app.state.token},
    )
    assert r.status_code == 400
    assert r.json()["detail"] == t(
        "executor.unknown", "en", id=repr("nope"), ids=", ".join(EXECUTOR_IDS)
    )


def test_stream_endpoint_requires_executor_like_query(
    client: TestClient, clean_config: None
) -> None:
    """/query/stream aplica la MISMA validación RULE-2 que /query (no se puede
    saltar los checks de ejecutor por la vía de streaming)."""
    token = client.app.state.token
    r = client.post(
        "/api/agent/query/stream",
        headers={"X-Agentopsy-Token": token},
        json={"prompt": "analiza", "os_profile": "unix", "case_id": "c1", "evidence_id": "e1"},
    )
    assert r.status_code == 422
    assert "executor" in r.json()["detail"]
