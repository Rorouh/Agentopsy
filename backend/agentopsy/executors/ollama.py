"""Ollama executor — HTTP to the compose ``ollama`` service. The 100% local option.

No credentials and no subprocess: one POST to ``{OLLAMA_HOST}/api/generate``
(``stream: false``; the answer comes back in the ``response`` field). In the
compose, ``OLLAMA_HOST`` is ``http://ollama:11434`` (internal network, no
published port); standalone runs set it explicitly — there is NO built-in
default host (RULE 2).

The model name is resolved by the CALLER (router): operator-set ``OLLAMA_MODEL``
from Settings wins, else the agent package's declared ``model.name``. This
executor demands it in ``context['model']`` and never invents one.

Uses stdlib ``urllib`` so the base install works without extra dependencies.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from agentopsy.i18n import Mensaje, t
from agentopsy.config import config
from agentopsy.executors.base import (
    ExecutorAvailability,
    ExecutorError,
    ExecutorResult,
    PromptExecutor,
    Usage,
    _as_int,
    resolve_timeout,
    sha256_text,
)

_PROBE_TIMEOUT_S = 3


class OllamaExecutor(PromptExecutor):
    id = "ollama"
    name = "Ollama"
    is_local = True

    @staticmethod
    def _host() -> str | None:
        host = config.get("OLLAMA_HOST")
        if isinstance(host, str) and host.strip():
            return host.strip().rstrip("/")
        return None

    def is_available(self) -> ExecutorAvailability:
        host = self._host()
        if host is None:
            return ExecutorAvailability(
                available=False,
                reason=t("ollama.hostUnset"),
            )
        try:
            req = urllib.request.Request(f"{host}/api/version", method="GET")
            with urllib.request.urlopen(req, timeout=_PROBE_TIMEOUT_S):
                pass
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return ExecutorAvailability(
                available=False,
                reason=t("ollama.noAnswer", host=host, error=exc),
            )
        return ExecutorAvailability(available=True)

    def list_models(self) -> list[str]:
        """Installed model names from ``{host}/api/tags`` (sorted, de-duped).

        Raises ``ExecutorError`` (actionable) when the host is unset or unreachable —
        RULE 2: no silent empty list masking a misconfiguration.
        """
        host = self._host()
        if host is None:
            raise ExecutorError(Mensaje("ollama.hostUnsetForList"))
        try:
            req = urllib.request.Request(f"{host}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=_PROBE_TIMEOUT_S) as resp:
                body = resp.read().decode("utf-8")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ExecutorError(
                Mensaje("ollama.listFailed", host=host, error=exc)
            ) from exc
        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            raise ExecutorError(Mensaje("ollama.tagsNotJson")) from exc
        entries = data.get("models") if isinstance(data, dict) else None
        names = {
            m["name"]
            for m in (entries or [])
            if isinstance(m, dict) and isinstance(m.get("name"), str) and m["name"].strip()
        }
        return sorted(names)

    def run(self, prompt: str, context: dict[str, Any] | None = None) -> ExecutorResult:
        ctx = context or {}
        host = self._host()
        if host is None:
            raise ExecutorError(Mensaje("ollama.hostUnsetForRun"))
        model = ctx.get("model")
        if not isinstance(model, str) or not model.strip():
            raise ExecutorError(
                "falta 'model' en el contexto del ejecutor ollama. Fija OLLAMA_MODEL "
                "en Settings o declara model.name en el paquete de agente, Agentopsy "
                "no elige un modelo por ti (RULE 2)."
            )

        url = f"{host}/api/generate"
        payload: dict[str, Any] = {"model": model, "prompt": prompt, "stream": False}
        temperature = ctx.get("temperature")
        if temperature is not None:
            payload["options"] = {"temperature": float(temperature)}

        timeout = resolve_timeout(ctx)
        audit = ctx.get("audit")
        case_id = ctx.get("case_id")

        if audit is not None:
            # No argv here (HTTP executor): the literal request is recorded
            # instead, with the prompt bound by hash + full text like the CLIs
            # carry it inside argv (FORENSIC INVARIANT 4).
            audit.append(
                {
                    "action": "executor_run_start",
                    "executor": self.id,
                    "local": True,
                    "case_id": case_id,
                    "http": {"url": url, "model": model},
                    "prompt": prompt,
                    "prompt_sha256": sha256_text(prompt),
                    "prompt_chars": len(prompt),
                }
            )

        started = time.monotonic()
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            self._audit_finish(audit, case_id, started, error=f"HTTP {exc.code}: {detail}")
            raise ExecutorError(
                Mensaje("ollama.httpError", code=exc.code, url=url, detail=detail)
            ) from exc
        except (urllib.error.URLError, OSError) as exc:
            self._audit_finish(audit, case_id, started, error=str(exc))
            raise ExecutorError(f"no se pudo contactar con Ollama en {url}: {exc}") from exc

        duration_ms = int((time.monotonic() - started) * 1000)
        try:
            envelope = json.loads(body)
        except json.JSONDecodeError as exc:
            self._audit_finish(audit, case_id, started, error="unparseable body")
            raise ExecutorError(
                Mensaje("ollama.bodyNotJson", sample=repr(body.strip()[:500]))
            ) from exc

        text = envelope.get("response") if isinstance(envelope, dict) else None
        if not isinstance(text, str):
            self._audit_finish(audit, case_id, started, error="missing 'response' field")
            raise ExecutorError(
                "la respuesta de Ollama no contiene el campo 'response' de texto"
            )

        usage = self._extract_usage_from(envelope)
        if audit is not None:
            event = {
                "action": "executor_run_finish",
                "executor": self.id,
                "case_id": case_id,
                "exit_code": None,
                "duration_ms": duration_ms,
                "response_sha256": sha256_text(text),
                "response_chars": len(text),
            }
            if usage is not None:
                event.update(usage.as_audit_fields())
            audit.append(event)
        return ExecutorResult(
            executor=self.id,
            text=text,
            argv=None,
            exit_code=None,
            duration_ms=duration_ms,
            raw=body,
            usage=usage,
        )

    def _extract_usage(self, raw: str) -> Usage | None:
        try:
            return self._extract_usage_from(json.loads(raw))
        except (json.JSONDecodeError, TypeError):
            return None

    @staticmethod
    def _extract_usage_from(envelope: Any) -> Usage | None:
        # /api/generate with stream:false returns prompt_eval_count (input) and
        # eval_count (output) — stable, documented fields. Ollama is local so
        # there is no cost_usd. Missing → None (Bug 008 Nivel 0).
        # No cache fields: Ollama bills nothing and has no prompt-cache tier, so
        # prompt_eval_count IS the whole prompt and `total_input_tokens` resolves
        # to it correctly. Here the prefix-reuse work buys context window and
        # latency, not money.
        if not isinstance(envelope, dict):
            return None
        u = Usage(
            input_tokens=_as_int(envelope.get("prompt_eval_count")),
            output_tokens=_as_int(envelope.get("eval_count")),
            source="ollama.eval_count",
        )
        return u if (u.input_tokens or u.output_tokens) is not None else None

    @staticmethod
    def _audit_finish(audit: Any, case_id: str | None, started: float, *, error: str) -> None:
        if audit is None:
            return
        audit.append(
            {
                "action": "executor_run_finish",
                "executor": "ollama",
                "case_id": case_id,
                "exit_code": None,
                "duration_ms": int((time.monotonic() - started) * 1000),
                "error": error,
            }
        )
