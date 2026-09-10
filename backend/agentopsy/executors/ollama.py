"""Ollama executor — HTTP to the Ollama the operator pointed Agentopsy at. The 100% local option.

No credentials and no subprocess: one POST to ``{OLLAMA_HOST}/api/generate``
(``stream: false``; the answer comes back in the ``response`` field). There is NO
built-in default host (RULE 2): the value comes from Settings, or from the
environment the deployment set. The compose sets ``http://ollama:11434`` (its own
bundled service, internal network, no published port) as the baseline; whatever
the operator saves in Settings wins over it (see ``agentopsy.config``).

**The Ollama running on the operator's own machine.** A big model is usually
already served by the host (``ollama run qwen2.5:32b``), on the host's GPU, with
the models the examiner has downloaded. To use it the operator writes the URL as
they know it, ``http://localhost:11434``. Inside the api container that URL means
the CONTAINER, where nothing listens, so it is resolved to the name by which the
host machine is reachable from the container. That name is not invented here: the
DEPLOYMENT declares it in ``AGENTOPSY_HOST_GATEWAY`` (the compose sets
``host.docker.internal`` and adds the matching ``extra_hosts`` entry). Unset, as in
a standalone ``python -m agentopsy.server``, there is no container boundary and no
rewrite happens. The rewrite is never silent: it is what the availability reason
names, what the audit event records as the literal request, and what Settings
shows next to the field.

The model name is resolved by the CALLER (router): operator-set ``OLLAMA_MODEL``
from Settings wins, else the agent package's declared ``model.name``. This
executor demands it in ``context['model']`` and never invents one.

Uses stdlib ``urllib`` so the base install works without extra dependencies.
"""

from __future__ import annotations

import ipaddress
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
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

#: Environment key through which the DEPLOYMENT declares the name that resolves,
#: from inside the api container, to the machine running Docker. The compose sets
#: it to ``host.docker.internal`` together with the ``extra_hosts`` entry that
#: makes that name resolve on Linux too. Absent or empty means "no container
#: boundary": loopback is left exactly as the operator wrote it.
HOST_GATEWAY_ENV = "AGENTOPSY_HOST_GATEWAY"


@dataclass(frozen=True)
class ResolvedHost:
    """What the operator configured, and what urllib is actually asked to contact."""

    configured: str
    effective: str

    @property
    def rewritten(self) -> bool:
        return self.configured != self.effective

    @property
    def display(self) -> str:
        """Both URLs when the rewrite applied, so an error never names a host the
        operator did not write, nor hides the one actually contacted."""
        if self.rewritten:
            return f"{self.configured} ({self.effective})"
        return self.effective


def _is_loopback(hostname: str | None) -> bool:
    if not hostname:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        # urlsplit().hostname already strips the brackets of an IPv6 literal.
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def resolve_host(raw: str) -> ResolvedHost:
    """Point a loopback URL at the host machine when running inside a container.

    Only the HOSTNAME changes, and only when it is loopback and the deployment
    declared a gateway name: scheme, port and path are the operator's.
    """
    base = raw.strip().rstrip("/")
    gateway = (os.environ.get(HOST_GATEWAY_ENV) or "").strip()
    if not gateway:
        return ResolvedHost(base, base)
    parts = urllib.parse.urlsplit(base)
    if not _is_loopback(parts.hostname):
        return ResolvedHost(base, base)
    userinfo = ""
    if parts.username:
        userinfo = parts.username
        if parts.password:
            userinfo = f"{userinfo}:{parts.password}"
        userinfo = f"{userinfo}@"
    port = f":{parts.port}" if parts.port is not None else ""
    effective = urllib.parse.urlunsplit(
        (parts.scheme, f"{userinfo}{gateway}{port}", parts.path, parts.query, parts.fragment)
    )
    return ResolvedHost(base, effective.rstrip("/"))


class OllamaExecutor(PromptExecutor):
    id = "ollama"
    name = "Ollama"
    is_local = True

    # Sin límite de tiempo. El tope compartido protege de un turno de nube que
    # muere en el límite habiendo pagado el prompt entero, y de un CLI colgado
    # que quema una sesión de pago sin devolver respuesta. Aquí no hay ninguna de
    # las dos cosas: el modelo corre en la máquina del perito, nadie factura la
    # espera, y un modelo local sobre CPU emulada tarda minutos en un turno que
    # una API resuelve en segundos, así que el tope no acotaba un fallo sino que
    # cortaba trabajo legítimo. Lo que se pierde al cortarlo es real: el turno se
    # tira entero y con él las herramientas que ya habían corrido.
    # El precio de esta decisión, dicho aquí porque el código no lo puede
    # arreglar solo: una petición que se cuelgue de verdad (el servidor de Ollama
    # trabado) ya no se destraba sola, y `jobs.cancel` solo se consulta ENTRE
    # iteraciones, así que no interrumpe la llamada en vuelo. La salida es
    # reiniciar el servicio.
    bounded_by_timeout = False

    @staticmethod
    def _host() -> ResolvedHost | None:
        host = config.get("OLLAMA_HOST")
        if isinstance(host, str) and host.strip():
            return resolve_host(host)
        return None

    @staticmethod
    def _unreachable(host: ResolvedHost, error: object) -> tuple[str, dict[str, object]]:
        """Catalog key + params for "Ollama did not answer", naming BOTH URLs when
        the loopback rewrite applied.

        When it did, the likely cause is not that Ollama is down but that it only
        listens on the host's own loopback, where a container cannot reach it, so
        the message names that fix instead of leaving the operator with a bare
        "does not answer". Returned unrendered because the two callers want
        different renderings: the availability probe speaks the request's
        language, the run error is a ``Mensaje`` (canonical text plus code).
        """
        if host.rewritten:
            return "ollama.noAnswerHostMachine", {
                "configured": host.configured,
                "effective": host.effective,
                "error": error,
            }
        return "ollama.noAnswer", {"host": host.effective, "error": error}

    def is_available(self) -> ExecutorAvailability:
        host = self._host()
        if host is None:
            return ExecutorAvailability(
                available=False,
                reason=t("ollama.hostUnset"),
            )
        try:
            req = urllib.request.Request(f"{host.effective}/api/version", method="GET")
            with urllib.request.urlopen(req, timeout=_PROBE_TIMEOUT_S):
                pass
        except (urllib.error.URLError, OSError, ValueError) as exc:
            clave, params = self._unreachable(host, exc)
            return ExecutorAvailability(available=False, reason=t(clave, **params))
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
            req = urllib.request.Request(f"{host.effective}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=_PROBE_TIMEOUT_S) as resp:
                body = resp.read().decode("utf-8")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ExecutorError(
                Mensaje("ollama.listFailed", host=host.display, error=exc)
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

        url = f"{host.effective}/api/generate"
        payload: dict[str, Any] = {"model": model, "prompt": prompt, "stream": False}
        temperature = ctx.get("temperature")
        if temperature is not None:
            payload["options"] = {"temperature": float(temperature)}

        timeout = resolve_timeout(ctx, bounded=self.bounded_by_timeout)
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
                    # `url` is the LITERAL request that leaves the process, which
                    # is the rewritten one when the operator wrote loopback and
                    # the deployment declared a host gateway; `configured_host`
                    # keeps what they actually typed, so the audit shows both
                    # halves of the resolution (FORENSIC INVARIANT 4).
                    "http": {
                        "url": url,
                        "model": model,
                        **(
                            {"configured_host": host.configured}
                            if host.rewritten
                            else {}
                        ),
                    },
                    "prompt": prompt,
                    "prompt_sha256": sha256_text(prompt),
                    "prompt_chars": len(prompt),
                    # Bajo qué régimen de tiempo corrió, para que el registro no
                    # dependa de saber qué versión llevaba el código: `null` es
                    # sin límite (FORENSIC INVARIANT 4, se registra lo que pasó).
                    "timeout_s": timeout,
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
            clave, params = self._unreachable(host, exc)
            raise ExecutorError(Mensaje(clave, **params)) from exc

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
