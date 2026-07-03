"""The maletín model + the availability probe `capabilities` reports (RULE 1).

Every forensic tool physically lives in one or both of the two compose maletín
images — `toolkit-windows` / `toolkit-unix` — long-running Linux containers built by
`docker compose up --build`. The api service bundles NONE of them; it reaches a tool
inside its maletín. This module owns:

  - the maletín registry (id → compose service → default container name + exec-agent URL), and
  - the probe: is the maletín's exec-agent reachable, and is a tool's binary present in it.

Resolver order (CLAUDE.md RULE 1): env override (`FORENSIA_<BIN>_BIN`, resolvable where
the api runs) → the declared maletín(es) in the catalog. RULE 2: the probe NEVER falls
back from one maletín to the other — a windows-only tool whose maletín is down is
unavailable, full stop; a Cross tool is reported per maletín it actually lives in.

Channel (docs/operacion/exec-agent.md, proximos-pasos.md §B): the api talks to each
maletín through its **exec-agent** — a tiny HTTP service the maletín runs on the
compose-internal network (`http://toolkit-unix:8666` / `http://toolkit-windows:8666`,
no published port). This replaces the earlier need for the host Docker socket in the
api (§A): the api never controls the host daemon; it just calls the exec-agent, the
same trust model it uses for `ollama`. When the URL is not configured (standalone dev
without the compose) the probe reports each maletín as *not consultable* with an
actionable reason — the honest truth — instead of guessing availability.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import TYPE_CHECKING, Any

from forensia.toolkit.resolver import resolve

if TYPE_CHECKING:  # avoid an import cycle — snapshot() takes the catalog as an argument
    from collections.abc import Iterable

    from forensia.toolkit.tool import Tool

# Canonical maletín ids (also used by catalog.py `toolkits=`).
TOOLKIT_WINDOWS = "toolkit-windows"
TOOLKIT_UNIX = "toolkit-unix"
MALETINES: tuple[str, ...] = (TOOLKIT_UNIX, TOOLKIT_WINDOWS)

# compose service → default container_name (docker-compose.yml pins these). Overridable
# per-service via FORENSIA_TOOLKIT_WINDOWS_CONTAINER / FORENSIA_TOOLKIT_UNIX_CONTAINER
# so a non-default compose project name still resolves. Kept for the display `container`
# field; the exec-agent channel is addressed by URL, not by container name.
_DEFAULT_CONTAINER = {
    TOOLKIT_WINDOWS: "forensia-toolkit-windows",
    TOOLKIT_UNIX: "forensia-toolkit-unix",
}

# compose service → env var carrying its exec-agent base URL. The compose `api` service
# sets these to the internal-network URLs; standalone runs export them explicitly.
_URL_ENV = {
    TOOLKIT_WINDOWS: "FORENSIA_TOOLKIT_WINDOWS_URL",
    TOOLKIT_UNIX: "FORENSIA_TOOLKIT_UNIX_URL",
}

# Probe HTTP budget: a maletín whose exec-agent does not answer quickly is treated as
# unreachable rather than blocking the capabilities snapshot.
_PROBE_TIMEOUT = 5

# Default wall-clock for a tool run when the caller does not pass one. The HTTP read
# timeout is set above the tool timeout so the transport never trips before the tool.
_EXEC_DEFAULT_TIMEOUT = 600


class MaletinExecError(RuntimeError):
    """The exec-agent could not run the argv (URL not configured, unreachable, or a
    malformed response). Raised by `run_argv_in_maletin`; the dispatcher translates it
    into a `ToolExecutionError`. A tool that RUNS and fails is NOT this — that returns a
    non-zero exit code."""


def container_name(service: str) -> str:
    if service not in _DEFAULT_CONTAINER:
        raise ValueError(f"unknown maletín service {service!r} (expected one of {MALETINES})")
    key = f"FORENSIA_{service.upper().replace('-', '_')}_CONTAINER"
    return os.environ.get(key) or _DEFAULT_CONTAINER[service]


def service_url(service: str) -> str | None:
    """Base URL of a maletín's exec-agent, or None when it is not configured."""
    if service not in _URL_ENV:
        raise ValueError(f"unknown maletín service {service!r} (expected one of {MALETINES})")
    val = os.environ.get(_URL_ENV[service])
    return val.strip().rstrip("/") if val and val.strip() else None


def _request(
    method: str, url: str, payload: dict | None = None, *, timeout: float = _PROBE_TIMEOUT
) -> tuple[int, dict]:
    """Single shell-free HTTP choke point so tests can monkeypatch the exec-agent calls.

    Returns (status_code, parsed_json). Raises urllib/OSError on a transport failure and
    ValueError on an unparseable body — callers translate those into an actionable reason.
    `timeout` defaults to the short probe budget; `/exec` passes a longer one.
    """
    data = None
    headers: dict[str, str] = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    token = os.environ.get("FORENSIA_EXEC_AGENT_TOKEN")
    if token:
        headers["X-Forensia-Exec-Token"] = token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — fixed internal URL
        body = resp.read().decode("utf-8")
        return resp.status, (json.loads(body) if body else {})


def run_argv_in_maletin(
    service: str, argv: list[str], *, timeout: float | None = None
) -> tuple[int, str, str]:
    """Run a fully-resolved argv inside a maletín via its exec-agent `POST /exec`.

    `argv` is `[binary, *args]` as the tool sees it inside the maletín — paths must
    reference the maletín's mounts (`/evidence` ro, `/cases`), which are the SAME host
    dirs the api mounts, so no path translation is needed. Returns (exit, stdout, stderr).
    Raises `MaletinExecError` when the exec-agent cannot be reached / is not configured;
    a tool that runs and fails returns a non-zero exit code (not an exception).
    """
    base_url = service_url(service)
    if not base_url:
        raise MaletinExecError(_no_url_reason(service))
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise MaletinExecError("argv debe ser una list[str] no vacía (shell-free)")
    http_timeout = (float(timeout) if timeout else _EXEC_DEFAULT_TIMEOUT) + 30
    try:
        status, body = _request(
            "POST", f"{base_url}/exec", {"argv": argv, "timeout": timeout}, timeout=http_timeout
        )
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise MaletinExecError(
            f"no se pudo ejecutar en el exec-agent {base_url} ({type(exc).__name__}): {exc}"
        ) from exc
    if status != 200 or not isinstance(body, dict) or "exit" not in body:
        raise MaletinExecError(
            f"el exec-agent {base_url} devolvió una respuesta inesperada (estado {status})"
        )
    return int(body["exit"]), str(body.get("stdout", "")), str(body.get("stderr", ""))


def _no_url_reason(service: str) -> str:
    return (
        f"el servicio api no tiene configurada la URL del exec-agent del maletín "
        f"('{_URL_ENV[service]}'). En el compose la fija el servicio api "
        f"(http://{service}:8666); en ejecución standalone expórtala. Ver "
        f"docs/operacion/exec-agent.md"
    )


def probe_service(service: str, *, base_url: str | None) -> dict[str, Any]:
    """Report whether a maletín's exec-agent is reachable.

    `running` is True when the exec-agent answers, False when it answers with an error,
    and None when the api has no way to consult it (no URL, or a transport failure) —
    then `reason` names why.
    """
    name = container_name(service)
    base: dict[str, Any] = {"service": service, "container": name, "url": base_url}
    if not base_url:
        return {**base, "running": None, "reason": _no_url_reason(service)}
    try:
        status, body = _request("GET", f"{base_url}/health")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {
            **base,
            "running": None,
            "reason": (
                f"no se pudo consultar el exec-agent en {base_url} "
                f"({type(exc).__name__}) — ¿está el maletín '{name}' levantado?"
            ),
        }
    if status == 200 and isinstance(body, dict) and body.get("ok"):
        return {**base, "running": True, "reason": None}
    return {
        **base,
        "running": False,
        "reason": f"exec-agent en {base_url} respondió estado {status} — maletín '{name}' inaccesible",
    }


def probe_binaries(service: str, binaries: Iterable[str], *, base_url: str) -> set[str] | None:
    """Return the subset of `binaries` present on PATH inside the maletín.

    One POST /which per maletín (batched). None if the call itself could not complete —
    the caller then reports the binaries as un-checkable.
    """
    names = list(binaries)
    if not names:
        return set()
    try:
        status, body = _request("POST", f"{base_url}/which", {"binaries": names})
    except (urllib.error.URLError, OSError, ValueError):
        return None
    if status != 200 or not isinstance(body, dict):
        return None
    present = body.get("present")
    if not isinstance(present, list):
        return None
    return {b for b in present if isinstance(b, str)}


def _tool_status(
    tool: Tool,
    services: dict[str, dict[str, Any]],
    present: dict[str, set[str] | None],
) -> dict[str, Any]:
    """Per-tool availability from pre-probed service + binary-presence maps.

    RULE 1 order: an env override / api-PATH resolution wins outright. RULE 2: only the
    tool's OWN declared maletines are ever consulted; a Cross tool is `available` when
    its binary is confirmed in AT LEAST ONE of the maletines it lives in (genuine
    per-profile routing, not a fallback).
    """
    toolkits = list(tool.toolkits)

    if resolve(tool.binary) is not None:
        return {
            "available": True,
            "toolkits": toolkits,
            "via": "env-override-or-api-path",
            "reason": None,
            "detail": {},
        }

    if not toolkits:
        return {
            "available": False,
            "toolkits": [],
            "via": None,
            "reason": f"'{tool.id}' no declara maletín (toolkits vacío)",
            "detail": {},
        }

    detail: dict[str, Any] = {}
    reasons: list[str] = []
    any_present = False
    for service in toolkits:
        svc = services.get(service)
        if svc is None or svc["running"] is None:
            reason = svc["reason"] if svc else f"servicio {service!r} desconocido"
            detail[service] = {"running": None, "binary_present": None, "reason": reason}
            reasons.append(f"{service}: {reason}")
            continue
        if not svc["running"]:
            detail[service] = {"running": False, "binary_present": None, "reason": svc["reason"]}
            reasons.append(f"{service}: {svc['reason']}")
            continue
        found = present.get(service)
        if found is None:
            reason = f"{service}: no se pudo comprobar el binario '{tool.binary}'"
            detail[service] = {"running": True, "binary_present": None, "reason": reason}
            reasons.append(reason)
            continue
        is_present = tool.binary in found
        detail[service] = {
            "running": True,
            "binary_present": is_present,
            "reason": None if is_present else f"binario '{tool.binary}' ausente en {service}",
        }
        if is_present:
            any_present = True
        else:
            reasons.append(f"{service}: binario '{tool.binary}' ausente")

    return {
        "available": any_present,
        "toolkits": toolkits,
        "via": "maletin" if any_present else None,
        "reason": None if any_present else "; ".join(reasons),
        "detail": detail,
    }


def snapshot(catalog: Iterable[Tool]) -> dict[str, Any]:
    """Full maletín view for `capabilities`: per-maletín status + per-tool availability.

    Probes each maletín's exec-agent once and batches the binary check per reachable
    maletín, so a snapshot costs at most 2 GET /health + 2 POST /which calls (and zero
    when no maletín URL is configured). Takes the catalog as an argument to avoid an
    import cycle.
    """
    tools = list(catalog)
    urls = {svc: service_url(svc) for svc in MALETINES}
    any_url = any(u is not None for u in urls.values())

    services = {svc: probe_service(svc, base_url=urls[svc]) for svc in MALETINES}

    present: dict[str, set[str] | None] = {}
    for svc, info in services.items():
        if info["running"]:
            wanted = sorted({t.binary for t in tools if svc in t.toolkits})
            present[svc] = probe_binaries(svc, wanted, base_url=urls[svc])

    return {
        # True when at least one maletín exec-agent URL is configured — i.e. the api has
        # a channel to consult the maletines at all. Per-maletín reachability is in
        # `services`.
        "client": any_url,
        "services": services,
        "tools": {t.id: _tool_status(t, services, present) for t in tools},
    }
