"""The maletín model + the availability probe `capabilities` reports (RULE 1).

Every forensic tool physically lives in one or both of the two compose maletín
images — `toolkit-windows` / `toolkit-unix` — long-running Linux containers built by
`docker compose up --build`. The api service bundles NONE of them; it reaches a tool
inside its maletín. This module owns:

  - the maletín registry (id → compose service → default container name), and
  - the probe: is the maletín container running, and is a tool's binary present in it.

Resolver order (CLAUDE.md RULE 1): env override (`FORENSIA_<BIN>_BIN`, resolvable where
the api runs) → the declared maletín(es) in the catalog. RULE 2: the probe NEVER falls
back from one maletín to the other — a windows-only tool whose maletín is down is
unavailable, full stop; a Cross tool is reported per maletín it actually lives in.

The probe talks to the maletín through the host OCI client (`docker`/`podman`). The
current compose does NOT wire an api→maletín exec path (no docker socket in the api, no
exec-agent), so in the shipped stack the probe reports each maletín as *not consultable
from the api* with an actionable reason — the honest truth — instead of the old silent
"all tools false". Whenever the client IS reachable (a dev running the api on a host
with docker + the maletines up, or once the exec path is wired) the probe returns the
real per-tool status. Wiring that path is tracked in
docs/operacion/proximos-pasos.md §A/§B.
"""

from __future__ import annotations

import os
import subprocess
from typing import TYPE_CHECKING, Any

from forensia.toolkit.resolver import container_runtime, resolve

if TYPE_CHECKING:  # avoid an import cycle — snapshot() takes the catalog as an argument
    from collections.abc import Iterable

    from forensia.toolkit.tool import Tool

# Canonical maletín ids (also used by catalog.py `toolkits=`).
TOOLKIT_WINDOWS = "toolkit-windows"
TOOLKIT_UNIX = "toolkit-unix"
MALETINES: tuple[str, ...] = (TOOLKIT_UNIX, TOOLKIT_WINDOWS)

# compose service → default container_name (docker-compose.yml pins these). Overridable
# per-service via FORENSIA_TOOLKIT_WINDOWS_CONTAINER / FORENSIA_TOOLKIT_UNIX_CONTAINER
# so a non-default compose project name still resolves.
_DEFAULT_CONTAINER = {
    TOOLKIT_WINDOWS: "forensia-toolkit-windows",
    TOOLKIT_UNIX: "forensia-toolkit-unix",
}

# Probe subprocess budget: a maletín that does not answer quickly is treated as
# unreachable rather than blocking the capabilities snapshot.
_PROBE_TIMEOUT = 5


def container_name(service: str) -> str:
    if service not in _DEFAULT_CONTAINER:
        raise ValueError(f"unknown maletín service {service!r} (expected one of {MALETINES})")
    key = f"FORENSIA_{service.upper().replace('-', '_')}_CONTAINER"
    return os.environ.get(key) or _DEFAULT_CONTAINER[service]


def _run(argv: list[str]) -> subprocess.CompletedProcess:
    """Single shell-free choke point so tests can monkeypatch the OCI calls."""
    return subprocess.run(  # noqa: S603 — argv list, shell=False, no interpolation
        argv,
        capture_output=True,
        text=True,
        timeout=_PROBE_TIMEOUT,
        shell=False,
    )


def _no_client_reason() -> str:
    return (
        "el servicio api no puede consultar los maletines: no hay cliente OCI "
        "(docker/podman) ni un canal api→maletín cableado — ver "
        "docs/operacion/proximos-pasos.md §A/§B"
    )


def probe_service(service: str, *, client: str | None) -> dict[str, Any]:
    """Report whether a maletín container is running.

    `running` is True/False when we could ask, or None when the api has no way to
    consult the maletín (then `reason` names why).
    """
    name = container_name(service)
    base: dict[str, Any] = {"service": service, "container": name}
    if client is None:
        return {**base, "running": None, "reason": _no_client_reason()}
    try:
        proc = _run([client, "inspect", "-f", "{{.State.Running}}", name])
    except (OSError, subprocess.SubprocessError) as exc:
        return {**base, "running": None, "reason": f"no se pudo consultar '{name}': {type(exc).__name__}"}
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip().splitlines()
        why = detail[-1][:200] if detail else "contenedor no encontrado o daemon inaccesible"
        return {**base, "running": False, "reason": f"maletín '{name}' inaccesible: {why}"}
    running = proc.stdout.strip().lower() == "true"
    reason = None if running else f"maletín '{name}' existe pero no está en ejecución"
    return {**base, "running": running, "reason": reason}


def probe_binaries(service: str, binaries: Iterable[str], *, client: str) -> set[str] | None:
    """Return the subset of `binaries` present on PATH inside the maletín container.

    One `exec` per maletín (batched). Binaries are passed as positional args to an
    in-container `sh` (never interpolated into the command string). None if the exec
    itself could not run — the caller then reports the binaries as un-checkable.
    """
    names = list(binaries)
    if not names:
        return set()
    name = container_name(service)
    # The trailing `:` forces the script to exit 0 whatever the last `command -v` did —
    # a `for` loop otherwise inherits the status of its final iteration, so a missing
    # LAST binary would look like an exec failure. Binaries are positional args ($@),
    # never interpolated into the command string.
    argv = [
        client, "exec", name,
        "sh", "-c",
        'for b in "$@"; do command -v "$b" >/dev/null 2>&1 && printf "%s\\n" "$b"; done; :',
        "sh", *names,
    ]
    try:
        proc = _run(argv)
    except (OSError, subprocess.SubprocessError):
        return None
    # A non-zero code now means `docker exec` itself could not launch (container not
    # running, 125/126/127) — we could not check, so the caller degrades truthfully.
    if proc.returncode != 0:
        return None
    return {line.strip() for line in proc.stdout.splitlines() if line.strip()}


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

    Probes each maletín once and batches the binary check per running maletín, so a
    snapshot costs at most 2 `inspect` + 2 `exec` calls (and zero when the api has no
    OCI client). Takes the catalog as an argument to avoid an import cycle.
    """
    tools = list(catalog)
    runtime = container_runtime()
    client = str(runtime) if runtime is not None else None

    services = {svc: probe_service(svc, client=client) for svc in MALETINES}

    present: dict[str, set[str] | None] = {}
    if client is not None:
        for svc, info in services.items():
            if info["running"]:
                wanted = sorted({t.binary for t in tools if svc in t.toolkits})
                present[svc] = probe_binaries(svc, wanted, client=client)

    return {
        "client": client is not None,
        "services": services,
        "tools": {t.id: _tool_status(t, services, present) for t in tools},
    }
