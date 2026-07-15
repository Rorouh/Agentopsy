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

# Hard ceiling the exec-agent applies to a single tool run — MUST mirror `_MAX_TIMEOUT_S`
# in docker/docker/forensic-toolkit/exec_agent.py. A `timeout=None` from the api runs
# bounded by THIS ceiling inside the maletín (never unbounded), so a run can never exceed
# it. A test pins the mirror so drift in either file is caught.
_EXEC_AGENT_MAX_TIMEOUT = 1800
# Extra wall-clock the HTTP client waits ON TOP of the exec-agent's effective ceiling, so
# the exec-agent ALWAYS kills the child, hashes its stdout and replies BEFORE the transport
# gives up. Without this margin the client could disconnect while the maletín process is
# still writing, and the dispatcher would hash a still-mutating artifact (INVARIANT 4).
# Explicit constant, no silent default (RULE 2).
_HTTP_TIMEOUT_MARGIN = 60


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
    service: str,
    argv: list[str],
    *,
    timeout: float | None = None,
    stdout_path: str | None = None,
    ewf_image: str | None = None,
) -> tuple[int, str, str]:
    """Run a fully-resolved argv inside a maletín via its exec-agent `POST /exec`.

    `argv` is `[binary, *args]` as the tool sees it inside the maletín — paths must
    reference the maletín's mounts (`/evidence` ro, `/cases`), which are the SAME host
    dirs the api mounts, so no path translation is needed. Returns (exit, stdout, stderr).
    Raises `MaletinExecError` when the exec-agent cannot be reached / is not configured;
    a tool that runs and fails returns a non-zero exit code (not an exception).

    Binary-safe mode (`stdout_path`): for tools whose stdout is RAW BINARY (TSK `icat`),
    the exec-agent writes the child's stdout CRUDO to `stdout_path` — a path inside the
    shared `/cases` mount, so the api reads the exact same file — and answers with its
    SHA-256/size instead of a (lossy) text field. The returned stdout is then `""`; the
    payload lives on disk, where the api re-hashes it as an artifact (INVARIANT 4).

    EWF mode (`ewf_image`): TSK cannot read a `.E01` natively. When `ewf_image` names the
    exact argv token holding the EWF path, the exec-agent exposes it as a raw block device
    via `ewfmount` (FUSE, read-only, no filesystem mount — INVARIANT 3) for the duration of
    the run, rewrites that token to the raw `ewf1`, and unmounts always. If `ewfmount`/FUSE
    is unavailable the exec-agent answers non-200 naming the dependency, surfaced here as a
    `MaletinExecError` — never a silent raw treatment of the `.E01` (RULE 2).
    """
    base_url = service_url(service)
    if not base_url:
        raise MaletinExecError(_no_url_reason(service))
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise MaletinExecError("argv debe ser una list[str] no vacía (shell-free)")
    # The exec-agent caps this run at `min(timeout, ceiling)` (or the ceiling itself when
    # the api passes no timeout — see `_EXEC_AGENT_MAX_TIMEOUT`). Wait strictly longer so
    # the exec-agent ALWAYS finishes first: it kills the child, hashes stdout and replies
    # before the transport gives up. This is what keeps the dispatcher from ever hashing an
    # artifact while the maletín process is still writing to it (INVARIANT 4). RULE 2: the
    # bound is an explicit constant, never an implicit "trip early and retry".
    effective_ceiling = (
        _EXEC_AGENT_MAX_TIMEOUT
        if timeout is None
        else min(float(timeout), _EXEC_AGENT_MAX_TIMEOUT)
    )
    http_timeout = effective_ceiling + _HTTP_TIMEOUT_MARGIN
    request_body: dict[str, Any] = {"argv": argv, "timeout": timeout}
    if stdout_path is not None:
        request_body["stdout_path"] = stdout_path
    if ewf_image is not None:
        request_body["ewf_image"] = ewf_image
    try:
        status, body = _request(
            "POST", f"{base_url}/exec", request_body, timeout=http_timeout
        )
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise MaletinExecError(
            f"no se pudo ejecutar en el exec-agent {base_url} ({type(exc).__name__}): {exc}"
        ) from exc
    if status != 200 or not isinstance(body, dict) or "exit" not in body:
        # The exec-agent names an actionable reason (e.g. ewfmount/FUSE missing) in `error`;
        # carry it through so the operator sees the concrete dependency, not just a status.
        detail = body.get("error") if isinstance(body, dict) else None
        raise MaletinExecError(
            f"el exec-agent {base_url} devolvió una respuesta inesperada (estado {status})"
            + (f": {detail}" if detail else "")
        )
    # P0.5-4 (FORENSIC INVARIANT 4): the argv the maletín ACTUALLY launched must match
    # the argv the api audited — identical without EWF, and differing ONLY in the
    # ``ewf_image`` token(s) rewritten to the raw ``ewf1`` block when EWF routing ran.
    # The exec-agent is not trusted blindly: a divergence here is a custody violation
    # and the run is closed as an error, never accepted.
    _verify_executed_argv(base_url, argv, body.get("executed_argv"), ewf_image)
    if stdout_path is not None:
        # Binary-safe: stdout went to `stdout_path` on the shared mount, not over the wire.
        return int(body["exit"]), "", str(body.get("stderr", ""))
    return int(body["exit"]), str(body.get("stdout", "")), str(body.get("stderr", ""))


def _verify_executed_argv(
    base_url: str,
    requested: list[str],
    executed: object,
    ewf_image: str | None,
) -> None:
    """Token-by-token proof that the maletín executed EXACTLY the audited argv.

    Contract (P0.5-4): every 200 from ``POST /exec`` carries ``executed_argv`` — the
    literal list the exec-agent passed to ``subprocess.run``. Without ``ewf_image`` it
    must equal the requested argv verbatim. With it, every position whose requested
    token equals ``ewf_image`` must be rewritten — all to the SAME absolute raw block
    whose basename is ``ewf1`` (what ``ewfmount`` exposes; never a filesystem mount,
    FORENSIC INVARIANT 3) — and every other token must be untouched. Anything else
    (missing field, length drift, altered token, unrewritten EWF token, a rewrite that
    is not the raw block) raises ``MaletinExecError``: the caller closes the run as an
    error and the artifact is never trusted (RULE 2 — no "probably fine").
    """
    if not isinstance(executed, list) or not all(isinstance(t, str) for t in executed):
        raise MaletinExecError(
            f"el exec-agent {base_url} no devolvió 'executed_argv' (o no es list[str]) — "
            "la imagen del maletín es anterior al contrato P0.5-4; reconstruye con "
            "docker compose build. Sin el argv ejecutado no se puede verificar que el "
            "maletín corrió el comando auditado (FORENSIC INVARIANT 4)."
        )
    if len(executed) != len(requested):
        raise MaletinExecError(
            f"custodia rota: el exec-agent {base_url} ejecutó un argv de "
            f"{len(executed)} tokens cuando el auditado tiene {len(requested)} — "
            "el comando ejecutado no es el registrado (FORENSIC INVARIANT 4)."
        )
    rewrites: set[str] = set()
    for index, (req, got) in enumerate(zip(requested, executed)):
        if ewf_image is not None and req == ewf_image:
            if got == req:
                raise MaletinExecError(
                    f"custodia rota: el exec-agent {base_url} no reescribió el token "
                    f"EWF (posición {index}) — la tool habría leído el contenedor "
                    ".E01 directamente, que TSK no interpreta (RULE 2: el routing "
                    "EWF no puede degradarse en silencio)."
                )
            if not got.startswith("/") or got.rsplit("/", 1)[-1] != "ewf1":
                raise MaletinExecError(
                    f"custodia rota: el exec-agent {base_url} reescribió el token EWF "
                    f"(posición {index}) a {got!r}, que no es el bloque raw 'ewf1' "
                    "absoluto que expone ewfmount — reescritura no reconocida "
                    "(FORENSIC INVARIANT 3/4)."
                )
            rewrites.add(got)
        elif got != req:
            raise MaletinExecError(
                f"custodia rota: el exec-agent {base_url} ejecutó un argv distinto "
                f"del auditado (posición {index}: se auditó {req!r}, se ejecutó "
                f"{got!r}) — FORENSIC INVARIANT 4; el resultado no se acepta."
            )
    if ewf_image is not None:
        if not rewrites:
            raise MaletinExecError(
                f"custodia rota: se pidió routing EWF para {ewf_image!r} pero ese "
                f"token no aparece en el argv auditado — bug del llamador; el "
                f"exec-agent {base_url} no pudo haberlo reescrito."
            )
        if len(rewrites) > 1:
            raise MaletinExecError(
                f"custodia rota: el exec-agent {base_url} reescribió el token EWF a "
                f"rutas distintas en posiciones distintas ({sorted(rewrites)}) — "
                "reescritura inconsistente (FORENSIC INVARIANT 4)."
            )


# Version identities the manifest must never contain: they carry no reproducibility
# information and would silently satisfy the "a version exists" contract (RULE 2).
_FORBIDDEN_VERSION_VALUES = frozenset({"", "unknown", "latest", "null", "none"})


def _is_forbidden_version(version: str) -> bool:
    """True for placeholder identities — whole-string OR embedded as a token
    ("hayabusa latest" is as unreproducible as "latest")."""
    lowered = version.strip().lower()
    if lowered in _FORBIDDEN_VERSION_VALUES:
        return True
    return any(token in _FORBIDDEN_VERSION_VALUES for token in lowered.split())


def tool_versions(service: str) -> dict[str, str]:
    """The maletín's IMMUTABLE build-time version manifest, via ``GET /versions``.

    The manifest (``versions.json``) is generated during the image build — the build
    FAILS if any declared tool lacks a deterministic, non-empty version — and served by
    the exec-agent as a closed, allowlisted map ``{binary: version}``. Raises
    ``MaletinExecError`` (never a placeholder) when the URL is not configured, the
    transport fails, or the manifest is missing/corrupt (RULE 2: no fallback).
    """
    base_url = service_url(service)
    if not base_url:
        raise MaletinExecError(_no_url_reason(service))
    try:
        status, body = _request("GET", f"{base_url}/versions")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise MaletinExecError(
            f"no se pudo consultar el manifiesto de versiones del exec-agent "
            f"{base_url} ({type(exc).__name__}): {exc}"
        ) from exc
    versions = body.get("versions") if isinstance(body, dict) else None
    if status != 200 or not isinstance(versions, dict):
        detail = body.get("error") if isinstance(body, dict) else None
        raise MaletinExecError(
            f"el exec-agent {base_url} no sirvió un manifiesto de versiones válido "
            f"(estado {status})" + (f": {detail}" if detail else "")
            + " — reconstruye el maletín (docker compose build) para hornear "
            "versions.json (RULE 1)."
        )
    for binary, version in versions.items():
        if (
            not isinstance(binary, str)
            or not isinstance(version, str)
            or _is_forbidden_version(version)
        ):
            raise MaletinExecError(
                f"el manifiesto de versiones de {service} contiene una entrada "
                f"inválida ({binary!r}: {version!r}) — manifiesto corrupto; "
                "reconstruye el maletín."
            )
    return {binary: version.strip() for binary, version in versions.items()}


def tool_version(service: str, binary: str) -> str:
    """Authoritative version of ``binary`` in ``service``'s build manifest.

    Fails loud when the manifest does not name the binary — a tool without a version
    identity must not execute anchored (FORENSIC INVARIANT 4); there is no probe-and-
    fallback and no cross-maletín lookup (RULE 2).
    """
    versions = tool_versions(service)
    version = versions.get(binary)
    if version is None:
        raise MaletinExecError(
            f"el manifiesto de versiones de {service} no contiene el binario "
            f"{binary!r} — la tool no tiene identidad de versión en ese maletín; "
            "alinea docker/docker/forensic-toolkit/tool-binaries.json con el catálogo "
            "y reconstruye la imagen (RULE 2: sin versión no hay ejecución anclada)."
        )
    return version


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
    versions: dict[str, dict[str, str] | None],
) -> dict[str, Any]:
    """Per-tool availability from pre-probed service + binary-presence maps.

    RULE 1 order: an env override / api-PATH resolution wins outright. RULE 2: only the
    tool's OWN declared maletines are ever consulted; a Cross tool is `available` when
    its binary is confirmed in AT LEAST ONE of the maletines it lives in (genuine
    per-profile routing, not a fallback).

    ``version`` reports the tool's build-manifest version identity (or ``None`` with
    the reason in ``version_reason``): an available binary WITHOUT a version identity
    cannot run anchored (INVARIANT 4), and this snapshot says so explicitly.
    """
    toolkits = list(tool.toolkits)

    if resolve(tool.binary) is not None:
        return {
            "available": True,
            "toolkits": toolkits,
            "via": "env-override-or-api-path",
            "reason": None,
            "version": None,
            "version_reason": (
                "vía api-PATH/env-override: sin manifiesto de versiones de build — "
                "las ejecuciones ancladas a caso exigen el maletín (INVARIANT 4)"
            ),
            "detail": {},
        }

    if not toolkits:
        return {
            "available": False,
            "toolkits": [],
            "via": None,
            "reason": f"'{tool.id}' no declara maletín (toolkits vacío)",
            "version": None,
            "version_reason": None,
            "detail": {},
        }

    detail: dict[str, Any] = {}
    reasons: list[str] = []
    any_present = False
    seen_versions: set[str] = set()
    version_reasons: list[str] = []
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
        service_versions = versions.get(service)
        service_version = (
            service_versions.get(tool.binary) if service_versions is not None else None
        )
        detail[service] = {
            "running": True,
            "binary_present": is_present,
            "reason": None if is_present else f"binario '{tool.binary}' ausente en {service}",
            "version": service_version,
        }
        if is_present:
            any_present = True
            if service_version is not None:
                seen_versions.add(service_version)
            elif service_versions is None:
                version_reasons.append(
                    f"{service}: manifiesto de versiones no disponible (reconstruye el maletín)"
                )
            else:
                version_reasons.append(
                    f"{service}: '{tool.binary}' sin identidad de versión en el manifiesto"
                )
        else:
            reasons.append(f"{service}: binario '{tool.binary}' ausente")

    version: str | None = None
    version_reason: str | None = None
    if any_present:
        if len(seen_versions) == 1 and not version_reasons:
            version = next(iter(seen_versions))
        elif len(seen_versions) > 1:
            version_reason = (
                f"versiones divergentes entre maletines: {sorted(seen_versions)}"
            )
        else:
            version_reason = "; ".join(version_reasons) or None

    return {
        "available": any_present,
        "toolkits": toolkits,
        "via": "maletin" if any_present else None,
        "reason": None if any_present else "; ".join(reasons),
        "version": version,
        "version_reason": version_reason,
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
    versions: dict[str, dict[str, str] | None] = {}
    for svc, info in services.items():
        if info["running"]:
            wanted = sorted({t.binary for t in tools if svc in t.toolkits})
            present[svc] = probe_binaries(svc, wanted, base_url=urls[svc])
            # Version identities from the maletín's baked build manifest. A maletín
            # without a (valid) manifest reports None — each affected tool then carries
            # an explicit `version_reason` instead of a made-up value (RULE 2).
            try:
                versions[svc] = tool_versions(svc)
            except MaletinExecError:
                versions[svc] = None

    return {
        # True when at least one maletín exec-agent URL is configured — i.e. the api has
        # a channel to consult the maletines at all. Per-maletín reachability is in
        # `services`.
        "client": any_url,
        "services": services,
        "tools": {t.id: _tool_status(t, services, present, versions) for t in tools},
    }
