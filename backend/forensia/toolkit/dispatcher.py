"""End-to-end dispatcher: from `(tool_id, params)` to a parsed result.

Glue between the catalog, the resolver, the bundled runner (`run_argv`) and the maletín
exec-agent (`maletin.run_argv_in_maletin`, §B). The agent never invokes a tool directly —
it picks a tool id from `BY_ID` and passes typed params; this dispatcher does the rest
(CLAUDE.md RULE 3: surfaces stay thin, logic in `forensia/toolkit`). Execution venue is
the RULE 1 resolver order: a binary on the api's PATH (env override / dev) runs bundled;
otherwise it runs inside the tool's maletín via the exec-agent, chosen per `os_profile`
with no cross-maletín fallback (RULE 2).

When ``case_id`` is supplied, the run is anchored to that case:
    - an ``ArtifactRun`` is opened via ``artifact_store`` (output_dir injected
      into params if the wrapper expects one and the caller did not pre-fill it),
    - the literal argv + result are recorded in the per-case append-only audit log
      (``case_dir/audit.jsonl``), and
    - the returned dict carries ``case_id``, ``run_id`` and the full ``artifact_run``
      manifest so the caller can render/forward it.

When ``case_id`` is ``None`` the behaviour is identical to the original signature
``execute(tool_id, params)`` — used by the dev toolkit-tester panel.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from forensia.artifacts.store import artifact_store
from forensia.audit.log import AuditLog
from forensia.cases.manager import case_manager
from forensia.toolkit import maletin
from forensia.toolkit.catalog import BY_ID
from forensia.toolkit.resolver import resolve
from forensia.toolkit.tool import Tool, run_argv


class ToolExecutionError(RuntimeError):
    """Raised when a tool cannot be executed (not when it runs and fails — that
    case returns a non-zero exit_code in the result dict)."""


def execute(
    tool_id: str,
    params: dict[str, Any],
    *,
    case_id: str | None = None,
    os_profile: str | None = None,
    timeout: int | None = None,
) -> dict[str, Any]:
    """Resolve, run, and parse a tool by id. Returns a result dict.

    The result is structured for the audit log: it includes the literal argv that
    was executed (not the LLM's stated intent), exit code, stdout/stderr samples,
    and the parsed structured output when the tool succeeded.

    If ``case_id`` is provided, the dispatcher also opens an ``ArtifactRun`` and
    appends audit-log entries before/after execution; see module docstring.
    """
    tool = BY_ID.get(tool_id)
    if tool is None:
        raise ToolExecutionError(f"unknown tool id: {tool_id!r}")

    # If we're anchored to a case, we have to allocate the output directory BEFORE
    # asking the wrapper to build argv — some wrappers embed output_dir into the
    # argv array (e.g. bulk_extractor -o, EvtxECmd --csv). We open the run first,
    # inject the path, then build argv.
    run_id: str | None = None
    audit: AuditLog | None = None
    effective_params: dict[str, Any] = dict(params)

    if case_id is not None:
        case_dir = case_manager.case_dir(case_id)
        audit = AuditLog(case_dir / "audit.jsonl")
        # Pre-allocate the run with a placeholder argv; we patch it after build_argv
        # (the store keeps run_id stable, only the argv field is overwritten by the
        # finalize_run step using whatever the dispatcher actually ran).
        run_id, out_dir = artifact_store.start_run(case_id, tool_id, argv=[])
        # Only inject output_dir if the caller did not pre-fill it. That preserves
        # the contract of wrappers that explicitly accept output_dir as a param.
        if "output_dir" not in effective_params:
            effective_params["output_dir"] = str(out_dir)

    argv_tail = tool.build_argv(effective_params)
    if not isinstance(argv_tail, list) or not all(isinstance(a, str) for a in argv_tail):
        raise ToolExecutionError(
            f"tool {tool_id!r} build_argv returned a non-list[str]: {type(argv_tail).__name__}"
        )

    # Execution venue (RULE 1 resolver order): an env override / a binary on the api's
    # own PATH wins outright (dev / standalone). Otherwise the tool's binary lives inside
    # its maletín — run it there through the exec-agent (§B, docs/operacion/exec-agent.md).
    # The evidence (/cases, /evidence) is mounted at the SAME paths in api and maletín, so
    # the argv paths need no translation.
    if resolve(tool.binary) is not None:
        argv, exit_code, stdout, stderr = _run_bundled(tool, argv_tail, timeout=timeout)
    else:
        argv, exit_code, stdout, stderr = _run_maletin(
            tool, argv_tail, os_profile=os_profile, timeout=timeout
        )

    result = _build_result(tool, argv, exit_code, stdout, stderr)

    if case_id is None or run_id is None or audit is None:
        return result

    # Audit BEFORE finalize so a crash during finalize still leaves a record that
    # the tool actually ran. We record the literal argv (not the LLM's intent).
    audit.append(
        {
            "action": "tool_run_start",
            "case_id": case_id,
            "run_id": run_id,
            "tool_id": tool_id,
            "argv": argv,
            "params": _scrub_for_audit(effective_params),
        }
    )

    artifact_run = artifact_store.finalize_run(
        case_id,
        run_id,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
    )

    audit.append(
        {
            "action": "tool_run_finish",
            "case_id": case_id,
            "run_id": run_id,
            "exit_code": exit_code,
            "stdout_sha256": artifact_run.stdout_sha256,
            "stderr_sha256": artifact_run.stderr_sha256,
            "output_files_count": len(artifact_run.output_files),
        }
    )

    result["case_id"] = case_id
    result["run_id"] = run_id
    result["artifact_run"] = asdict(artifact_run)
    return result


def _run_bundled(
    tool: Tool, argv_tail: list[str], *, timeout: int | None
) -> tuple[list[str], int, str, str]:
    binary_path = resolve(tool.binary)
    if binary_path is None:
        raise ToolExecutionError(
            f"bundled binary {tool.binary!r} for tool {tool.id!r} is not resolvable "
            f"(env override / PATH both empty)"
        )
    argv = [str(binary_path), *argv_tail]
    result = run_argv(argv, timeout=timeout)
    return argv, result.returncode, result.stdout, result.stderr


def _select_maletin(tool: Tool, os_profile: str | None) -> str:
    """Which maletín runs `tool`, honouring RULE 2 (no fallback between maletines).

    - No declared maletín + not on the api PATH → nowhere to run (RULE 1).
    - os_profile given → the matching maletín, and only if the tool actually lives there.
    - No os_profile + a single declared maletín → that one.
    - No os_profile + several → refuse to guess (the caller must anchor the profile).
    """
    toolkits = tool.toolkits
    if not toolkits:
        raise ToolExecutionError(
            f"tool {tool.id!r}: su binario {tool.binary!r} no está en el PATH del api y no "
            f"declara maletín (toolkits vacío) — no hay dónde ejecutarlo (RULE 1)."
        )
    if os_profile is not None:
        expected = f"toolkit-{os_profile}"
        if expected in toolkits:
            return expected
        raise ToolExecutionError(
            f"tool {tool.id!r} no vive en el maletín del perfil {os_profile!r} "
            f"(está en {list(toolkits)}) — RULE 2: sin fallback entre maletines."
        )
    if len(toolkits) == 1:
        return toolkits[0]
    raise ToolExecutionError(
        f"tool {tool.id!r} vive en varios maletines {list(toolkits)}; indica os_profile "
        f"para elegir — RULE 2: el dispatcher no adivina."
    )


def _run_maletin(
    tool: Tool,
    argv_tail: list[str],
    *,
    os_profile: str | None,
    timeout: int | None,
) -> tuple[list[str], int, str, str]:
    """Run the tool inside its maletín via the exec-agent (§B). The recorded argv is
    `[binary, *args]` as it ran inside the maletín (FORENSIC INVARIANT 4: the literal
    command, not the transport)."""
    service = _select_maletin(tool, os_profile)
    argv = [tool.binary, *argv_tail]
    try:
        exit_code, stdout, stderr = maletin.run_argv_in_maletin(service, argv, timeout=timeout)
    except maletin.MaletinExecError as exc:
        raise ToolExecutionError(str(exc)) from exc
    return argv, exit_code, stdout, stderr


def _build_result(
    tool: Tool,
    argv: list[str],
    exit_code: int,
    stdout: str,
    stderr: str,
) -> dict[str, Any]:
    parsed: Any | None = None
    if exit_code == 0:
        try:
            parsed = tool.parse(stdout)
        except Exception as exc:  # noqa: BLE001 — parser bugs become structured errors, not crashes
            parsed = {"parse_error": f"{type(exc).__name__}: {exc}"}
    return {
        "tool_id": tool.id,
        "argv": argv,
        "exit_code": exit_code,
        "stdout_sample": stdout[:4000],
        "stderr_sample": stderr[:4000],
        "parsed": parsed,
    }


def _scrub_for_audit(params: dict[str, Any]) -> dict[str, Any]:
    """Coerce non-JSON-native values (Path, bytes) to strings so the audit log's
    canonical JSON serialization never fails mid-write."""
    scrubbed: dict[str, Any] = {}
    for k, v in params.items():
        if isinstance(v, (str, int, float, bool)) or v is None:
            scrubbed[k] = v
        elif isinstance(v, (list, tuple)):
            scrubbed[k] = [str(x) for x in v]
        elif isinstance(v, dict):
            scrubbed[k] = {str(kk): str(vv) for kk, vv in v.items()}
        else:
            scrubbed[k] = str(v)
    return scrubbed
