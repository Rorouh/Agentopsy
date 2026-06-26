"""End-to-end dispatcher: from `(tool_id, params)` to a parsed result.

Glue between the catalog, the resolver, the bundled runner (`run_argv`) and the
container runner (`run_in_container`). The agent never invokes a tool directly —
it picks a tool id from `BY_ID` and passes typed params; this dispatcher does the
rest (CLAUDE.md RULE 3: surfaces stay thin, logic in `forensia/toolkit`).

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
from forensia.toolkit.catalog import BY_ID
from forensia.toolkit.container import run_in_container
from forensia.toolkit.resolver import current_host_os, resolve
from forensia.toolkit.tool import Tool, run_argv


class ToolExecutionError(RuntimeError):
    """Raised when a tool cannot be executed (not when it runs and fails — that
    case returns a non-zero exit_code in the result dict)."""


def execute(
    tool_id: str,
    params: dict[str, Any],
    *,
    case_id: str | None = None,
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

    host = current_host_os()
    mode = tool.delivery_for(host)

    if mode == "bundled":
        argv, exit_code, stdout, stderr = _run_bundled(tool, argv_tail, timeout=timeout)
    elif mode == "container":
        argv, exit_code, stdout, stderr = _run_container(
            tool, argv_tail, effective_params, timeout=timeout
        )
    else:
        # If we reserved a run slot, the caller will see no finalized artifact — but
        # we leave the directory in place rather than half-clean it, so the failure
        # is auditable.
        raise ToolExecutionError(
            f"tool {tool_id!r} has no delivery declared for host {host!r}"
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
            f"(env override / vendor / PATH all empty)"
        )
    argv = [str(binary_path), *argv_tail]
    result = run_argv(argv, timeout=timeout)
    return argv, result.returncode, result.stdout, result.stderr


def _run_container(
    tool: Tool,
    argv_tail: list[str],
    params: dict[str, Any],
    *,
    timeout: int | None,
) -> tuple[list[str], int, str, str]:
    if tool.host_mounts is None:
        raise ToolExecutionError(
            f"container tool {tool.id!r} lacks a host_mounts callable in the catalog"
        )
    mounts_ro, mounts_rw = tool.host_mounts(params)
    result = run_in_container(
        tool,
        argv_inside=argv_tail,
        mounts_ro=mounts_ro,
        mounts_rw=mounts_rw,
        timeout=timeout,
    )
    # For the audit log we record the argv as it ran inside the container; the host
    # command (docker run ...) is bookkeeping and lives at run_in_container's level.
    return argv_tail, result.returncode, result.stdout, result.stderr


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
