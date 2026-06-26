"""End-to-end dispatcher: from `(tool_id, params)` to a parsed result.

Glue between the catalog, the resolver, the bundled runner (`run_argv`) and the
container runner (`run_in_container`). The agent never invokes a tool directly —
it picks a tool id from `BY_ID` and passes typed params; this dispatcher does the
rest (CLAUDE.md RULE 3: surfaces stay thin, logic in `forensia/toolkit`).
"""

from __future__ import annotations

from typing import Any

from forensia.toolkit.catalog import BY_ID
from forensia.toolkit.container import run_in_container
from forensia.toolkit.resolver import current_host_os, resolve
from forensia.toolkit.tool import Tool, run_argv


class ToolExecutionError(RuntimeError):
    """Raised when a tool cannot be executed (not when it runs and fails — that
    case returns a non-zero exit_code in the result dict)."""


def execute(tool_id: str, params: dict[str, Any], *, timeout: int | None = None) -> dict[str, Any]:
    """Resolve, run, and parse a tool by id. Returns a result dict.

    The result is structured for the audit log: it includes the literal argv that
    was executed (not the LLM's stated intent), exit code, stdout/stderr samples,
    and the parsed structured output when the tool succeeded.
    """
    tool = BY_ID.get(tool_id)
    if tool is None:
        raise ToolExecutionError(f"unknown tool id: {tool_id!r}")

    argv_tail = tool.build_argv(params)
    if not isinstance(argv_tail, list) or not all(isinstance(a, str) for a in argv_tail):
        raise ToolExecutionError(
            f"tool {tool_id!r} build_argv returned a non-list[str]: {type(argv_tail).__name__}"
        )

    host = current_host_os()
    mode = tool.delivery_for(host)

    if mode == "bundled":
        return _run_bundled(tool, argv_tail, timeout=timeout)
    if mode == "container":
        return _run_container(tool, argv_tail, params, timeout=timeout)
    raise ToolExecutionError(
        f"tool {tool_id!r} has no delivery declared for host {host!r}"
    )


def _run_bundled(tool: Tool, argv_tail: list[str], *, timeout: int | None) -> dict[str, Any]:
    binary_path = resolve(tool.binary)
    if binary_path is None:
        raise ToolExecutionError(
            f"bundled binary {tool.binary!r} for tool {tool.id!r} is not resolvable "
            f"(env override / vendor / PATH all empty)"
        )
    argv = [str(binary_path), *argv_tail]
    result = run_argv(argv, timeout=timeout)
    return _build_result(tool, argv, result.returncode, result.stdout, result.stderr)


def _run_container(
    tool: Tool, argv_tail: list[str], params: dict[str, Any], *, timeout: int | None
) -> dict[str, Any]:
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
    return _build_result(tool, argv_tail, result.returncode, result.stdout, result.stderr)


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
