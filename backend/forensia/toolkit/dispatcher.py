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
    - the literal argv is recorded as ``tool_run_start`` in the per-case append-only
      audit log *before* the runner is invoked; controlled completion and failure paths
      attempt at most one ``tool_run_finish`` (transport/timeout errors invent no exit
      code, and a finish-append failure is propagated without retry), and
    - the returned dict carries ``case_id``, ``run_id`` and the established successful
      ``artifact_run`` projection. The storage API exposes the full canonical manifest.

When ``case_id`` is ``None``, any case-scoped input/output is rejected. Only tools with
no case path, or an exact bundled/runtime identifier, can reach a runner unanchored.
"""

from __future__ import annotations

import hmac
import inspect
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from forensia.artifact_ref import is_artifact_ref, validate_artifact_ref
from forensia.artifacts.store import ArtifactIntegrityError, artifact_store
from forensia.audit.log import AuditLog
from forensia.cases.manager import case_manager
from forensia.path_policy import (
    PathPolicyError,
    PathRole,
    generated_run_output,
    map_exact_identifier,
    resolve_existing_confined_path,
)
from forensia.toolkit import maletin
from forensia.toolkit.catalog import BY_ID
from forensia.toolkit.resolver import resolve
from forensia.toolkit.tool import Tool, run_argv


class ToolExecutionError(RuntimeError):
    """Raised when a tool cannot be executed (not when it runs and fails — that
    case returns a non-zero exit_code in the result dict)."""


_PENDING_OUTPUT_DIR = "__forensia_pending_output_dir__"


# Filename, inside the run's ``out/`` dir, that receives the raw stdout of a
# ``binary_stdout`` tool. It is hashed by the artifact store like any other output file.
_BINARY_STDOUT_FILENAME = "stdout.bin"


# EWF containers (Expert Witness Format): the first segment is ``.E01`` and EWF/EWFX
# segmented sets use ``.E02…`` / ``.Ex01…``. TSK does not read these natively, so the
# maletín exposes them as a raw block device via ``ewfmount`` around the run. Matched on
# the copied evidence's suffix (``original.E01``). Case-insensitive.
_EWF_SUFFIX_RE = re.compile(r"^\.ex?\d{2}$", re.IGNORECASE)


def _is_ewf_path(path: str) -> bool:
    dot = path.rfind(".")
    return dot != -1 and bool(_EWF_SUFFIX_RE.match(path[dot:]))


@dataclass(frozen=True)
class _PreparedExecution:
    """Literal argv plus its single, already-resolved execution venue."""

    argv: list[str]
    maletin_service: str | None
    # Set only for ``binary_stdout`` tools: the file (inside the run's ``out/``) the
    # runner must write the child's raw stdout to, instead of decoding it as text.
    stdout_path: str | None = None
    # Set only when the tool reads an EWF disk image (``.E01``) inside a maletín: the exact
    # argv token the exec-agent must expose as a raw block device via ``ewfmount`` (RO,
    # no filesystem mount) for the duration of the run, then unmount. ``None`` otherwise.
    ewf_image: str | None = None


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

    # A ``binary_stdout`` tool streams raw bytes; those bytes must land in a hashed
    # artifact file, which only exists for an anchored run. Refuse loudly rather than
    # fall back to a lossy text capture (RULE 2, FORENSIC INVARIANT 4).
    if tool.binary_stdout and case_id is None:
        raise ToolExecutionError(
            f"tool {tool_id!r} emite stdout binario y debe ejecutarse anclado a un caso "
            "(case_id) para que su salida se guarde y hashee como artefacto; no hay "
            "captura en texto para binario (RULE 2 / FORENSIC INVARIANT 4)."
        )

    # Validate caller-controlled params before allocating an ArtifactRun. Wrappers that
    # require the dispatcher-owned output_dir receive a non-executable marker during
    # this pure validation pass; the literal argv is built once the real run dir exists.
    run_id: str | None = None
    audit: AuditLog | None = None
    effective_params: dict[str, Any] = dict(params)
    binary_stdout_path: str | None = None
    # Derivation links (source artifact → this run) to record in ``tool_run_start``.
    derived_inputs = _gate_path_parameters(tool, effective_params, case_id)

    # If this tool reads a disk image and that image is an EWF container (`.E01`), the
    # maletín must expose it as a raw block device via `ewfmount` around the run. The api
    # decides (it holds the allowlist and the param) and names the EXACT argv token; the
    # exec-agent only mounts/rewrites/unmounts. A non-EWF image (raw/vmdk) → None, no change.
    ewf_image: str | None = None
    if tool.image_param is not None:
        candidate = effective_params.get(tool.image_param)
        if isinstance(candidate, str) and _is_ewf_path(candidate):
            ewf_image = candidate

    if case_id is not None:
        _validate_params_before_artifact(tool, effective_params)
        case_dir = case_manager.case_dir(case_id)
        audit = AuditLog(case_dir / "audit.jsonl")
        run_id, out_dir = artifact_store.start_run(case_id, tool_id, argv=[])
        _inject_run_outputs(tool, effective_params, out_dir)
        if tool.binary_stdout:
            binary_stdout_path = str(out_dir / _BINARY_STDOUT_FILENAME)

    try:
        argv_tail = _build_argv_tail(tool, effective_params)
        prepared = _prepare_execution(
            tool,
            argv_tail,
            os_profile=os_profile,
            stdout_path=binary_stdout_path,
            ewf_image=ewf_image,
        )
        if case_id is not None and run_id is not None:
            artifact_store.set_run_argv(case_id, run_id, prepared.argv)
    except Exception as exc:
        # No executable argv reached the audit log or runner. If a run had already
        # been allocated for output_dir, close it explicitly rather than leaving a
        # misleading in-flight manifest.
        if case_id is not None and run_id is not None:
            try:
                artifact_store.fail_run(
                    case_id,
                    run_id,
                    error_type=type(exc).__name__,
                    error_message=_exception_message(exc),
                )
            except Exception as close_exc:  # noqa: BLE001 — preserve the original failure
                exc.add_note(
                    "ArtifactRun could not be closed after pre-execution failure: "
                    f"{type(close_exc).__name__}: {close_exc}"
                )
        raise

    if case_id is None or run_id is None or audit is None:
        try:
            exit_code, stdout, stderr = _invoke_prepared(prepared, timeout=timeout)
        except maletin.MaletinExecError as exc:
            raise ToolExecutionError(str(exc)) from exc
        return _build_result(tool, prepared.argv, exit_code, stdout, stderr)

    # The literal command and its venue are fixed. Persist the start before crossing
    # the runner boundary so transport/exec-agent/process failures remain auditable.
    start_entry: dict[str, Any] = {
        "action": "tool_run_start",
        "case_id": case_id,
        "run_id": run_id,
        "tool_id": tool_id,
        "argv": prepared.argv,
        "params": _scrub_for_audit(effective_params),
    }
    # INVARIANT 4: record which prior artifact(s) fed this run (id, relpath, verified hash).
    if derived_inputs:
        start_entry["derived_inputs"] = derived_inputs
    try:
        audit.append(start_entry)
    except Exception as exc:  # noqa: BLE001 — execution is forbidden without durable start
        artifact_close_error: Exception | None = None
        try:
            artifact_store.fail_run(
                case_id,
                run_id,
                error_type=type(exc).__name__,
                error_message=_exception_message(exc),
            )
        except Exception as close_exc:  # noqa: BLE001 — preserve both actionable causes
            artifact_close_error = close_exc

        message = (
            f"could not persist tool_run_start for tool {tool_id!r} "
            f"({type(exc).__name__}): {_exception_message(exc)}; "
            "the tool was not executed"
        )
        if artifact_close_error is not None:
            message += (
                "; additionally, the ArtifactRun could not be closed "
                f"({type(artifact_close_error).__name__}): "
                f"{_exception_message(artifact_close_error)}"
            )
        raise ToolExecutionError(message) from exc

    try:
        exit_code, stdout, stderr = _invoke_prepared(prepared, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 — every post-start failure needs one closure
        error_type = type(exc).__name__
        error_message = _exception_message(exc)
        partial_stdout, partial_stderr = _partial_streams(exc)
        artifact_run = None
        artifact_close_error: Exception | None = None
        try:
            artifact_run = artifact_store.fail_run(
                case_id,
                run_id,
                error_type=error_type,
                error_message=error_message,
                stdout=partial_stdout,
                stderr=partial_stderr,
            )
        except Exception as close_exc:  # noqa: BLE001 — audit the runner failure regardless
            artifact_close_error = close_exc

        finish = {
            "action": "tool_run_finish",
            "case_id": case_id,
            "run_id": run_id,
            "status": "error",
            "exit_code": None,
            "error_type": error_type,
            "error_message": error_message,
            "stdout_sha256": artifact_run.stdout_sha256 if artifact_run else None,
            "stderr_sha256": artifact_run.stderr_sha256 if artifact_run else None,
            "output_files_count": len(artifact_run.output_files) if artifact_run else None,
        }
        if artifact_close_error is not None:
            finish["artifact_error_type"] = type(artifact_close_error).__name__
            finish["artifact_error_message"] = _exception_message(artifact_close_error)
        runner_error = _runner_error(tool, prepared, exc, artifact_close_error)
        _append_finish_or_raise(
            audit,
            finish,
            tool_id=tool_id,
            failure_context=str(runner_error),
            primary_error=exc,
        )
        raise runner_error from exc

    try:
        artifact_run = artifact_store.finalize_run(
            case_id,
            run_id,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
        )
    except Exception as exc:  # noqa: BLE001 — the start still requires one explicit closure
        failure_context = (
            f"tool {tool_id!r} returned exit_code {exit_code}, but its ArtifactRun "
            f"could not be finalized ({type(exc).__name__}): {_exception_message(exc)}"
        )
        _append_finish_or_raise(
            audit,
            {
                "action": "tool_run_finish",
                "case_id": case_id,
                "run_id": run_id,
                "status": "error",
                "exit_code": exit_code,
                "error_type": type(exc).__name__,
                "error_message": _exception_message(exc),
                "stdout_sha256": None,
                "stderr_sha256": None,
                "output_files_count": None,
            },
            tool_id=tool_id,
            failure_context=failure_context,
            primary_error=exc,
        )
        raise ToolExecutionError(failure_context) from exc

    _append_finish_or_raise(
        audit,
        {
            "action": "tool_run_finish",
            "case_id": case_id,
            "run_id": run_id,
            "status": "finished",
            "exit_code": exit_code,
            "stdout_sha256": artifact_run.stdout_sha256,
            "stderr_sha256": artifact_run.stderr_sha256,
            "output_files_count": len(artifact_run.output_files),
        },
        tool_id=tool_id,
        failure_context=(
            f"tool {tool_id!r} already executed and its ArtifactRun was finalized "
            f"with exit_code {exit_code}"
        ),
    )

    result = _build_result(
        tool, prepared.argv, exit_code, stdout, stderr, artifact_run=artifact_run
    )
    result["case_id"] = case_id
    result["run_id"] = run_id
    artifact_result = asdict(artifact_run)
    # ``status`` / error detail extend the store contract, not the successful
    # execute() response. Preserve its established public shape for exit 0 and != 0.
    for internal_field in ("status", "error_type", "error_message"):
        artifact_result.pop(internal_field)
    result["artifact_run"] = artifact_result
    return result


def _gate_path_parameters(
    tool: Tool, params: dict[str, Any], case_id: str | None
) -> list[dict[str, Any]]:
    """Apply the Tool's declared path roles and canonicalize values in place."""
    links: list[dict[str, Any]] = []
    case_dir: Path | None = None
    for spec in tool.path_parameters:
        value = params.get(spec.name)
        if PathRole.RUN_OUTPUT in spec.roles:
            if spec.name in params:
                raise ToolExecutionError(
                    f"tool {tool.id!r}: {spec.name!r} is RUN_OUTPUT and is owned by "
                    "the dispatcher/ArtifactStore; callers may not override it"
                )
            if case_id is None:
                raise ToolExecutionError(
                    f"tool {tool.id!r}: RUN_OUTPUT {spec.name!r} requires case_id"
                )
            continue
        if value is None:
            if spec.required:
                raise ToolExecutionError(
                    f"tool {tool.id!r}: required path parameter {spec.name!r} is missing"
                )
            continue
        if is_artifact_ref(value):
            if PathRole.DERIVED_INPUT not in spec.roles:
                raise ToolExecutionError(
                    f"tool {tool.id!r}: {spec.name!r} does not accept DERIVED_INPUT refs"
                )
            if case_id is None:
                raise ToolExecutionError(
                    f"tool {tool.id!r}: DERIVED_INPUT {spec.name!r} requires case_id"
                )
            ref = validate_artifact_ref(value)
            links.append(_resolve_artifact_ref(spec.name, ref, case_id, params))
            continue
        if isinstance(value, dict):
            raise ToolExecutionError(
                f"tool {tool.id!r}: malformed artifact ref for {spec.name!r}; "
                "expected {run_id, relpath} with optional sha256 and size, and no "
                "unknown keys"
            )
        mapped = map_exact_identifier(spec, value)
        if mapped is not None:
            params[spec.name] = mapped
            continue
        mapped_only = all(
            role in (PathRole.BUNDLED_RULESET, PathRole.RUNTIME_DEVICE)
            for role in spec.roles
        )
        if mapped_only:
            allowed = [entry.id for entry in spec.bundled]
            raise ToolExecutionError(
                f"tool {tool.id!r}: invalid identifier for {spec.name!r}: {value!r}; "
                f"allowed exact ids: {allowed}"
            )
        concrete_roles = [
            role
            for role in spec.roles
            if role in (PathRole.EVIDENCE_INPUT, PathRole.CASE_INPUT)
        ]
        if len(concrete_roles) != 1:
            raise ToolExecutionError(
                f"tool {tool.id!r}: {spec.name!r} has no unambiguous string-path role"
            )
        if case_id is None:
            raise ToolExecutionError(
                f"tool {tool.id!r}: case-scoped path {spec.name!r} requires case_id"
            )
        if case_dir is None:
            case_dir = case_manager.case_dir(case_id)
        root = (
            case_dir / "evidence"
            if concrete_roles[0] is PathRole.EVIDENCE_INPUT
            else case_dir
        )
        try:
            resolved = resolve_existing_confined_path(
                value, root=root, kind=spec.kind, parameter=spec.name
            )
            artifacts_root = (case_dir / "artifacts").resolve()
            if (
                concrete_roles[0] is PathRole.CASE_INPUT
                and (resolved == artifacts_root or artifacts_root in resolved.parents)
            ):
                raise PathPolicyError(
                    f"{spec.name}: paths under artifacts/ are DERIVED_INPUT and must "
                    "be supplied as exactly {run_id, relpath} for re-hash"
                )
            params[spec.name] = str(resolved)
        except PathPolicyError as exc:
            raise ToolExecutionError(f"tool {tool.id!r}: {exc}") from exc
    return links


def _resolve_artifact_ref(
    name: str, ref: dict[str, Any], case_id: str, params: dict[str, Any]
) -> dict[str, Any]:
    try:
        path, sha256, size = artifact_store.resolve_output_file(
            case_id, ref["run_id"], ref["relpath"]
        )
    except ArtifactIntegrityError as exc:
        raise ToolExecutionError(
            f"input derivado para {name!r}: {exc} — custodia rota; no se ejecuta"
        ) from exc
    except (KeyError, ValueError) as exc:
        raise ToolExecutionError(
            f"input derivado para {name!r}: no se pudo resolver {ref!r} en el caso "
            f"{case_id!r} ({type(exc).__name__}: {exc})"
        ) from exc
    advertised_sha256 = ref.get("sha256")
    if advertised_sha256 is not None and not hmac.compare_digest(
        advertised_sha256.casefold(), sha256.casefold()
    ):
        raise ToolExecutionError(
            f"input derivado para {name!r}: ArtifactRef sha256 no coincide con el "
            "SHA-256 autoritativo re-hasheado por ArtifactStore; no se ejecuta"
        )
    advertised_size = ref.get("size")
    if advertised_size is not None and advertised_size != size:
        raise ToolExecutionError(
            f"input derivado para {name!r}: ArtifactRef size={advertised_size} no "
            f"coincide con el tamaño autoritativo {size} de ArtifactStore; no se ejecuta"
        )
    params[name] = str(path)
    return {
        "param": name,
        "source_run_id": ref["run_id"],
        "relpath": ref["relpath"],
        "sha256": sha256,
        "size": size,
        "resolved_path": str(path),
    }


def _inject_run_outputs(tool: Tool, params: dict[str, Any], out_dir: Path) -> None:
    for spec in tool.path_parameters:
        if PathRole.RUN_OUTPUT in spec.roles:
            params[spec.name] = str(generated_run_output(spec, out_dir))


def _binary_artifact_ref(artifact_run: Any | None) -> dict[str, Any]:
    """Reference to the hashed stdout artifact a ``binary_stdout`` tool produced.

    Shaped EXACTLY like the artifact-ref a downstream tool consumes as input
    (``{run_id, relpath}``) plus its verified ``sha256``/``size``, so the agent can hand
    ``icat``'s output straight to a consumer (RegRipper) without inventing a path.
    """
    if artifact_run is None:
        return {"artifact": None}
    match = next(
        (of for of in artifact_run.output_files if of.relpath == _BINARY_STDOUT_FILENAME),
        None,
    )
    return {
        "artifact": {
            "run_id": artifact_run.run_id,
            "relpath": _BINARY_STDOUT_FILENAME,
            "sha256": match.sha256 if match else None,
            "size": match.size if match else None,
        }
    }


def _validate_params_before_artifact(tool: Tool, params: dict[str, Any]) -> None:
    """Run wrapper validation before allocating an anchored ArtifactRun.

    ``build_argv`` is a pure validation/assembly contract and anchored runs call it
    twice. Dispatcher-owned RUN_OUTPUT params receive a marker in this first pass;
    it is never resolved, audited or run.
    """
    validation_params = dict(params)
    for spec in tool.path_parameters:
        if PathRole.RUN_OUTPUT in spec.roles:
            validation_params[spec.name] = _PENDING_OUTPUT_DIR
    _build_argv_tail(tool, validation_params)


def _build_argv_tail(tool: Tool, params: dict[str, Any]) -> list[str]:
    argv_tail = tool.build_argv(params)
    if not isinstance(argv_tail, list) or not all(isinstance(a, str) for a in argv_tail):
        raise ToolExecutionError(
            f"tool {tool.id!r} build_argv returned a non-list[str]: "
            f"{type(argv_tail).__name__}"
        )
    return argv_tail


def _prepare_execution(
    tool: Tool,
    argv_tail: list[str],
    *,
    os_profile: str | None,
    stdout_path: str | None = None,
    ewf_image: str | None = None,
) -> _PreparedExecution:
    """Resolve one venue and construct the exact argv without invoking a runner."""
    binary_path = resolve(tool.binary)
    if binary_path is not None:
        # api-PATH venue (dev only): no exec-agent to run ewfmount in, so EWF is not
        # rewritten here — TSK would fail loud on a `.E01` with its own "Unsupported image
        # type" (RULE 2: no silent raw treatment). The product path is the maletín below.
        return _PreparedExecution(
            argv=[str(binary_path), *argv_tail],
            maletin_service=None,
            stdout_path=stdout_path,
        )

    service = _select_maletin(tool, os_profile)
    return _PreparedExecution(
        argv=[tool.binary, *argv_tail],
        maletin_service=service,
        stdout_path=stdout_path,
        ewf_image=ewf_image,
    )


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


def _invoke_prepared(
    prepared: _PreparedExecution, *, timeout: int | None
) -> tuple[int, str, str]:
    """Cross the runner boundary for an already-fixed literal argv and venue."""
    # `stdout_path` (binary_stdout tools only) and `ewf_image` (EWF disk tools in a maletín
    # only) are threaded conditionally so text tools — and every existing runner stub — keep
    # their unchanged (service, argv, timeout) call.
    extra = {} if prepared.stdout_path is None else {"stdout_path": prepared.stdout_path}
    if prepared.maletin_service is not None:
        if prepared.ewf_image is not None:
            extra["ewf_image"] = prepared.ewf_image
        return maletin.run_argv_in_maletin(
            prepared.maletin_service,
            prepared.argv,
            timeout=timeout,
            **extra,
        )
    completed = run_argv(prepared.argv, timeout=timeout, **extra)
    return completed.returncode, completed.stdout, completed.stderr


def _exception_message(exc: BaseException) -> str:
    return str(exc) or repr(exc)


def _append_finish_or_raise(
    audit: AuditLog,
    finish: dict[str, Any],
    *,
    tool_id: str,
    failure_context: str,
    primary_error: Exception | None = None,
) -> None:
    """Attempt one finish append and surface uncertainty without retrying.

    An append may have reached the file before its flush/fsync reports failure, so
    retrying could duplicate the closure. When another failure led here, retain it
    as the Python cause and include the append failure in the actionable message.
    """
    try:
        audit.append(finish)
    except Exception as append_exc:  # noqa: BLE001 — every finish append is controlled
        message = (
            f"{failure_context}; could not persist tool_run_finish for tool "
            f"{tool_id!r} ({type(append_exc).__name__}): "
            f"{_exception_message(append_exc)}; the tool was not re-executed "
            "and the finish append was not retried"
        )
        raise ToolExecutionError(message) from (primary_error or append_exc)


def _stream_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return ""


def _partial_streams(exc: BaseException) -> tuple[str, str]:
    """Return subprocess timeout captures when available; transports have none."""
    if isinstance(exc, subprocess.TimeoutExpired):
        return _stream_text(exc.stdout), _stream_text(exc.stderr)
    return "", ""


def _runner_error(
    tool: Tool,
    prepared: _PreparedExecution,
    exc: Exception,
    artifact_close_error: Exception | None,
) -> ToolExecutionError:
    """Translate a runner exception while retaining it as the Python cause."""
    if isinstance(exc, maletin.MaletinExecError):
        message = str(exc)
    elif isinstance(exc, subprocess.TimeoutExpired):
        message = (
            f"tool {tool.id!r} timed out after {exc.timeout}s while executing "
            f"{prepared.argv[0]!r}"
        )
    else:
        venue = prepared.maletin_service or "api-local"
        message = (
            f"tool {tool.id!r} runner failed in {venue!r} "
            f"({type(exc).__name__}): {_exception_message(exc)}"
        )
    if artifact_close_error is not None:
        message += (
            "; additionally, ArtifactRun closure failed "
            f"({type(artifact_close_error).__name__}): "
            f"{_exception_message(artifact_close_error)}"
        )
    return ToolExecutionError(message)


def _parse_wants_stderr(parse_fn: Any) -> bool:
    """True when a wrapper's ``parse`` accepts a second positional arg (stderr).

    Wrappers whose useful summary lands on stderr (chainsaw) opt in by declaring
    ``parse(stdout, stderr)``; the default ``parse(stdout)`` keeps working unchanged.
    """
    try:
        params = inspect.signature(parse_fn).parameters
    except (TypeError, ValueError):
        return False
    positional = [
        p
        for p in params.values()
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
    ]
    return len(positional) >= 2


def _build_result(
    tool: Tool,
    argv: list[str],
    exit_code: int,
    stdout: str,
    stderr: str,
    *,
    artifact_run: Any | None = None,
) -> dict[str, Any]:
    parsed: Any | None = None
    if tool.binary_stdout:
        # A binary_stdout tool streamed its RAW bytes to a hashed artifact file, so
        # ``stdout`` is "" here. Surface the artifact REFERENCE — never ``parse("")``,
        # which (e.g. icat) reports ``content_length: 0`` and misreads as "the tool
        # returned nothing". Only on success: a non-zero exit is a real failure.
        if exit_code == 0:
            parsed = _binary_artifact_ref(artifact_run)
    elif exit_code == 0:
        try:
            # Bug 007: algunas tools (chainsaw) emiten su resumen por STDERR, no stdout.
            # Los wrappers que necesitan stderr declaran `parse(stdout, stderr)`; el resto
            # sigue con `parse(stdout)`. Elegimos por aridad para no romper el contrato.
            if _parse_wants_stderr(tool.parse):
                parsed = tool.parse(stdout, stderr)
            else:
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
