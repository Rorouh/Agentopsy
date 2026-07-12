"""Central filesystem-path policy for forensic tool parameters.

The catalog declares every path-bearing parameter explicitly. Surfaces may reject a
bad request earlier, but the dispatcher is the mandatory enforcement point before any
runner or audit ``tool_run_start`` boundary is crossed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePath, PurePosixPath
from typing import Any

from forensia.artifact_ref import is_artifact_ref


class PathRole(str, Enum):
    EVIDENCE_INPUT = "evidence_input"
    CASE_INPUT = "case_input"
    DERIVED_INPUT = "derived_input"
    RUN_OUTPUT = "run_output"
    BUNDLED_RULESET = "bundled_ruleset"
    RUNTIME_DEVICE = "runtime_device"


class PathKind(str, Enum):
    FILE = "file"
    DIRECTORY = "directory"
    FILE_OR_DIRECTORY = "file_or_directory"


@dataclass(frozen=True)
class BundledPath:
    id: str
    path: str

    def __post_init__(self) -> None:
        if not self.id or not isinstance(self.id, str):
            raise ValueError("bundled path id must be a non-empty string")
        if (
            not self.path
            or not isinstance(self.path, str)
            or not PurePosixPath(self.path).is_absolute()
        ):
            raise ValueError("bundled path must be an absolute, non-empty string")


@dataclass(frozen=True)
class PathParameter:
    name: str
    roles: tuple[PathRole, ...]
    kind: PathKind
    required: bool = True
    output_relpath: str | None = None
    bundled: tuple[BundledPath, ...] = ()

    def __post_init__(self) -> None:
        if not self.name or not isinstance(self.name, str):
            raise ValueError("path parameter name must be a non-empty string")
        if not self.roles or len(set(self.roles)) != len(self.roles):
            raise ValueError(f"path parameter {self.name!r} needs unique roles")
        output = PathRole.RUN_OUTPUT in self.roles
        mapped = any(
            role in self.roles
            for role in (PathRole.BUNDLED_RULESET, PathRole.RUNTIME_DEVICE)
        )
        if output != (self.output_relpath is not None):
            raise ValueError(
                f"path parameter {self.name!r}: RUN_OUTPUT requires output_relpath"
            )
        if mapped != bool(self.bundled):
            raise ValueError(
                f"path parameter {self.name!r}: mapped roles require an allowlist"
            )
        if output and len(self.roles) != 1:
            raise ValueError(f"RUN_OUTPUT parameter {self.name!r} cannot have another role")
        ids = [entry.id for entry in self.bundled]
        if len(ids) != len(set(ids)):
            raise ValueError(f"duplicate bundled id in path parameter {self.name!r}")
        if self.output_relpath is not None:
            rel = PurePath(self.output_relpath)
            if rel.is_absolute() or ".." in rel.parts:
                raise ValueError(f"unsafe output_relpath for {self.name!r}")


class PathPolicyError(ValueError):
    """A caller-controlled path violates its declared Tool role."""


_SENSITIVE_PARTS = frozenset(
    {
        ".ssh",
        ".aws",
        ".gnupg",
        ".kube",
        ".azure",
        ".codex",
        ".claude",
        ".gemini",
        "keychains",
        "host-creds",
        "forensia-cli-auth",
    }
)


def resolve_existing_confined_path(
    value: Any, *, root: Path, kind: PathKind, parameter: str
) -> Path:
    """Canonicalize an existing input and require it to remain under ``root``."""
    if not isinstance(value, str) or not value:
        raise PathPolicyError(f"{parameter}: path must be a non-empty string")
    raw = Path(value).expanduser()
    if ".." in raw.parts:
        raise PathPolicyError(f"{parameter}: path traversal ('..') is forbidden")
    if any(part.casefold() in _SENSITIVE_PARTS for part in raw.parts):
        raise PathPolicyError(
            f"{parameter}: sensitive directories are forbidden ({value!r})"
        )
    confined_root = root.resolve(strict=True)
    candidate = raw if raw.is_absolute() else confined_root / raw
    try:
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise PathPolicyError(
            f"{parameter}: input path must exist and be resolvable: {value!r}"
        ) from exc
    if resolved != confined_root and confined_root not in resolved.parents:
        raise PathPolicyError(
            f"{parameter}: path {value!r} resolves outside authorized root "
            f"{str(confined_root)!r} (resolved {str(resolved)!r})"
        )
    if kind is PathKind.FILE and not resolved.is_file():
        raise PathPolicyError(f"{parameter}: expected an existing file: {value!r}")
    if kind is PathKind.DIRECTORY and not resolved.is_dir():
        raise PathPolicyError(f"{parameter}: expected an existing directory: {value!r}")
    if kind is PathKind.FILE_OR_DIRECTORY and not (
        resolved.is_file() or resolved.is_dir()
    ):
        raise PathPolicyError(
            f"{parameter}: expected an existing file or directory: {value!r}"
        )
    return resolved


def map_exact_identifier(spec: PathParameter, value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    return next((entry.path for entry in spec.bundled if entry.id == value), None)


def generated_run_output(spec: PathParameter, out_dir: Path) -> Path:
    if PathRole.RUN_OUTPUT not in spec.roles or spec.output_relpath is None:
        raise PathPolicyError(f"{spec.name}: not declared as RUN_OUTPUT")
    root = out_dir.resolve(strict=True)
    target = (root / spec.output_relpath).resolve(strict=False)
    if target != root and root not in target.parents:
        raise PathPolicyError(f"{spec.name}: generated output escapes current run out/")
    return target


def inject_evidence_path(
    path_parameters: tuple[PathParameter, ...],
    params: dict[str, Any],
    evidence_path: str,
) -> dict[str, Any]:
    """Inject the single catalog-declared evidence input, rejecting caller overrides."""
    evidence_specs = [
        spec for spec in path_parameters if PathRole.EVIDENCE_INPUT in spec.roles
    ]
    if not evidence_specs:
        return params
    if len(evidence_specs) != 1:
        raise PathPolicyError(
            "automatic evidence injection requires exactly one EVIDENCE_INPUT parameter"
        )
    spec = evidence_specs[0]
    if spec.name in params:
        if (
            PathRole.DERIVED_INPUT in spec.roles
            and is_artifact_ref(params[spec.name])
        ):
            return params
        raise PathPolicyError(
            f"{spec.name}: caller/model may not choose an EVIDENCE_INPUT path; "
            "FORENSIA injects it from the selected evidence handle"
        )
    params[spec.name] = evidence_path
    return params


__all__ = [
    "BundledPath",
    "PathKind",
    "PathParameter",
    "PathPolicyError",
    "PathRole",
    "generated_run_output",
    "inject_evidence_path",
    "map_exact_identifier",
    "resolve_existing_confined_path",
]
