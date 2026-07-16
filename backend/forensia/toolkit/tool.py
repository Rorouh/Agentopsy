"""The Tool contract and the ONLY sanctioned way to execute one.

Security (THREAT_MODEL gates 5-7):
- The LLM never emits a command string; it picks a Tool.id (closed enum) + typed params.
- `run_argv` refuses anything but a list and always runs with shell=False.
- Big outputs are returned as an artifact reference, not as text in the model's context.

Delivery (CLAUDE.md RULE 1):
- The physical home of every tool is one or both compose maletines: `toolkits`
  declares which maletín image(s) — `toolkit-windows` / `toolkit-unix` — carry the
  binary. Cross tools (in the shared `base` stage) live in BOTH; OS-specific artifacts
  live in one. `forensia.toolkit.maletin` probes those services and is what
  `capabilities` reports.
- The legacy `delivery` (per-host-OS `bundled` | `container`) + `container_image` fields
  drive the not-yet-realigned dispatcher execution path (per-tool OCI images). Unifying
  execution onto the maletines is tracked in docs/operacion/proximos-pasos.md §A/§B.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from forensia.path_policy import PathParameter, PathRole

ReturnKind = Literal["inline", "artifact"]
OsProfile = Literal["unix", "windows"]
HostOs = Literal["linux", "mac", "windows"]
DeliveryMode = Literal["bundled", "container"]
Tier = Literal["core", "extended"]

# Pre-canned delivery declarations. Tuples (not dicts) so Tool stays hashable
# under @dataclass(frozen=True).
DELIVERY_ALL_BUNDLED: tuple[tuple[HostOs, DeliveryMode], ...] = (
    ("linux", "bundled"),
    ("mac", "bundled"),
    ("windows", "bundled"),
)
DELIVERY_ALL_CONTAINER: tuple[tuple[HostOs, DeliveryMode], ...] = (
    ("linux", "container"),
    ("mac", "container"),
    ("windows", "container"),
)
DELIVERY_WINDOWS_NATIVE: tuple[tuple[HostOs, DeliveryMode], ...] = (
    ("linux", "container"),
    ("mac", "container"),
    ("windows", "bundled"),
)


def _not_built(*_args, **_kwargs):
    raise NotImplementedError("tool wrapper not implemented yet (skeleton)")


@dataclass(frozen=True)
class Tool:
    id: str
    binary: str
    os_profiles: tuple[OsProfile, ...]
    returns: ReturnKind = "inline"
    side_effecting: bool = False
    allowed_flags: frozenset[str] = field(default_factory=frozenset)
    delivery: tuple[tuple[HostOs, DeliveryMode], ...] = DELIVERY_ALL_BUNDLED
    container_image: str | None = None
    # Which compose maletín image(s) physically carry this tool's binary. Values are
    # maletín ids ("toolkit-windows" / "toolkit-unix"); a Cross tool declares both.
    # `forensia.toolkit.maletin` probes these; `capabilities` reports them. RULE 2:
    # a tool is NEVER resolved against a maletín it does not declare here.
    toolkits: tuple[str, ...] = ()
    tier: Tier = "extended"
    # The tool streams RAW BINARY to stdout (e.g. TSK `icat` extracting a file's bytes).
    # Its stdout must NOT be decoded as text — the transport captures it to a file inside
    # the run's ``out/`` directory (hashed there, FORENSIC INVARIANT 4) instead of carrying
    # it as a (lossy) string. Text tools keep the default and are unaffected.
    binary_stdout: bool = False
    # Name of a param whose truthiness makes THIS invocation stream stdout to the same
    # hashed ``out/`` artifact file as ``binary_stdout`` — for DUAL-MODE tools whose stdout
    # is an inline result in one mode and a consumable artifact in another. TSK ``fls``
    # lists files inline normally, but with ``-m`` (``body_format``) its stdout IS the
    # bodyfile that ``mactime`` consumes as a ``{run_id, relpath}`` input; captured to
    # ``out/`` it becomes referenceable and hash-verified (FORENSIC INVARIANTS 1-2, 4)
    # instead of living only in the lossy text ``stdout_sample``. ``None`` → stdout capture
    # is decided solely by ``binary_stdout`` (default, unchanged).
    stdout_artifact_param: str | None = None
    # Name of the param that carries the RAW DISK IMAGE path this tool reads (TSK
    # `mmls`/`fls`/`icat` → ``"image_path"``). When that path is an EWF container
    # (`.E01`/`.ExNN`), the dispatcher asks the maletín's exec-agent to expose it as a raw
    # block device via ``ewfmount`` (FUSE, read-only, no filesystem mount — FORENSIC
    # INVARIANT 3) for the duration of the run. ``None`` → the tool consumes no disk image,
    # so no EWF handling (default, unchanged).
    image_param: str | None = None
    # Params that MAY be given as a DERIVED-ARTIFACT reference (`{"run_id", "relpath"}`)
    # instead of a literal path — the "derived handoff": a downstream tool consuming a
    # file a previous run produced (RegRipper over a hive TSK ``icat`` extracted →
    # ``("hive_path",)``). The dispatcher resolves such a ref to the artifact's on-disk
    # path inside the case and RE-HASHES it against the producing run's manifest before
    # ``build_argv`` (custody of derivatives, FORENSIC INVARIANTS 1-2), recording the
    # derivation link in the audit (INVARIANT 4). Literal strings are accepted only when
    # the corresponding path role also declares EVIDENCE_INPUT or CASE_INPUT.
    input_artifact_params: tuple[str, ...] = ()
    # Closed declaration of every filesystem path carried in params. The dispatcher
    # enforces it before crossing the runner boundary; schemas and wrappers consume it.
    path_parameters: tuple[PathParameter, ...] = ()
    build_argv: Callable[[dict[str, Any]], list[str]] = _not_built
    parse: Callable[[str], Any] = _not_built
    # Container-delivered tools set this so the executor knows what to mount.
    # Returns (read-only mounts, read-write mounts). None for bundled tools.
    host_mounts: Callable[[dict[str, Any]], tuple[dict, dict]] | None = None

    def delivery_for(self, host: HostOs) -> DeliveryMode | None:
        for h, mode in self.delivery:
            if h == host:
                return mode
        return None

    def __post_init__(self) -> None:
        names = [spec.name for spec in self.path_parameters]
        if len(names) != len(set(names)):
            raise ValueError(f"tool {self.id!r} declares duplicate path parameters")
        declared_derived = {
            spec.name
            for spec in self.path_parameters
            if PathRole.DERIVED_INPUT in spec.roles
        }
        if set(self.input_artifact_params) != declared_derived:
            raise ValueError(
                f"tool {self.id!r}: input_artifact_params must match DERIVED_INPUT "
                f"declarations ({sorted(declared_derived)})"
            )
        if self.image_param is not None and self.image_param not in names:
            raise ValueError(
                f"tool {self.id!r}: image_param {self.image_param!r} lacks a path declaration"
            )


def run_argv(
    argv: list[str],
    *,
    cwd: str | None = None,
    timeout: int | None = None,
    stdout_path: str | None = None,
):
    """Execute a fully-resolved argv array. shell-free by construction.

    Default: capture stdout+stderr as decoded text (the common case). When
    ``stdout_path`` is given, the child's stdout is written as RAW BYTES to that file
    (never decoded) — the binary-safe path for tools like TSK ``icat`` whose stdout is
    a file's exact bytes. stderr is still captured as text. The returned
    ``CompletedProcess.stdout`` is then ``""`` (the payload lives on disk).
    """
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        raise TypeError("argv must be a list[str] — never a shell string")
    if stdout_path is None:
        return subprocess.run(  # noqa: S603 — shell=False, argv is validated above
            argv,
            cwd=cwd,
            timeout=timeout,
            capture_output=True,
            text=True,
            shell=False,
        )
    with open(stdout_path, "wb") as stdout_file:  # noqa: PTH123 — need a real fd for the child
        completed = subprocess.run(  # noqa: S603 — shell=False, argv is validated above
            argv,
            cwd=cwd,
            timeout=timeout,
            stdout=stdout_file,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            shell=False,
        )
    return subprocess.CompletedProcess(argv, completed.returncode, "", completed.stderr)
