"""Execute a Tool inside its declared OCI image.

Security (THREAT_MODEL gates 5-7):
- Network: `--network none` by default — forensic tools must not phone home.
- Filesystem: only the explicit mounts pass through. The wrapper decides what enters
  the container; the agent never names paths directly.
- Argv: still a list[str], shell=False. The container is just the execution venue —
  it does not relax the argv contract enforced by `build_argv` / `allowed_flags`.

Evidence soundness (soundness-forense.md §5):
- A raw evidence image (`.raw`/`.dd`/`.img`/`.vmdk`/`.E01`/`.aff`) MUST NOT appear in
  any container mount, read-only or otherwise. On macOS/Windows the OCI runtime proxies
  through a journaling VM (HyperKit / WSL2) that can write to the underlying image and
  break the baseline hash. Wrappers pre-extract the artifacts they need on the host
  (TSK `icat` / `fls`) and pass only those derived files.
- This module enforces the constraint defensively via `_validate_mount_paths`.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from forensia.toolkit.resolver import container_runtime
from forensia.toolkit.tool import Tool

# Extensions of raw evidence containers that must never be mounted inside a container.
# This is a defence-in-depth check; the primary discipline lives in each wrapper.
_FORBIDDEN_EVIDENCE_SUFFIXES = frozenset(
    {".raw", ".dd", ".img", ".vmdk", ".vmem", ".e01", ".aff", ".lime", ".ad1"}
)


def _validate_mount_paths(mounts: dict[Path, str] | None, label: str) -> None:
    if not mounts:
        return
    for host_path in mounts:
        if not isinstance(host_path, Path):
            raise TypeError(f"{label} keys must be pathlib.Path instances")
        suffix = host_path.suffix.lower()
        if suffix in _FORBIDDEN_EVIDENCE_SUFFIXES:
            raise ValueError(
                f"refusing to mount raw evidence {host_path.name!r} inside the OCI "
                f"runtime (FORENSIC_SOUNDNESS §5). Pre-extract the artifacts on the "
                f"host (TSK icat / fls) and pass the derived files."
            )


def run_in_container(
    tool: Tool,
    *,
    argv_inside: list[str],
    mounts_ro: dict[Path, str] | None = None,
    mounts_rw: dict[Path, str] | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess:
    """Run `tool.container_image` with `argv_inside` against the host's OCI runtime.

    `argv_inside` is the argv as the tool sees it INSIDE the container — paths must
    reference the mount targets (e.g. `/in/hive`), not the host paths.
    """
    if not tool.container_image:
        raise ValueError(f"tool {tool.id!r} has no container_image declared")
    if not isinstance(argv_inside, list) or not all(
        isinstance(a, str) for a in argv_inside
    ):
        raise TypeError("argv_inside must be a list[str], never a shell string")

    runtime = container_runtime()
    if runtime is None:
        raise RuntimeError(
            "no OCI runtime (docker/podman/nerdctl) on PATH. "
            "Install one, see CLAUDE.md RULE 1."
        )

    _validate_mount_paths(mounts_ro, "mounts_ro")
    _validate_mount_paths(mounts_rw, "mounts_rw")

    argv: list[str] = [str(runtime), "run", "--rm", "--network", "none"]
    for host, target in (mounts_ro or {}).items():
        argv += ["-v", f"{host.resolve()}:{target}:ro"]
    for host, target in (mounts_rw or {}).items():
        argv += ["-v", f"{host.resolve()}:{target}"]
    argv += [tool.container_image, *argv_inside]

    return subprocess.run(  # noqa: S603 — argv assembled from validated components
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
    )
