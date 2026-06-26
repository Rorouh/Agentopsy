"""The Tool contract and the ONLY sanctioned way to execute one.

Security (THREAT_MODEL gates 5-7):
- The LLM never emits a command string; it picks a Tool.id (closed enum) + typed params.
- `run_argv` refuses anything but a list and always runs with shell=False.
- Big outputs are returned as an artifact reference, not as text in the model's context.

Delivery (CLAUDE.md RULE 1):
- Each tool declares per-host-OS how it reaches the user: `bundled` (vendored binary or
  inside the PyInstaller sidecar) or `container` (OCI image executed via the host runtime).
- Tools with no viable native build on a given OS (e.g. EvtxECmd on Linux/Mac) are
  declared as `container` for that OS only.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

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
    tier: Tier = "extended"
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


def run_argv(argv: list[str], *, cwd: str | None = None, timeout: int | None = None):
    """Execute a fully-resolved argv array. shell-free by construction."""
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        raise TypeError("argv must be a list[str] — never a shell string")
    return subprocess.run(  # noqa: S603 — shell=False, argv is validated above
        argv,
        cwd=cwd,
        timeout=timeout,
        capture_output=True,
        text=True,
        shell=False,
    )
