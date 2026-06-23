"""The Tool contract and the ONLY sanctioned way to execute one.

Security (THREAT_MODEL gates 5-7):
- The LLM never emits a command string; it picks a Tool.id (closed enum) + typed params.
- `run_argv` refuses anything but a list and always runs with shell=False.
- Big outputs are returned as an artifact reference, not as text in the model's context.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

ReturnKind = Literal["inline", "artifact"]
OsProfile = Literal["unix", "windows"]


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
    build_argv: Callable[[dict[str, Any]], list[str]] = _not_built
    parse: Callable[[str], Any] = _not_built


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
