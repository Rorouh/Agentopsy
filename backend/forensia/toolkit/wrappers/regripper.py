"""RegRipper wrapper — run a plugin against a pre-extracted Windows registry hive.

Container-only delivery (`forensia/regripper:latest`). FORENSIC_SOUNDNESS §5 forbids
mounting the raw image inside the container, so the caller must pre-extract the hive
(TSK `icat` on the host) and provide the path to the resulting file. The wrapper then
mounts that single file read-only at `/in/hive` inside the container.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

ALLOWED_FLAGS = frozenset({"-r", "-p", "-l", "-f"})

_PLUGIN_NAME_MAX = 64


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for rip.pl as it runs INSIDE the container.

    params:
        hive_path (str, required for plugin/profile runs): host path to the
            pre-extracted hive. The wrapper mounts it as `/in/hive` read-only.
        plugin (str, optional): name of a single RegRipper plugin to run.
        profile (str, optional): name of a plugin profile (`-f`).
        list (bool, optional): `True` to list plugins; ignores other params.
    """
    if params.get("list"):
        return ["-l"]

    hive_path = params.get("hive_path")
    if not hive_path or not isinstance(hive_path, str):
        raise ValueError("regripper requires params.hive_path: str (a pre-extracted hive)")

    plugin = params.get("plugin")
    profile = params.get("profile")
    if plugin and profile:
        raise ValueError("regripper: pass either 'plugin' or 'profile', not both")

    argv = ["-r", "/in/hive"]
    if plugin:
        if not _is_valid_plugin_name(plugin):
            raise ValueError(f"invalid regripper plugin name: {plugin!r}")
        argv += ["-p", plugin]
    elif profile:
        if not _is_valid_plugin_name(profile):
            raise ValueError(f"invalid regripper profile name: {profile!r}")
        argv += ["-f", profile]
    return argv


def parse(stdout: str) -> dict[str, Any]:
    """RegRipper writes plain text; structure varies by plugin.

    The wrapper returns the raw text plus a few summary signals the agent can use
    without re-parsing.
    """
    lines = stdout.splitlines()
    return {
        "raw": stdout,
        "lines": len(lines),
        "looks_empty": all(not ln.strip() or ln.startswith("Launching") for ln in lines),
    }


def host_mounts(params: dict[str, Any]) -> tuple[dict[Path, str], dict[Path, str]]:
    """Mounts for `container.run_in_container`: read-only hive, no writable volume."""
    if params.get("list"):
        return ({}, {})
    hive = Path(params["hive_path"]).resolve()
    return ({hive: "/in/hive"}, {})


def _is_valid_plugin_name(name: str) -> bool:
    if not name or len(name) > _PLUGIN_NAME_MAX:
        return False
    return all(c.isalnum() or c in {"_", "-"} for c in name)
