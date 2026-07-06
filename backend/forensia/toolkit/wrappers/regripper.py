"""RegRipper wrapper — run a plugin against a pre-extracted Windows registry hive.

Runs `rip.pl` inside the `toolkit-windows` maletín via the exec-agent. FORENSIC_SOUNDNESS
§5 forbids mounting the raw image inside the container, so the caller must pre-extract the
hive (TSK `icat`) and pass the path to the resulting file (already under the read-only
`/evidence` mount); the argv references that path directly.
"""

from __future__ import annotations

from typing import Any

ALLOWED_FLAGS = frozenset({"-r", "-p", "-l", "-f"})

_PLUGIN_NAME_MAX = 64


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for rip.pl as it runs INSIDE the container.

    params:
        hive_path (str, required for plugin/profile runs): path to the pre-extracted
            hive under the maletín's read-only `/evidence` mount; passed to `-r`.
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

    argv = ["-r", hive_path]
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


def _is_valid_plugin_name(name: str) -> bool:
    if not name or len(name) > _PLUGIN_NAME_MAX:
        return False
    return all(c.isalnum() or c in {"_", "-"} for c in name)
