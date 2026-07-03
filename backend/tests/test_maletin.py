"""Unit tests for the maletín availability probe (forensia.toolkit.maletin).

The probe is what `capabilities` reports (CLAUDE.md RULE 1). Two invariants matter
most here and are pinned below:

- **Truthful degradation**: when the api has no OCI client / no way to reach a maletín,
  the probe says so with an actionable reason — it never guesses availability.
- **RULE 2 (no fallback between maletines)**: a tool is only ever resolved against the
  maletín(es) it declares. A windows-only tool whose maletín is down stays unavailable
  even if the *other* maletín is up and happens to carry the same binary.

Every subprocess call goes through `maletin._run`, monkeypatched here so no test needs
docker or a running maletín.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from forensia.toolkit import maletin
from forensia.toolkit.maletin import TOOLKIT_UNIX, TOOLKIT_WINDOWS
from forensia.toolkit.tool import Tool


def _proc(returncode: int = 0, stdout: str = "", stderr: str = "") -> SimpleNamespace:
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


# --------------------------------------------------------------------------- #
# container_name
# --------------------------------------------------------------------------- #
def test_container_name_defaults_match_compose() -> None:
    assert maletin.container_name(TOOLKIT_WINDOWS) == "forensia-toolkit-windows"
    assert maletin.container_name(TOOLKIT_UNIX) == "forensia-toolkit-unix"


def test_container_name_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORENSIA_TOOLKIT_UNIX_CONTAINER", "proj_toolkit-unix_1")
    assert maletin.container_name(TOOLKIT_UNIX) == "proj_toolkit-unix_1"


def test_container_name_rejects_unknown_service() -> None:
    with pytest.raises(ValueError, match="unknown maletín service"):
        maletin.container_name("toolkit-solaris")


# --------------------------------------------------------------------------- #
# probe_service
# --------------------------------------------------------------------------- #
def test_probe_service_without_client_is_unknown_with_actionable_reason() -> None:
    out = maletin.probe_service(TOOLKIT_WINDOWS, client=None)
    assert out["running"] is None
    assert "proximos-pasos" in out["reason"]
    assert out["container"] == "forensia-toolkit-windows"


def test_probe_service_running(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(maletin, "_run", lambda argv: _proc(0, "true\n"))
    out = maletin.probe_service(TOOLKIT_UNIX, client="/usr/bin/docker")
    assert out["running"] is True
    assert out["reason"] is None


def test_probe_service_stopped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(maletin, "_run", lambda argv: _proc(0, "false\n"))
    out = maletin.probe_service(TOOLKIT_UNIX, client="/usr/bin/docker")
    assert out["running"] is False
    assert "no está en ejecución" in out["reason"]


def test_probe_service_absent_container(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        maletin, "_run", lambda argv: _proc(1, "", "Error: No such object: forensia-toolkit-unix")
    )
    out = maletin.probe_service(TOOLKIT_UNIX, client="/usr/bin/docker")
    assert out["running"] is False
    assert "inaccesible" in out["reason"]


def test_probe_service_timeout_is_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(argv: list[str]):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=5)

    monkeypatch.setattr(maletin, "_run", _boom)
    out = maletin.probe_service(TOOLKIT_UNIX, client="/usr/bin/docker")
    assert out["running"] is None
    assert "TimeoutExpired" in out["reason"]


# --------------------------------------------------------------------------- #
# probe_binaries
# --------------------------------------------------------------------------- #
def test_probe_binaries_parses_present_set(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, list[str]] = {}

    def fake_run(argv: list[str]) -> SimpleNamespace:
        captured["argv"] = argv
        return _proc(0, "fls\nvol\n")  # the absent one (hayabusa, LAST) is simply not echoed

    monkeypatch.setattr(maletin, "_run", fake_run)
    found = maletin.probe_binaries(TOOLKIT_UNIX, ["fls", "vol", "hayabusa"], client="/usr/bin/docker")
    assert found == {"fls", "vol"}
    # The in-container script must force exit 0 (trailing `:`) so a MISSING LAST binary
    # is not mistaken for an exec failure. Binaries travel as positional args, not text.
    script = captured["argv"][captured["argv"].index("-c") + 1]
    assert script.rstrip().endswith(":"), "script must end with `:` to force exit 0"
    assert captured["argv"][-3:] == ["fls", "vol", "hayabusa"]


def test_probe_binaries_empty_input_skips_exec(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fail(argv: list[str]):
        raise AssertionError("must not exec for an empty binary list")

    monkeypatch.setattr(maletin, "_run", _fail)
    assert maletin.probe_binaries(TOOLKIT_UNIX, [], client="/usr/bin/docker") == set()


def test_probe_binaries_exec_failure_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(maletin, "_run", lambda argv: _proc(126, "", "exec failed"))
    assert maletin.probe_binaries(TOOLKIT_UNIX, ["fls"], client="/usr/bin/docker") is None


# --------------------------------------------------------------------------- #
# _tool_status — RULE 1 order + RULE 2 no-fallback
# --------------------------------------------------------------------------- #
def _win_tool() -> Tool:
    return Tool("hayabusa", "hayabusa", ("windows",), toolkits=(TOOLKIT_WINDOWS,))


def _cross_tool() -> Tool:
    return Tool("fls", "fls", ("unix", "windows"), toolkits=(TOOLKIT_UNIX, TOOLKIT_WINDOWS))


def test_env_override_wins_over_maletin(monkeypatch: pytest.MonkeyPatch) -> None:
    # RULE 1 order: a binary resolvable where the api runs is available outright.
    monkeypatch.setattr(maletin, "resolve", lambda binary: "/opt/bin/hayabusa")
    out = maletin._tool_status(_win_tool(), services={}, present={})
    assert out["available"] is True
    assert out["via"] == "env-override-or-api-path"


def test_rule2_no_fallback_between_maletines(monkeypatch: pytest.MonkeyPatch) -> None:
    """A windows-only tool must NOT be reported available just because toolkit-unix is
    up and carries a same-named binary — the unix maletín is never consulted for it."""
    monkeypatch.setattr(maletin, "resolve", lambda binary: None)
    services = {
        TOOLKIT_WINDOWS: {"service": TOOLKIT_WINDOWS, "container": "c-win", "running": False,
                          "reason": "maletín 'c-win' existe pero no está en ejecución"},
        TOOLKIT_UNIX: {"service": TOOLKIT_UNIX, "container": "c-unix", "running": True, "reason": None},
    }
    present = {TOOLKIT_UNIX: {"hayabusa"}}  # present in the WRONG maletín
    out = maletin._tool_status(_win_tool(), services=services, present=present)
    assert out["available"] is False
    assert TOOLKIT_UNIX not in out["detail"]  # unix maletín never inspected for it
    assert set(out["detail"]) == {TOOLKIT_WINDOWS}


def test_cross_tool_available_if_present_in_any_declared_maletin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(maletin, "resolve", lambda binary: None)
    services = {
        TOOLKIT_UNIX: {"service": TOOLKIT_UNIX, "container": "c-unix", "running": True, "reason": None},
        TOOLKIT_WINDOWS: {"service": TOOLKIT_WINDOWS, "container": "c-win", "running": False,
                          "reason": "down"},
    }
    present = {TOOLKIT_UNIX: {"fls"}}
    out = maletin._tool_status(_cross_tool(), services=services, present=present)
    assert out["available"] is True
    assert out["detail"][TOOLKIT_UNIX]["binary_present"] is True


def test_binary_absent_in_running_maletin_reports_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(maletin, "resolve", lambda binary: None)
    services = {
        TOOLKIT_WINDOWS: {"service": TOOLKIT_WINDOWS, "container": "c-win", "running": True, "reason": None},
    }
    present = {TOOLKIT_WINDOWS: set()}  # running, but binary not installed
    out = maletin._tool_status(_win_tool(), services=services, present=present)
    assert out["available"] is False
    assert "ausente" in out["reason"]


def test_tool_without_declared_toolkit_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(maletin, "resolve", lambda binary: None)
    orphan = Tool("orphan", "orphan", ("unix",), toolkits=())
    out = maletin._tool_status(orphan, services={}, present={})
    assert out["available"] is False
    assert "no declara maletín" in out["reason"]


# --------------------------------------------------------------------------- #
# snapshot — end to end with a faked OCI client
# --------------------------------------------------------------------------- #
def test_snapshot_without_client_probes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(maletin, "container_runtime", lambda: None)
    monkeypatch.setattr(maletin, "resolve", lambda binary: None)

    def _fail(argv: list[str]):
        raise AssertionError("no OCI client → must not run any subprocess")

    monkeypatch.setattr(maletin, "_run", _fail)

    snap = maletin.snapshot([_win_tool(), _cross_tool()])
    assert snap["client"] is False
    assert all(svc["running"] is None for svc in snap["services"].values())
    assert snap["tools"]["hayabusa"]["available"] is False
    assert "proximos-pasos" in snap["tools"]["hayabusa"]["reason"]


def test_snapshot_reports_real_presence_when_maletines_up(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(maletin, "container_runtime", lambda: "/usr/bin/docker")
    monkeypatch.setattr(maletin, "resolve", lambda binary: None)

    def fake_run(argv: list[str]) -> SimpleNamespace:
        if "inspect" in argv:
            return _proc(0, "true\n")  # both maletines running
        if "exec" in argv:
            # Emulate `command -v` loop: echo whichever wanted binaries "exist". The
            # wanted names are the positional args after the inner-`sh` $0 placeholder
            # (the LAST "sh" token — argv is [..., "-c", LOOP, "sh", *names]).
            last_sh = len(argv) - 1 - argv[::-1].index("sh")
            wanted = argv[last_sh + 1 :]
            installed = {"fls", "vol", "hayabusa"}
            return _proc(0, "\n".join(b for b in wanted if b in installed) + "\n")
        raise AssertionError(f"unexpected argv: {argv}")

    monkeypatch.setattr(maletin, "_run", fake_run)

    win, cross = _win_tool(), _cross_tool()
    snap = maletin.snapshot([win, cross])
    assert snap["client"] is True
    assert snap["services"][TOOLKIT_WINDOWS]["running"] is True
    assert snap["tools"]["hayabusa"]["available"] is True
    assert snap["tools"]["hayabusa"]["via"] == "maletin"
    assert snap["tools"]["fls"]["available"] is True
