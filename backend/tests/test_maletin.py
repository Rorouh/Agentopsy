"""Unit tests for the maletín availability probe (forensia.toolkit.maletin).

The probe is what `capabilities` reports (CLAUDE.md RULE 1). Two invariants matter
most here and are pinned below:

- **Truthful degradation**: when the api has no channel to a maletín (exec-agent URL not
  configured, or unreachable), the probe says so with an actionable reason — it never
  guesses availability.
- **RULE 2 (no fallback between maletines)**: a tool is only ever resolved against the
  maletín(es) it declares. A windows-only tool whose maletín is down stays unavailable
  even if the *other* maletín is up and happens to carry the same binary.

Since the §B wiring, the channel is the maletín **exec-agent** over HTTP (no host Docker
socket). Every HTTP call goes through `maletin._request`, monkeypatched here so no test
needs docker or a running maletín.
"""

from __future__ import annotations

import urllib.error

import pytest

from forensia.i18n import t
from forensia.toolkit import maletin
from forensia.toolkit.maletin import TOOLKIT_UNIX, TOOLKIT_WINDOWS
from forensia.toolkit.tool import Tool

_UNIX_URL = "http://toolkit-unix:8666"
_WIN_URL = "http://toolkit-windows:8666"


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
# service_url
# --------------------------------------------------------------------------- #
def test_service_url_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORENSIA_TOOLKIT_UNIX_URL", "http://toolkit-unix:8666/")
    # trailing slash trimmed
    assert maletin.service_url(TOOLKIT_UNIX) == "http://toolkit-unix:8666"


def test_service_url_absent_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FORENSIA_TOOLKIT_WINDOWS_URL", raising=False)
    assert maletin.service_url(TOOLKIT_WINDOWS) is None


# --------------------------------------------------------------------------- #
# probe_service
# --------------------------------------------------------------------------- #
def test_probe_service_without_url_is_unknown_with_actionable_reason() -> None:
    out = maletin.probe_service(TOOLKIT_WINDOWS, base_url=None)
    assert out["running"] is None
    assert "exec-agent" in out["reason"]
    assert out["container"] == "forensia-toolkit-windows"


def test_probe_service_running(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(maletin, "_request", lambda m, u, p=None: (200, {"ok": True, "stage": "unix"}))
    out = maletin.probe_service(TOOLKIT_UNIX, base_url=_UNIX_URL)
    assert out["running"] is True
    assert out["reason"] is None


def test_probe_service_error_status_is_inaccessible(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(maletin, "_request", lambda m, u, p=None: (503, {}))
    out = maletin.probe_service(TOOLKIT_UNIX, base_url=_UNIX_URL)
    assert out["running"] is False
    assert out["reason"] == t(
        "maletin.probeStatus",
        None,
        url="http://toolkit-unix:8666",
        status=503,
        name="forensia-toolkit-unix",
    )


def test_probe_service_transport_failure_is_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(method: str, url: str, payload=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(maletin, "_request", _boom)
    out = maletin.probe_service(TOOLKIT_UNIX, base_url=_UNIX_URL)
    assert out["running"] is None
    assert out["reason"].startswith(t("maletin.probeFailed", None, url="", error="", name="")[:16])


# --------------------------------------------------------------------------- #
# probe_binaries
# --------------------------------------------------------------------------- #
def test_probe_binaries_parses_present_set(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_request(method: str, url: str, payload=None):
        captured["method"] = method
        captured["url"] = url
        captured["payload"] = payload
        return 200, {"present": ["fls", "vol"]}  # hayabusa absent

    monkeypatch.setattr(maletin, "_request", fake_request)
    found = maletin.probe_binaries(TOOLKIT_UNIX, ["fls", "vol", "hayabusa"], base_url=_UNIX_URL)
    assert found == {"fls", "vol"}
    assert captured["method"] == "POST"
    assert captured["url"] == f"{_UNIX_URL}/which"
    assert captured["payload"] == {"binaries": ["fls", "vol", "hayabusa"]}


def test_probe_binaries_empty_input_skips_call(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fail(method: str, url: str, payload=None):
        raise AssertionError("must not call the exec-agent for an empty binary list")

    monkeypatch.setattr(maletin, "_request", _fail)
    assert maletin.probe_binaries(TOOLKIT_UNIX, [], base_url=_UNIX_URL) == set()


def test_probe_binaries_transport_failure_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(method: str, url: str, payload=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(maletin, "_request", _boom)
    assert maletin.probe_binaries(TOOLKIT_UNIX, ["fls"], base_url=_UNIX_URL) is None


def test_probe_binaries_error_status_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(maletin, "_request", lambda m, u, p=None: (500, {}))
    assert maletin.probe_binaries(TOOLKIT_UNIX, ["fls"], base_url=_UNIX_URL) is None


# --------------------------------------------------------------------------- #
# _tool_status — RULE 1 order + RULE 2 no-fallback (transport-independent)
# --------------------------------------------------------------------------- #
def _win_tool() -> Tool:
    return Tool("hayabusa", "hayabusa", ("windows",), toolkits=(TOOLKIT_WINDOWS,))


def _cross_tool() -> Tool:
    return Tool("fls", "fls", ("unix", "windows"), toolkits=(TOOLKIT_UNIX, TOOLKIT_WINDOWS))


def test_env_override_wins_over_maletin(monkeypatch: pytest.MonkeyPatch) -> None:
    # RULE 1 order: a binary resolvable where the api runs is available outright.
    monkeypatch.setattr(maletin, "resolve", lambda binary: "/opt/bin/hayabusa")
    out = maletin._tool_status(_win_tool(), services={}, present={}, versions={})
    assert out["available"] is True
    assert out["via"] == "env-override-or-api-path"
    # …but it has NO build-manifest version identity: anchored runs need the maletín.
    assert out["version"] is None
    assert out["version_reason"] == t("maletin.viaPathNoManifest")


def test_rule2_no_fallback_between_maletines(monkeypatch: pytest.MonkeyPatch) -> None:
    """A windows-only tool must NOT be reported available just because toolkit-unix is
    up and carries a same-named binary — the unix maletín is never consulted for it."""
    monkeypatch.setattr(maletin, "resolve", lambda binary: None)
    services = {
        TOOLKIT_WINDOWS: {"service": TOOLKIT_WINDOWS, "container": "c-win", "running": False,
                          "reason": "maletín 'c-win' inaccesible"},
        TOOLKIT_UNIX: {"service": TOOLKIT_UNIX, "container": "c-unix", "running": True, "reason": None},
    }
    present = {TOOLKIT_UNIX: {"hayabusa"}}  # present in the WRONG maletín
    out = maletin._tool_status(_win_tool(), services=services, present=present, versions={})
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
    versions = {TOOLKIT_UNIX: {"fls": "sleuthkit 4.12.1 (dpkg)"}}
    out = maletin._tool_status(
        _cross_tool(), services=services, present=present, versions=versions
    )
    assert out["available"] is True
    assert out["detail"][TOOLKIT_UNIX]["binary_present"] is True
    # single consistent manifest identity → reported as THE version
    assert out["version"] == "sleuthkit 4.12.1 (dpkg)"
    assert out["version_reason"] is None


def test_binary_absent_in_running_maletin_reports_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(maletin, "resolve", lambda binary: None)
    services = {
        TOOLKIT_WINDOWS: {"service": TOOLKIT_WINDOWS, "container": "c-win", "running": True, "reason": None},
    }
    present = {TOOLKIT_WINDOWS: set()}  # running, but binary not installed
    out = maletin._tool_status(_win_tool(), services=services, present=present, versions={})
    assert out["available"] is False
    assert "ausente" in out["reason"]


def test_tool_without_declared_toolkit_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(maletin, "resolve", lambda binary: None)
    orphan = Tool("orphan", "orphan", ("unix",), toolkits=())
    out = maletin._tool_status(orphan, services={}, present={}, versions={})
    assert out["available"] is False
    assert out["reason"] == t("maletin.noToolkitDeclared", None, tool="orphan")


# --------------------------------------------------------------------------- #
# snapshot — end to end with a faked exec-agent
# --------------------------------------------------------------------------- #
def test_snapshot_without_urls_probes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FORENSIA_TOOLKIT_UNIX_URL", raising=False)
    monkeypatch.delenv("FORENSIA_TOOLKIT_WINDOWS_URL", raising=False)
    monkeypatch.setattr(maletin, "resolve", lambda binary: None)

    def _fail(method: str, url: str, payload=None):
        raise AssertionError("no maletín URL configured → must not make any HTTP call")

    monkeypatch.setattr(maletin, "_request", _fail)

    snap = maletin.snapshot([_win_tool(), _cross_tool()])
    assert snap["client"] is False
    assert all(svc["running"] is None for svc in snap["services"].values())
    assert snap["tools"]["hayabusa"]["available"] is False
    assert "exec-agent" in snap["tools"]["hayabusa"]["reason"]


def test_snapshot_reports_real_presence_when_maletines_up(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORENSIA_TOOLKIT_UNIX_URL", _UNIX_URL)
    monkeypatch.setenv("FORENSIA_TOOLKIT_WINDOWS_URL", _WIN_URL)
    monkeypatch.setattr(maletin, "resolve", lambda binary: None)

    installed = {"fls", "vol", "hayabusa"}
    manifest = {"fls": "sleuthkit 4.12.1 (dpkg)", "hayabusa": "hayabusa 2.15.0 (release)"}

    def fake_request(method: str, url: str, payload=None, *, timeout=None):
        if url.endswith("/health"):
            return 200, {"ok": True, "stage": "x"}
        if url.endswith("/which"):
            wanted = payload["binaries"]
            return 200, {"present": [b for b in wanted if b in installed]}
        if url.endswith("/versions"):
            return 200, {"stage": "x", "versions": manifest}
        raise AssertionError(f"unexpected call: {method} {url}")

    monkeypatch.setattr(maletin, "_request", fake_request)

    win, cross = _win_tool(), _cross_tool()
    snap = maletin.snapshot([win, cross])
    assert snap["client"] is True
    assert snap["services"][TOOLKIT_WINDOWS]["running"] is True
    assert snap["tools"]["hayabusa"]["available"] is True
    assert snap["tools"]["hayabusa"]["via"] == "maletin"
    assert snap["tools"]["fls"]["available"] is True
    # the snapshot surfaces the build-manifest version identity per tool
    assert snap["tools"]["hayabusa"]["version"] == "hayabusa 2.15.0 (release)"
    assert snap["tools"]["fls"]["version"] == "sleuthkit 4.12.1 (dpkg)"
