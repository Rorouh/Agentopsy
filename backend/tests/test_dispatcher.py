"""Tests for forensia.toolkit.dispatcher.execute and _build_result.

`execute()` is the only blessed entry point from the agent to the toolkit. The
unit tests below pin its contract end-to-end without ever launching a real
forensic binary:

    - Unknown tool id → ToolExecutionError.
    - RULE 1 venue: a binary on the api PATH runs bundled; otherwise it routes to the
      tool's maletín via the exec-agent (§B).
    - RULE 2: no cross-maletín fallback when choosing where to run.
    - _build_result returns the documented shape; parser exceptions surface as
      `parsed: {"parse_error": ...}` instead of crashing the dispatcher.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from forensia.toolkit import dispatcher as dispatcher_mod
from forensia.toolkit import maletin as maletin_mod
from forensia.toolkit.catalog import BY_ID
from forensia.toolkit.dispatcher import ToolExecutionError, _build_result, _select_maletin, execute
from forensia.toolkit.tool import DELIVERY_ALL_BUNDLED, Tool


# --------------------------------------------------------------------------- #
# execute() error paths
# --------------------------------------------------------------------------- #
def test_execute_unknown_tool_raises() -> None:
    with pytest.raises(ToolExecutionError, match="unknown tool"):
        execute("does_not_exist", {})


def test_execute_unresolved_without_toolkit_raises(monkeypatch) -> None:
    # Binary not on the api PATH AND no maletín declared → nowhere to run (RULE 1).
    monkeypatch.setattr(dispatcher_mod, "resolve", lambda _binary: None)
    orphan = Tool(
        id="fake_orphan",
        binary="definitely_absent_bin_xyz",
        os_profiles=("unix",),
        toolkits=(),
        build_argv=lambda _p: [],
    )
    monkeypatch.setitem(dispatcher_mod.BY_ID, "fake_orphan", orphan)
    with pytest.raises(ToolExecutionError, match="no hay dónde ejecutarlo"):
        execute("fake_orphan", {})


def test_execute_unresolved_routes_to_maletin_and_reports_when_unreachable(monkeypatch) -> None:
    # mmls is not on the api PATH → route to its maletín; with no exec-agent URL
    # configured the dispatcher surfaces an actionable ToolExecutionError (no guessing).
    monkeypatch.setattr(dispatcher_mod, "resolve", lambda _binary: None)
    monkeypatch.setattr(maletin_mod, "service_url", lambda _svc: None)
    with pytest.raises(ToolExecutionError, match="case_id"):
        execute("tsk_mmls", {"image_path": "/cases/img.raw"}, os_profile="unix")


def test_execute_build_argv_non_list_raises(monkeypatch) -> None:
    # If a wrapper misbehaves and returns a non-list, dispatcher must catch it
    # (before choosing a venue) rather than passing garbage downstream.
    fake_tool = Tool(
        id="fake_bad_build",
        binary="echo",
        os_profiles=("unix", "windows"),
        delivery=DELIVERY_ALL_BUNDLED,
        build_argv=lambda _p: "not a list",
    )
    monkeypatch.setitem(dispatcher_mod.BY_ID, "fake_bad_build", fake_tool)
    with pytest.raises(ToolExecutionError, match="non-list"):
        execute("fake_bad_build", {})


# --------------------------------------------------------------------------- #
# _select_maletin — RULE 2 (no fallback between maletines)
# --------------------------------------------------------------------------- #
def test_select_maletin_single_declared_needs_no_profile() -> None:
    win = Tool("hb", "hayabusa", ("windows",), toolkits=("toolkit-windows",))
    assert _select_maletin(win, None) == "toolkit-windows"


def test_select_maletin_ambiguous_without_profile_raises() -> None:
    cross = Tool("fls", "fls", ("unix", "windows"), toolkits=("toolkit-unix", "toolkit-windows"))
    with pytest.raises(ToolExecutionError, match="varios maletines"):
        _select_maletin(cross, None)


def test_select_maletin_wrong_profile_is_no_fallback() -> None:
    win = Tool("hb", "hayabusa", ("windows",), toolkits=("toolkit-windows",))
    with pytest.raises(ToolExecutionError, match="sin fallback"):
        _select_maletin(win, "unix")


def test_select_maletin_picks_matching_profile() -> None:
    cross = Tool("fls", "fls", ("unix", "windows"), toolkits=("toolkit-unix", "toolkit-windows"))
    assert _select_maletin(cross, "unix") == "toolkit-unix"


# --------------------------------------------------------------------------- #
# execute() happy path — bundled tool (binary on the api PATH)
# --------------------------------------------------------------------------- #
def test_execute_path_tool_without_case_is_rejected_before_runner(monkeypatch) -> None:
    monkeypatch.setattr(dispatcher_mod, "resolve", lambda _b: Path("/usr/bin/mmls"))

    captured = {}

    def fake_run_argv(argv, **kwargs):
        captured["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, "DOS Partition Table\n", "")

    monkeypatch.setattr(dispatcher_mod, "run_argv", fake_run_argv)

    with pytest.raises(ToolExecutionError, match="case_id"):
        execute("tsk_mmls", {"image_path": "/tmp/img.raw"})
    assert captured == {}


# --------------------------------------------------------------------------- #
# execute() happy path — maletín tool (binary not on the api PATH → exec-agent)
# --------------------------------------------------------------------------- #
def test_execute_maletin_path_tool_without_case_is_rejected(monkeypatch) -> None:
    monkeypatch.setattr(dispatcher_mod, "resolve", lambda _b: None)

    captured = {}

    def fake_exec(service, argv, *, timeout=None):
        captured["service"] = service
        captured["argv"] = argv
        return 0, "d/d 769:\thome\n", ""

    monkeypatch.setattr(maletin_mod, "run_argv_in_maletin", fake_exec)

    with pytest.raises(ToolExecutionError, match="case_id"):
        execute("tsk_fls", {"image_path": "/cases/original.raw"}, os_profile="unix")
    assert captured == {}


# --------------------------------------------------------------------------- #
# _build_result shape
# --------------------------------------------------------------------------- #
def test_build_result_shape() -> None:
    tool = BY_ID["tsk_mmls"]
    result = _build_result(tool, ["mmls", "/tmp/img"], 0, "DOS Partition Table\n", "")
    assert set(result.keys()) == {
        "tool_id",
        "argv",
        "exit_code",
        "stdout_sample",
        "stderr_sample",
        "parsed",
    }
    assert result["tool_id"] == "tsk_mmls"
    assert result["argv"] == ["mmls", "/tmp/img"]
    assert result["exit_code"] == 0
    assert isinstance(result["parsed"], dict)


def test_build_result_truncates_large_streams() -> None:
    tool = BY_ID["tsk_mmls"]
    big = "x" * 10_000
    result = _build_result(tool, ["mmls"], 0, big, big)
    assert len(result["stdout_sample"]) == 4000
    assert len(result["stderr_sample"]) == 4000


def test_build_result_nonzero_exit_skips_parse() -> None:
    tool = BY_ID["tsk_mmls"]
    result = _build_result(tool, ["mmls"], 1, "useless", "boom")
    assert result["exit_code"] == 1
    assert result["parsed"] is None


def test_build_result_passes_stderr_to_two_arg_parser() -> None:
    """Bug 007: wrappers whose useful summary lands on stderr declare
    parse(stdout, stderr); the dispatcher must feed stderr in that case."""

    def parse_with_stderr(stdout, stderr=""):
        return {"saw_stderr": stderr}

    tool = Tool(
        id="fake_stderr_parser",
        binary="x",
        os_profiles=("windows",),
        parse=parse_with_stderr,
    )
    result = _build_result(tool, ["x"], 0, "", "[+] 56 Detections found")
    assert result["parsed"] == {"saw_stderr": "[+] 56 Detections found"}


def test_build_result_single_arg_parser_gets_only_stdout() -> None:
    """A classic parse(stdout) must keep receiving stdout alone — no arity break."""

    def parse_stdout_only(stdout):
        return {"seen": stdout}

    tool = Tool(
        id="fake_stdout_parser",
        binary="x",
        os_profiles=("unix",),
        parse=parse_stdout_only,
    )
    result = _build_result(tool, ["x"], 0, "hello", "ignored-stderr")
    assert result["parsed"] == {"seen": "hello"}


def test_build_result_parser_exception_becomes_structured_error() -> None:
    """If a wrapper's parse() raises, the dispatcher must NOT crash — the
    structured error is what reaches the audit log."""

    def explode(_stdout):
        raise RuntimeError("synthetic parser failure")

    fake_tool = Tool(
        id="fake_explosive_parser",
        binary="x",
        os_profiles=("unix",),
        parse=explode,
    )
    result = _build_result(fake_tool, ["x"], 0, "anything", "")
    assert isinstance(result["parsed"], dict)
    assert "parse_error" in result["parsed"]
    assert "RuntimeError" in result["parsed"]["parse_error"]
    assert "synthetic parser failure" in result["parsed"]["parse_error"]
