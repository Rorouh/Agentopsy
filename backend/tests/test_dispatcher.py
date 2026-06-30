"""Tests for forensia.toolkit.dispatcher.execute and _build_result.

`execute()` is the only blessed entry point from the agent to the toolkit. The
unit tests below pin its contract end-to-end without ever launching a real
forensic binary:

    - Unknown tool id → ToolExecutionError.
    - Bundled tool with no resolvable binary → ToolExecutionError (no fallback).
    - Container tool without host_mounts → ToolExecutionError.
    - _build_result returns the documented shape.
    - Parser exceptions surface as `parsed: {"parse_error": ...}` instead of
      crashing the dispatcher.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from forensia.toolkit import dispatcher as dispatcher_mod
from forensia.toolkit.catalog import BY_ID
from forensia.toolkit.dispatcher import ToolExecutionError, _build_result, execute
from forensia.toolkit.tool import (
    DELIVERY_ALL_BUNDLED,
    DELIVERY_ALL_CONTAINER,
    Tool,
)


# --------------------------------------------------------------------------- #
# execute() error paths
# --------------------------------------------------------------------------- #
def test_execute_unknown_tool_raises() -> None:
    with pytest.raises(ToolExecutionError, match="unknown tool"):
        execute("does_not_exist", {})


def test_execute_bundled_binary_unresolvable_raises(monkeypatch) -> None:
    # current_host_os() returns the real host; mmls is bundled on every host so
    # this exercises the bundled branch when the resolver yields None.
    monkeypatch.setattr(dispatcher_mod, "resolve", lambda _binary: None)
    with pytest.raises(ToolExecutionError, match="not resolvable"):
        execute("tsk_mmls", {"image_path": "/tmp/img.raw"})


def test_execute_build_argv_non_list_raises(monkeypatch) -> None:
    # If a wrapper misbehaves and returns a non-list, dispatcher must catch it
    # rather than passing garbage to run_argv.
    def bad_build(_params):
        return "not a list"

    fake_tool = Tool(
        id="fake_bad_build",
        binary="echo",
        os_profiles=("unix", "windows"),
        delivery=DELIVERY_ALL_BUNDLED,
        build_argv=bad_build,
    )
    monkeypatch.setitem(dispatcher_mod.BY_ID, "fake_bad_build", fake_tool)
    with pytest.raises(ToolExecutionError, match="non-list"):
        execute("fake_bad_build", {})


def test_execute_container_tool_without_host_mounts_raises(monkeypatch) -> None:
    """A container-delivered Tool that forgot to declare host_mounts must NOT
    silently fall through to a no-mount run — that would risk leaking the host
    cwd into the container."""

    def build_argv(_params):
        return ["--help"]

    no_mounts_tool = Tool(
        id="fake_container_no_mounts",
        binary="placeholder",
        os_profiles=("unix",),
        delivery=DELIVERY_ALL_CONTAINER,
        container_image="forensia/fake:latest",
        build_argv=build_argv,
    )
    monkeypatch.setitem(dispatcher_mod.BY_ID, "fake_container_no_mounts", no_mounts_tool)
    monkeypatch.setattr(dispatcher_mod, "current_host_os", lambda: "linux")
    with pytest.raises(ToolExecutionError, match="host_mounts"):
        execute("fake_container_no_mounts", {})


def test_execute_no_delivery_for_host_raises(monkeypatch) -> None:
    # Make the host be an OS that the tool doesn't list — bundled tools declare
    # all three by default, so we craft one that only declares linux and then
    # claim the host is windows.
    def build_argv(_params):
        return []

    tool = Tool(
        id="fake_linux_only",
        binary="x",
        os_profiles=("unix",),
        delivery=(("linux", "bundled"),),
        build_argv=build_argv,
    )
    monkeypatch.setitem(dispatcher_mod.BY_ID, "fake_linux_only", tool)
    monkeypatch.setattr(dispatcher_mod, "current_host_os", lambda: "windows")
    with pytest.raises(ToolExecutionError, match="no delivery declared"):
        execute("fake_linux_only", {})


# --------------------------------------------------------------------------- #
# execute() happy path — bundled tool
# --------------------------------------------------------------------------- #
def test_execute_bundled_runs_and_returns_result(monkeypatch) -> None:
    monkeypatch.setattr(dispatcher_mod, "resolve", lambda _b: Path("/usr/bin/mmls"))
    monkeypatch.setattr(dispatcher_mod, "current_host_os", lambda: "linux")

    captured = {}

    def fake_run_argv(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(argv, 0, "DOS Partition Table\n", "")

    monkeypatch.setattr(dispatcher_mod, "run_argv", fake_run_argv)

    result = execute("tsk_mmls", {"image_path": "/tmp/img.raw"})
    assert result["tool_id"] == "tsk_mmls"
    # See test_container.py for the same as_posix() rationale: on Windows the
    # mocked Path serialises with backslashes; the test means "argv[0] is the
    # resolved bundled binary path", independent of OS separator.
    assert Path(result["argv"][0]).as_posix() == "/usr/bin/mmls"
    assert result["argv"][-1] == "/tmp/img.raw"
    assert result["exit_code"] == 0
    # mmls parse with this stdout yields the documented shape
    assert "partitions" in result["parsed"]


# --------------------------------------------------------------------------- #
# execute() happy path — container tool
# --------------------------------------------------------------------------- #
def test_execute_container_runs_and_returns_result(monkeypatch, tmp_path) -> None:
    hive = tmp_path / "SYSTEM"
    hive.write_bytes(b"x")

    monkeypatch.setattr(dispatcher_mod, "current_host_os", lambda: "linux")

    captured = {}

    def fake_container_run(tool, *, argv_inside, mounts_ro, mounts_rw, timeout):
        captured["tool_id"] = tool.id
        captured["argv_inside"] = argv_inside
        captured["mounts_ro"] = mounts_ro
        captured["mounts_rw"] = mounts_rw
        return subprocess.CompletedProcess(argv_inside, 0, "", "")

    monkeypatch.setattr(dispatcher_mod, "run_in_container", fake_container_run)

    result = execute("regripper", {"hive_path": str(hive), "plugin": "compname"})
    assert result["tool_id"] == "regripper"
    # argv recorded for the audit log is the inside-container argv (per docstring)
    assert result["argv"] == captured["argv_inside"]
    assert captured["tool_id"] == "regripper"
    # the ro mount key is the resolved Path
    ro_key = next(iter(captured["mounts_ro"]))
    assert isinstance(ro_key, Path)
    assert captured["mounts_ro"][ro_key] == "/in/hive"


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
    # Truncated to the first 4000 chars
    assert len(result["stdout_sample"]) == 4000
    assert len(result["stderr_sample"]) == 4000


def test_build_result_nonzero_exit_skips_parse() -> None:
    tool = BY_ID["tsk_mmls"]
    result = _build_result(tool, ["mmls"], 1, "useless", "boom")
    assert result["exit_code"] == 1
    assert result["parsed"] is None


def test_build_result_parser_exception_becomes_structured_error(monkeypatch) -> None:
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
