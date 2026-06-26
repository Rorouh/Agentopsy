"""Tests for forensia.toolkit.container — runtime execution + mount guard.

Critical invariants exercised here:
    - Raw-evidence suffixes are refused as container mounts (FORENSIC_SOUNDNESS §5).
    - Non-Path keys are refused (TypeError, not ValueError — explicit programmer bug).
    - No OCI runtime on PATH → RuntimeError (no silent fallback per RULE 2).
    - Tools with no container_image → ValueError.
    - argv_inside is strictly a list[str] (gate 5 / 6).
    - When invoked successfully the runtime argv contains `--network none` and
      the expected `-v host:target:ro` strings for read-only mounts.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from forensia.toolkit import container as container_mod
from forensia.toolkit.container import _validate_mount_paths, run_in_container
from forensia.toolkit.tool import DELIVERY_ALL_CONTAINER, Tool


# --------------------------------------------------------------------------- #
# _validate_mount_paths — defence in depth
# --------------------------------------------------------------------------- #
FORBIDDEN_SUFFIXES = [".raw", ".dd", ".img", ".vmdk", ".vmem", ".e01", ".aff", ".lime", ".ad1"]


@pytest.mark.parametrize("suffix", FORBIDDEN_SUFFIXES)
def test_validate_mount_paths_rejects_raw_evidence(suffix: str) -> None:
    mounts = {Path(f"/tmp/evidence{suffix}"): "/in/img"}
    with pytest.raises(ValueError, match="raw evidence"):
        _validate_mount_paths(mounts, "mounts_ro")


@pytest.mark.parametrize("suffix", [s.upper() for s in FORBIDDEN_SUFFIXES])
def test_validate_mount_paths_is_case_insensitive(suffix: str) -> None:
    # the suffix check normalises to lower; uppercase E01 must also be rejected.
    mounts = {Path(f"/tmp/evidence{suffix}"): "/in/img"}
    with pytest.raises(ValueError, match="raw evidence"):
        _validate_mount_paths(mounts, "mounts_ro")


@pytest.mark.parametrize(
    "filename",
    ["Security.evtx", "report.json", "SYSTEM", "$MFT", "rules.yar", "data.csv"],
)
def test_validate_mount_paths_accepts_benign_files(filename: str) -> None:
    mounts = {Path(f"/tmp/{filename}"): "/in/x"}
    # must not raise
    _validate_mount_paths(mounts, "mounts_ro")


def test_validate_mount_paths_none_is_noop() -> None:
    _validate_mount_paths(None, "mounts_ro")
    _validate_mount_paths({}, "mounts_ro")


def test_validate_mount_paths_rejects_non_path_keys() -> None:
    with pytest.raises(TypeError, match="pathlib.Path"):
        _validate_mount_paths({"/tmp/foo.txt": "/x"}, "mounts_ro")


# --------------------------------------------------------------------------- #
# run_in_container — fixture: a synthetic Tool we control
# --------------------------------------------------------------------------- #
def _make_container_tool(container_image: str | None = "forensia/sample:latest") -> Tool:
    return Tool(
        id="sample_container_tool",
        binary="sample",
        os_profiles=("unix", "windows"),
        delivery=DELIVERY_ALL_CONTAINER,
        container_image=container_image,
    )


def test_run_in_container_requires_oci_runtime(monkeypatch) -> None:
    monkeypatch.setattr(container_mod, "container_runtime", lambda: None)
    tool = _make_container_tool()
    with pytest.raises(RuntimeError, match="no OCI runtime"):
        run_in_container(tool, argv_inside=["--help"])


def test_run_in_container_requires_container_image() -> None:
    tool = _make_container_tool(container_image=None)
    with pytest.raises(ValueError, match="container_image"):
        run_in_container(tool, argv_inside=["--help"])


def test_run_in_container_rejects_non_list_argv(monkeypatch) -> None:
    monkeypatch.setattr(container_mod, "container_runtime", lambda: Path("/usr/bin/true"))
    tool = _make_container_tool()
    with pytest.raises(TypeError, match="list"):
        run_in_container(tool, argv_inside="--help")  # type: ignore[arg-type]


def test_run_in_container_rejects_non_str_argv_elements(monkeypatch) -> None:
    monkeypatch.setattr(container_mod, "container_runtime", lambda: Path("/usr/bin/true"))
    tool = _make_container_tool()
    with pytest.raises(TypeError, match="list"):
        run_in_container(tool, argv_inside=["--flag", 5])  # type: ignore[list-item]


def test_run_in_container_rejects_raw_evidence_in_ro_mounts(monkeypatch) -> None:
    monkeypatch.setattr(container_mod, "container_runtime", lambda: Path("/usr/bin/true"))
    tool = _make_container_tool()
    with pytest.raises(ValueError, match="raw evidence"):
        run_in_container(
            tool,
            argv_inside=["--help"],
            mounts_ro={Path("/tmp/img.raw"): "/in/img"},
        )


def test_run_in_container_rejects_raw_evidence_in_rw_mounts(monkeypatch) -> None:
    monkeypatch.setattr(container_mod, "container_runtime", lambda: Path("/usr/bin/true"))
    tool = _make_container_tool()
    with pytest.raises(ValueError, match="raw evidence"):
        run_in_container(
            tool,
            argv_inside=["--help"],
            mounts_rw={Path("/tmp/disk.vmdk"): "/out/x"},
        )


def test_run_in_container_assembles_expected_argv(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(container_mod, "container_runtime", lambda: Path("/usr/bin/true"))

    captured: dict = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(container_mod.subprocess, "run", fake_run)

    hive = tmp_path / "SYSTEM"
    hive.write_bytes(b"hive")
    out = tmp_path / "out"
    out.mkdir()

    tool = _make_container_tool()
    result = run_in_container(
        tool,
        argv_inside=["-r", "/in/hive", "-p", "compname"],
        mounts_ro={hive: "/in/hive"},
        mounts_rw={out: "/out"},
        timeout=60,
    )

    assert result.returncode == 0
    argv = captured["argv"]
    # Runtime + run + --rm
    assert argv[0] == "/usr/bin/true"
    assert "run" in argv
    assert "--rm" in argv
    # Network isolation
    assert "--network" in argv
    assert "none" in argv
    # Mount strings — resolved absolute paths + :ro for read-only
    ro_mount = f"{hive.resolve()}:/in/hive:ro"
    rw_mount = f"{out.resolve()}:/out"
    assert ro_mount in argv
    assert rw_mount in argv
    # Container image and inside argv come last
    image_idx = argv.index("forensia/sample:latest")
    assert argv[image_idx + 1 :] == ["-r", "/in/hive", "-p", "compname"]
    # shell=False is non-negotiable
    assert captured["kwargs"].get("shell") is False
    assert captured["kwargs"].get("timeout") == 60


def test_run_in_container_with_no_mounts(monkeypatch) -> None:
    monkeypatch.setattr(container_mod, "container_runtime", lambda: Path("/usr/bin/true"))
    captured: dict = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(container_mod.subprocess, "run", fake_run)
    tool = _make_container_tool()
    run_in_container(tool, argv_inside=["-l"])
    # No -v segments when no mounts were declared
    assert "-v" not in captured["argv"]
