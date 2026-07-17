"""Container-disk routing through `qemu-storage-daemon`'s FUSE export (Bug 4).

The maletín's TSK does not open vmdk/vdi/qcow2/vhd/vhdx natively (no libvmdk/libvhdi:
`mmls -i vmdk` → "Unsupported image type"), and the GIFT PPA ships no `vmdkmount`. The
known-sound path — verified live in the running maletín — is: the exec-agent exposes the
container as a raw block via `qemu-storage-daemon`'s FUSE export (read-only, block-level,
WITHOUT mounting the evidence filesystem, FORENSIC INVARIANT 3) at a file named `raw.img`,
rewrites the argv token holding the container path to that raw view, runs the tool, and
tears the export down ALWAYS.

These tests pin the same two properties the EWF suite does (see `test_ewf_routing.py`):

  * the decision + wiring (the api names the EXACT argv token and the qemu format from the
    evidence suffix; the dispatcher forwards `qemu_image`+`qemu_format` for a container and
    NOT for a raw/E01 image, and anchors `image_format` to raw), and
  * the mechanism (the exec-agent rewrites the argv to the raw `raw.img`, tears down even
    when the tool fails, validates the format enum, and fails LOUD naming
    `qemu-storage-daemon` when it is unavailable — RULE 2).

No docker / no real qemu-storage-daemon needed: the export is faked (mount/unmount are
module-level and monkeypatched), and the "qemu-storage-daemon missing" path is exercised
with the real helper (the dev host / CI runner has no `qemu-storage-daemon` on PATH).
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from _custody import FAKE_TOOL_VERSION, context_for, register_evidence, wire_dispatcher_custody
from forensia.artifacts.store import ArtifactStore
from forensia.audit.log import AuditLog
from forensia.cases.manager import CaseManager
from forensia.toolkit import dispatcher, maletin
from forensia.toolkit.dispatcher import _qemu_format_for_path

REPO_ROOT = Path(__file__).resolve().parents[2]
EXEC_AGENT_PY = REPO_ROOT / "docker" / "docker" / "forensic-toolkit" / "exec_agent.py"

# A tiny child that copies the raw bytes of argv[1] to its stdout buffer. After the
# exec-agent rewrites the argv, argv[1] is the raw `raw.img` path the (fake) export produced.
_EMIT_STDOUT = "import sys; sys.stdout.buffer.write(open(sys.argv[1], 'rb').read())"


@pytest.fixture
def dispatch_case(monkeypatch, tmp_path):
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create("vmdk", "alice", os_profile="unix")
    store = ArtifactStore(cases)
    wire_dispatcher_custody(monkeypatch, dispatcher, cases, store)
    return cases, case


# --------------------------------------------------------------------------- #
# 0) the container-format predicate the dispatcher decides on
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "path,fmt",
    [
        ("a.vmdk", "vmdk"),
        ("/cases/x/original.VMDK", "vmdk"),
        ("a.vdi", "vdi"),
        ("a.qcow2", "qcow2"),
        ("a.qcow", "qcow2"),
        ("a.vhd", "vpc"),
        ("a.vhdx", "vhdx"),
    ],
)
def test_qemu_format_for_container(path: str, fmt: str) -> None:
    assert _qemu_format_for_path(path) == fmt


@pytest.mark.parametrize("path", ["a.raw", "a.dd", "a.001", "a.E01", "a.img", "noext"])
def test_qemu_format_none_for_non_container(path: str) -> None:
    assert _qemu_format_for_path(path) is None


# --------------------------------------------------------------------------- #
# 1) dispatcher decision: forward qemu_image+qemu_format for a container, and only then
# --------------------------------------------------------------------------- #
def _force_maletin_and_capture(monkeypatch) -> dict:
    """Force the maletín venue (no api-PATH binary) and capture the exec-agent call."""
    monkeypatch.setattr(dispatcher, "resolve", lambda _binary: None)
    seen: dict = {}

    def fake_maletin(
        service, argv, *, timeout=None, stdout_path=None,
        ewf_image=None, qemu_image=None, qemu_format=None,
    ):
        seen["service"] = service
        seen["argv"] = list(argv)
        seen["ewf_image"] = ewf_image
        seen["qemu_image"] = qemu_image
        seen["qemu_format"] = qemu_format
        return 0, "DOS Partition Table\n", ""

    monkeypatch.setattr(dispatcher.maletin, "run_argv_in_maletin", fake_maletin)
    return seen


def test_dispatcher_forwards_qemu_image_for_vmdk(monkeypatch, dispatch_case, tmp_path) -> None:
    seen = _force_maletin_and_capture(monkeypatch)
    cases, case = dispatch_case
    handle = register_evidence(cases, case.id, tmp_path, payload=b"KDMV", name="disk.vmdk")
    image = str(handle.original_path)
    dispatcher.execute(
        "tsk_mmls",
        {"image_path": image},
        case_id=case.id,
        os_profile="unix",
        evidence_context=context_for(handle),
    )
    assert seen["service"] == "toolkit-unix"
    assert seen["qemu_image"] == image
    assert seen["qemu_format"] == "vmdk"
    assert seen["qemu_image"] in seen["argv"]
    assert seen["ewf_image"] is None
    entries = AuditLog(cases.root / case.id / "audit.jsonl").entries()
    for entry in entries:
        if entry.get("action") in ("tool_run_start", "tool_run_finish"):
            assert entry["tool_version"] == FAKE_TOOL_VERSION


def test_dispatcher_no_qemu_image_for_raw(monkeypatch, dispatch_case, tmp_path) -> None:
    seen = _force_maletin_and_capture(monkeypatch)
    cases, case = dispatch_case
    handle = register_evidence(cases, case.id, tmp_path, payload=b"raw", name="disk.raw")
    dispatcher.execute(
        "tsk_mmls",
        {"image_path": str(handle.original_path)},
        case_id=case.id,
        os_profile="unix",
        evidence_context=context_for(handle),
    )
    assert seen["qemu_image"] is None
    assert seen["qemu_format"] is None
    assert seen["ewf_image"] is None


def test_dispatcher_anchors_image_format_to_raw_for_container(
    monkeypatch, dispatch_case, tmp_path
) -> None:
    """A stray model-supplied image_format=vmdk is normalised to raw: after the FUSE export
    the block IS raw, so `-i vmdk` on it would fail (RULE 2 — the format is anchored)."""
    seen = _force_maletin_and_capture(monkeypatch)
    cases, case = dispatch_case
    handle = register_evidence(cases, case.id, tmp_path, payload=b"KDMV", name="disk.vmdk")
    dispatcher.execute(
        "tsk_mmls",
        {"image_path": str(handle.original_path), "image_format": "vmdk"},
        case_id=case.id,
        os_profile="unix",
        evidence_context=context_for(handle),
    )
    # The argv the maletín is asked to run carries `-i raw`, never `-i vmdk`.
    assert "vmdk" not in seen["argv"]
    assert "raw" in seen["argv"]


# --------------------------------------------------------------------------- #
# exec-agent harness (real loopback HTTP, in-process — no docker)
# --------------------------------------------------------------------------- #
def _load_exec_agent():
    spec = importlib.util.spec_from_file_location("forensia_exec_agent_vmdk_test", EXEC_AGENT_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _post_exec(module, payload: dict) -> tuple[int, dict]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/exec",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 — loopback test
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)


# --------------------------------------------------------------------------- #
# 2) mechanism: the argv token is rewritten to the raw `raw.img`, and teardown runs
# --------------------------------------------------------------------------- #
def test_exec_agent_qemu_rewrites_argv_and_tears_down(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("FORENSIA_EXEC_AGENT_TOKEN", raising=False)
    module = _load_exec_agent()

    raw_bytes = b"RAW-DISK-IMAGE-VIA-RAW.IMG"
    torn_down: list[str] = []

    def fake_mount(qemu_image, qemu_format, mountpoint_dir):
        assert qemu_format == "vmdk"
        raw = os.path.join(mountpoint_dir, "raw.img")
        with open(raw, "wb") as handle:
            handle.write(raw_bytes)
        return raw, object()  # (raw_path, daemon placeholder)

    def fake_unmount(mountpoint_dir, daemon):
        torn_down.append(mountpoint_dir)

    monkeypatch.setattr(module, "qemu_mount", fake_mount)
    monkeypatch.setattr(module, "qemu_unmount", fake_unmount)

    qemu_image = str(tmp_path / "original.vmdk")
    argv = [sys.executable, "-c", _EMIT_STDOUT, qemu_image]
    status, body = _post_exec(
        module,
        {"argv": argv, "timeout": 60, "qemu_image": qemu_image, "qemu_format": "vmdk"},
    )

    assert status == 200
    assert body["exit"] == 0
    assert body["stdout"] == raw_bytes.decode()
    assert len(torn_down) == 1
    executed = body["executed_argv"]
    assert len(executed) == len(argv)
    assert executed[:-1] == argv[:-1]
    assert executed[-1] != qemu_image
    assert executed[-1].replace("\\", "/").rsplit("/", 1)[-1] == "raw.img"


def test_exec_agent_qemu_tears_down_even_when_tool_fails(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("FORENSIA_EXEC_AGENT_TOKEN", raising=False)
    module = _load_exec_agent()

    teardowns = {"n": 0}

    def fake_mount(qemu_image, qemu_format, mountpoint_dir):
        return os.path.join(mountpoint_dir, "raw.img"), object()

    def fake_unmount(mountpoint_dir, daemon):
        teardowns["n"] += 1

    monkeypatch.setattr(module, "qemu_mount", fake_mount)
    monkeypatch.setattr(module, "qemu_unmount", fake_unmount)

    qemu_image = str(tmp_path / "original.vmdk")
    argv = ["forensia-no-such-binary-xyz", qemu_image]
    status, body = _post_exec(
        module, {"argv": argv, "qemu_image": qemu_image, "qemu_format": "vmdk"}
    )
    assert status == 200
    assert body["exit"] == 127
    assert teardowns["n"] == 1


# --------------------------------------------------------------------------- #
# 3) validation + RULE 2 at the exec-agent
# --------------------------------------------------------------------------- #
def test_exec_agent_qemu_image_must_be_argv_token(monkeypatch) -> None:
    monkeypatch.delenv("FORENSIA_EXEC_AGENT_TOKEN", raising=False)
    module = _load_exec_agent()
    status, body = _post_exec(
        module,
        {"argv": ["mmls", "/cases/x/original.vmdk"],
         "qemu_image": "/cases/OTHER.vmdk", "qemu_format": "vmdk"},
    )
    assert status == 400
    assert "argv" in body["error"]


def test_exec_agent_qemu_format_must_be_valid(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("FORENSIA_EXEC_AGENT_TOKEN", raising=False)
    module = _load_exec_agent()
    qemu_image = str(tmp_path / "original.vmdk")
    status, body = _post_exec(
        module,
        {"argv": ["mmls", qemu_image], "qemu_image": qemu_image, "qemu_format": "ntfs"},
    )
    assert status == 400
    assert "qemu_format" in body["error"]


def test_exec_agent_ewf_and_qemu_mutually_exclusive(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("FORENSIA_EXEC_AGENT_TOKEN", raising=False)
    module = _load_exec_agent()
    image = str(tmp_path / "original.vmdk")
    status, body = _post_exec(
        module,
        {"argv": ["mmls", image], "ewf_image": image,
         "qemu_image": image, "qemu_format": "vmdk"},
    )
    assert status == 400
    assert "mutually exclusive" in body["error"]


def test_exec_agent_qemu_missing_daemon_is_actionable(monkeypatch, tmp_path) -> None:
    """No `qemu-storage-daemon` on the dev host / CI runner → 424 naming the dependency,
    never a silent raw treatment of the container (RULE 2). Uses the REAL helper."""
    monkeypatch.delenv("FORENSIA_EXEC_AGENT_TOKEN", raising=False)
    module = _load_exec_agent()
    qemu_image = tmp_path / "original.vmdk"
    qemu_image.write_bytes(b"KDMV-not-a-real-vmdk")  # exists; daemon absent OR dies fast
    status, body = _post_exec(
        module,
        {"argv": ["mmls", str(qemu_image)],
         "qemu_image": str(qemu_image), "qemu_format": "vmdk"},
    )
    assert status == 424
    assert "qemu-storage-daemon" in body["error"]


# --------------------------------------------------------------------------- #
# 4) custody proof: the maletín client verifies the qemu rewrite token-by-token
# --------------------------------------------------------------------------- #
def _exec_fake(monkeypatch, body_for_payload):
    monkeypatch.setenv("FORENSIA_TOOLKIT_UNIX_URL", "http://toolkit-unix:8666")
    monkeypatch.delenv("FORENSIA_EXEC_AGENT_TOKEN", raising=False)

    def fake_request(method, url, payload=None, *, timeout=maletin._PROBE_TIMEOUT):
        assert url.endswith("/exec")
        return 200, body_for_payload(payload)

    monkeypatch.setattr(maletin, "_request", fake_request)


def test_maletin_rejects_unrewritten_qemu_token(monkeypatch) -> None:
    image = "/cases/x/original.vmdk"
    _exec_fake(
        monkeypatch,
        lambda p: {"exit": 0, "stdout": "", "stderr": "", "executed_argv": list(p["argv"])},
    )
    with pytest.raises(maletin.MaletinExecError, match="no reescribió"):
        maletin.run_argv_in_maletin(
            "toolkit-unix", ["mmls", image], qemu_image=image, qemu_format="vmdk"
        )


def test_maletin_rejects_qemu_rewrite_that_is_not_raw_img(monkeypatch) -> None:
    image = "/cases/x/original.vmdk"

    def lie(p):
        executed = ["/etc/passwd" if t == image else t for t in p["argv"]]
        return {"exit": 0, "stdout": "", "stderr": "", "executed_argv": executed}

    _exec_fake(monkeypatch, lie)
    with pytest.raises(maletin.MaletinExecError, match="raw.img"):
        maletin.run_argv_in_maletin(
            "toolkit-unix", ["mmls", image], qemu_image=image, qemu_format="vmdk"
        )


def test_maletin_accepts_correct_qemu_rewrite(monkeypatch) -> None:
    image = "/cases/x/original.vmdk"

    def truthful(p):
        executed = ["/tmp/forensia-qemu-abc/raw.img" if t == image else t for t in p["argv"]]
        return {"exit": 0, "stdout": "DOS\n", "stderr": "", "executed_argv": executed}

    _exec_fake(monkeypatch, truthful)
    exit_code, stdout, _ = maletin.run_argv_in_maletin(
        "toolkit-unix", ["mmls", image], qemu_image=image, qemu_format="vmdk"
    )
    assert (exit_code, stdout) == (0, "DOS\n")


def test_maletin_rejects_invalid_qemu_format(monkeypatch) -> None:
    _exec_fake(monkeypatch, lambda p: {"exit": 0, "stdout": "", "stderr": "",
                                       "executed_argv": list(p["argv"])})
    with pytest.raises(maletin.MaletinExecError, match="qemu_format"):
        maletin.run_argv_in_maletin(
            "toolkit-unix", ["mmls", "/cases/x.vmdk"],
            qemu_image="/cases/x.vmdk", qemu_format="ntfs",
        )


def test_maletin_rejects_ewf_and_qemu_together(monkeypatch) -> None:
    _exec_fake(monkeypatch, lambda p: {"exit": 0, "stdout": "", "stderr": "",
                                       "executed_argv": list(p["argv"])})
    with pytest.raises(maletin.MaletinExecError, match="mutuamente excluyentes"):
        maletin.run_argv_in_maletin(
            "toolkit-unix", ["mmls", "/cases/x.vmdk"],
            ewf_image="/cases/x.vmdk", qemu_image="/cases/x.vmdk", qemu_format="vmdk",
        )


def test_maletin_surfaces_qemu_dependency_error(monkeypatch) -> None:
    monkeypatch.setenv("FORENSIA_TOOLKIT_UNIX_URL", "http://toolkit-unix:8666")
    monkeypatch.delenv("FORENSIA_EXEC_AGENT_TOKEN", raising=False)
    image = "/cases/x/original.vmdk"

    def fake_request(method, url, payload=None, *, timeout=maletin._PROBE_TIMEOUT):
        assert payload["qemu_image"] == image
        assert payload["qemu_format"] == "vmdk"
        return 424, {"error": "qemu-storage-daemon no está instalado en el maletín (qemu-utils)"}

    monkeypatch.setattr(maletin, "_request", fake_request)
    with pytest.raises(maletin.MaletinExecError, match="qemu-storage-daemon"):
        maletin.run_argv_in_maletin(
            "toolkit-unix", ["mmls", image], qemu_image=image, qemu_format="vmdk"
        )
