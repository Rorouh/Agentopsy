"""EWF (`.E01`) routing through `ewfmount` (bloqueante del audit — gap libewf).

TSK does not read Expert Witness Format natively (`mmls -i ewf` → "Unsupported image
type"). The known-sound path is: the maletín's exec-agent mounts the `.E01` with `ewfmount`
(FUSE, read-only — exposes the image as a raw block device `ewf1`, WITHOUT mounting the
evidence filesystem, FORENSIC INVARIANT 3), rewrites the argv token that holds the `.E01`
to that raw path, runs the tool, and unmounts ALWAYS.

These tests pin the two properties that matter:

  * the decision + wiring (the api names the EXACT argv token; the dispatcher forwards
    `ewf_image` for a `.E01` and NOT for a raw image), and
  * the mechanism (the exec-agent rewrites the argv to the raw `ewf1`, unmounts even when
    the tool fails, and fails LOUD naming `ewfmount` when it is unavailable — RULE 2).

No docker / no real ewfmount needed: the mount is faked (mount/unmount are module-level and
monkeypatched), and the "ewfmount missing" path is exercised with the real helper (the dev
host / CI runner has no `ewfmount` on PATH → FileNotFoundError).
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
from agentopsy.artifacts.store import ArtifactStore
from agentopsy.audit.log import AuditLog
from agentopsy.cases.manager import CaseManager
from agentopsy.toolkit import dispatcher, maletin
from agentopsy.toolkit.dispatcher import _is_ewf_path

REPO_ROOT = Path(__file__).resolve().parents[2]
EXEC_AGENT_PY = REPO_ROOT / "docker" / "docker" / "forensic-toolkit" / "exec_agent.py"

# A tiny child that copies the raw bytes of argv[1] to its stdout buffer. After the
# exec-agent rewrites the argv, argv[1] is the raw `ewf1` path the (fake) mount produced.
_EMIT_STDOUT = "import sys; sys.stdout.buffer.write(open(sys.argv[1], 'rb').read())"


@pytest.fixture
def dispatch_case(monkeypatch, tmp_path):
    cases = CaseManager(root=tmp_path / "cases")
    case = cases.create("ewf", "alice", os_profile="unix")
    store = ArtifactStore(cases)
    wire_dispatcher_custody(monkeypatch, dispatcher, cases, store)
    return cases, case


# --------------------------------------------------------------------------- #
# 0) the EWF-extension predicate the dispatcher decides on
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path", ["a.E01", "a.e01", "a.Ex01", "a.E12", "/cases/x/original.E01"])
def test_is_ewf_path_true(path: str) -> None:
    assert _is_ewf_path(path)


@pytest.mark.parametrize("path", ["a.raw", "a.vmdk", "a.dd", "a.001", "noext", "a.E1", "a.E123"])
def test_is_ewf_path_false(path: str) -> None:
    assert not _is_ewf_path(path)


# --------------------------------------------------------------------------- #
# 1) dispatcher decision: forward ewf_image for a .E01, and only then
# --------------------------------------------------------------------------- #
def _force_maletin_and_capture(monkeypatch) -> dict:
    """Force the maletín venue (no api-PATH binary) and capture the exec-agent call."""
    monkeypatch.setattr(dispatcher, "resolve", lambda _binary: None)
    seen: dict = {}

    def fake_maletin(service, argv, *, timeout=None, stdout_path=None, ewf_image=None):
        seen["service"] = service
        seen["argv"] = list(argv)
        seen["ewf_image"] = ewf_image
        return 0, "DOS Partition Table\n", ""

    monkeypatch.setattr(dispatcher.maletin, "run_argv_in_maletin", fake_maletin)
    return seen


def test_dispatcher_forwards_ewf_image_for_e01(monkeypatch, dispatch_case, tmp_path) -> None:
    seen = _force_maletin_and_capture(monkeypatch)
    cases, case = dispatch_case
    # Registered through the real hash gate; the .E01 suffix is preserved by register().
    handle = register_evidence(cases, case.id, tmp_path, payload=b"ewf", name="disk.E01")
    image = str(handle.original_path)
    dispatcher.execute(
        "tsk_mmls",
        {"image_path": image},
        case_id=case.id,
        os_profile="unix",
        evidence_context=context_for(handle),
    )

    assert seen["service"] == "toolkit-unix"
    # The token named to the exec-agent is the EXACT path present in the argv it will run.
    assert seen["ewf_image"] == image
    assert seen["ewf_image"] in seen["argv"]
    # An EWF run keeps the resolved authoritative tool_version on start AND finish.
    entries = AuditLog(cases.root / case.id / "audit.jsonl").entries()
    for entry in entries:
        if entry.get("action") in ("tool_run_start", "tool_run_finish"):
            assert entry["tool_version"] == FAKE_TOOL_VERSION


def test_dispatcher_no_ewf_image_for_raw(monkeypatch, dispatch_case, tmp_path) -> None:
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
    # A non-EWF image is untouched: default behaviour, no mount asked for.
    assert seen["ewf_image"] is None
    # A non-EWF run carries the same version custody as an EWF one.
    entries = AuditLog(cases.root / case.id / "audit.jsonl").entries()
    for entry in entries:
        if entry.get("action") in ("tool_run_start", "tool_run_finish"):
            assert entry["tool_version"] == FAKE_TOOL_VERSION


# --------------------------------------------------------------------------- #
# exec-agent harness (real loopback HTTP, in-process — no docker)
# --------------------------------------------------------------------------- #
def _load_exec_agent():
    spec = importlib.util.spec_from_file_location("agentopsy_exec_agent_ewf_test", EXEC_AGENT_PY)
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
        except urllib.error.HTTPError as exc:  # 4xx still carries a JSON body
            return exc.code, json.loads(exc.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)


# --------------------------------------------------------------------------- #
# 2) mechanism: the argv token is rewritten to the raw `ewf1`, and unmount runs
# --------------------------------------------------------------------------- #
def test_exec_agent_ewf_rewrites_argv_and_unmounts(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("AGENTOPSY_EXEC_AGENT_TOKEN", raising=False)
    module = _load_exec_agent()

    raw_bytes = b"RAW-DISK-IMAGE-VIA-EWF1"
    unmounted: list[str] = []

    def fake_mount(ewf_image, mountpoint):
        raw = os.path.join(mountpoint, "ewf1")
        with open(raw, "wb") as handle:
            handle.write(raw_bytes)
        return raw

    def fake_unmount(mountpoint):
        unmounted.append(mountpoint)

    monkeypatch.setattr(module, "ewf_mount", fake_mount)
    monkeypatch.setattr(module, "ewf_unmount", fake_unmount)

    ewf_image = str(tmp_path / "original.E01")  # absolute, and a token of argv below
    argv = [sys.executable, "-c", _EMIT_STDOUT, ewf_image]
    status, body = _post_exec(module, {"argv": argv, "timeout": 60, "ewf_image": ewf_image})

    assert status == 200
    assert body["exit"] == 0
    # The child read the RAW `ewf1` (the rewritten token), not the `.E01` path.
    assert body["stdout"] == raw_bytes.decode()
    # And the mount was released — exactly once, in the finally.
    assert len(unmounted) == 1
    # P0.5-4: the response carries the argv ACTUALLY executed — identical to the
    # requested one except the EWF token, rewritten to the raw ewf1 block.
    executed = body["executed_argv"]
    assert len(executed) == len(argv)
    assert executed[:-1] == argv[:-1]
    assert executed[-1] != ewf_image
    # Separator-agnostic: the fake mount produces an OS-native tmp path on Windows.
    assert executed[-1].replace("\\", "/").rsplit("/", 1)[-1] == "ewf1"


def test_exec_agent_ewf_unmounts_even_when_tool_fails(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("AGENTOPSY_EXEC_AGENT_TOKEN", raising=False)
    module = _load_exec_agent()

    unmounts = {"n": 0}

    def fake_mount(ewf_image, mountpoint):
        return os.path.join(mountpoint, "ewf1")  # a failing tool never reads it

    def fake_unmount(mountpoint):
        unmounts["n"] += 1

    monkeypatch.setattr(module, "ewf_mount", fake_mount)
    monkeypatch.setattr(module, "ewf_unmount", fake_unmount)

    ewf_image = str(tmp_path / "original.E01")
    argv = ["agentopsy-no-such-binary-xyz", ewf_image]  # FileNotFoundError → exit 127
    status, body = _post_exec(module, {"argv": argv, "ewf_image": ewf_image})

    assert status == 200
    assert body["exit"] == 127
    assert unmounts["n"] == 1  # unmount happened despite the tool failing


# --------------------------------------------------------------------------- #
# 3) RULE 2: ewfmount unavailable → 424 naming the dependency (real helper)
# --------------------------------------------------------------------------- #
def test_exec_agent_ewf_missing_ewfmount_is_actionable(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("AGENTOPSY_EXEC_AGENT_TOKEN", raising=False)
    module = _load_exec_agent()  # real ewf_mount — no `ewfmount` on the dev host / CI runner

    ewf_image = tmp_path / "original.E01"
    ewf_image.write_bytes(b"EVF\x09\x0d")  # exists, but ewfmount is absent

    status, body = _post_exec(
        module, {"argv": ["mmls", str(ewf_image)], "ewf_image": str(ewf_image)}
    )

    assert status == 424
    assert "ewfmount" in body["error"]  # names the missing dependency, not a silent raw run


def test_exec_agent_ewf_image_must_be_argv_token(monkeypatch) -> None:
    monkeypatch.delenv("AGENTOPSY_EXEC_AGENT_TOKEN", raising=False)
    module = _load_exec_agent()
    # The api names the exact token; mounting something absent from the command is guessing.
    status, body = _post_exec(
        module, {"argv": ["mmls", "/cases/x/original.E01"], "ewf_image": "/cases/OTHER.E01"}
    )
    assert status == 400
    assert "argv" in body["error"]


# --------------------------------------------------------------------------- #
# 4) P0.5-4 — executed_argv: the maletín proves it ran EXACTLY the audited argv
# --------------------------------------------------------------------------- #
def _exec_fake(monkeypatch, body_for_payload):
    """Wire run_argv_in_maletin's transport to a fake /exec responder."""
    monkeypatch.setenv("AGENTOPSY_TOOLKIT_UNIX_URL", "http://toolkit-unix:8666")
    monkeypatch.delenv("AGENTOPSY_EXEC_AGENT_TOKEN", raising=False)

    def fake_request(method, url, payload=None, *, timeout=maletin._PROBE_TIMEOUT):
        assert url.endswith("/exec")
        return 200, body_for_payload(payload)

    monkeypatch.setattr(maletin, "_request", fake_request)


def test_maletin_accepts_exact_executed_argv(monkeypatch) -> None:
    _exec_fake(
        monkeypatch,
        lambda p: {"exit": 0, "stdout": "ok", "stderr": "",
                   "executed_argv": list(p["argv"])},
    )
    exit_code, stdout, _ = maletin.run_argv_in_maletin("toolkit-unix", ["mmls", "/cases/x.raw"])
    assert (exit_code, stdout) == (0, "ok")


def test_maletin_rejects_missing_executed_argv_as_pre_contract_image(monkeypatch) -> None:
    """An exec-agent that does not report what it executed cannot be verified — the
    actionable error names the rebuild, never a silent acceptance (RULE 2)."""
    _exec_fake(monkeypatch, lambda p: {"exit": 0, "stdout": "", "stderr": ""})
    with pytest.raises(maletin.MaletinExecError, match="executed_argv"):
        maletin.run_argv_in_maletin("toolkit-unix", ["mmls", "/cases/x.raw"])


def test_maletin_rejects_altered_token(monkeypatch) -> None:
    """A maletín that ran a DIFFERENT command than the audited one is a custody break."""
    def lie(p):
        executed = list(p["argv"])
        executed[-1] = "/cases/OTHER.raw"  # not what the audit log says
        return {"exit": 0, "stdout": "", "stderr": "", "executed_argv": executed}

    _exec_fake(monkeypatch, lie)
    with pytest.raises(maletin.MaletinExecError, match="custodia rota"):
        maletin.run_argv_in_maletin("toolkit-unix", ["mmls", "/cases/x.raw"])


def test_maletin_rejects_length_drift(monkeypatch) -> None:
    _exec_fake(
        monkeypatch,
        lambda p: {"exit": 0, "stdout": "", "stderr": "",
                   "executed_argv": [*p["argv"], "--extra-flag"]},
    )
    with pytest.raises(maletin.MaletinExecError, match="custodia rota"):
        maletin.run_argv_in_maletin("toolkit-unix", ["mmls", "/cases/x.raw"])


def test_maletin_rejects_unrewritten_ewf_token(monkeypatch) -> None:
    """EWF requested but the token came back untouched: the tool would have read the
    raw .E01 — the silent degradation RULE 2 forbids."""
    image = "/cases/x/original.E01"
    _exec_fake(
        monkeypatch,
        lambda p: {"exit": 0, "stdout": "", "stderr": "",
                   "executed_argv": list(p["argv"])},
    )
    with pytest.raises(maletin.MaletinExecError, match="no reescribió"):
        maletin.run_argv_in_maletin("toolkit-unix", ["mmls", image], ewf_image=image)


def test_maletin_rejects_ewf_rewrite_that_is_not_raw_ewf1(monkeypatch) -> None:
    image = "/cases/x/original.E01"

    def lie(p):
        executed = ["/etc/passwd" if t == image else t for t in p["argv"]]
        return {"exit": 0, "stdout": "", "stderr": "", "executed_argv": executed}

    _exec_fake(monkeypatch, lie)
    with pytest.raises(maletin.MaletinExecError, match="ewf1"):
        maletin.run_argv_in_maletin("toolkit-unix", ["mmls", image], ewf_image=image)


def test_maletin_rejects_inconsistent_ewf_rewrites(monkeypatch) -> None:
    image = "/cases/x/original.E01"

    def lie(p):
        raws = iter(["/tmp/a/ewf1", "/tmp/b/ewf1"])
        executed = [next(raws) if t == image else t for t in p["argv"]]
        return {"exit": 0, "stdout": "", "stderr": "", "executed_argv": executed}

    _exec_fake(monkeypatch, lie)
    with pytest.raises(maletin.MaletinExecError, match="inconsistente"):
        maletin.run_argv_in_maletin(
            "toolkit-unix", ["ewfinfo", image, image], ewf_image=image
        )


def test_maletin_accepts_correct_ewf_rewrite(monkeypatch) -> None:
    image = "/cases/x/original.E01"

    def truthful(p):
        executed = ["/tmp/agentopsy-ewf-abc/ewf1" if t == image else t for t in p["argv"]]
        return {"exit": 0, "stdout": "DOS\n", "stderr": "", "executed_argv": executed}

    _exec_fake(monkeypatch, truthful)
    exit_code, stdout, _ = maletin.run_argv_in_maletin(
        "toolkit-unix", ["mmls", image], ewf_image=image
    )
    assert (exit_code, stdout) == (0, "DOS\n")


def test_dispatcher_closes_run_as_error_when_maletin_lies(
    monkeypatch, dispatch_case, tmp_path
) -> None:
    """End to end: a lying exec-agent (tampered executed_argv) crosses the runner
    boundary AFTER tool_run_start — the dispatcher closes the run as an error with the
    full custody context, and the result is never accepted (INVARIANT 4)."""
    cases, case = dispatch_case
    handle = register_evidence(cases, case.id, tmp_path, payload=b"raw", name="disk.raw")
    monkeypatch.setattr(dispatcher, "resolve", lambda _binary: None)
    monkeypatch.setenv("AGENTOPSY_TOOLKIT_UNIX_URL", "http://toolkit-unix:8666")
    monkeypatch.delenv("AGENTOPSY_EXEC_AGENT_TOKEN", raising=False)

    def lie(method, url, payload=None, *, timeout=maletin._PROBE_TIMEOUT):
        executed = list(payload["argv"])
        executed[-1] = "/evidence/OTRA.raw"  # ran against a DIFFERENT image
        return 200, {"exit": 0, "stdout": "DOS\n", "stderr": "",
                     "executed_argv": executed}

    monkeypatch.setattr(maletin, "_request", lie)

    with pytest.raises(dispatcher.ToolExecutionError, match="custodia rota"):
        dispatcher.execute(
            "tsk_mmls",
            {"image_path": str(handle.original_path)},
            case_id=case.id,
            os_profile="unix",
            evidence_context=context_for(handle),
        )
    entries = AuditLog(cases.root / case.id / "audit.jsonl").entries()
    start = next(e for e in entries if e.get("action") == "tool_run_start")
    finish = next(e for e in entries if e.get("action") == "tool_run_finish")
    assert finish["status"] == "error"
    assert finish["exit_code"] is None  # no exit code is invented for a rejected result
    # Every closure keeps the forensic context + version (P0.5-3 machinery).
    assert finish["evidence_id"] == start["evidence_id"] == handle.evidence_id
    assert finish["tool_version"] == start["tool_version"]
    assert AuditLog(cases.root / case.id / "audit.jsonl").verify() is True


# --------------------------------------------------------------------------- #
# 5) the maletín client surfaces the 424 as an actionable MaletinExecError
# --------------------------------------------------------------------------- #
def test_maletin_surfaces_ewf_dependency_error(monkeypatch) -> None:
    monkeypatch.setenv("AGENTOPSY_TOOLKIT_UNIX_URL", "http://toolkit-unix:8666")
    monkeypatch.delenv("AGENTOPSY_EXEC_AGENT_TOKEN", raising=False)
    image = "/cases/x/original.E01"

    def fake_request(method, url, payload=None, *, timeout=maletin._PROBE_TIMEOUT):
        # The client forwarded ewf_image so the exec-agent can mount it.
        assert payload["ewf_image"] == image
        return 424, {"error": "ewfmount no está instalado en el maletín (ewf-tools/libewf)"}

    monkeypatch.setattr(maletin, "_request", fake_request)

    with pytest.raises(maletin.MaletinExecError, match="ewfmount"):
        maletin.run_argv_in_maletin("toolkit-unix", ["mmls", image], ewf_image=image)
