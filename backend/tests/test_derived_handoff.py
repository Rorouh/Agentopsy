"""Derived handoff: a binary tool's output refers to its artifact, and a downstream
tool consumes that artifact as input — resolved + RE-HASHED by the backend, and with
its evidence PROVENANCE verified (P0.5-3 Bloqueante D).

Properties pinned for the chain ``icat → artefacto → RegRipper``:

  * SURFACE (1): a ``binary_stdout`` tool (TSK ``icat``) whose raw bytes went to a hashed
    artifact file must REMIT TO THE ARTIFACT ({run_id, relpath, sha256, size}) in its
    result — never ``content_length: 0``.
  * DERIVED HANDOFF (2): the consumer's ArtifactRef is resolved to the producing run's
    on-disk file, RE-VERIFYING its SHA-256 against the manifest BEFORE running and
    recording the derivation LINK in the audit. A hash mismatch fails loud (RULE 2).
  * PROVENANCE (3): the producing run's manifest records WHICH evidence it acted on
    (deterministic, keyed by run_id); the consumer's verified context must match.
    Same-case is NOT same-evidence: a derivative of evidence B never runs under A's
    context; a legacy manifest without provenance is rejected loudly; a tampered
    provenance is rejected.

No docker / no maletín: the maletín runner + version transport are faked at the
transport level; evidence is registered for REAL through EvidenceManager's hash gate.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from _custody import context_for, register_evidence, wire_dispatcher_custody
from forensia.artifacts.store import ArtifactIntegrityError, ArtifactStore
from forensia.audit.log import AuditLog
from forensia.cases.manager import CaseManager
from forensia.toolkit import dispatcher

# A byte-exact "hive" the (fake) icat extracts; deliberately not valid UTF-8 so a text
# round-trip would change it. Its identity downstream is its SHA-256.
_HIVE_BYTES = b"regf\x00\x01\xff\xfe\x00SOFTWARE-hive\x80\x81\x00bytes\xc3\x28"
_HIVE_SHA = hashlib.sha256(_HIVE_BYTES).hexdigest()


# --------------------------------------------------------------------------- #
# fixtures (same wiring as the other case-anchored dispatcher tests)
# --------------------------------------------------------------------------- #
@pytest.fixture
def cases(tmp_path) -> CaseManager:
    return CaseManager(root=tmp_path / "cases")


@pytest.fixture
def store(cases) -> ArtifactStore:
    return ArtifactStore(cases)


@pytest.fixture
def anchored(cases, tmp_path):
    case = cases.create(name="op", examiner="alice", os_profile="windows")
    handle = register_evidence(cases, case.id, tmp_path, payload=b"disk")
    return {"case": case, "handle": handle, "ctx": context_for(handle)}


@pytest.fixture
def wired_dispatcher(monkeypatch, cases, store):
    wire_dispatcher_custody(monkeypatch, dispatcher, cases, store)
    # Force the maletín venue for every tool (no api-PATH binary in the test env).
    monkeypatch.setattr(dispatcher, "resolve", lambda _binary: None)
    return dispatcher


def _tool_audit(cases: CaseManager, case_id: str) -> list[dict]:
    return [
        e
        for e in AuditLog(cases.root / case_id / "audit.jsonl").entries()
        if str(e.get("action", "")).startswith("tool_run_")
    ]


def _fake_maletin(captured: dict):
    """A faked exec-agent: binary tools (icat) get their bytes written to stdout_path;
    text tools (regripper) have their argv captured. Accepts every kwarg the dispatcher
    threads so it stands in for both venues."""

    def run(service, argv, *, timeout=None, stdout_path=None, ewf_image=None):
        captured.setdefault("calls", []).append(
            {"service": service, "argv": list(argv), "stdout_path": stdout_path}
        )
        if stdout_path is not None:
            Path(stdout_path).write_bytes(_HIVE_BYTES)
            return 0, "", ""
        return 0, "regripper ran\n", ""

    return run


def _run_icat(wired_dispatcher, monkeypatch, anchored, captured) -> dict:
    monkeypatch.setattr(
        wired_dispatcher.maletin, "run_argv_in_maletin", _fake_maletin(captured)
    )
    return wired_dispatcher.execute(
        "tsk_icat",
        {"image_path": str(anchored["handle"].original_path), "inode": 5},
        case_id=anchored["case"].id,
        os_profile="windows",
        evidence_context=anchored["ctx"],
    )


# --------------------------------------------------------------------------- #
# (1) a binary tool's result refers to the artifact, not content_length:0
# --------------------------------------------------------------------------- #
def test_binary_result_refers_to_artifact_not_content_length_zero(
    wired_dispatcher, monkeypatch, anchored
) -> None:
    captured: dict = {}
    result = _run_icat(wired_dispatcher, monkeypatch, anchored, captured)

    parsed = result["parsed"]
    # The misleading empty-payload summary is gone; the parsed output is an artifact ref.
    assert "content_length" not in parsed
    ref = parsed["artifact"]
    assert ref["run_id"] == result["run_id"]
    assert ref["relpath"] == "stdout.bin"
    assert ref["sha256"] == _HIVE_SHA
    assert ref["size"] == len(_HIVE_BYTES)


# --------------------------------------------------------------------------- #
# (2) relevo icat → RegRipper: resolved + re-hashed OK, derivation link audited
# --------------------------------------------------------------------------- #
def test_icat_to_regripper_handoff_rehash_ok_and_audit_link(
    wired_dispatcher, monkeypatch, anchored, cases
) -> None:
    captured: dict = {}
    case, ctx = anchored["case"], anchored["ctx"]
    icat = _run_icat(wired_dispatcher, monkeypatch, anchored, captured)
    ref = icat["parsed"]["artifact"]  # {run_id, relpath, sha256, size}

    # The consumer takes the icat artifact ref where it expects `hive_path` — no path
    # invented by the agent. The dispatcher resolves + re-hashes it before running.
    regripper = wired_dispatcher.execute(
        "regripper",
        {"hive_path": ref, "plugin": "compname"},
        case_id=case.id,
        os_profile="windows",
        evidence_context=ctx,
    )
    assert regripper["exit_code"] == 0

    # RegRipper ran with the RESOLVED on-disk path of the hive (not the raw ref/dict).
    regripper_call = captured["calls"][-1]
    resolved = (
        cases.root / case.id / "artifacts" / ref["run_id"] / "out" / "stdout.bin"
    ).resolve()
    assert str(resolved) in regripper_call["argv"]
    assert Path(str(resolved)).read_bytes() == _HIVE_BYTES  # untouched, RO in spirit

    # INVARIANT 4: the audit records the derivation (artifact of run A → input of run B)
    # INCLUDING the producer's verified evidence provenance.
    starts = [
        e
        for e in _tool_audit(cases, case.id)
        if e.get("action") == "tool_run_start" and e.get("run_id") == regripper["run_id"]
    ]
    assert len(starts) == 1
    links = starts[0]["derived_inputs"]
    assert len(links) == 1
    link = links[0]
    assert link["param"] == "hive_path"
    assert link["source_run_id"] == ref["run_id"]
    assert link["source_evidence_id"] == ctx.evidence_id
    assert link["relpath"] == "stdout.bin"
    assert link["sha256"] == _HIVE_SHA  # the digest actually re-verified before running


def test_icat_to_regripper_handoff_hash_mismatch_fails_loud(
    wired_dispatcher, monkeypatch, anchored, cases
) -> None:
    captured: dict = {}
    case, ctx = anchored["case"], anchored["ctx"]
    icat = _run_icat(wired_dispatcher, monkeypatch, anchored, captured)
    ref = icat["parsed"]["artifact"]

    # Custody break: the derived file's bytes change after its run recorded their SHA-256.
    on_disk = cases.root / case.id / "artifacts" / ref["run_id"] / "out" / "stdout.bin"
    on_disk.write_bytes(_HIVE_BYTES + b"TAMPERED")

    starts_before = len(
        [e for e in _tool_audit(cases, case.id) if e.get("action") == "tool_run_start"]
    )
    with pytest.raises(wired_dispatcher.ToolExecutionError, match="custodia|SHA-256|match"):
        wired_dispatcher.execute(
            "regripper",
            {"hive_path": ref, "plugin": "compname"},
            case_id=case.id,
            os_profile="windows",
            evidence_context=ctx,
        )

    # A tampered derivative never reaches the runner (RULE 2): no start for a 2nd run.
    starts_after = len(
        [e for e in _tool_audit(cases, case.id) if e.get("action") == "tool_run_start"]
    )
    assert starts_after == starts_before


def test_minimal_artifact_ref_remains_compatible(
    wired_dispatcher, monkeypatch, anchored
) -> None:
    captured: dict = {}
    icat = _run_icat(wired_dispatcher, monkeypatch, anchored, captured)
    ref = icat["parsed"]["artifact"]
    result = wired_dispatcher.execute(
        "regripper",
        {
            "hive_path": {"run_id": ref["run_id"], "relpath": ref["relpath"]},
            "plugin": "compname",
        },
        case_id=anchored["case"].id,
        os_profile="windows",
        evidence_context=anchored["ctx"],
    )
    assert result["exit_code"] == 0


@pytest.mark.parametrize(
    "mutated",
    [
        {"extra": "forbidden"},
        {"sha256": "0" * 64},
        {"size": len(_HIVE_BYTES) + 1},
    ],
)
def test_artifact_ref_unknown_or_false_metadata_fails_before_runner_and_start(
    wired_dispatcher, monkeypatch, anchored, cases, mutated
) -> None:
    captured: dict = {}
    case, ctx = anchored["case"], anchored["ctx"]
    icat = _run_icat(wired_dispatcher, monkeypatch, anchored, captured)
    ref = {**icat["parsed"]["artifact"], **mutated}
    calls_before = len(captured["calls"])
    starts_before = len(
        [e for e in _tool_audit(cases, case.id) if e.get("action") == "tool_run_start"]
    )

    with pytest.raises(
        wired_dispatcher.ToolExecutionError,
        match="ArtifactRef|sha256|size|unknown",
    ):
        wired_dispatcher.execute(
            "regripper",
            {"hive_path": ref, "plugin": "compname"},
            case_id=case.id,
            os_profile="windows",
            evidence_context=ctx,
        )

    assert len(captured["calls"]) == calls_before
    starts_after = len(
        [e for e in _tool_audit(cases, case.id) if e.get("action") == "tool_run_start"]
    )
    assert starts_after == starts_before


def test_artifact_ref_without_case_id_fails_loud(wired_dispatcher) -> None:
    # Resolving + re-hashing a derivative needs the case; a ref without case_id is refused
    # rather than passed to the wrapper as if it were a literal path.
    with pytest.raises(wired_dispatcher.ToolExecutionError, match="case_id|anclada|contexto"):
        wired_dispatcher.execute(
            "regripper",
            {"hive_path": {"run_id": "x", "relpath": "stdout.bin"}, "plugin": "compname"},
        )


# --------------------------------------------------------------------------- #
# (3) PROVENANCE — Bloqueante D: same-case is not same-evidence
# --------------------------------------------------------------------------- #
def test_cross_evidence_derived_input_rejected_before_runner_and_start(
    wired_dispatcher, monkeypatch, anchored, cases, tmp_path
) -> None:
    """A derivative produced from evidence B must never run under evidence A's
    verified context — rejected before the consumer's start (INVARIANT 4)."""
    captured: dict = {}
    case = anchored["case"]
    # Evidence B in the SAME case, and an icat run anchored to B.
    handle_b = register_evidence(
        cases, case.id, tmp_path, payload=b"disk-B", name="b.raw"
    )
    ctx_b = context_for(handle_b)
    monkeypatch.setattr(
        wired_dispatcher.maletin, "run_argv_in_maletin", _fake_maletin(captured)
    )
    icat_b = wired_dispatcher.execute(
        "tsk_icat",
        {"image_path": str(handle_b.original_path), "inode": 5},
        case_id=case.id,
        os_profile="windows",
        evidence_context=ctx_b,
    )
    ref_b = icat_b["parsed"]["artifact"]

    starts_before = len(
        [e for e in _tool_audit(cases, case.id) if e.get("action") == "tool_run_start"]
    )
    # Consumer anchored to evidence A tries to eat B's artifact → cross-provenance.
    with pytest.raises(
        wired_dispatcher.ToolExecutionError, match="procedencia cruzada"
    ):
        wired_dispatcher.execute(
            "regripper",
            {"hive_path": ref_b, "plugin": "compname"},
            case_id=case.id,
            os_profile="windows",
            evidence_context=anchored["ctx"],
        )
    starts_after = len(
        [e for e in _tool_audit(cases, case.id) if e.get("action") == "tool_run_start"]
    )
    assert starts_after == starts_before
    # …while the SAME artifact under B's own context is allowed (A→A equivalent).
    ok = wired_dispatcher.execute(
        "regripper",
        {"hive_path": ref_b, "plugin": "compname"},
        case_id=case.id,
        os_profile="windows",
        evidence_context=ctx_b,
    )
    assert ok["exit_code"] == 0
    assert AuditLog(cases.root / case.id / "audit.jsonl").verify() is True


def test_producer_manifest_without_provenance_is_rejected(
    wired_dispatcher, monkeypatch, anchored, cases
) -> None:
    captured: dict = {}
    case, ctx = anchored["case"], anchored["ctx"]
    icat = _run_icat(wired_dispatcher, monkeypatch, anchored, captured)
    ref = icat["parsed"]["artifact"]
    # Simulate a legacy (pre-P0.5-3) producer manifest: strip its provenance.
    manifest_path = cases.root / case.id / "artifacts" / ref["run_id"] / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.pop("evidence_id", None)
    manifest.pop("evidence_baseline_sha256", None)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

    with pytest.raises(
        wired_dispatcher.ToolExecutionError, match="no registra procedencia"
    ):
        wired_dispatcher.execute(
            "regripper",
            {"hive_path": ref, "plugin": "compname"},
            case_id=case.id,
            os_profile="windows",
            evidence_context=ctx,
        )


def test_tampered_producer_provenance_is_rejected(
    wired_dispatcher, monkeypatch, anchored, cases
) -> None:
    captured: dict = {}
    case, ctx = anchored["case"], anchored["ctx"]
    icat = _run_icat(wired_dispatcher, monkeypatch, anchored, captured)
    ref = icat["parsed"]["artifact"]
    manifest_path = cases.root / case.id / "artifacts" / ref["run_id"] / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["evidence_id"] = "ffffffff-ffff-4fff-8fff-ffffffffffff"  # forged
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

    with pytest.raises(
        wired_dispatcher.ToolExecutionError, match="procedencia cruzada"
    ):
        wired_dispatcher.execute(
            "regripper",
            {"hive_path": ref, "plugin": "compname"},
            case_id=case.id,
            os_profile="windows",
            evidence_context=ctx,
        )
    # The audit hash-chain of REAL entries is untouched by the attempted consumption.
    assert AuditLog(cases.root / case.id / "audit.jsonl").verify() is True


# --------------------------------------------------------------------------- #
# (P0.5-5) producer COMPLETION gate: only a successfully closed producer feeds a
# consumer — running (bytes may mutate), error-closed (partial) and exit!=0 (failed
# by the tool's own account) are all rejected BEFORE the consumer's start.
# --------------------------------------------------------------------------- #
def _producer_in_state(store: ArtifactStore, anchored, *, state: str) -> dict:
    """A producer run with ctx-matching provenance whose artifact bytes are INTACT —
    so the completion gate, not provenance nor re-hash, is what must reject it."""
    case, ctx = anchored["case"], anchored["ctx"]
    run_id, out_dir = store.start_run(
        case.id,
        "tsk_icat",
        argv=["icat"],
        evidence_id=ctx.evidence_id,
        evidence_baseline_sha256=ctx.baseline_sha256,
        tool_version="sleuthkit 4.12 (dpkg)",
    )
    (out_dir / "stdout.bin").write_bytes(_HIVE_BYTES)
    if state == "error":
        store.fail_run(
            case.id, run_id,
            error_type="TimeoutExpired", error_message="icat matado por timeout",
        )
    elif state == "nonzero":
        store.finalize_run(case.id, run_id, exit_code=2, stdout="", stderr="boom")
    elif state != "running":
        raise AssertionError(f"unknown producer state {state!r}")
    return {"run_id": run_id, "relpath": "stdout.bin"}


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ("running", "sigue en ejecución"),
        ("error", "no completó con éxito"),
        ("nonzero", "no completó con éxito"),
    ],
)
def test_incomplete_producer_is_rejected_before_start(
    wired_dispatcher, store, anchored, cases, state, expected
) -> None:
    case, ctx = anchored["case"], anchored["ctx"]
    ref = _producer_in_state(store, anchored, state=state)
    starts_before = sum(
        1 for e in _tool_audit(cases, case.id) if e["action"] == "tool_run_start"
    )
    with pytest.raises(wired_dispatcher.ToolExecutionError, match=expected):
        wired_dispatcher.execute(
            "regripper",
            {"hive_path": ref, "plugin": "compname"},
            case_id=case.id,
            os_profile="windows",
            evidence_context=ctx,
        )
    starts_after = sum(
        1 for e in _tool_audit(cases, case.id) if e["action"] == "tool_run_start"
    )
    assert starts_after == starts_before  # the consumer never started
    assert AuditLog(cases.root / case.id / "audit.jsonl").verify() is True


def test_error_producer_rejection_names_the_actionable_cause(
    wired_dispatcher, store, anchored
) -> None:
    """The rejection is actionable: it names the producer's error and the remedy."""
    case, ctx = anchored["case"], anchored["ctx"]
    ref = _producer_in_state(store, anchored, state="error")
    with pytest.raises(
        wired_dispatcher.ToolExecutionError,
        match="TimeoutExpired.*re-ejecuta el productor",
    ):
        wired_dispatcher.execute(
            "regripper",
            {"hive_path": ref, "plugin": "compname"},
            case_id=case.id,
            os_profile="windows",
            evidence_context=ctx,
        )


# --------------------------------------------------------------------------- #
# (4) the store's custody gate in isolation: confinement + re-hash
# --------------------------------------------------------------------------- #
_PROV = {
    "evidence_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "evidence_baseline_sha256": "a" * 64,
    "tool_version": "sleuthkit 4.12 (dpkg)",
}


@pytest.fixture
def case(cases):
    return cases.create(name="op", examiner="alice", os_profile="windows")


def _finished_run_with_output(store: ArtifactStore, case_id: str, payload: bytes) -> str:
    run_id, out_dir = store.start_run(case_id, "tsk_icat", argv=["icat"], **_PROV)
    (out_dir / "stdout.bin").write_bytes(payload)
    store.finalize_run(case_id, run_id, exit_code=0, stdout="", stderr="")
    return run_id


def test_resolve_output_file_ok(store, case) -> None:
    run_id = _finished_run_with_output(store, case.id, _HIVE_BYTES)
    path, sha256, size = store.resolve_output_file(case.id, run_id, "stdout.bin")
    assert path.read_bytes() == _HIVE_BYTES
    assert sha256 == _HIVE_SHA
    assert size == len(_HIVE_BYTES)


def test_resolve_output_file_mismatch_raises_integrity(store, case) -> None:
    run_id = _finished_run_with_output(store, case.id, _HIVE_BYTES)
    # Overwrite the bytes after the manifest recorded their hash.
    (store._run_dir(case.id, run_id) / "out" / "stdout.bin").write_bytes(b"different")
    with pytest.raises(ArtifactIntegrityError, match="no longer matches"):
        store.resolve_output_file(case.id, run_id, "stdout.bin")


def test_resolve_output_file_unknown_relpath_raises_keyerror(store, case) -> None:
    run_id = _finished_run_with_output(store, case.id, _HIVE_BYTES)
    with pytest.raises(KeyError):
        store.resolve_output_file(case.id, run_id, "nope.bin")


@pytest.mark.parametrize("bad", ["/etc/passwd", "../../secret", "a/../../b"])
def test_resolve_output_file_rejects_traversal(store, case, bad) -> None:
    run_id = _finished_run_with_output(store, case.id, _HIVE_BYTES)
    with pytest.raises(ValueError, match="relative|escape"):
        store.resolve_output_file(case.id, run_id, bad)
