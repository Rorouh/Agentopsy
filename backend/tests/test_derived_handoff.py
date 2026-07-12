"""Derived handoff: a binary tool's output refers to its artifact, and a downstream
tool consumes that artifact as input — resolved + RE-HASHED by the backend (bloqueante
del audit: la cadena multi-tool con custodia).

Two properties pin the chain ``icat → artefacto → RegRipper``:

  * SURFACE (1): a ``binary_stdout`` tool (TSK ``icat``) whose raw bytes went to a hashed
    artifact file must REMIT TO THE ARTIFACT ({run_id, relpath, sha256, size}) in its
    result — never ``content_length: 0``, which reads as "the tool returned nothing".
  * DERIVED HANDOFF (2): a consumer (RegRipper) may take, for a declared input param, an
    ArtifactRef ({run_id, relpath, sha256?, size?}) the dispatcher resolves to the
    producing run's
    on-disk file, RE-VERIFYING its SHA-256 against the manifest BEFORE running (custody of
    the derivative — FORENSIC INVARIANTS 1-2) and recording the derivation LINK in the
    audit (INVARIANT 4). A hash mismatch fails loud (RULE 2), never runs on a tampered file.

No docker / no maletín: the maletín runner is faked, storage lives in ``tmp_path``.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

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
def case(cases):
    created = cases.create(name="op", examiner="alice", os_profile="windows")
    (cases.root / created.id / "evidence" / "original.raw").write_bytes(b"disk")
    return created


@pytest.fixture
def wired_dispatcher(monkeypatch, cases, store):
    monkeypatch.setattr(dispatcher, "case_manager", cases)
    monkeypatch.setattr(dispatcher, "artifact_store", store)
    # Force the maletín venue for every tool (no api-PATH binary in the test env).
    monkeypatch.setattr(dispatcher, "resolve", lambda _binary: None)
    return dispatcher


def _audit_entries(cases: CaseManager, case_id: str) -> list[dict]:
    return AuditLog(cases.root / case_id / "audit.jsonl").entries()


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


def _run_icat(wired_dispatcher, monkeypatch, case, captured) -> dict:
    monkeypatch.setattr(
        wired_dispatcher.maletin, "run_argv_in_maletin", _fake_maletin(captured)
    )
    return wired_dispatcher.execute(
        "tsk_icat",
        {
            "image_path": str(
                wired_dispatcher.case_manager.root
                / case.id
                / "evidence"
                / "original.raw"
            ),
            "inode": 5,
        },
        case_id=case.id,
        os_profile="windows",
    )


# --------------------------------------------------------------------------- #
# (1) a binary tool's result refers to the artifact, not content_length:0
# --------------------------------------------------------------------------- #
def test_binary_result_refers_to_artifact_not_content_length_zero(
    wired_dispatcher, monkeypatch, case
) -> None:
    captured: dict = {}
    result = _run_icat(wired_dispatcher, monkeypatch, case, captured)

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
    wired_dispatcher, monkeypatch, case, cases
) -> None:
    captured: dict = {}
    icat = _run_icat(wired_dispatcher, monkeypatch, case, captured)
    ref = icat["parsed"]["artifact"]  # {run_id, relpath, sha256, size}

    # The consumer takes the icat artifact ref where it expects `hive_path` — no path
    # invented by the agent. The dispatcher resolves + re-hashes it before running.
    regripper = wired_dispatcher.execute(
        "regripper",
        {"hive_path": ref, "plugin": "compname"},
        case_id=case.id,
        os_profile="windows",
    )
    assert regripper["exit_code"] == 0

    # RegRipper ran with the RESOLVED on-disk path of the hive (not the raw ref/dict).
    regripper_call = captured["calls"][-1]
    resolved = (
        cases.root / case.id / "artifacts" / ref["run_id"] / "out" / "stdout.bin"
    ).resolve()
    assert str(resolved) in regripper_call["argv"]
    assert Path(str(resolved)).read_bytes() == _HIVE_BYTES  # untouched, RO in spirit

    # INVARIANT 4: the audit records the derivation (artifact of run A → input of run B).
    starts = [
        e
        for e in _audit_entries(cases, case.id)
        if e.get("action") == "tool_run_start" and e.get("run_id") == regripper["run_id"]
    ]
    assert len(starts) == 1
    links = starts[0]["derived_inputs"]
    assert len(links) == 1
    link = links[0]
    assert link["param"] == "hive_path"
    assert link["source_run_id"] == ref["run_id"]
    assert link["relpath"] == "stdout.bin"
    assert link["sha256"] == _HIVE_SHA  # the digest actually re-verified before running


def test_icat_to_regripper_handoff_hash_mismatch_fails_loud(
    wired_dispatcher, monkeypatch, case, cases
) -> None:
    captured: dict = {}
    icat = _run_icat(wired_dispatcher, monkeypatch, case, captured)
    ref = icat["parsed"]["artifact"]

    # Custody break: the derived file's bytes change after its run recorded their SHA-256.
    on_disk = cases.root / case.id / "artifacts" / ref["run_id"] / "out" / "stdout.bin"
    on_disk.write_bytes(_HIVE_BYTES + b"TAMPERED")

    with pytest.raises(wired_dispatcher.ToolExecutionError, match="custodia|SHA-256|match"):
        wired_dispatcher.execute(
            "regripper",
            {"hive_path": ref, "plugin": "compname"},
            case_id=case.id,
            os_profile="windows",
        )

    # A tampered derivative never reaches the runner (RULE 2): no start for a 2nd run.
    starts = [e for e in _audit_entries(cases, case.id) if e.get("action") == "tool_run_start"]
    assert len(starts) == 1  # only the icat run started


def test_minimal_artifact_ref_remains_compatible(
    wired_dispatcher, monkeypatch, case
) -> None:
    captured: dict = {}
    icat = _run_icat(wired_dispatcher, monkeypatch, case, captured)
    ref = icat["parsed"]["artifact"]
    result = wired_dispatcher.execute(
        "regripper",
        {
            "hive_path": {"run_id": ref["run_id"], "relpath": ref["relpath"]},
            "plugin": "compname",
        },
        case_id=case.id,
        os_profile="windows",
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
    wired_dispatcher, monkeypatch, case, cases, mutated
) -> None:
    captured: dict = {}
    icat = _run_icat(wired_dispatcher, monkeypatch, case, captured)
    ref = {**icat["parsed"]["artifact"], **mutated}
    calls_before = len(captured["calls"])
    starts_before = len(
        [e for e in _audit_entries(cases, case.id) if e.get("action") == "tool_run_start"]
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
        )

    assert len(captured["calls"]) == calls_before
    starts_after = len(
        [e for e in _audit_entries(cases, case.id) if e.get("action") == "tool_run_start"]
    )
    assert starts_after == starts_before


def test_artifact_ref_without_case_id_fails_loud(wired_dispatcher) -> None:
    # Resolving + re-hashing a derivative needs the case; a ref without case_id is refused
    # rather than passed to the wrapper as if it were a literal path.
    with pytest.raises(wired_dispatcher.ToolExecutionError, match="case_id|artefacto"):
        wired_dispatcher.execute(
            "regripper",
            {"hive_path": {"run_id": "x", "relpath": "stdout.bin"}, "plugin": "compname"},
        )


# --------------------------------------------------------------------------- #
# (3) the store's custody gate in isolation: confinement + re-hash
# --------------------------------------------------------------------------- #
def _finished_run_with_output(store: ArtifactStore, case_id: str, payload: bytes) -> str:
    run_id, out_dir = store.start_run(case_id, "tsk_icat", argv=["icat"])
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
