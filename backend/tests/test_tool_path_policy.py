"""P0.5-2: mandatory path-role gate before every forensic runner boundary."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from forensia.agent.agent import ForensicAgent
from forensia.agent.tool_schemas import TOOL_PARAM_SCHEMAS
from forensia.artifact_ref import validate_artifact_ref
from forensia.artifacts.store import ArtifactStore
from forensia.audit.log import AuditLog
from forensia.cases.manager import CaseManager
from forensia.evidence import evidence_manager
from forensia.evidence_context import EvidenceContext
from forensia.mcp.toolkit import _dispatch_forensic
from forensia.mcp.schemas import RegRipperParams
from forensia.toolkit import dispatcher
from _symlink_support import requires_symlinks

# Verified evidence context an anchored, evidence-reading run carries (INVARIANT 4).
_CTX = EvidenceContext(
    evidence_id="a1a1a1a1-a1a1-4a1a-8a1a-a1a1a1a1a1a1", baseline_sha256="6" * 64
)


@pytest.fixture
def cases(tmp_path) -> CaseManager:
    return CaseManager(root=tmp_path / "cases")


@pytest.fixture
def store(cases) -> ArtifactStore:
    return ArtifactStore(cases)


@pytest.fixture
def active_case(cases):
    case = cases.create("active", "alice", os_profile="windows")
    evidence_dir = cases.root / case.id / "evidence" / "e1"
    evidence_dir.mkdir()
    evidence_file = evidence_dir / "original.raw"
    evidence_file.write_bytes(b"evidence")
    return case, evidence_file


@pytest.fixture
def other_case(cases):
    case = cases.create("other", "bob", os_profile="windows")
    evidence_dir = cases.root / case.id / "evidence" / "e2"
    evidence_dir.mkdir()
    evidence_file = evidence_dir / "original.raw"
    evidence_file.write_bytes(b"other")
    return case, evidence_file


@pytest.fixture
def wired(monkeypatch, cases, store):
    calls: list[list[str]] = []
    monkeypatch.setattr(dispatcher, "case_manager", cases)
    monkeypatch.setattr(dispatcher, "artifact_store", store)
    monkeypatch.setattr(dispatcher, "resolve", lambda binary: Path("/fake") / binary)

    def fake_run(argv, *, timeout=None, stdout_path=None):
        del timeout, stdout_path
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "ok", "")

    monkeypatch.setattr(dispatcher, "run_argv", fake_run)
    return calls


def _audit(cases: CaseManager, case_id: str) -> list[dict]:
    return AuditLog(cases.root / case_id / "audit.jsonl").entries()


def test_artifact_ref_shared_contract_accepts_minimal_and_producer_shape() -> None:
    minimal = {"run_id": "run-1", "relpath": "stdout.bin"}
    complete = {
        **minimal,
        "sha256": "a" * 64,
        "size": 17,
    }
    assert validate_artifact_ref(minimal) == minimal
    assert validate_artifact_ref(complete) == complete
    assert (
        RegRipperParams(hive_path=complete)
        .model_dump(exclude_none=True)["hive_path"]
        == complete
    )
    agent_schema = TOOL_PARAM_SCHEMAS["regripper"]["properties"]["hive_path"]
    assert set(agent_schema["required"]) == {"run_id", "relpath"}
    assert agent_schema["additionalProperties"] is False
    assert {"sha256", "size"} <= set(agent_schema["properties"])


@pytest.mark.parametrize(
    "bad",
    [
        {"run_id": "", "relpath": "x"},
        {"run_id": "r", "relpath": ""},
        {"run_id": "r", "relpath": "x", "sha256": "not-a-sha256"},
        {"run_id": "r", "relpath": "x", "size": -1},
        {"run_id": "r", "relpath": "x", "size": 1.5},
        {"run_id": "r", "relpath": "x", "unknown": True},
    ],
)
def test_artifact_ref_shared_contract_rejects_invalid_shape(bad) -> None:
    with pytest.raises(ValueError, match="ArtifactRef"):
        validate_artifact_ref(bad)


@pytest.mark.parametrize(
    "candidate",
    ["../case.json", "/etc/passwd", "~/.ssh/id_rsa", "~/.aws/credentials"],
)
def test_untrusted_evidence_paths_rejected_before_runner_and_audit_start(
    wired, cases, active_case, candidate
) -> None:
    case, _ = active_case
    with pytest.raises(dispatcher.ToolExecutionError, match="path|sensitive|root"):
        dispatcher.execute(
            "file_info", {"image_path": candidate}, case_id=case.id, os_profile="windows"
        )
    assert wired == []
    assert _audit(cases, case.id) == []


@requires_symlinks
def test_symlink_escape_from_case_is_rejected(wired, cases, active_case, tmp_path) -> None:
    case, _ = active_case
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"secret")
    link = cases.root / case.id / "evidence" / "escape.bin"
    link.symlink_to(outside)
    with pytest.raises(dispatcher.ToolExecutionError, match="outside authorized root"):
        dispatcher.execute(
            "file_info", {"image_path": str(link)}, case_id=case.id, os_profile="windows"
        )
    assert wired == []


def test_cross_case_input_rejected(wired, active_case, other_case) -> None:
    case, _ = active_case
    _, other_evidence = other_case
    with pytest.raises(dispatcher.ToolExecutionError, match="outside authorized root"):
        dispatcher.execute(
            "file_info",
            {"image_path": str(other_evidence)},
            case_id=case.id,
            os_profile="windows",
        )
    assert wired == []


def test_existing_same_case_evidence_is_canonicalized_and_accepted(
    wired, active_case
) -> None:
    case, evidence_file = active_case
    result = dispatcher.execute(
        "file_info",
        {"image_path": str(evidence_file)},
        case_id=case.id,
        os_profile="windows",
        evidence_context=_CTX,
    )
    assert result["exit_code"] == 0
    assert wired[0][-1] == str(evidence_file.resolve())


def test_case_input_is_same_case_only_for_yara(wired, cases, active_case, other_case) -> None:
    case, evidence_file = active_case
    rules = cases.root / case.id / "rules.yar"
    rules.write_text("rule x { condition: true }", encoding="utf-8")
    result = dispatcher.execute(
        "yara",
        {"rules_path": str(rules), "target_path": str(evidence_file)},
        case_id=case.id,
        os_profile="windows",
        evidence_context=_CTX,
    )
    assert result["exit_code"] == 0

    other, _ = other_case
    other_rules = cases.root / other.id / "rules.yar"
    other_rules.write_text("rule y { condition: true }", encoding="utf-8")
    with pytest.raises(dispatcher.ToolExecutionError, match="outside authorized root"):
        dispatcher.execute(
            "yara",
            {"rules_path": str(other_rules), "target_path": str(evidence_file)},
            case_id=case.id,
            os_profile="windows",
        )


def test_derived_input_rejects_free_artifact_path_and_accepts_verified_ref(
    wired, store, cases, active_case
) -> None:
    case, _ = active_case
    source_run, out_dir = store.start_run(case.id, "producer", ["producer"])
    produced = out_dir / "data.json"
    produced.write_text('{"value": 7}', encoding="utf-8")
    store.finalize_run(case.id, source_run, exit_code=0, stdout="", stderr="")

    with pytest.raises(dispatcher.ToolExecutionError, match="DERIVED_INPUT"):
        dispatcher.execute(
            "jq",
            {"filter": ".value", "input_path": str(produced)},
            case_id=case.id,
            os_profile="windows",
        )
    result = dispatcher.execute(
        "jq",
        {
            "filter": ".value",
            "input_path": {"run_id": source_run, "relpath": "data.json"},
        },
        case_id=case.id,
        os_profile="windows",
    )
    assert result["exit_code"] == 0
    assert str(produced.resolve()) in wired[-1]
    start = next(
        entry
        for entry in _audit(cases, case.id)
        if entry.get("action") == "tool_run_start" and entry.get("run_id") == result["run_id"]
    )
    assert start["derived_inputs"][0]["source_run_id"] == source_run


@pytest.mark.parametrize(
    "override",
    ["case.json", "audit.jsonl", "baseline.json", "artifacts/other-run/out"],
)
def test_run_output_override_cannot_target_case_metadata_or_another_run(
    wired, cases, active_case, override
) -> None:
    case, evidence_file = active_case
    attempted = cases.root / case.id / override
    with pytest.raises(dispatcher.ToolExecutionError, match="RUN_OUTPUT"):
        dispatcher.execute(
            "bulk_extractor",
            {"image_path": str(evidence_file), "output_dir": str(attempted)},
            case_id=case.id,
            os_profile="windows",
        )
    assert wired == []
    assert _audit(cases, case.id) == []


def test_bulk_extractor_gets_fresh_run_subdir_and_manifest_hashes_outputs(
    monkeypatch, wired, store, cases, active_case
) -> None:
    case, evidence_file = active_case
    captured: dict[str, Path] = {}

    def fake_run(argv, *, timeout=None, stdout_path=None):
        del timeout, stdout_path
        output_arg = Path(argv[argv.index("-o") + 1])
        captured["output"] = output_arg
        assert not output_arg.exists()
        output_arg.mkdir()
        (output_arg / "report.txt").write_bytes(b"bulk report")
        return subprocess.CompletedProcess(argv, 0, "ok", "")

    monkeypatch.setattr(dispatcher, "run_argv", fake_run)
    result = dispatcher.execute(
        "bulk_extractor",
        {"image_path": str(evidence_file)},
        case_id=case.id,
        os_profile="windows",
        evidence_context=_CTX,
    )
    out_dir = (
        cases.root / case.id / "artifacts" / result["run_id"] / "out"
    ).resolve()
    output_arg = captured["output"].resolve()
    assert output_arg == out_dir / "bulk_extractor"
    run = store.get_run(case.id, result["run_id"])
    output = next(
        of for of in run.output_files if of.relpath == "bulk_extractor/report.txt"
    )
    assert output.sha256 == hashlib.sha256(b"bulk report").hexdigest()


def test_bundled_ruleset_maps_exact_id_and_rejects_free_paths(
    wired, active_case
) -> None:
    case, evidence_file = active_case
    target_dir = evidence_file.parent
    result = dispatcher.execute(
        "chainsaw",
        {
            "target_dir": str(target_dir),
            "ruleset": "chainsaw-native",
            "output_format": "csv",
        },
        case_id=case.id,
        os_profile="windows",
        evidence_context=_CTX,
    )
    assert result["exit_code"] == 0
    assert "/opt/chainsaw-src/rules" in wired[0]
    assert "chainsaw-native" not in wired[0]

    with pytest.raises(dispatcher.ToolExecutionError, match="allowed exact ids"):
        dispatcher.execute(
            "chainsaw",
            {
                "target_dir": str(target_dir),
                "ruleset": "/opt/chainsaw-src/rules",
                "output_format": "csv",
            },
            case_id=case.id,
            os_profile="windows",
        )


def test_qemu_nbd_writable_request_rejected_before_runner_and_start(
    wired, cases, active_case
) -> None:
    case, evidence_file = active_case
    with pytest.raises(ValueError, match="always read-only"):
        dispatcher.execute(
            "qemu_nbd",
            {
                "image_path": str(evidence_file),
                "nbd_device": "nbd0",
                "read_only": False,
            },
            case_id=case.id,
            os_profile="unix",
            evidence_context=_CTX,
        )
    assert wired == []
    assert _audit(cases, case.id) == []


def test_agent_injection_rejects_llm_chosen_evidence_path() -> None:
    with pytest.raises(ValueError, match="may not choose an EVIDENCE_INPUT"):
        ForensicAgent._inject_runtime_paths(
            "yara", {"target_path": "/etc/passwd", "rules_path": "rules.yar"}, "/safe"
        )


async def test_mcp_path_flows_to_shared_dispatcher_gate(
    monkeypatch, wired, cases, active_case
) -> None:
    case, evidence_file = active_case
    package = SimpleNamespace(
        id="test-package",
        os_profile="windows",
        policy=SimpleNamespace(allowed_tools=("yara",)),
    )
    session = SimpleNamespace(
        case_id=case.id,
        evidence_id="e1",
        agent_package=package,
    )
    monkeypatch.setattr(
        evidence_manager,
        "get",
        # A real EvidenceHandle carries evidence_id + baseline sha256; the MCP path builds
        # the verified EvidenceContext from it before dispatching (INVARIANT 4).
        lambda case_id, evidence_id: SimpleNamespace(
            evidence_id=evidence_id,
            original_path=evidence_file,
            sha256="7" * 64,
        ),
    )
    outside_rules = cases.root.parent / "outside.yar"
    outside_rules.write_text("rule outside { condition: true }", encoding="utf-8")
    response = await _dispatch_forensic(
        "yara", {"rules_path": str(outside_rules)}, session
    )
    payload = json.loads(response[0].text)
    assert payload["isError"] is True
    assert "outside authorized root" in payload["error"]
    assert wired == []
    assert _audit(cases, case.id) == []
