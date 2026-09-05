"""P0.5-2/3: mandatory path-role gate before every forensic runner boundary.

Anchored runs now carry the verified ``EvidenceContext`` (validated against
``EvidenceManager``) and an authoritative maletín ``tool_version``; fixtures register
REAL evidence through the hash gate and drive the maletín venue (transport faked).
``EVIDENCE_INPUT`` paths are confined to the CONTEXT evidence's own directory —
same-case is not same-evidence.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from _custody import context_for, register_evidence, wire_dispatcher_custody
from _symlink_support import requires_symlinks
from agentopsy.agent.agent import ForensicAgent
from agentopsy.agent.tool_schemas import TOOL_PARAM_SCHEMAS
from agentopsy.artifact_ref import validate_artifact_ref
from agentopsy.artifacts.store import ArtifactStore
from agentopsy.audit.log import AuditLog
from agentopsy.cases.manager import CaseManager
from agentopsy.evidence import EvidenceManager
from agentopsy.mcp.schemas import RegRipperParams
from agentopsy.mcp.toolkit import _dispatch_forensic
from agentopsy.toolkit import dispatcher


@pytest.fixture
def cases(tmp_path) -> CaseManager:
    return CaseManager(root=tmp_path / "cases")


@pytest.fixture
def store(cases) -> ArtifactStore:
    return ArtifactStore(cases)


@pytest.fixture
def active_case(cases, tmp_path):
    case = cases.create("active", "alice", os_profile="windows")
    handle = register_evidence(
        cases, case.id, tmp_path, payload=b"evidence", name="active.raw"
    )
    return case, handle, context_for(handle)


@pytest.fixture
def other_case(cases, tmp_path):
    case = cases.create("other", "bob", os_profile="windows")
    handle = register_evidence(
        cases, case.id, tmp_path, payload=b"other", name="other.raw"
    )
    return case, handle, context_for(handle)


@pytest.fixture
def wired(monkeypatch, cases, store):
    """Maletín-venue wiring: captured argv list + faked version transport."""
    calls: list[list[str]] = []
    wire_dispatcher_custody(monkeypatch, dispatcher, cases, store)
    monkeypatch.setattr(dispatcher, "resolve", lambda _binary: None)

    def fake_exec(service, argv, *, timeout=None, stdout_path=None, ewf_image=None):
        del service, timeout, stdout_path, ewf_image
        calls.append(list(argv))
        return 0, "ok", ""

    monkeypatch.setattr(dispatcher.maletin, "run_argv_in_maletin", fake_exec)
    return calls


def _tool_audit(cases: CaseManager, case_id: str) -> list[dict]:
    return [
        e
        for e in AuditLog(cases.root / case_id / "audit.jsonl").entries()
        if str(e.get("action", "")).startswith("tool_run_")
    ]


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
    case, _handle, ctx = active_case
    with pytest.raises(dispatcher.ToolExecutionError, match="path|sensitive|root"):
        dispatcher.execute(
            "file_info",
            {"image_path": candidate},
            case_id=case.id,
            os_profile="windows",
            evidence_context=ctx,
        )
    assert wired == []
    assert _tool_audit(cases, case.id) == []


@requires_symlinks
def test_symlink_escape_from_evidence_dir_is_rejected(
    wired, cases, active_case, tmp_path
) -> None:
    case, handle, ctx = active_case
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"secret")
    link = handle.original_path.parent / "escape.bin"
    link.symlink_to(outside)
    with pytest.raises(dispatcher.ToolExecutionError, match="outside authorized root"):
        dispatcher.execute(
            "file_info",
            {"image_path": str(link)},
            case_id=case.id,
            os_profile="windows",
            evidence_context=ctx,
        )
    assert wired == []


def test_cross_case_input_rejected(wired, active_case, other_case) -> None:
    case, _handle, ctx = active_case
    _, other_handle, _ = other_case
    with pytest.raises(dispatcher.ToolExecutionError, match="outside authorized root"):
        dispatcher.execute(
            "file_info",
            {"image_path": str(other_handle.original_path)},
            case_id=case.id,
            os_profile="windows",
            evidence_context=ctx,
        )
    assert wired == []


def test_same_case_other_evidence_path_rejected_under_this_context(
    wired, cases, active_case, tmp_path
) -> None:
    """Same-case is NOT same-evidence: a path to evidence B cannot run with A's
    verified context — the audit would bind the action to the wrong evidence."""
    case, _handle_a, ctx_a = active_case
    handle_b = register_evidence(
        cases, case.id, tmp_path, payload=b"second-evidence", name="b.raw"
    )
    with pytest.raises(dispatcher.ToolExecutionError, match="outside authorized root"):
        dispatcher.execute(
            "file_info",
            {"image_path": str(handle_b.original_path)},
            case_id=case.id,
            os_profile="windows",
            evidence_context=ctx_a,
        )
    assert wired == []
    assert _tool_audit(cases, case.id) == []


def test_same_case_other_evidence_path_rejected_as_case_input(
    wired, cases, active_case, tmp_path
) -> None:
    """The same-evidence rule also binds AUXILIARY inputs: a CASE_INPUT (yara
    rules_path) pointing under case_dir/evidence/ is rejected — evidence bytes enter
    only through the context-confined EVIDENCE_INPUT or a re-hashed ArtifactRef,
    never as a side-door 'auxiliary' read of another evidence of the case."""
    case, handle_a, ctx_a = active_case
    handle_b = register_evidence(
        cases, case.id, tmp_path, payload=b"second-evidence", name="b.raw"
    )
    with pytest.raises(dispatcher.ToolExecutionError, match="misma evidencia"):
        dispatcher.execute(
            "yara",
            {
                "rules_path": str(handle_b.original_path),  # evidence B as "rules"
                "target_path": str(handle_a.original_path),
            },
            case_id=case.id,
            os_profile="windows",
            evidence_context=ctx_a,
        )
    # Even THIS context's own evidence is not a valid CASE_INPUT (role confusion):
    # the auxiliary role must never alias evidence bytes.
    with pytest.raises(dispatcher.ToolExecutionError, match="misma evidencia"):
        dispatcher.execute(
            "yara",
            {
                "rules_path": str(handle_a.original_path),
                "target_path": str(handle_a.original_path),
            },
            case_id=case.id,
            os_profile="windows",
            evidence_context=ctx_a,
        )
    # Nor an ANCESTOR directory that subsumes the reserved subtrees: rules_path =
    # case_dir would let the tool walk into evidence/<B>/ (and artifacts/) anyway
    # (directory-kind bypass) — either reserved-subtree rejection is correct.
    with pytest.raises(
        dispatcher.ToolExecutionError, match="misma evidencia|artifacts/"
    ):
        dispatcher.execute(
            "yara",
            {
                "rules_path": str(cases.root / case.id),
                "target_path": str(handle_a.original_path),
            },
            case_id=case.id,
            os_profile="windows",
            evidence_context=ctx_a,
        )
    assert wired == []
    assert _tool_audit(cases, case.id) == []
    # handle_b's registration stays intact — only the auxiliary read was refused.
    assert handle_b.original_path.exists()


def test_existing_same_case_evidence_is_canonicalized_and_accepted(
    wired, active_case
) -> None:
    case, handle, ctx = active_case
    result = dispatcher.execute(
        "file_info",
        {"image_path": str(handle.original_path)},
        case_id=case.id,
        os_profile="windows",
        evidence_context=ctx,
    )
    assert result["exit_code"] == 0
    assert wired[0][-1] == str(handle.original_path.resolve())


def test_case_input_is_same_case_only_for_yara(
    wired, cases, active_case, other_case
) -> None:
    case, handle, ctx = active_case
    rules = cases.root / case.id / "rules.yar"
    rules.write_text("rule x { condition: true }", encoding="utf-8")
    result = dispatcher.execute(
        "yara",
        {"rules_path": str(rules), "target_path": str(handle.original_path)},
        case_id=case.id,
        os_profile="windows",
        evidence_context=ctx,
    )
    assert result["exit_code"] == 0

    other, _other_handle, _ = other_case
    other_rules = cases.root / other.id / "rules.yar"
    other_rules.write_text("rule y { condition: true }", encoding="utf-8")
    with pytest.raises(dispatcher.ToolExecutionError, match="outside authorized root"):
        dispatcher.execute(
            "yara",
            {"rules_path": str(other_rules), "target_path": str(handle.original_path)},
            case_id=case.id,
            os_profile="windows",
            evidence_context=ctx,
        )


def test_derived_input_rejects_free_artifact_path_and_accepts_verified_ref(
    wired, store, cases, active_case
) -> None:
    case, _handle, ctx = active_case
    source_run, out_dir = store.start_run(
        case.id,
        "producer",
        ["producer"],
        evidence_id=ctx.evidence_id,
        evidence_baseline_sha256=ctx.baseline_sha256,
        tool_version="producer 1.0 (dpkg)",
    )
    produced = out_dir / "data.json"
    produced.write_text('{"value": 7}', encoding="utf-8")
    store.finalize_run(case.id, source_run, exit_code=0, stdout="", stderr="")

    with pytest.raises(dispatcher.ToolExecutionError, match="DERIVED_INPUT"):
        dispatcher.execute(
            "jq",
            {"filter": ".value", "input_path": str(produced)},
            case_id=case.id,
            os_profile="windows",
            evidence_context=ctx,
        )
    result = dispatcher.execute(
        "jq",
        {
            "filter": ".value",
            "input_path": {"run_id": source_run, "relpath": "data.json"},
        },
        case_id=case.id,
        os_profile="windows",
        evidence_context=ctx,
    )
    assert result["exit_code"] == 0
    assert str(produced.resolve()) in wired[-1]
    start = next(
        entry
        for entry in _tool_audit(cases, case.id)
        if entry.get("action") == "tool_run_start" and entry.get("run_id") == result["run_id"]
    )
    assert start["derived_inputs"][0]["source_run_id"] == source_run
    # The derivation link records the producer's verified evidence provenance.
    assert start["derived_inputs"][0]["source_evidence_id"] == ctx.evidence_id


@pytest.mark.parametrize(
    "override",
    ["case.json", "audit.jsonl", "baseline.json", "artifacts/other-run/out"],
)
def test_run_output_override_cannot_target_case_metadata_or_another_run(
    wired, cases, active_case, override
) -> None:
    case, handle, ctx = active_case
    attempted = cases.root / case.id / override
    with pytest.raises(dispatcher.ToolExecutionError, match="RUN_OUTPUT"):
        dispatcher.execute(
            "bulk_extractor",
            {"image_path": str(handle.original_path), "output_dir": str(attempted)},
            case_id=case.id,
            os_profile="windows",
            evidence_context=ctx,
        )
    assert wired == []
    assert _tool_audit(cases, case.id) == []


def test_bulk_extractor_gets_fresh_run_subdir_and_manifest_hashes_outputs(
    monkeypatch, wired, store, cases, active_case
) -> None:
    case, handle, ctx = active_case
    captured: dict[str, Path] = {}

    def fake_exec(service, argv, *, timeout=None, stdout_path=None, ewf_image=None):
        del service, timeout, stdout_path, ewf_image
        output_arg = Path(argv[argv.index("-o") + 1])
        captured["output"] = output_arg
        assert not output_arg.exists()
        output_arg.mkdir()
        (output_arg / "report.txt").write_bytes(b"bulk report")
        return 0, "ok", ""

    monkeypatch.setattr(dispatcher.maletin, "run_argv_in_maletin", fake_exec)
    result = dispatcher.execute(
        "bulk_extractor",
        {"image_path": str(handle.original_path)},
        case_id=case.id,
        os_profile="windows",
        evidence_context=ctx,
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
    case, handle, ctx = active_case
    target_dir = handle.original_path.parent
    result = dispatcher.execute(
        "chainsaw",
        {
            "target_dir": str(target_dir),
            "ruleset": "chainsaw-native",
            "output_format": "csv",
        },
        case_id=case.id,
        os_profile="windows",
        evidence_context=ctx,
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
            evidence_context=ctx,
        )


def test_qemu_nbd_writable_request_rejected_before_runner_and_start(
    wired, cases, active_case
) -> None:
    case, handle, ctx = active_case
    with pytest.raises(ValueError, match="always read-only"):
        dispatcher.execute(
            "qemu_nbd",
            {
                "image_path": str(handle.original_path),
                "nbd_device": "nbd0",
                "read_only": False,
            },
            case_id=case.id,
            os_profile="windows",
            evidence_context=ctx,
        )
    assert wired == []
    assert _tool_audit(cases, case.id) == []


def test_agent_injection_rejects_llm_chosen_evidence_path() -> None:
    with pytest.raises(ValueError, match="may not choose an EVIDENCE_INPUT"):
        ForensicAgent._inject_runtime_paths(
            "yara", {"target_path": "/etc/passwd", "rules_path": "rules.yar"}, "/safe"
        )


async def test_mcp_path_flows_to_shared_dispatcher_gate(
    monkeypatch, wired, cases, active_case
) -> None:
    case, handle, _ctx = active_case
    package = SimpleNamespace(
        id="test-package",
        os_profile="windows",
        policy=SimpleNamespace(allowed_tools=("yara",), redaction_patterns=()),
    )
    session = SimpleNamespace(
        case_id=case.id,
        evidence_id=handle.evidence_id,
        agent_package=package,
    )
    # The MCP surface reads the module-level singleton at call time; point it at the
    # SAME tmp-rooted EvidenceManager the dispatcher validates against.
    monkeypatch.setattr("agentopsy.evidence.evidence_manager", EvidenceManager(cases))
    outside_rules = cases.root.parent / "outside.yar"
    outside_rules.write_text("rule outside { condition: true }", encoding="utf-8")
    response = await _dispatch_forensic(
        "yara", {"rules_path": str(outside_rules)}, session
    )
    payload = json.loads(response[0].text)
    assert payload["isError"] is True
    assert "outside authorized root" in payload["error"]
    assert wired == []
    assert _tool_audit(cases, case.id) == []
