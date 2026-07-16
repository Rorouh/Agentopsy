"""Cloud-egress safety: redaction (F1) and audit (F3).

These guard the egress border of FORENSIC_SOUNDNESS §5: the per-package
``policy/redaction.yaml`` is actually applied to a cloud payload (and only to a
cloud payload), and every egress + finding is chained into the case audit log.

Per-case cloud-egress consent was removed (2026-07-16): a cloud run no longer
requires a recorded ``consent_ref``. The redaction + audit protections below are
unaffected — they are what actually minimizes and records what crosses the wire.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from forensia.agent.agent import ForensicAgent
from forensia.agent.package import (
    AgentPackage,
    AgentPackageModel,
    AgentPackagePolicy,
    AgentPackagePrompts,
    RedactionPattern,
)
from forensia.agent.redaction import apply_redaction, redact_messages
from forensia.audit.log import AuditLog
from forensia.cases.manager import CaseManager
from forensia.evidence import EvidenceManager
from forensia.findings.store import FindingStore
from forensia.models.base import FinalAnswer, ModelBackend, ModelCapabilities, ToolCall

# Two of the real forensia-unix patterns — enough to prove the egress border.
EMAIL = RedactionPattern(
    name="email",
    regex=r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    replacement="<EMAIL>",
)
IPV4 = RedactionPattern(
    name="ipv4",
    regex=r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    replacement="<IPV4>",
)
PATTERNS = (EMAIL, IPV4)

# Evidence-derived PII a tool would surface (e.g. bulk_extractor output).
SECRET_EMAIL = "suspect.alice@corp.example"
SECRET_IP = "10.13.37.42"
_RUN_UUID = "11111111-1111-4111-8111-111111111111"


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #
class ScriptedBackend(ModelBackend):
    """A ModelBackend that replays a fixed script and records exactly what it was
    sent on each ``next_action`` (so a test can assert what crossed the wire)."""

    def __init__(self, actions, is_local: bool) -> None:
        self.name = "scripted"
        self.model_name = "scripted-model"
        self._actions = list(actions)
        self._is_local = is_local
        self.seen_messages: list[list[dict]] = []
        self.calls = 0

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            supports_native_tools=True,
            json_mode=True,
            max_context=128_000,
            is_local=self._is_local,
        )

    def next_action(self, state, tools):
        self.calls += 1
        # Snapshot the payload as received (post-redaction for a cloud backend).
        self.seen_messages.append(json.loads(json.dumps(state["messages"], default=str)))
        if self._actions:
            return self._actions.pop(0)
        return FinalAnswer(text="listo")


def _fake_execute(
    tool_id, params, *, case_id=None, os_profile=None, timeout=None, evidence_context=None
):
    """Stand-in for the dispatcher: a tool run whose stdout carries PII.

    Mirrors ``forensia.toolkit.dispatcher.execute`` — keyword-only ``case_id`` /
    ``os_profile`` / ``timeout`` / ``evidence_context`` — so it stays in step with the
    merged agent loop (which passes ``os_profile=self.os_profile`` and the verified
    ``evidence_context`` built from the handle)."""
    return {
        "tool_id": tool_id,
        "exit_code": 0,
        "run_id": _RUN_UUID,
        "parsed": {"hint": "ver stdout"},
        "stdout_sample": f"owner {SECRET_EMAIL} connected from {SECRET_IP}",
        "stderr_sample": "",
        "argv": [tool_id],
        "artifact_run": {"run_id": _RUN_UUID, "exit_code": 0, "output_files": []},
    }


def _make_package(patterns=PATTERNS) -> AgentPackage:
    return AgentPackage(
        id="test-unix",
        name="Test Unix",
        version="0.1.0",
        os_profile="unix",
        authors=("tester",),
        path=Path("/nonexistent"),
        model=AgentPackageModel(
            name="scripted-model", temperature=0.0, max_iterations=4
        ),
        prompts=AgentPackagePrompts(system="SYS", identity="ID", playbook="PB"),
        policy=AgentPackagePolicy(
            allowed_tools=("file_info",), redaction_patterns=patterns
        ),
    )


@pytest.fixture
def anchored(tmp_path):
    """A real case + registered evidence on a tmp-rooted CaseManager."""
    cases = CaseManager(root=tmp_path / "cases")
    evidence = EvidenceManager(cases)
    case = cases.create(name="op", examiner="alice", os_profile="unix")
    src = tmp_path / "e.raw"
    src.write_bytes(b"FORENSIA-EVIDENCE")
    handle = evidence.register(case.id, str(src))
    return {"cases": cases, "evidence": evidence, "case": case, "handle": handle}


# --------------------------------------------------------------------------- #
# F1 — redaction is applied at the cloud-egress boundary (and only there)
# --------------------------------------------------------------------------- #
class TestRedaction:
    def test_apply_redaction_replaces_email_and_ip(self):
        out = apply_redaction(f"mail {SECRET_EMAIL} ip {SECRET_IP}", PATTERNS)
        assert SECRET_EMAIL not in out
        assert SECRET_IP not in out
        assert out == "mail <EMAIL> ip <IPV4>"

    def test_apply_redaction_empty_patterns_is_noop(self):
        assert apply_redaction(SECRET_EMAIL, ()) == SECRET_EMAIL

    def test_redact_messages_does_not_mutate_input(self):
        msgs = [{"role": "tool", "content": f"x {SECRET_IP}"}]
        out = redact_messages(msgs, PATTERNS)
        assert msgs[0]["content"] == f"x {SECRET_IP}"  # original untouched
        assert out[0]["content"] == "x <IPV4>"

    def test_cloud_egress_redacts_tool_results(self, anchored, monkeypatch):
        import forensia.toolkit.dispatcher as disp

        monkeypatch.setattr(disp, "execute", _fake_execute)

        backend = ScriptedBackend(
            actions=[ToolCall(tool_id="file_info", params={}, call_id="c1")],
            is_local=False,
        )
        agent = ForensicAgent(
            package=_make_package(),
            model=backend,
            evidence=anchored["evidence"],
            audit=None,
        )
        agent.run(
            prompt="analiza el archivo",
            case_id=anchored["case"].id,
            evidence_id=anchored["handle"].evidence_id,
        )

        # Last payload = the conversation AFTER the tool result was appended.
        assert backend.calls >= 2
        sent = json.dumps(backend.seen_messages[-1])
        assert SECRET_EMAIL not in sent
        assert SECRET_IP not in sent
        assert "<EMAIL>" in sent
        assert "<IPV4>" in sent

    def test_local_backend_does_not_redact(self, anchored, monkeypatch):
        import forensia.toolkit.dispatcher as disp

        monkeypatch.setattr(disp, "execute", _fake_execute)

        backend = ScriptedBackend(
            actions=[ToolCall(tool_id="file_info", params={}, call_id="c1")],
            is_local=True,
        )
        agent = ForensicAgent(
            package=_make_package(),
            model=backend,
            evidence=anchored["evidence"],
            audit=None,
        )
        agent.run(
            prompt="analiza el archivo",
            case_id=anchored["case"].id,
            evidence_id=anchored["handle"].evidence_id,
        )

        sent = json.dumps(backend.seen_messages[-1])
        assert SECRET_EMAIL in sent  # raw bytes pass through intact
        assert SECRET_IP in sent
        assert "<EMAIL>" not in sent


# --------------------------------------------------------------------------- #
# F3 — egress + findings are chained into the case audit log
# --------------------------------------------------------------------------- #
class TestAudit:
    def test_run_audits_start_egress_and_finding(self, anchored, monkeypatch):
        cases = anchored["cases"]
        # Point the agent's finding store at the tmp case root.
        monkeypatch.setattr(
            "forensia.agent.agent.finding_store", FindingStore(cases)
        )

        audit = AuditLog(cases.case_dir(anchored["case"].id) / "audit.jsonl")
        finding_call = ToolCall(
            tool_id="record_finding",
            params={
                "title": "Hallazgo", "summary": "algo relevante", "severity": "low",
                # Hallazgo afirmativo: el store exige procedencia (run_id) — RULE 2.
                "run_id": "11111111-1111-4111-8111-111111111111",
            },
            call_id="c1",
        )
        backend = ScriptedBackend(actions=[finding_call], is_local=False)
        agent = ForensicAgent(
            package=_make_package(),
            model=backend,
            evidence=anchored["evidence"],
            audit=audit,
        )
        agent.run(
            prompt="analiza",
            case_id=anchored["case"].id,
            evidence_id=anchored["handle"].evidence_id,
        )

        events = [
            json.loads(line)
            for line in audit.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        # The audit also carries the `evidence_register` entry from the fixture
        # (keyed on "action", not "event"); key on .get so those don't KeyError.
        kinds = [e.get("event") for e in events]
        assert "agent_run_start" in kinds
        assert "agent_cloud_egress" in kinds
        assert "agent_finding" in kinds
        # The chain is intact.
        assert audit.verify() is True

        egress = next(e for e in events if e.get("event") == "agent_cloud_egress")
        assert len(egress["redacted_payload_sha256"]) == 64
        assert egress["message_count"] >= 2
        # No raw evidence bytes in the audit — only hashes/metadata.
        assert SECRET_EMAIL not in audit.path.read_text(encoding="utf-8")

        finding_ev = next(e for e in events if e.get("event") == "agent_finding")
        assert finding_ev["finding_id"]

    def test_local_run_audits_start_without_egress(self, anchored):
        cases = anchored["cases"]
        audit = AuditLog(cases.case_dir(anchored["case"].id) / "audit.jsonl")
        backend = ScriptedBackend(actions=[FinalAnswer(text="ok")], is_local=True)
        agent = ForensicAgent(
            package=_make_package(),
            model=backend,
            evidence=anchored["evidence"],
            audit=audit,
        )
        agent.run(
            prompt="analiza",
            case_id=anchored["case"].id,
            evidence_id=anchored["handle"].evidence_id,
        )
        kinds = [
            json.loads(line).get("event")
            for line in audit.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert "agent_run_start" in kinds
        assert "agent_cloud_egress" not in kinds  # local never egresses
        assert audit.verify() is True
