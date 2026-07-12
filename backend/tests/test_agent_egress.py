"""Cloud-egress safety: redaction (F1), per-case consent (F2), audit (F3).

These guard THREAT_MODEL gate 9 ("sin consentimiento → 0 bytes salen") and the
egress border of FORENSIC_SOUNDNESS §5: the per-package ``policy/redaction.yaml``
is actually applied, cloud needs recorded consent, and every egress + finding is
chained into the case audit log.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

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
from forensia.cases.manager import CaseManager, CloudConsent
from forensia.evidence import EvidenceManager
from forensia.executors import ClaudeCodeExecutor, ExecutorAvailability
from forensia.executors.base import ExecutorResult
from forensia.findings.store import FindingStore
from forensia.models.base import FinalAnswer, ModelBackend, ModelCapabilities, ToolCall
from forensia.server import create_app

PORT = 51001

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
            consent_ref="ref-x",
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
        # Local needs no consent_ref — nothing leaves the host.
        agent.run(
            prompt="analiza el archivo",
            case_id=anchored["case"].id,
            evidence_id=anchored["handle"].evidence_id,
        )

        sent = json.dumps(backend.seen_messages[-1])
        assert SECRET_EMAIL in sent  # raw bytes pass through intact
        assert SECRET_IP in sent
        assert "<EMAIL>" not in sent

    def test_cloud_without_consent_ref_refuses_before_egress(self, anchored):
        backend = ScriptedBackend(actions=[], is_local=False)
        agent = ForensicAgent(
            package=_make_package(),
            model=backend,
            evidence=anchored["evidence"],
            audit=None,
        )
        with pytest.raises(ValueError, match="consent_ref"):
            agent.run(
                prompt="analiza",
                case_id=anchored["case"].id,
                evidence_id=anchored["handle"].evidence_id,
            )
        assert backend.calls == 0  # zero bytes left the host


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
            params={"title": "Hallazgo", "summary": "algo relevante", "severity": "low"},
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
            consent_ref="ref-123",
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
        assert egress["consent_ref"] == "ref-123"
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


# --------------------------------------------------------------------------- #
# F2 — per-case consent state + the grant endpoint
# --------------------------------------------------------------------------- #
class TestConsentState:
    def test_new_case_has_no_consent(self, tmp_path):
        cases = CaseManager(root=tmp_path / "cases")
        case = cases.create(name="op", examiner="alice", os_profile="unix")
        assert case.cloud_consent is None

    def test_grant_cloud_consent_persists_and_roundtrips(self, tmp_path):
        cases = CaseManager(root=tmp_path / "cases")
        case = cases.create(name="op", examiner="alice", os_profile="unix")
        updated = cases.grant_cloud_consent(case.id, by="alice")
        assert isinstance(updated.cloud_consent, CloudConsent)
        assert updated.cloud_consent.granted is True
        assert updated.cloud_consent.by == "alice"
        assert updated.cloud_consent.ref
        reloaded = cases.load(case.id)
        assert reloaded.cloud_consent == updated.cloud_consent

    def test_grant_cloud_consent_rejects_empty_by(self, tmp_path):
        cases = CaseManager(root=tmp_path / "cases")
        case = cases.create(name="op", examiner="alice", os_profile="unix")
        with pytest.raises(ValueError, match="by"):
            cases.grant_cloud_consent(case.id, by="")


# --------------------------------------------------------------------------- #
# F2 — the /api/agent/query cloud-consent gate (no consent → 403, 0 egress)
# --------------------------------------------------------------------------- #
class TestConsentGate:
    """HTTP enforcement of SECURITY INVARIANT 7 on the NEW executor architecture.

    Consent is no longer a ``case.cloud_consent`` field toggled by
    ``POST /api/cases/{id}/consent`` (which returned ``consent_required``): it is
    a per-(case, executor) entry in the case's hash-chained audit log
    (``forensia.consent``), recorded via ``POST /api/agent/cloud-consent`` and
    enforced by ``/api/agent/query`` with a hard **403** raised BEFORE any
    executor backend is constructed — so an API client cannot bypass the UI-only
    warning. The engine-level proof that a cloud run redacts and audits the
    egress (``agent_cloud_egress`` + redacted-payload SHA-256) lives in
    ``TestRedaction`` / ``TestAudit`` above; here we prove the HTTP gate itself.
    """

    def _wire(self, tmp_path, monkeypatch):
        cases = CaseManager(root=tmp_path / "cases")
        evidence = EvidenceManager(cases)
        import forensia.routers.agent as agent_router

        monkeypatch.setattr(agent_router, "case_manager", cases)
        monkeypatch.setattr(agent_router, "evidence_manager", evidence)

        # The cloud CLI is "logged in" so the query reaches the consent gate
        # rather than failing earlier on availability (503).
        monkeypatch.setattr(
            ClaudeCodeExecutor,
            "is_available",
            lambda self: ExecutorAvailability(available=True),
        )

        case = cases.create(name="op", examiner="alice", os_profile="unix")
        src = tmp_path / "e.raw"
        src.write_bytes(b"x")
        handle = evidence.register(case.id, str(src))

        app = create_app(PORT)
        client = TestClient(app, base_url=f"http://127.0.0.1:{PORT}")
        auth = {"X-Forensia-Token": app.state.token}
        return cases, case, handle, client, auth

    def test_cloud_query_without_consent_is_403_and_zero_egress(
        self, tmp_path, monkeypatch
    ):
        _, case, handle, client, auth = self._wire(tmp_path, monkeypatch)

        # If the gate ever failed open, the executor would run — and case-derived
        # bytes would cross to the vendor. Prove zero egress: run() must not fire.
        def _forbidden_run(self, prompt, context=None):
            raise AssertionError("executor.run reached without recorded consent")

        monkeypatch.setattr(ClaudeCodeExecutor, "run", _forbidden_run)

        r = client.post(
            "/api/agent/query",
            json={
                "os_profile": "unix",
                "case_id": case.id,
                "evidence_id": handle.evidence_id,
                "prompt": "analiza el archivo",
                "executor": "claude-code",
            },
            headers=auth,
        )
        assert r.status_code == 403, r.text
        detail = r.json()["detail"]
        assert "cloud-consent" in detail
        assert "claude-code" in detail

    def test_cloud_query_with_consent_runs_and_anchors_consent_ref(
        self, tmp_path, monkeypatch
    ):
        """Regresión del fallo E2E 2026-07-06 (chat con claude-code): el router
        validaba el consentimiento (403 sin él) pero NO pasaba ``consent_ref`` a
        ``ForensicAgent.run``, cuyo borde de egress rechazaba entonces TODO run
        cloud con consentimiento ya registrado (422 «cloud egress requires a
        recorded consent_ref»). Con consentimiento registrado, el run debe
        ejecutarse y el audit debe anclar el ``entry_hash`` de la línea de
        consentimiento en ``agent_run_start`` y en cada ``agent_cloud_egress``."""
        cases, case, handle, client, auth = self._wire(tmp_path, monkeypatch)

        # Record consent for this case + executor through the real endpoint
        # (exercises the /api/agent/cloud-consent wiring, not a shortcut).
        g = client.post(
            "/api/agent/cloud-consent",
            json={"case_id": case.id, "executor": "claude-code"},
            headers=auth,
        )
        assert g.status_code == 200, g.text
        assert g.json()["recorded"] is True

        audit = AuditLog(cases.case_dir(case.id) / "audit.jsonl")
        consent_entry = next(
            e for e in audit.entries() if e.get("action") == "cloud_executor_consent"
        )
        consent_hash = consent_entry["entry_hash"]
        assert consent_hash

        # The executor answers the response contract's final-answer envelope —
        # the shape ExecutorBackend._parse_action demands (models/base.py).
        def _scripted_run(self, prompt, context=None):
            text = json.dumps({"action": "final", "text": "hola operador"})
            return ExecutorResult(
                executor="claude-code",
                text=text,
                argv=("claude", "-p", "<prompt>", "--output-format", "json"),
                exit_code=0,
                duration_ms=1,
                raw=text,
            )

        monkeypatch.setattr(ClaudeCodeExecutor, "run", _scripted_run)

        r = client.post(
            "/api/agent/query",
            json={
                "os_profile": "unix",
                "case_id": case.id,
                "evidence_id": handle.evidence_id,
                "prompt": "analiza el archivo",
                "executor": "claude-code",
            },
            headers=auth,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["reply"] == "hola operador"
        assert body["iterations"] == 1

        events = audit.entries()
        run_start = next(e for e in events if e.get("event") == "agent_run_start")
        assert run_start["consent_ref"] == consent_hash
        egress = next(e for e in events if e.get("event") == "agent_cloud_egress")
        assert egress["consent_ref"] == consent_hash
        assert audit.verify() is True
