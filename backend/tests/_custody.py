"""Shared helpers for the P0.5-3 anchored-run custody contract.

Every ANCHORED dispatcher run now requires (a) a verified ``EvidenceContext`` that the
dispatcher re-validates against ``EvidenceManager`` (the single owner of evidence), and
(b) an authoritative tool version resolved from the selected maletín's build manifest
BEFORE ``tool_run_start``. Tests therefore register REAL evidence through
``EvidenceManager`` (the actual hash gate) instead of fabricating handles.

``wire_dispatcher_custody`` fakes ONLY the maletín version transport
(``maletin.tool_version``) for unit tests; the REAL ``GET /versions`` path is exercised
end-to-end by the loopback exec-agent tests (``test_tool_version.py``,
``test_e2e_chain.py``), so no test fakes the property it claims to prove.
"""

from __future__ import annotations

from pathlib import Path

from agentopsy.artifacts.store import ArtifactStore
from agentopsy.cases.manager import CaseManager
from agentopsy.evidence import EvidenceManager
from agentopsy.evidence_context import EvidenceContext

# Realistic build-manifest identity used when the version TRANSPORT is faked.
FAKE_TOOL_VERSION = "sleuthkit 4.12.1+dfsg-1ppa1 (dpkg)"


def register_evidence(
    cases: CaseManager,
    case_id: str,
    src_dir: Path,
    *,
    payload: bytes = b"\x00" * 4096,
    name: str = "disk.raw",
):
    """Register real evidence through EvidenceManager's hash gate; returns the handle."""
    src = src_dir / name
    src.write_bytes(payload)
    return EvidenceManager(cases).register(case_id, str(src))


def context_for(handle) -> EvidenceContext:
    return EvidenceContext.from_handle(handle)


def wire_dispatcher_custody(
    monkeypatch,
    dispatcher_module,
    cases: CaseManager,
    store: ArtifactStore,
    *,
    fake_version: str | None = FAKE_TOOL_VERSION,
) -> EvidenceManager:
    """Point the dispatcher's singletons at tmp-rooted storage/evidence.

    ``fake_version`` short-circuits ONLY the maletín version lookup transport (unit
    tests); pass ``None`` to keep the real ``maletin.tool_version`` (loopback tests
    that serve a real manifest via the exec-agent).
    """
    evidence = EvidenceManager(cases)
    monkeypatch.setattr(dispatcher_module, "case_manager", cases)
    monkeypatch.setattr(dispatcher_module, "artifact_store", store)
    monkeypatch.setattr(dispatcher_module, "evidence_manager", evidence)
    if fake_version is not None:
        monkeypatch.setattr(
            dispatcher_module.maletin,
            "tool_version",
            lambda _service, _binary: fake_version,
        )
    return evidence
