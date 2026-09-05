"""tool_version — the AUTHORITATIVE version identity of every anchored tool run.

FORENSIC INVARIANT 4 requires the audit log to record the tool version of every run.
P0.5-3 closes the gap end to end:

  build time   gen_versions.py bakes an IMMUTABLE ``versions.json`` into each maletín
               image (one designated source per binary; the BUILD FAILS if a declared
               tool has no deterministic version — no placeholder ever exists);
  exec-agent   serves that manifest through the CLOSED ``GET /versions`` endpoint
               (no parameters, no caller paths, no command execution);
  maletin.py   ``tool_versions``/``tool_version`` fetch it, rejecting forbidden values
               ("unknown"/"latest"/empty) and missing binaries with actionable errors;
  dispatcher   resolves the version BEFORE ``ArtifactRun``/``tool_run_start`` — an
               unresolvable version means NO start entry and NO runner crossing (RULE 2:
               no per-run ``--version`` probe, no local fallback, no cross-maletín
               lookup) — and stamps the SAME resolved version on the start and on every
               finish path (success, exit≠0, runner exception);
  capabilities ``_tool_status`` reports the version identity (or the concrete reason
               there is none) so a tool without version identity is visible, not silent.

The catalog and the build manifest's declared-binaries list must never diverge: the
consistency gate below fails when a tool is added to ``catalog.py`` without adding its
binary to ``tool-binaries.json`` (or vice versa).
"""

from __future__ import annotations

import importlib.util
import json
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
from agentopsy.toolkit.catalog import CATALOG
from agentopsy.toolkit.maletin import TOOLKIT_UNIX, TOOLKIT_WINDOWS

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLKIT_DIR = REPO_ROOT / "docker" / "docker" / "forensic-toolkit"
EXEC_AGENT_PY = TOOLKIT_DIR / "exec_agent.py"
GEN_VERSIONS_PY = TOOLKIT_DIR / "gen_versions.py"
TOOL_BINARIES_JSON = TOOLKIT_DIR / "tool-binaries.json"

_UNIX_URL = "http://toolkit-unix:8666"

_VALID_MANIFEST = {
    "schema": 1,
    "stage": "unix",
    "versions": {"mmls": "sleuthkit 4.12.1+dfsg-1ppa1 (dpkg)", "jq": "jq 1.7.1-3build1"},
}


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _get(module, path: str, headers: dict | None = None) -> tuple[int, dict]:
    """One GET against an in-process loopback exec-agent."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}{path}", headers=headers or {}, method="GET"
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 — loopback test
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:  # non-2xx still carries a JSON body
            return exc.code, json.loads(exc.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)


# --------------------------------------------------------------------------- #
# 1) exec-agent GET /versions — closed endpoint over the baked manifest
# --------------------------------------------------------------------------- #
def test_versions_endpoint_serves_valid_manifest(monkeypatch, tmp_path) -> None:
    manifest = tmp_path / "versions.json"
    manifest.write_text(json.dumps(_VALID_MANIFEST), encoding="utf-8")
    monkeypatch.delenv("AGENTOPSY_EXEC_AGENT_TOKEN", raising=False)
    monkeypatch.setenv("AGENTOPSY_VERSIONS_MANIFEST", str(manifest))
    module = _load_module(EXEC_AGENT_PY, "exec_agent_versions_ok")

    status, body = _get(module, "/versions")
    assert status == 200
    assert body["versions"] == _VALID_MANIFEST["versions"]
    assert body["stage"] == "unix"


def test_versions_endpoint_missing_manifest_is_actionable_500(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("AGENTOPSY_EXEC_AGENT_TOKEN", raising=False)
    monkeypatch.setenv("AGENTOPSY_VERSIONS_MANIFEST", str(tmp_path / "nope.json"))
    module = _load_module(EXEC_AGENT_PY, "exec_agent_versions_missing")

    status, body = _get(module, "/versions")
    assert status == 500
    # Actionable: names the missing manifest and the rebuild path — never a placeholder.
    assert "reconstruye" in body["error"]
    assert "versions" not in body


@pytest.mark.parametrize(
    "content",
    [
        "not json at all {",
        json.dumps({"schema": 1, "stage": "unix"}),  # no versions map
        json.dumps({"versions": {"mmls": ""}}),  # empty version value
        json.dumps({"versions": {"mmls": 7}}),  # non-string version
        json.dumps({"versions": ["mmls"]}),  # wrong shape
    ],
)
def test_versions_endpoint_corrupt_manifest_is_500(monkeypatch, tmp_path, content) -> None:
    manifest = tmp_path / "versions.json"
    manifest.write_text(content, encoding="utf-8")
    monkeypatch.delenv("AGENTOPSY_EXEC_AGENT_TOKEN", raising=False)
    monkeypatch.setenv("AGENTOPSY_VERSIONS_MANIFEST", str(manifest))
    module = _load_module(EXEC_AGENT_PY, "exec_agent_versions_corrupt")

    status, body = _get(module, "/versions")
    assert status == 500
    assert "manifiesto" in body["error"]


def test_versions_endpoint_requires_token_when_configured(monkeypatch, tmp_path) -> None:
    manifest = tmp_path / "versions.json"
    manifest.write_text(json.dumps(_VALID_MANIFEST), encoding="utf-8")
    monkeypatch.setenv("AGENTOPSY_EXEC_AGENT_TOKEN", "sekrit")
    monkeypatch.setenv("AGENTOPSY_VERSIONS_MANIFEST", str(manifest))
    module = _load_module(EXEC_AGENT_PY, "exec_agent_versions_token")

    status, body = _get(module, "/versions")
    assert status == 401
    status, body = _get(module, "/versions", headers={"X-Agentopsy-Exec-Token": "sekrit"})
    assert status == 200
    assert body["versions"] == _VALID_MANIFEST["versions"]


def test_versions_endpoint_is_closed_no_parameters(monkeypatch, tmp_path) -> None:
    """No caller-controlled inputs: a query string is not the closed route → 404, and
    no other GET path exists that could read arbitrary files or run commands."""
    manifest = tmp_path / "versions.json"
    manifest.write_text(json.dumps(_VALID_MANIFEST), encoding="utf-8")
    monkeypatch.delenv("AGENTOPSY_EXEC_AGENT_TOKEN", raising=False)
    monkeypatch.setenv("AGENTOPSY_VERSIONS_MANIFEST", str(manifest))
    module = _load_module(EXEC_AGENT_PY, "exec_agent_versions_closed")

    status, _ = _get(module, "/versions?path=/etc/passwd")
    assert status == 404
    status, _ = _get(module, "/versions/../exec")
    assert status == 404


# --------------------------------------------------------------------------- #
# 2) maletin client — tool_versions / tool_version (no placeholder survives)
# --------------------------------------------------------------------------- #
def test_tool_versions_without_url_fails_actionable(monkeypatch) -> None:
    monkeypatch.delenv("AGENTOPSY_TOOLKIT_UNIX_URL", raising=False)
    with pytest.raises(maletin.MaletinExecError, match="AGENTOPSY_TOOLKIT_UNIX_URL"):
        maletin.tool_versions(TOOLKIT_UNIX)


def test_tool_versions_transport_error_fails(monkeypatch) -> None:
    monkeypatch.setenv("AGENTOPSY_TOOLKIT_UNIX_URL", _UNIX_URL)

    def _boom(method, url, payload=None, *, timeout=maletin._PROBE_TIMEOUT):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(maletin, "_request", _boom)
    with pytest.raises(maletin.MaletinExecError, match="no se pudo consultar"):
        maletin.tool_versions(TOOLKIT_UNIX)


def test_tool_versions_non_200_fails_with_detail(monkeypatch) -> None:
    monkeypatch.setenv("AGENTOPSY_TOOLKIT_UNIX_URL", _UNIX_URL)
    monkeypatch.setattr(
        maletin,
        "_request",
        lambda m, u, p=None, *, timeout=maletin._PROBE_TIMEOUT: (
            500,
            {"error": "manifiesto de versiones ausente"},
        ),
    )
    with pytest.raises(maletin.MaletinExecError, match="ausente"):
        maletin.tool_versions(TOOLKIT_UNIX)


@pytest.mark.parametrize(
    "bad",
    ["", "unknown", "latest", "null", "none", "  Unknown ", "hayabusa latest", "tsk unknown"],
)
def test_tool_versions_rejects_forbidden_values(monkeypatch, bad) -> None:
    monkeypatch.setenv("AGENTOPSY_TOOLKIT_UNIX_URL", _UNIX_URL)
    monkeypatch.setattr(
        maletin,
        "_request",
        lambda m, u, p=None, *, timeout=maletin._PROBE_TIMEOUT: (
            200,
            {"versions": {"mmls": bad}},
        ),
    )
    with pytest.raises(maletin.MaletinExecError, match="inválida|corrupto"):
        maletin.tool_versions(TOOLKIT_UNIX)


def test_tool_version_returns_manifest_entry(monkeypatch) -> None:
    monkeypatch.setenv("AGENTOPSY_TOOLKIT_UNIX_URL", _UNIX_URL)
    monkeypatch.setattr(
        maletin,
        "_request",
        lambda m, u, p=None, *, timeout=maletin._PROBE_TIMEOUT: (
            200,
            {"versions": dict(_VALID_MANIFEST["versions"])},
        ),
    )
    assert maletin.tool_version(TOOLKIT_UNIX, "mmls") == "sleuthkit 4.12.1+dfsg-1ppa1 (dpkg)"


def test_tool_version_missing_binary_fails_naming_alignment(monkeypatch) -> None:
    monkeypatch.setenv("AGENTOPSY_TOOLKIT_UNIX_URL", _UNIX_URL)
    monkeypatch.setattr(
        maletin,
        "_request",
        lambda m, u, p=None, *, timeout=maletin._PROBE_TIMEOUT: (
            200,
            {"versions": dict(_VALID_MANIFEST["versions"])},
        ),
    )
    with pytest.raises(maletin.MaletinExecError, match="tool-binaries.json"):
        maletin.tool_version(TOOLKIT_UNIX, "hayabusa")


# --------------------------------------------------------------------------- #
# 3) dispatcher — version resolved BEFORE start; same version on every closure
# --------------------------------------------------------------------------- #
@pytest.fixture
def cases(tmp_path) -> CaseManager:
    return CaseManager(root=tmp_path / "cases")


@pytest.fixture
def store(cases) -> ArtifactStore:
    return ArtifactStore(cases)


@pytest.fixture
def anchored(cases, tmp_path):
    case = cases.create(name="op", examiner="alice", os_profile="unix")
    handle = register_evidence(cases, case.id, tmp_path, payload=b"\x00" * 512)
    return {"case": case, "handle": handle, "ctx": context_for(handle)}


def _tool_entries(cases: CaseManager, case_id: str) -> list[dict]:
    path = cases.root / case_id / "audit.jsonl"
    if not path.exists():
        return []
    return [
        e
        for e in AuditLog(path).entries()
        if str(e.get("action", "")).startswith("tool_run_")
    ]


def _run_dirs(cases: CaseManager, case_id: str) -> list[Path]:
    artifacts = cases.root / case_id / "artifacts"
    return sorted(artifacts.iterdir()) if artifacts.exists() else []


def test_unresolvable_version_blocks_before_start_and_runner(
    monkeypatch, cases, store, anchored
) -> None:
    """Transport failure looking up the version → NO ArtifactRun, NO tool_run_start,
    and the runner is NEVER crossed (order: version → start → runner)."""
    case, handle, ctx = anchored["case"], anchored["handle"], anchored["ctx"]
    wire_dispatcher_custody(monkeypatch, dispatcher, cases, store, fake_version=None)
    monkeypatch.setattr(dispatcher, "resolve", lambda _b: None)  # maletín venue

    def _no_version(service, binary):
        raise maletin.MaletinExecError(f"no se pudo consultar el manifiesto de {service}")

    def _forbidden_runner(*args, **kwargs):
        raise AssertionError("runner reached without an authoritative tool_version")

    monkeypatch.setattr(maletin, "tool_version", _no_version)
    monkeypatch.setattr(maletin, "run_argv_in_maletin", _forbidden_runner)

    with pytest.raises(dispatcher.ToolExecutionError, match="no se ejecuta sin versión"):
        dispatcher.execute(
            "tsk_mmls",
            {"image_path": str(handle.original_path)},
            case_id=case.id,
            os_profile="unix",
            evidence_context=ctx,
        )
    assert _tool_entries(cases, case.id) == []  # no start, no finish
    assert _run_dirs(cases, case.id) == []  # no ArtifactRun was ever reserved


def test_anchored_api_path_venue_has_no_manifest_and_refuses(
    monkeypatch, cases, store, anchored, tmp_path
) -> None:
    """An anchored run whose binary resolves on the api PATH (dev/env-override) has no
    build manifest to answer for it: refuse loudly — no local fallback, no probe."""
    case, handle, ctx = anchored["case"], anchored["handle"], anchored["ctx"]
    wire_dispatcher_custody(monkeypatch, dispatcher, cases, store, fake_version=None)
    monkeypatch.setattr(dispatcher, "resolve", lambda _b: tmp_path / "mmls")

    def _forbidden_lookup(service, binary):
        raise AssertionError("maletín manifest must not be consulted for api-PATH venue")

    monkeypatch.setattr(maletin, "tool_version", _forbidden_lookup)

    with pytest.raises(dispatcher.ToolExecutionError, match="manifiesto de build"):
        dispatcher.execute(
            "tsk_mmls",
            {"image_path": str(handle.original_path)},
            case_id=case.id,
            os_profile="unix",
            evidence_context=ctx,
        )
    assert _tool_entries(cases, case.id) == []
    assert _run_dirs(cases, case.id) == []


def _wired_success(monkeypatch, cases, store, exit_code=0, stderr=""):
    wire_dispatcher_custody(monkeypatch, dispatcher, cases, store)  # fake version transport
    monkeypatch.setattr(dispatcher, "resolve", lambda _b: None)

    def _fake_exec(service, argv, **_kw):
        return exit_code, "DOS Partition Table\n" if exit_code == 0 else "", stderr

    monkeypatch.setattr(maletin, "run_argv_in_maletin", _fake_exec)


def _start_finish(cases, case_id, run_id):
    entries = _tool_entries(cases, case_id)
    start = next(e for e in entries if e["action"] == "tool_run_start" and e["run_id"] == run_id)
    finish = next(
        e for e in entries if e["action"] == "tool_run_finish" and e["run_id"] == run_id
    )
    return start, finish


def test_success_start_and_finish_carry_same_resolved_version(
    monkeypatch, cases, store, anchored
) -> None:
    case, handle, ctx = anchored["case"], anchored["handle"], anchored["ctx"]
    _wired_success(monkeypatch, cases, store, exit_code=0)
    result = dispatcher.execute(
        "tsk_mmls",
        {"image_path": str(handle.original_path)},
        case_id=case.id,
        os_profile="unix",
        evidence_context=ctx,
    )
    start, finish = _start_finish(cases, case.id, result["run_id"])
    assert start["tool_version"] == finish["tool_version"] == FAKE_TOOL_VERSION
    assert store.get_run(case.id, result["run_id"]).tool_version == FAKE_TOOL_VERSION
    assert AuditLog(cases.root / case.id / "audit.jsonl").verify() is True


def test_nonzero_exit_finish_keeps_version(monkeypatch, cases, store, anchored) -> None:
    case, handle, ctx = anchored["case"], anchored["handle"], anchored["ctx"]
    _wired_success(monkeypatch, cases, store, exit_code=2, stderr="cannot read image")
    result = dispatcher.execute(
        "tsk_mmls",
        {"image_path": str(handle.original_path)},
        case_id=case.id,
        os_profile="unix",
        evidence_context=ctx,
    )
    assert result["exit_code"] == 2
    start, finish = _start_finish(cases, case.id, result["run_id"])
    assert finish["status"] == "finished"
    assert start["tool_version"] == finish["tool_version"] == FAKE_TOOL_VERSION


def test_runner_exception_finish_keeps_version(monkeypatch, cases, store, anchored) -> None:
    case, ctx = anchored["case"], anchored["ctx"]
    wire_dispatcher_custody(monkeypatch, dispatcher, cases, store)
    monkeypatch.setattr(dispatcher, "resolve", lambda _b: None)

    def _explode(service, argv, **_kw):
        raise maletin.MaletinExecError("exec-agent caído a mitad de la corrida")

    monkeypatch.setattr(maletin, "run_argv_in_maletin", _explode)

    with pytest.raises(dispatcher.ToolExecutionError, match="exec-agent caído"):
        dispatcher.execute(
            "tsk_mmls",
            {"image_path": str(anchored["handle"].original_path)},
            case_id=case.id,
            os_profile="unix",
            evidence_context=ctx,
        )
    entries = _tool_entries(cases, case.id)
    start = next(e for e in entries if e["action"] == "tool_run_start")
    finish = next(e for e in entries if e["action"] == "tool_run_finish")
    assert finish["status"] == "error"
    assert start["tool_version"] == finish["tool_version"] == FAKE_TOOL_VERSION
    assert AuditLog(cases.root / case.id / "audit.jsonl").verify() is True


# --------------------------------------------------------------------------- #
# 4) capabilities — divergent duplicate versions are surfaced, never averaged
# --------------------------------------------------------------------------- #
def test_divergent_versions_across_maletines_report_no_single_identity(monkeypatch) -> None:
    from agentopsy.toolkit.tool import Tool

    monkeypatch.setattr(maletin, "resolve", lambda _b: None)
    cross = Tool("fls", "fls", ("unix", "windows"), toolkits=(TOOLKIT_UNIX, TOOLKIT_WINDOWS))
    services = {
        svc: {"service": svc, "container": f"c-{svc}", "running": True, "reason": None}
        for svc in (TOOLKIT_UNIX, TOOLKIT_WINDOWS)
    }
    present = {TOOLKIT_UNIX: {"fls"}, TOOLKIT_WINDOWS: {"fls"}}
    versions = {
        TOOLKIT_UNIX: {"fls": "sleuthkit 4.12.1 (dpkg)"},
        TOOLKIT_WINDOWS: {"fls": "sleuthkit 4.13.0 (dpkg)"},
    }
    out = maletin._tool_status(cross, services, present, versions)
    assert out["available"] is True
    assert out["version"] is None  # no single identity is invented
    assert "divergentes" in out["version_reason"]


# --------------------------------------------------------------------------- #
# 5) catalog ↔ tool-binaries.json consistency gate (build manifest completeness)
# --------------------------------------------------------------------------- #
def test_catalog_and_build_manifest_declare_the_same_binaries() -> None:
    declared = json.loads(TOOL_BINARIES_JSON.read_text(encoding="utf-8"))
    base = set(declared["base"])
    windows_extra = set(declared["windows"])

    unix_binaries = {t.binary for t in CATALOG if TOOLKIT_UNIX in t.toolkits}
    windows_binaries = {t.binary for t in CATALOG if TOOLKIT_WINDOWS in t.toolkits}

    # The unix stage ships exactly the base list; the windows stage ships base + extra.
    assert unix_binaries == base, (
        "catalog.py y tool-binaries.json divergen para toolkit-unix: "
        f"solo-catálogo={sorted(unix_binaries - base)}, "
        f"solo-manifiesto={sorted(base - unix_binaries)}"
    )
    assert windows_binaries == base | windows_extra, (
        "catalog.py y tool-binaries.json divergen para toolkit-windows: "
        f"solo-catálogo={sorted(windows_binaries - (base | windows_extra))}, "
        f"solo-manifiesto={sorted((base | windows_extra) - windows_binaries)}"
    )
    # A windows-extra binary never duplicates a base one (single designated stage list).
    assert not (base & windows_extra)


# --------------------------------------------------------------------------- #
# 6) gen_versions.py — the build fails when a declared tool has no version
# --------------------------------------------------------------------------- #
@pytest.fixture
def gen(monkeypatch, tmp_path):
    module = _load_module(GEN_VERSIONS_PY, "gen_versions_under_test")
    declared = tmp_path / "tool-binaries.json"
    declared.write_text(
        json.dumps({"base": ["alpha", "beta"], "windows": ["gamma"]}), encoding="utf-8"
    )
    monkeypatch.setattr(module, "TOOL_BINARIES", str(declared))
    return module


def test_gen_versions_writes_manifest_when_all_resolve(monkeypatch, gen, tmp_path) -> None:
    out = tmp_path / "versions.json"
    monkeypatch.setattr(gen.shutil, "which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(gen, "resolve_version", lambda b, env, ez: f"{b} 1.2.3 (dpkg)")
    monkeypatch.setattr(sys, "argv", ["gen_versions", "--stage", "unix", "--out", str(out)])

    assert gen.main() == 0
    manifest = json.loads(out.read_text(encoding="utf-8"))
    assert manifest["stage"] == "unix"
    assert manifest["versions"] == {"alpha": "alpha 1.2.3 (dpkg)", "beta": "beta 1.2.3 (dpkg)"}


def test_gen_versions_windows_stage_includes_extra_binaries(monkeypatch, gen, tmp_path) -> None:
    out = tmp_path / "versions.json"
    monkeypatch.setattr(gen.shutil, "which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(gen, "resolve_version", lambda b, env, ez: f"{b} 9 (dpkg)")
    monkeypatch.setattr(sys, "argv", ["gen_versions", "--stage", "windows", "--out", str(out)])

    assert gen.main() == 0
    manifest = json.loads(out.read_text(encoding="utf-8"))
    assert set(manifest["versions"]) == {"alpha", "beta", "gamma"}


def test_gen_versions_aborts_when_binary_missing(monkeypatch, gen, tmp_path, capsys) -> None:
    out = tmp_path / "versions.json"
    monkeypatch.setattr(gen.shutil, "which", lambda b: None if b == "beta" else f"/u/{b}")
    monkeypatch.setattr(gen, "resolve_version", lambda b, env, ez: f"{b} 1 (dpkg)")
    monkeypatch.setattr(sys, "argv", ["gen_versions", "--stage", "unix", "--out", str(out)])

    assert gen.main() == 1
    assert not out.exists()  # no partial manifest is ever written
    assert "beta" in capsys.readouterr().err


@pytest.mark.parametrize("bad", [None, "unknown", "latest", "", "  NONE ", "alpha latest"])
def test_gen_versions_aborts_on_unresolvable_or_forbidden_version(
    monkeypatch, gen, tmp_path, capsys, bad
) -> None:
    out = tmp_path / "versions.json"
    monkeypatch.setattr(gen.shutil, "which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(
        gen, "resolve_version", lambda b, env, ez: bad if b == "alpha" else f"{b} 1 (dpkg)"
    )
    monkeypatch.setattr(sys, "argv", ["gen_versions", "--stage", "unix", "--out", str(out)])

    assert gen.main() == 1
    assert not out.exists()
    assert "alpha" in capsys.readouterr().err


def test_gen_versions_designated_sources(monkeypatch, tmp_path) -> None:
    """One designated source per binary — the ARG env for the pinned releases, the
    versions.tsv self-report for EZ tools; no source substitutes another."""
    module = _load_module(GEN_VERSIONS_PY, "gen_versions_sources")
    env = {"HAYABUSA_VERSION": "2.15.0", "CHAINSAW_VERSION": "2.9.1"}
    ez = {"evtxecmd": "EvtxECmd 1.5.1.0 (zip:abcdefabcdef)"}

    assert module.resolve_version("hayabusa", env, ez) == "hayabusa 2.15.0"
    assert module.resolve_version("chainsaw", env, ez) == "chainsaw 2.9.1"
    assert module.resolve_version("EvtxECmd", env, ez) == "EvtxECmd 1.5.1.0 (zip:abcdefabcdef)"
    # A missing designated source is None (→ build abort), never another source's value.
    assert module.resolve_version("hayabusa", {}, ez) is None
    assert module.resolve_version("MFTECmd", env, ez) is None  # not in versions.tsv
