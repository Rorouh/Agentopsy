"""Tests for ``forensia.mcp.toolkit`` — the MCP server S1.

Uses in-process memory streams via ``mcp.shared.memory`` to drive a Client
against a Server without spawning a subprocess. Hardware end-to-end (real
stdio + a real client like Claude Desktop) lives in a separate manual demo.

Each test enters its own client/server context — using a fixture trips
anyio's cancel-scope-across-tasks assertion. The `async with`-per-test
pattern is verbose but reliable.

Coverage map (mirrors §5 of mcp-toolkit-s1.md):

- Round-trip: initialize → tools/list (4 Jira tools when no case selected).
- Happy path Jira: list_cases → select_case → list_evidence → select_evidence.
- Error paths (RULE 2, no fallbacks).
- L2: schema rejects extra fields (raw paths).
- L1: exactly one tool_run_start + one tool_run_finish per MCP call.
- Differential: dispatcher vs MCP — argv, exit_code, output sha256 match.
- D5': resource_link returns + resources/read.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from forensia.cases.manager import case_manager
from forensia.mcp.toolkit import build_server


# ---- helpers --------------------------------------------------------------

REAL_CASE_ID = "f3abd274-c954-43a8-b130-cbd0d2bdeb0a"
REAL_EVIDENCE_ID = "cc212366-835d-43dd-b1e5-4a9cd58ddf13"


def _has_real_case() -> bool:
    try:
        case_manager.load(REAL_CASE_ID)
        case_manager.case_dir(REAL_CASE_ID)
        return True
    except (KeyError, ValueError):
        return False


def _extract_payload(result) -> Any:
    """Pull the JSON dict out of a CallToolResult's first text content block."""
    if not result.content:
        return ""
    first = result.content[0]
    if not hasattr(first, "text"):
        return ""
    try:
        return json.loads(first.text)
    except json.JSONDecodeError:
        return first.text


def _build_session_cm():
    server, lifecycle = build_server(consent_ref="pytest")
    return create_connected_server_and_client_session(server), lifecycle


# ---- 1. Round-trip + initial tools/list ----------------------------------


async def test_initial_tools_list_has_only_jira_tools() -> None:
    cm, _ = _build_session_cm()
    async with cm as session:
        result = await session.list_tools()
        names = {t.name for t in result.tools}
        assert names == {
            "list_cases",
            "select_case",
            "list_evidence",
            "select_evidence",
        }


# ---- 2. Happy path Jira ---------------------------------------------------


@pytest.mark.skipif(not _has_real_case(), reason="real case not registered on this host")
async def test_select_case_changes_tools_list() -> None:
    cm, _ = _build_session_cm()
    async with cm as session:
        before = await session.list_tools()
        assert {t.name for t in before.tools} == {
            "list_cases",
            "select_case",
            "list_evidence",
            "select_evidence",
        }

        # list_cases finds the real case
        r = await session.call_tool("list_cases", {})
        payload = _extract_payload(r)
        assert isinstance(payload, dict)
        case_ids = {c["id"] for c in payload["cases"]}
        assert REAL_CASE_ID in case_ids

        # select_case → success
        r = await session.call_tool("select_case", {"case_id": REAL_CASE_ID})
        payload = _extract_payload(r)
        assert isinstance(payload, dict)
        assert payload["selected_case"]["id"] == REAL_CASE_ID

        # Tools list expanded
        after = await session.list_tools()
        after_names = {t.name for t in after.tools}
        assert "volatility3" in after_names
        assert "tsk_mmls" in after_names


# ---- 3. Error paths -------------------------------------------------------


async def test_forensic_tool_without_select_case_fails_loud() -> None:
    cm, _ = _build_session_cm()
    async with cm as session:
        # volatility3 isn't published before select_case, but it's still routable
        # as a forensic tool name; the dispatch path rejects it.
        r = await session.call_tool("volatility3", {"plugin": "windows.info.Info"})
        payload = _extract_payload(r)
        # Either the SDK rejected (no such tool in tools/list) or our server
        # rejected (no case selected). Both are RULE 2 compliant.
        if isinstance(payload, dict):
            assert payload.get("isError") is True
            assert "select_case" in payload.get("error", "") or "case" in payload.get(
                "error", ""
            )
        else:
            # SDK-level rejection comes back as a plain string.
            assert isinstance(payload, str)
            assert "tool" in payload.lower() or "volatility3" in payload.lower()


async def test_select_case_unknown_uuid_fails_loud() -> None:
    cm, _ = _build_session_cm()
    async with cm as session:
        bogus = "12345678-1234-4567-8901-123456789abc"
        r = await session.call_tool("select_case", {"case_id": bogus})
        payload = _extract_payload(r)
        assert isinstance(payload, dict)
        assert payload.get("isError") is True
        assert "unknown case_id" in payload.get("error", "")


async def test_select_case_invalid_uuid_format_fails_at_schema() -> None:
    cm, _ = _build_session_cm()
    async with cm as session:
        # Pattern doesn't match UUID4 (no version digit) — SDK validates schema.
        r = await session.call_tool("select_case", {"case_id": "not-a-uuid"})
        payload = _extract_payload(r)
        # Either a string error from the SDK or a dict with isError. Both fine.
        if isinstance(payload, dict):
            assert payload.get("isError") is True
        else:
            assert isinstance(payload, str)
            # The SDK rejects with a schema validation message. We don't pin
            # the exact wording, just confirm it's a rejection of the bad input.
            assert (
                "not-a-uuid" in payload
                or "validation" in payload.lower()
                or "match" in payload.lower()
            )


# ---- 4. Schema enforcement (L2) -------------------------------------------


@pytest.mark.skipif(not _has_real_case(), reason="real case not registered on this host")
async def test_schema_rejects_raw_path() -> None:
    cm, _ = _build_session_cm()
    async with cm as session:
        await session.call_tool("select_case", {"case_id": REAL_CASE_ID})
        await session.call_tool("select_evidence", {"evidence_id": REAL_EVIDENCE_ID})

        # Send a raw path — extra='forbid' must reject.
        r = await session.call_tool(
            "tsk_mmls",
            {"image_path": "/etc/passwd", "type": "dos"},
        )
        payload = _extract_payload(r)
        # Could be SDK-validated (string) or server-validated (dict).
        if isinstance(payload, dict):
            assert payload.get("isError") is True
            assert (
                "Extra" in payload.get("error", "")
                or "image_path" in payload.get("error", "")
                or "Additional properties" in payload.get("error", "")
            )
        else:
            assert isinstance(payload, str)
            assert "image_path" in payload or "Additional" in payload


# ---- 5. Differential test (dispatcher equivalence) -----------------------


@pytest.mark.skipif(not _has_real_case(), reason="real case not registered on this host")
async def test_differential_dispatcher_vs_mcp() -> None:
    """Run windows.info both directly via dispatcher and via the MCP client.
    Compare argv + exit_code + output_files[].sha256 (not stdout).
    """
    from forensia.evidence import evidence_manager
    from forensia.toolkit.dispatcher import execute as dispatch_tool

    handle = evidence_manager.get(REAL_CASE_ID, REAL_EVIDENCE_ID)
    direct = dispatch_tool(
        "volatility3",
        {"plugin": "windows.info.Info", "dump_path": str(handle.original_path)},
        case_id=REAL_CASE_ID,
    )

    cm, _ = _build_session_cm()
    async with cm as session:
        await session.call_tool("select_case", {"case_id": REAL_CASE_ID})
        await session.call_tool("select_evidence", {"evidence_id": REAL_EVIDENCE_ID})
        r = await session.call_tool("volatility3", {"plugin": "windows.info.Info"})
        mcp_payload = _extract_payload(r)
        assert isinstance(mcp_payload, dict)
        assert not mcp_payload.get("isError"), f"mcp call failed: {mcp_payload}"

    assert direct["exit_code"] == mcp_payload["exit_code"]
    # Argv may differ in the binary path prefix; compare the tail (plugin + args).
    assert direct["argv"][-3:] == mcp_payload["argv"][-3:], (
        f"argv tails diverged:\n  direct={direct['argv']}\n  mcp={mcp_payload['argv']}"
    )

    direct_hashes = sorted(
        f["sha256"] for f in direct["artifact_run"]["output_files"]
    )
    mcp_hashes = sorted(
        f["sha256"] for f in mcp_payload["artifact_run"]["output_files"]
    )
    assert direct_hashes == mcp_hashes, (
        f"output sha256 diverged: direct={direct_hashes} mcp={mcp_hashes}"
    )


# ---- 6. L1 — exactly one tool_run_start per MCP call ---------------------


@pytest.mark.skipif(not _has_real_case(), reason="real case not registered on this host")
async def test_l1_one_audit_entry_per_run() -> None:
    case_dir = case_manager.case_dir(REAL_CASE_ID)
    audit_path = case_dir / "audit.jsonl"
    before_start = (
        audit_path.read_text().count('"action": "tool_run_start"')
        if audit_path.exists()
        else 0
    )

    cm, _ = _build_session_cm()
    async with cm as session:
        await session.call_tool("select_case", {"case_id": REAL_CASE_ID})
        await session.call_tool("select_evidence", {"evidence_id": REAL_EVIDENCE_ID})
        await session.call_tool("volatility3", {"plugin": "windows.info.Info"})

    after_start = audit_path.read_text().count('"action": "tool_run_start"')
    assert (
        after_start == before_start + 1
    ), "expected exactly one tool_run_start per MCP call_tool"


# ---- 7. ResourceLink + resources/read (D5') ------------------------------


@pytest.mark.skipif(not _has_real_case(), reason="real case not registered on this host")
async def test_output_files_returned_as_resource_links() -> None:
    cm, _ = _build_session_cm()
    async with cm as session:
        await session.call_tool("select_case", {"case_id": REAL_CASE_ID})
        await session.call_tool("select_evidence", {"evidence_id": REAL_EVIDENCE_ID})
        r = await session.call_tool("volatility3", {"plugin": "windows.info.Info"})

        from mcp.types import ResourceLink

        links = [c for c in r.content if isinstance(c, ResourceLink)]
        # The DFIR-1 fix ensures EVERY successful run produces at least two
        # links: stdout.txt + stderr.txt. Anything less means the fix
        # regressed.
        assert len(links) >= 2, (
            f"expected at least stdout.txt + stderr.txt links; got {len(links)}: {links}"
        )
        # link.uri is an AnyUrl; cast to str before string ops.
        for link in links:
            assert str(link.uri).startswith(f"artifact://{REAL_CASE_ID}/")


@pytest.mark.skipif(not _has_real_case(), reason="real case not registered on this host")
async def test_resources_read_serves_artifact() -> None:
    cm, _ = _build_session_cm()
    async with cm as session:
        await session.call_tool("select_case", {"case_id": REAL_CASE_ID})
        await session.call_tool("select_evidence", {"evidence_id": REAL_EVIDENCE_ID})
        r = await session.call_tool("volatility3", {"plugin": "windows.info.Info"})

        from mcp.types import ResourceLink

        links = [c for c in r.content if isinstance(c, ResourceLink)]
        if not links:
            pytest.skip("no artifact output files produced for this plugin")

        read = await session.read_resource(links[0].uri)
        assert len(read.contents) >= 1
