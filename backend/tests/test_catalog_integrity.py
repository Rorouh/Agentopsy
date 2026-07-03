"""Lightweight invariants over the catalog wiring.

These tests are a tripwire: any future edit that lands a half-wired Tool
(missing build_argv / parse / host_mounts / container_image) trips here long
before the agent tries to dispatch it.
"""

from __future__ import annotations

from forensia.toolkit.catalog import BY_ID, CATALOG, by_tier, for_profile
from forensia.toolkit.maletin import MALETINES, TOOLKIT_UNIX, TOOLKIT_WINDOWS
from forensia.toolkit.tool import _not_built

# os_profile → the maletín that must carry a tool applicable to that profile.
_PROFILE_MALETIN = {"unix": TOOLKIT_UNIX, "windows": TOOLKIT_WINDOWS}


# --------------------------------------------------------------------------- #
# Core-tier wiring
# --------------------------------------------------------------------------- #
_CORE_TOOL_IDS = frozenset(
    {
        "file_info",  # paso 0a del playbook: libmagic
        "xxd_head",   # paso 0b: ver bytes en hex
        "strings_head",  # paso 0c: vendor markers / kernel banners
        "tsk_mmls",
        "tsk_fls",
        "tsk_mactime",
        "ewf_info",
        "bulk_extractor",
        "yara",
        "volatility3",
        "hayabusa",
        "chainsaw",
        "evtxecmd",
        "mftecmd",
        "regripper",
        "jq",
    }
)


def test_core_tier_matches_expected_kit() -> None:
    core = by_tier("core")
    assert {t.id for t in core} == _CORE_TOOL_IDS
    assert len(core) == len(_CORE_TOOL_IDS)


def test_core_tools_have_real_build_argv_and_parse() -> None:
    """Every core tool must override the stub `_not_built` for both callables."""
    for tool in by_tier("core"):
        assert tool.build_argv is not _not_built, f"{tool.id} build_argv not wired"
        assert tool.parse is not _not_built, f"{tool.id} parse not wired"
        assert tool.allowed_flags, f"{tool.id} ALLOWED_FLAGS is empty"


def test_extended_tier_tools_use_stub_for_now() -> None:
    """Extended-tier tools are skeleton entries: they MUST keep _not_built
    so the dispatcher fails loudly (RULE 2) if the agent picks one before it
    is wired."""
    for tool in by_tier("extended"):
        assert tool.build_argv is _not_built, f"{tool.id} should still be stub"
        assert tool.parse is _not_built, f"{tool.id} should still be stub"


# --------------------------------------------------------------------------- #
# Container delivery wiring
# --------------------------------------------------------------------------- #
def test_container_tools_have_image_and_host_mounts() -> None:
    for tool in CATALOG:
        has_container = any(mode == "container" for _host, mode in tool.delivery)
        if not has_container:
            continue
        assert tool.container_image, (
            f"{tool.id} declares container delivery but no container_image"
        )
        assert tool.host_mounts is not None, (
            f"{tool.id} declares container delivery but no host_mounts callable"
        )


def test_bundled_only_tools_have_no_container_image() -> None:
    for tool in CATALOG:
        only_bundled = all(mode == "bundled" for _host, mode in tool.delivery)
        if not only_bundled:
            continue
        assert tool.container_image is None, (
            f"{tool.id} is bundled-only but declares a container_image"
        )


# --------------------------------------------------------------------------- #
# Maletín declaration (CLAUDE.md RULE 1): every tool declares where it lives
# --------------------------------------------------------------------------- #
def test_every_tool_declares_a_known_maletin() -> None:
    for tool in CATALOG:
        assert tool.toolkits, f"{tool.id} declares no maletín (toolkits empty)"
        for tk in tool.toolkits:
            assert tk in MALETINES, f"{tool.id} declares unknown maletín {tk!r}"


def test_toolkits_cover_every_os_profile_the_tool_serves() -> None:
    """A tool applicable to an OS profile must live in that profile's maletín — so a
    windows tool ships in toolkit-windows, a unix tool in toolkit-unix, a cross tool in
    both. (RULE 2 is enforced at resolution: a tool is never probed against a maletín it
    does not declare here.)"""
    for tool in CATALOG:
        for profile in tool.os_profiles:
            expected = _PROFILE_MALETIN[profile]
            assert expected in tool.toolkits, (
                f"{tool.id} serves {profile!r} but does not declare {expected!r}"
            )


# --------------------------------------------------------------------------- #
# Uniqueness and profile filtering
# --------------------------------------------------------------------------- #
def test_tool_ids_are_unique() -> None:
    ids = [t.id for t in CATALOG]
    assert len(ids) == len(set(ids)), f"duplicate tool ids: {ids}"


def test_by_id_index_matches_catalog() -> None:
    assert len(BY_ID) == len(CATALOG)
    for tool in CATALOG:
        assert BY_ID[tool.id] is tool


def test_for_profile_unix_returns_only_unix_tools() -> None:
    selected = for_profile("unix")
    assert selected, "expected at least one unix tool"
    for tool in selected:
        assert "unix" in tool.os_profiles


def test_for_profile_windows_returns_only_windows_tools() -> None:
    selected = for_profile("windows")
    assert selected, "expected at least one windows tool"
    for tool in selected:
        assert "windows" in tool.os_profiles


def test_for_profile_unknown_is_empty() -> None:
    assert for_profile("plan9") == ()


# --------------------------------------------------------------------------- #
# Sanity: allowed_flags is a frozenset, side_effecting is bool, etc.
# --------------------------------------------------------------------------- #
def test_tool_types_are_consistent() -> None:
    for tool in CATALOG:
        assert isinstance(tool.allowed_flags, frozenset), f"{tool.id}: allowed_flags not frozenset"
        assert tool.returns in {"inline", "artifact"}, f"{tool.id}: bad returns"
        assert tool.tier in {"core", "extended"}, f"{tool.id}: bad tier"
        assert isinstance(tool.side_effecting, bool)
