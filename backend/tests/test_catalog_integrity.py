"""Lightweight invariants over the catalog wiring.

These tests are a tripwire: any future edit that lands a half-wired Tool
(missing build_argv / parse / host_mounts / container_image) trips here long
before the agent tries to dispatch it.
"""

from __future__ import annotations

from forensia.mcp.schemas import _VOLATILITY_WINDOWS_PLUGINS
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


# Extended-tier tools not yet wired: they MUST keep _not_built so the dispatcher
# fails loudly (RULE 2) if the agent picks one before it is implemented. As each is
# wired (build_argv + parse + wrapper + test), remove it from this set.
# Todas las tools extended están ya integradas (campaña de pruebas 2026-07-04).
_EXTENDED_STILL_STUB: frozenset[str] = frozenset()


def test_extended_tier_stubs_and_wired_are_consistent() -> None:
    """Extended tools still in `_EXTENDED_STILL_STUB` keep the `_not_built` stub;
    any extended tool wired since (e.g. `hashdeep`) must have a real build_argv+parse."""
    for tool in by_tier("extended"):
        if tool.id in _EXTENDED_STILL_STUB:
            assert tool.build_argv is _not_built, f"{tool.id} should still be stub"
            assert tool.parse is _not_built, f"{tool.id} should still be stub"
        else:
            assert tool.build_argv is not _not_built, f"{tool.id} wired: needs real build_argv"
            assert tool.parse is not _not_built, f"{tool.id} wired: needs real parse"


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


# --------------------------------------------------------------------------- #
# Alcance real del agente: catálogo → allowlist → schema
# --------------------------------------------------------------------------- #
#: Tools del catálogo que a propósito NO se exponen al agente. `qemu_nbd` es
#: `side_effecting` (conecta dispositivos de bloque): se opera a mano desde el
#: maletín. Sacar algo de aquí exige darle schema; meterlo, justificarlo.
_NOT_EXPOSED_TO_AGENT = frozenset({"qemu_nbd"})


def test_every_allowed_tool_is_visible_to_the_llm() -> None:
    """Una tool permitida SIN schema es invisible: `tool_specs` la salta en silencio.

    Ese hueco tenía a plaso, hashdeep y foremost fuera del alcance del agente pese a
    estar en el maletín y en la allowlist (barrido 2026-07-17). Sin este tripwire, la
    allowlist derivada del catálogo hace creer que una tool está disponible cuando el
    LLM ni siquiera la ve.
    """
    from forensia.agent.loader import default_allowed_tools
    from forensia.agent.tool_schemas import tool_specs

    for profile in ("windows", "unix"):
        allowed = [t for t in default_allowed_tools(profile) if t not in _NOT_EXPOSED_TO_AGENT]
        visible = {spec["function"]["name"] for spec in tool_specs(allowed)}
        invisible = sorted(set(allowed) - visible)
        assert not invisible, (
            f"[{profile}] permitidas pero SIN schema (el LLM no puede pedirlas): {invisible}"
        )


def test_exposed_tools_have_both_schemas_and_a_description() -> None:
    """Las dos superficies (agente y MCP) publican el mismo conjunto de tools."""
    from forensia.agent.tool_schemas import TOOL_DESCRIPTIONS, TOOL_PARAM_SCHEMAS
    from forensia.mcp.schemas import SCHEMA_BY_TOOL

    for tool in CATALOG:
        if tool.id in _NOT_EXPOSED_TO_AGENT:
            continue
        assert tool.id in TOOL_PARAM_SCHEMAS, f"{tool.id}: sin schema de params (agente)"
        assert tool.id in TOOL_DESCRIPTIONS, f"{tool.id}: sin descripción para el LLM"
        assert tool.id in SCHEMA_BY_TOOL, f"{tool.id}: sin schema Pydantic (MCP)"


# --------------------------------------------------------------------------- #
# Volatility3 plugin policy (MCP enum)
# --------------------------------------------------------------------------- #
def test_credential_plugins_stay_exposed_to_the_agent() -> None:
    """Regresión de un fallo que costó un E1 (2026-07-17).

    El agente concluyó que `hashdump`/`lsadump`/`cachedump` "no existían en este
    build" cuando SÍ están (verificado sobre RAM Win7 real: 6 cuentas, exit 0);
    lo que faltaba era exponerlos aquí. Si alguien los quita del enum, el agente
    vuelve a leer una restricción de POLÍTICA como una ausencia de CAPACIDAD.
    Los ids son los canónicos `windows.registry.*` (los alias `windows.hashdump.*`
    los retira volatility tras 2026-09-25).
    """
    for plugin in (
        "windows.registry.hashdump.Hashdump",
        "windows.registry.lsadump.Lsadump",
        "windows.registry.cachedump.Cachedump",
    ):
        assert plugin in _VOLATILITY_WINDOWS_PLUGINS, (
            f"{plugin} salió del enum: el agente no podrá volcar credenciales de RAM"
        )


def test_volatility_plugin_ids_carry_module_and_class() -> None:
    """Todo id del enum termina en la CLASE del plugin (`…​.Clase`, CamelCase).

    Un id sin clase (`windows.hashdump`) es lo que provoca el `invalid choice`
    que en su día se malinterpretó como "el plugin no está". Los plugins de nivel
    superior (`timeliner.Timeliner`) tienen 2 segmentos; los de un SO, 3 o más.
    """
    for plugin in _VOLATILITY_WINDOWS_PLUGINS:
        segments = plugin.split(".")
        assert len(segments) >= 2, f"{plugin}: falta la clase (modulo.Clase)"
        assert segments[-1][:1].isupper(), f"{plugin}: el último segmento no es la clase"
        assert segments[-2][:1].islower(), f"{plugin}: el penúltimo segmento no es un módulo"


def test_path_parameter_inventory_is_exhaustive_and_explicit() -> None:
    """Tripwire for every wrapper parameter that represents a filesystem path."""
    expected = {
        "file_info": {"image_path"},
        "xxd_head": {"image_path"},
        "strings_head": {"image_path"},
        "tsk_mmls": {"image_path"},
        "tsk_fls": {"image_path"},
        "tsk_mactime": {"bodyfile_path"},
        "ewf_info": {"image_path"},
        "bulk_extractor": {"image_path", "output_dir"},
        "yara": {"rules_path", "target_path"},
        "volatility3": {"dump_path"},
        "hayabusa": {"evtx_dir", "output_csv"},
        "chainsaw": {"target_dir", "sigma_dir", "rules_dir", "ruleset", "output_path"},
        "evtxecmd": {"evtx_path", "output_dir"},
        "mftecmd": {"mft_path", "output_dir"},
        "regripper": {"hive_path"},
        "jq": {"input_path"},
        "tsk_icat": {"image_path"},
        "plaso_log2timeline": {"image_path", "output_dir"},
        "plaso_psort": {"plaso_path", "output_dir"},
        "hashdeep": {"image_path"},
        "foremost": {"image_path", "output_dir"},
        "qemu_nbd": {"image_path", "nbd_device"},
        "ftkimager": {"image_path", "output_dir"},
        "aff4imager": {"image_path", "output_dir"},
        "lecmd": {"target_path", "output_dir"},
        "jlecmd": {"target_path", "output_dir"},
        "recmd": {"hive_path", "output_dir", "batch"},
        "amcacheparser": {"hive_path", "output_dir"},
        "appcompatcacheparser": {"hive_path", "output_dir"},
        "sbecmd": {"target_path", "output_dir"},
        "wxtcmd": {"target_path", "output_dir"},
        "rbcmd": {"target_path", "output_dir"},
    }
    assert set(expected) == set(BY_ID)
    for tool_id, names in expected.items():
        assert {spec.name for spec in BY_ID[tool_id].path_parameters} == names
