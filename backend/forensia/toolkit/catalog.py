"""The curated maletín. Each entry is a closed-enum Tool the agent may select.

`build_argv`/`parse` are intentionally unimplemented in the skeleton; the contract
(id, binary, os_profiles, returns, delivery, tier) is what we lock now.

Tiers (see `docs/TOOLS_INVENTORY.md` — "Kit primeros 30 minutos"):
- `core`: the 13-tool kit needed for a fast post-mortem. Required for the MVP.
- `extended`: additional tools that ride along once the core is stable (Plaso, hashing,
  carving extras, mount helpers).

Delivery (CLAUDE.md RULE 1): each tool declares per-host-OS whether it's `bundled`
(PyInstaller sidecar for Python tools / vendored native binary for the rest) or
`container` (OCI image executed via the host runtime). Tools without a viable native
build on a given OS are declared as `container` for that OS only.
"""

from __future__ import annotations

from forensia.toolkit.tool import (
    DELIVERY_ALL_CONTAINER,
    DELIVERY_WINDOWS_NATIVE,
    Tool,
)

CATALOG: tuple[Tool, ...] = (
    # ====== CORE TIER — kit "primeros 30 minutos" ======

    # --- Sistema de ficheros / particiones (TSK, bundled cross) ---
    Tool("tsk_mmls", "mmls", ("unix", "windows"), tier="core"),
    Tool("tsk_fls", "fls", ("unix", "windows"), returns="artifact", tier="core"),
    Tool("tsk_mactime", "mactime", ("unix", "windows"), returns="artifact", tier="core"),

    # --- Imagen (libewf, bundled cross) ---
    Tool("ewf_info", "ewfinfo", ("unix", "windows"), tier="core"),

    # --- Carving / IoCs (bundled cross) ---
    Tool("bulk_extractor", "bulk_extractor", ("unix", "windows"), returns="artifact", tier="core"),
    Tool("yara", "yara", ("unix", "windows"), returns="artifact", tier="core"),

    # --- Memoria RAM (Volatility 3, dentro del sidecar) ---
    Tool("volatility3", "vol", ("unix", "windows"), returns="artifact", tier="core"),

    # --- EVTX / Sigma (Rust, bundled cross) ---
    Tool("hayabusa", "hayabusa", ("windows",), returns="artifact", tier="core"),
    Tool("chainsaw", "chainsaw", ("windows",), returns="artifact", tier="core"),

    # --- Eric Zimmerman .NET tools: nativos en Windows, container en Linux/Mac ---
    Tool(
        "evtxecmd",
        "EvtxECmd",
        ("windows",),
        returns="artifact",
        tier="core",
        delivery=DELIVERY_WINDOWS_NATIVE,
        container_image="forensia/evtxecmd:latest",
    ),
    Tool(
        "mftecmd",
        "MFTECmd",
        ("windows",),
        returns="artifact",
        tier="core",
        delivery=DELIVERY_WINDOWS_NATIVE,
        container_image="forensia/mftecmd:latest",
    ),

    # --- Registry (Perl): container en todos los OS para evitar bundlear Perl portable ---
    Tool(
        "regripper",
        "rip",
        ("windows",),
        returns="artifact",
        tier="core",
        delivery=DELIVERY_ALL_CONTAINER,
        container_image="forensia/regripper:latest",
    ),

    # --- Helper de filtrado JSON para el agente (bundled cross) ---
    Tool("jq", "jq", ("unix", "windows"), tier="core"),

    # ====== EXTENDED TIER — se añaden tras estabilizar el core ======

    # Extracción puntual de ficheros (TSK)
    Tool("tsk_icat", "icat", ("unix", "windows"), returns="artifact"),

    # Super-timeline (Plaso, dentro del sidecar) — lento, kit "primera tarde"
    Tool("plaso_log2timeline", "log2timeline.py", ("unix", "windows"), returns="artifact"),
    Tool("plaso_psort", "psort.py", ("unix", "windows"), returns="artifact"),

    # Hashing / carving extra
    Tool("hashdeep", "hashdeep", ("unix", "windows"), returns="artifact"),
    Tool("foremost", "foremost", ("unix",), returns="artifact"),

    # Montaje auxiliar (side-effecting)
    Tool("qemu_nbd", "qemu-nbd", ("unix",), side_effecting=True),
)

BY_ID = {tool.id: tool for tool in CATALOG}


def for_profile(os_profile: str) -> tuple[Tool, ...]:
    return tuple(t for t in CATALOG if os_profile in t.os_profiles)


def by_tier(tier: str) -> tuple[Tool, ...]:
    return tuple(t for t in CATALOG if t.tier == tier)
