"""The curated maletín. Each entry is a closed-enum Tool the agent may select.

Tiers (see `docs/maletin/inventario-tools.md` — "Kit primeros 30 minutos"):
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
from forensia.toolkit.wrappers import (
    bulk_extractor as _bulk_extractor,
)
from forensia.toolkit.wrappers import (
    file_info as _file_info,
)
from forensia.toolkit.wrappers import (
    strings_head as _strings_head,
)
from forensia.toolkit.wrappers import (
    xxd_head as _xxd_head,
)
from forensia.toolkit.wrappers import (
    chainsaw as _chainsaw,
)
from forensia.toolkit.wrappers import (
    evtxecmd as _evtxecmd,
)
from forensia.toolkit.wrappers import (
    ewf_info as _ewf_info,
)
from forensia.toolkit.wrappers import (
    hayabusa as _hayabusa,
)
from forensia.toolkit.wrappers import (
    jq as _jq,
)
from forensia.toolkit.wrappers import (
    mftecmd as _mftecmd,
)
from forensia.toolkit.wrappers import (
    regripper as _regripper,
)
from forensia.toolkit.wrappers import (
    tsk_fls as _tsk_fls,
)
from forensia.toolkit.wrappers import (
    tsk_mactime as _tsk_mactime,
)
from forensia.toolkit.wrappers import (
    tsk_mmls as _tsk_mmls,
)
from forensia.toolkit.wrappers import (
    volatility3 as _volatility3,
)
from forensia.toolkit.wrappers import (
    yara as _yara,
)

CATALOG: tuple[Tool, ...] = (
    # ====== CORE TIER — kit "primeros 30 minutos" ======

    # --- "Primer vistazo": characterize the file BEFORE invoking forensic tools ---
    Tool(
        "file_info",
        "file",
        ("unix", "windows"),
        tier="core",
        allowed_flags=_file_info.ALLOWED_FLAGS,
        build_argv=_file_info.build_argv,
        parse=_file_info.parse,
    ),
    Tool(
        "xxd_head",
        "xxd",
        ("unix", "windows"),
        tier="core",
        allowed_flags=_xxd_head.ALLOWED_FLAGS,
        build_argv=_xxd_head.build_argv,
        parse=_xxd_head.parse,
    ),
    Tool(
        "strings_head",
        "strings",
        ("unix", "windows"),
        tier="core",
        allowed_flags=_strings_head.ALLOWED_FLAGS,
        build_argv=_strings_head.build_argv,
        parse=_strings_head.parse,
    ),

    # --- Sistema de ficheros / particiones (TSK, bundled cross) ---
    Tool(
        "tsk_mmls",
        "mmls",
        ("unix", "windows"),
        tier="core",
        allowed_flags=_tsk_mmls.ALLOWED_FLAGS,
        build_argv=_tsk_mmls.build_argv,
        parse=_tsk_mmls.parse,
    ),
    Tool(
        "tsk_fls",
        "fls",
        ("unix", "windows"),
        returns="artifact",
        tier="core",
        allowed_flags=_tsk_fls.ALLOWED_FLAGS,
        build_argv=_tsk_fls.build_argv,
        parse=_tsk_fls.parse,
    ),
    Tool(
        "tsk_mactime",
        "mactime",
        ("unix", "windows"),
        returns="artifact",
        tier="core",
        allowed_flags=_tsk_mactime.ALLOWED_FLAGS,
        build_argv=_tsk_mactime.build_argv,
        parse=_tsk_mactime.parse,
    ),

    # --- Imagen (libewf, bundled cross) ---
    Tool(
        "ewf_info",
        "ewfinfo",
        ("unix", "windows"),
        tier="core",
        allowed_flags=_ewf_info.ALLOWED_FLAGS,
        build_argv=_ewf_info.build_argv,
        parse=_ewf_info.parse,
    ),

    # --- Carving / IoCs (bundled cross) ---
    Tool(
        "bulk_extractor",
        "bulk_extractor",
        ("unix", "windows"),
        returns="artifact",
        tier="core",
        allowed_flags=_bulk_extractor.ALLOWED_FLAGS,
        build_argv=_bulk_extractor.build_argv,
        parse=_bulk_extractor.parse,
    ),
    Tool(
        "yara",
        "yara",
        ("unix", "windows"),
        returns="artifact",
        tier="core",
        allowed_flags=_yara.ALLOWED_FLAGS,
        build_argv=_yara.build_argv,
        parse=_yara.parse,
    ),

    # --- Memoria RAM (Volatility 3, dentro del sidecar) ---
    Tool(
        "volatility3",
        "vol",
        ("unix", "windows"),
        returns="artifact",
        tier="core",
        allowed_flags=_volatility3.ALLOWED_FLAGS,
        build_argv=_volatility3.build_argv,
        parse=_volatility3.parse,
    ),

    # --- EVTX / Sigma (Rust, bundled cross) ---
    Tool(
        "hayabusa",
        "hayabusa",
        ("windows",),
        returns="artifact",
        tier="core",
        allowed_flags=_hayabusa.ALLOWED_FLAGS,
        build_argv=_hayabusa.build_argv,
        parse=_hayabusa.parse,
    ),
    Tool(
        "chainsaw",
        "chainsaw",
        ("windows",),
        returns="artifact",
        tier="core",
        allowed_flags=_chainsaw.ALLOWED_FLAGS,
        build_argv=_chainsaw.build_argv,
        parse=_chainsaw.parse,
    ),

    # --- Eric Zimmerman .NET tools: nativos en Windows, container en Linux/Mac ---
    Tool(
        "evtxecmd",
        "EvtxECmd",
        ("windows",),
        returns="artifact",
        tier="core",
        delivery=DELIVERY_WINDOWS_NATIVE,
        container_image="forensia/evtxecmd:latest",
        allowed_flags=_evtxecmd.ALLOWED_FLAGS,
        build_argv=_evtxecmd.build_argv,
        parse=_evtxecmd.parse,
        host_mounts=_evtxecmd.host_mounts,
    ),
    Tool(
        "mftecmd",
        "MFTECmd",
        ("windows",),
        returns="artifact",
        tier="core",
        delivery=DELIVERY_WINDOWS_NATIVE,
        container_image="forensia/mftecmd:latest",
        allowed_flags=_mftecmd.ALLOWED_FLAGS,
        build_argv=_mftecmd.build_argv,
        parse=_mftecmd.parse,
        host_mounts=_mftecmd.host_mounts,
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
        allowed_flags=_regripper.ALLOWED_FLAGS,
        build_argv=_regripper.build_argv,
        parse=_regripper.parse,
        host_mounts=_regripper.host_mounts,
    ),

    # --- Helper de filtrado JSON para el agente (bundled cross) ---
    Tool(
        "jq",
        "jq",
        ("unix", "windows"),
        tier="core",
        allowed_flags=_jq.ALLOWED_FLAGS,
        build_argv=_jq.build_argv,
        parse=_jq.parse,
    ),

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
