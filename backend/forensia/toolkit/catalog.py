"""The curated maletín. Each entry is a closed-enum Tool the agent may select.

Tiers (see `docs/maletin/inventario-tools.md` — "Kit primeros 30 minutos"):
- `core`: the 13-tool kit needed for a fast post-mortem. Required for the MVP.
- `extended`: additional tools that ride along once the core is stable (Plaso, hashing,
  carving extras, mount helpers).

Delivery (CLAUDE.md RULE 1): each tool declares the compose maletín image(s) that
physically carry its binary via `toolkits=` — `toolkit-unix` / `toolkit-windows`. Tools
in the shared `base` stage of `docker/docker/forensic-toolkit/Dockerfile` serve both
OS profiles and live in BOTH maletines (`MALETINES`); Windows-artifact tools (RegRipper,
hayabusa, chainsaw, the Eric Zimmerman .NET tools) live only in `toolkit-windows`.
`forensia.toolkit.maletin` probes those services and `capabilities` reports the result;
RULE 2 forbids resolving a tool against any maletín it does not declare here.

The legacy per-host-OS `delivery` + `container_image` fields are retained for the
not-yet-realigned dispatcher execution path; unifying execution onto the maletines is
tracked in `docs/operacion/proximos-pasos.md` §A/§B.
"""

from __future__ import annotations

from forensia.toolkit.maletin import MALETINES, TOOLKIT_WINDOWS
from forensia.toolkit.tool import Tool
from forensia.toolkit.wrappers import (
    bulk_extractor as _bulk_extractor,
)
from forensia.toolkit.wrappers import (
    file_info as _file_info,
)
from forensia.toolkit.wrappers import (
    foremost as _foremost,
)
from forensia.toolkit.wrappers import (
    hashdeep as _hashdeep,
)
from forensia.toolkit.wrappers import (
    plaso_log2timeline as _plaso_log2timeline,
)
from forensia.toolkit.wrappers import (
    plaso_psort as _plaso_psort,
)
from forensia.toolkit.wrappers import (
    qemu_nbd as _qemu_nbd,
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
    tsk_icat as _tsk_icat,
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

# Cross tools ship in the `base` stage inherited by BOTH maletines; Windows artifacts
# only in `toolkit-windows`. (No catalog tool is `toolkit-unix`-exclusive today — the
# unix stage only adds journalctl/lnav/fs helpers that are not in the catalog.)
_BOTH = MALETINES
_WINDOWS = (TOOLKIT_WINDOWS,)

CATALOG: tuple[Tool, ...] = (
    # ====== CORE TIER — kit "primeros 30 minutos" ======

    # --- "Primer vistazo": characterize the file BEFORE invoking forensic tools ---
    Tool(
        "file_info",
        "file",
        ("unix", "windows"),
        tier="core",
        toolkits=_BOTH,
        allowed_flags=_file_info.ALLOWED_FLAGS,
        build_argv=_file_info.build_argv,
        parse=_file_info.parse,
    ),
    Tool(
        "xxd_head",
        "xxd",
        ("unix", "windows"),
        tier="core",
        toolkits=_BOTH,
        allowed_flags=_xxd_head.ALLOWED_FLAGS,
        build_argv=_xxd_head.build_argv,
        parse=_xxd_head.parse,
    ),
    Tool(
        "strings_head",
        "strings",
        ("unix", "windows"),
        tier="core",
        toolkits=_BOTH,
        allowed_flags=_strings_head.ALLOWED_FLAGS,
        build_argv=_strings_head.build_argv,
        parse=_strings_head.parse,
    ),

    # --- Sistema de ficheros / particiones (TSK, en el stage base de ambos maletines) ---
    Tool(
        "tsk_mmls",
        "mmls",
        ("unix", "windows"),
        tier="core",
        toolkits=_BOTH,
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
        toolkits=_BOTH,
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
        toolkits=_BOTH,
        allowed_flags=_tsk_mactime.ALLOWED_FLAGS,
        build_argv=_tsk_mactime.build_argv,
        parse=_tsk_mactime.parse,
    ),

    # --- Imagen (libewf, stage base de ambos maletines) ---
    Tool(
        "ewf_info",
        "ewfinfo",
        ("unix", "windows"),
        tier="core",
        toolkits=_BOTH,
        allowed_flags=_ewf_info.ALLOWED_FLAGS,
        build_argv=_ewf_info.build_argv,
        parse=_ewf_info.parse,
    ),

    # --- Carving / IoCs (stage base de ambos maletines) ---
    Tool(
        "bulk_extractor",
        "bulk_extractor",
        ("unix", "windows"),
        returns="artifact",
        tier="core",
        toolkits=_BOTH,
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
        toolkits=_BOTH,
        allowed_flags=_yara.ALLOWED_FLAGS,
        build_argv=_yara.build_argv,
        parse=_yara.parse,
    ),

    # --- Memoria RAM (Volatility 3, stage base de ambos maletines) ---
    Tool(
        "volatility3",
        "vol",
        ("unix", "windows"),
        returns="artifact",
        tier="core",
        toolkits=_BOTH,
        allowed_flags=_volatility3.ALLOWED_FLAGS,
        build_argv=_volatility3.build_argv,
        parse=_volatility3.parse,
    ),

    # --- EVTX / Sigma (Rust, solo en el maletín windows) ---
    Tool(
        "hayabusa",
        "hayabusa",
        ("windows",),
        returns="artifact",
        tier="core",
        toolkits=_WINDOWS,
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
        toolkits=_WINDOWS,
        allowed_flags=_chainsaw.ALLOWED_FLAGS,
        build_argv=_chainsaw.build_argv,
        parse=_chainsaw.parse,
    ),

    # --- Eric Zimmerman .NET tools: viven en el maletín windows (EvtxECmd/MFTECmd,
    #     .dll net9 sobre el runtime .NET absorbido en su Dockerfile), ejecutados por
    #     el exec-agent como el resto (2026-07-04). ---
    Tool(
        "evtxecmd",
        "EvtxECmd",
        ("windows",),
        returns="artifact",
        tier="core",
        toolkits=_WINDOWS,
        allowed_flags=_evtxecmd.ALLOWED_FLAGS,
        build_argv=_evtxecmd.build_argv,
        parse=_evtxecmd.parse,
    ),
    Tool(
        "mftecmd",
        "MFTECmd",
        ("windows",),
        returns="artifact",
        tier="core",
        toolkits=_WINDOWS,
        allowed_flags=_mftecmd.ALLOWED_FLAGS,
        build_argv=_mftecmd.build_argv,
        parse=_mftecmd.parse,
    ),

    # --- Registry (Perl): vive en el maletín windows, ejecutado por el exec-agent ---
    Tool(
        "regripper",
        "rip.pl",
        ("windows",),
        returns="artifact",
        tier="core",
        toolkits=_WINDOWS,
        allowed_flags=_regripper.ALLOWED_FLAGS,
        build_argv=_regripper.build_argv,
        parse=_regripper.parse,
    ),

    # --- Helper de filtrado JSON para el agente (stage base de ambos maletines) ---
    Tool(
        "jq",
        "jq",
        ("unix", "windows"),
        tier="core",
        toolkits=_BOTH,
        allowed_flags=_jq.ALLOWED_FLAGS,
        build_argv=_jq.build_argv,
        parse=_jq.parse,
    ),

    # ====== EXTENDED TIER — se añaden tras estabilizar el core ======

    # Extracción puntual de ficheros (TSK, stage base)
    Tool(
        "tsk_icat",
        "icat",
        ("unix", "windows"),
        returns="artifact",
        toolkits=_BOTH,
        allowed_flags=_tsk_icat.ALLOWED_FLAGS,
        build_argv=_tsk_icat.build_argv,
        parse=_tsk_icat.parse,
    ),

    # Super-timeline (Plaso, stage base) — lento, kit "primera tarde"
    Tool(
        "plaso_log2timeline",
        "log2timeline.py",
        ("unix", "windows"),
        returns="artifact",
        toolkits=_BOTH,
        allowed_flags=_plaso_log2timeline.ALLOWED_FLAGS,
        build_argv=_plaso_log2timeline.build_argv,
        parse=_plaso_log2timeline.parse,
    ),
    Tool(
        "plaso_psort",
        "psort.py",
        ("unix", "windows"),
        returns="artifact",
        toolkits=_BOTH,
        allowed_flags=_plaso_psort.ALLOWED_FLAGS,
        build_argv=_plaso_psort.build_argv,
        parse=_plaso_psort.parse,
    ),

    # Hashing / carving extra (stage base)
    Tool(
        "hashdeep",
        "hashdeep",
        ("unix", "windows"),
        returns="artifact",
        toolkits=_BOTH,
        allowed_flags=_hashdeep.ALLOWED_FLAGS,
        build_argv=_hashdeep.build_argv,
        parse=_hashdeep.parse,
    ),
    Tool(
        "foremost",
        "foremost",
        ("unix",),
        returns="artifact",
        toolkits=_BOTH,
        allowed_flags=_foremost.ALLOWED_FLAGS,
        build_argv=_foremost.build_argv,
        parse=_foremost.parse,
    ),

    # Montaje auxiliar (side-effecting; qemu-utils en el stage base)
    Tool(
        "qemu_nbd",
        "qemu-nbd",
        ("unix",),
        side_effecting=True,
        toolkits=_BOTH,
        allowed_flags=_qemu_nbd.ALLOWED_FLAGS,
        build_argv=_qemu_nbd.build_argv,
        parse=_qemu_nbd.parse,
    ),
)

BY_ID = {tool.id: tool for tool in CATALOG}


def for_profile(os_profile: str) -> tuple[Tool, ...]:
    return tuple(t for t in CATALOG if os_profile in t.os_profiles)


def by_tier(tier: str) -> tuple[Tool, ...]:
    return tuple(t for t in CATALOG if t.tier == tier)
