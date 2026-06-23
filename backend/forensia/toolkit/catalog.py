"""The curated maletín. Each entry is a closed-enum Tool the agent may select.

`build_argv`/`parse` are intentionally unimplemented in the skeleton; the contract
(id, binary, os_profiles, returns) is what we lock now. Volatility3 and plaso ride
inside the PyInstaller sidecar; the rest are vendored native binaries.
"""

from __future__ import annotations

from forensia.toolkit.tool import Tool

CATALOG: tuple[Tool, ...] = (
    # --- Sistema de ficheros y carving (cross) ---
    Tool("tsk_fls", "fls", ("unix", "windows"), returns="artifact"),
    Tool("tsk_icat", "icat", ("unix", "windows"), returns="artifact"),
    Tool("tsk_mmls", "mmls", ("unix", "windows")),
    Tool("tsk_mactime", "mactime", ("unix", "windows"), returns="artifact"),
    Tool("bulk_extractor", "bulk_extractor", ("unix", "windows"), returns="artifact"),
    Tool("foremost", "foremost", ("unix",), returns="artifact"),
    # --- Imagen / montaje / integridad (cross) ---
    Tool("ewf_info", "ewfinfo", ("unix", "windows")),
    Tool("qemu_nbd", "qemu-nbd", ("unix",), side_effecting=True),
    Tool("hashdeep", "hashdeep", ("unix", "windows"), returns="artifact"),
    # --- Línea temporal (cross, en el sidecar) ---
    Tool("plaso_log2timeline", "log2timeline.py", ("unix", "windows"), returns="artifact"),
    Tool("plaso_psort", "psort.py", ("unix", "windows"), returns="artifact"),
    # --- Memoria RAM (cross, en el sidecar) ---
    Tool("volatility3", "vol", ("unix", "windows"), returns="artifact"),
    # --- Artefactos Windows ---
    Tool("regripper", "rip", ("windows",), returns="artifact"),
    Tool("hayabusa", "hayabusa", ("windows",), returns="artifact"),
    Tool("chainsaw", "chainsaw", ("windows",), returns="artifact"),
)

BY_ID = {tool.id: tool for tool in CATALOG}


def for_profile(os_profile: str) -> tuple[Tool, ...]:
    return tuple(t for t in CATALOG if os_profile in t.os_profiles)
