# PyInstaller spec — ONEDIR build of the FORENSIA sidecar.
# One native build per OS/arch (PyInstaller does not cross-compile). The resulting
# `forensia-sidecar/` folder is copied to desktop/resources/ before electron-builder.
# Run from backend/:  pyinstaller build/forensia.spec --noconfirm
#
# Volatility3 / plaso ride inside this bundle as Python deps — list them in
# `hiddenimports` / `collect_all` when pinned (see pyproject [forensics]).

import sys

from PyInstaller.utils.hooks import collect_submodules

hiddenimports = (
    collect_submodules("uvicorn")
    + collect_submodules("fastapi")
    + ["forensia.server"]
)

a = Analysis(
    ["../forensia/server.py"],
    pathex=[".."],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="forensia-sidecar",
    console=True,
    target_arch=None,  # native arch of the building Python
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    name="forensia-sidecar",
)
