"""Shared guard for tests that need to CREATE a symlink.

On Windows, ``os.symlink`` needs the ``SeCreateSymbolicLinkPrivilege`` — absent
for a non-admin account without Developer Mode, where it raises
``OSError [WinError 1314]``. The affected tests assert how FORENSIA handles
symlinks (evidence rejects them, artifact finalize + evidence-sources skip
them); they need a real symlink to exist. Rather than weaken those assertions,
we skip them ONLY on hosts that cannot create a symlink at all — on Linux/CI
they run exactly as before.
"""

from __future__ import annotations

import os
import tempfile

import pytest


def _symlinks_supported() -> bool:
    """True iff this process can create a symlink (probes a throwaway one)."""
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "target")
        link = os.path.join(d, "link")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write("x")
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            return False
        return True


SYMLINKS_SUPPORTED = _symlinks_supported()

requires_symlinks = pytest.mark.skipif(
    not SYMLINKS_SUPPORTED,
    reason=(
        "el proceso no puede crear symlinks (p. ej. Windows sin el privilegio "
        "SeCreateSymbolicLink → WinError 1314); en Linux/CI el test corre normal"
    ),
)
