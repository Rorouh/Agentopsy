"""foremost wrapper — file carving by header/footer from unallocated (and raw) space.

Recovers files whose metadata is gone by matching known magic headers/footers across the
raw image. Writes carved files (grouped by type) + an ``audit.txt`` summary into an output
directory. Best signal on a **used** disk with deleted content; on a clean image it still
carves file signatures embedded in allocated data.

The artifact-store pre-creates ``<run>/out/`` and hands it as ``output_dir``; foremost
REFUSES an existing output dir, so we carve into a fresh ``<output_dir>/foremost`` subdir.
"""

from __future__ import annotations

from typing import Any

ALLOWED_FLAGS = frozenset({"-t", "-o", "-i", "-q", "-a", "-w", "-v", "-T"})

# foremost built-in types (subset kept as an allowlist) + "all".
_TYPES = (
    "all", "jpg", "gif", "png", "bmp", "tif", "avi", "exe", "mpg", "wav", "riff",
    "wmv", "mov", "pdf", "ole", "doc", "zip", "rar", "htm", "cpp",
)


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for foremost.

    params:
        image_path (str, required): raw image to carve. Injected by Agentopsy.
        output_dir (str, required): run dir injected by the dispatcher. We carve into
            ``<output_dir>/foremost`` (fresh; foremost refuses an existing dir).
        types (list[str], optional): foremost type names to carve (default: all).
        quick (bool, optional): quick mode (`-q`, scans block boundaries — faster).
    """
    image_path = params.get("image_path")
    if not image_path or not isinstance(image_path, str):
        raise ValueError("foremost requires params.image_path: str")
    output_dir = params.get("output_dir")
    if not output_dir or not isinstance(output_dir, str):
        raise ValueError("foremost requires params.output_dir: str")

    types = params.get("types")
    argv: list[str] = []
    if types:
        if not isinstance(types, list) or not all(isinstance(t, str) for t in types):
            raise ValueError("foremost types must be a list[str]")
        for t in types:
            if t not in _TYPES:
                raise ValueError(f"foremost: invalid type {t!r} (allowed: {list(_TYPES)})")
        argv += ["-t", ",".join(types)]
    if params.get("quick"):
        argv.append("-q")

    carve_dir = output_dir.rstrip("/") + "/foremost"
    argv += ["-o", carve_dir, "-i", image_path]
    return argv


def parse(stdout: str) -> dict[str, Any]:
    """Summarise foremost stdout. The authoritative per-type breakdown lives in the
    ``audit.txt`` inside the output dir (an artifact); stdout only carries progress and
    the final counts line on some builds."""
    lines = [ln for ln in stdout.splitlines() if ln.strip()]
    # Some builds print "Foremost finished ..." / a "Num\tName" table; capture any
    # explicit extracted-count if present, else fall back to marker counts.
    found_markers = sum(1 for ln in lines if "foundat" in ln.lower())
    finished = any("foremost finished" in ln.lower() for ln in lines)
    return {
        "finished": finished,
        "foundat_markers": found_markers,
        "note": "desglose por tipo + nº de ficheros en audit.txt del output_dir (artefacto)",
        "tail": lines[-8:],
    }
