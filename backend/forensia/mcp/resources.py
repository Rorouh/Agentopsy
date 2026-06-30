"""``resources/read`` handler for MCP `mcp-toolkit` (D5').

URI scheme: ``artifact://<case_id>/<run_id>/<relpath>``.

The MCP client (Claude Desktop) calls ``resources/read`` with one of these
URIs after seeing it as a ``ResourceLink`` content block in a tool response.
We resolve the URI back to the case-anchored artifact directory, enforce the
boundary (must live inside ``~/.forensia/cases/<case>/artifacts/<run>/``,
must not escape via ``..``), apply a size cap, and return the bytes as
``ReadResourceContents`` — the duck-typed dataclass the SDK's
``@server.read_resource()`` decorator expects (``.content``,
``.mime_type``, ``.meta``). Returning ``TextResourceContents`` directly was a
plan-stage bug: the decorator iterates over our return and reads
``.content``, which would crash on ``TextResourceContents`` (whose payload is
under ``.text``). Verified by the robustness panel — F1 of the round-1
review.

Why a separate handler module:
- Keeps ``toolkit.py`` focused on the tool surface.
- The boundary check is critical (CLAUDE.md security gate 6 — canonicalize
  paths in the backend); easier to test in isolation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from mcp import types
from mcp.server.lowlevel.helper_types import ReadResourceContents

from forensia.cases.manager import case_manager


# Max bytes returned in a single resources/read. Larger artefacts must be
# inspected via downstream tools (jq, csv parsing). 1 MiB is enough for an
# excerpt of any realistic artefact and small enough to avoid bricking the
# Claude Desktop UI.
MAX_BYTES = 1 * 1024 * 1024

# Heuristic: if the first 4 KiB decode as UTF-8 cleanly, treat the file as
# text. Otherwise return it as base64 blob.
_TEXT_PROBE = 4096

_ARTIFACT_URI = re.compile(
    r"^artifact://(?P<case>[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})/"
    r"(?P<run>[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})/(?P<rel>.+)$"
)


@dataclass(frozen=True)
class ArtifactRef:
    case_id: str
    run_id: str
    relpath: str


def parse_artifact_uri(uri: str) -> ArtifactRef:
    """Parse ``artifact://<case>/<run>/<relpath>`` or raise ``ValueError``."""
    m = _ARTIFACT_URI.match(uri)
    if not m:
        raise ValueError(
            f"invalid artifact URI {uri!r} — expected "
            f"artifact://<case-uuid>/<run-uuid>/<relpath>"
        )
    return ArtifactRef(case_id=m["case"], run_id=m["run"], relpath=m["rel"])


def resolve_artifact_path(ref: ArtifactRef) -> Path:
    """Return the absolute, canonical filesystem path of the referenced artifact.

    Raises:
        KeyError: if the case does not exist.
        FileNotFoundError: if the artifact file does not exist.
        ValueError: if the resolved path escapes the case's artifacts dir
            (defence against ``..`` traversal in the URI's relpath).
    """
    case_dir = case_manager.case_dir(ref.case_id)  # raises KeyError on missing
    artifacts_root = (case_dir / "artifacts" / ref.run_id).resolve()
    candidate = (artifacts_root / ref.relpath).resolve()
    # Path-traversal guard: candidate must live INSIDE artifacts_root.
    if artifacts_root != candidate and artifacts_root not in candidate.parents:
        raise ValueError(
            f"artifact URI {ref.relpath!r} escapes the artifacts directory of "
            f"run {ref.run_id} (case {ref.case_id})"
        )
    if not candidate.is_file():
        raise FileNotFoundError(f"artifact not found: {candidate}")
    return candidate


def read_artifact(uri: str) -> list[ReadResourceContents]:
    """Resolve + read an ``artifact://`` URI. Returns the SDK's expected
    ``Iterable[ReadResourceContents]`` so the ``@server.read_resource()``
    decorator can wrap it into the wire-shape ``TextResourceContents`` /
    ``BlobResourceContents`` itself.

    For files larger than ``MAX_BYTES`` we return the first chunk with a
    ``truncated`` flag in the meta so the client knows there is more.
    """
    ref = parse_artifact_uri(uri)
    path = resolve_artifact_path(ref)

    size = path.stat().st_size
    truncated = size > MAX_BYTES
    with path.open("rb") as fh:
        raw = fh.read(MAX_BYTES)

    # Decide text vs binary on the first chunk.
    try:
        _probe = raw[:_TEXT_PROBE].decode("utf-8")
        # If the probe decoded but the rest fails, fall through to text decode
        # with errors="replace" — the artefact is probably text with a
        # single non-utf8 byte; better to return readable text than blob.
        text = raw.decode("utf-8", errors="replace")
        mime = "text/plain; charset=utf-8"
        if path.suffix.lower() == ".json":
            mime = "application/json"
        elif path.suffix.lower() == ".csv":
            mime = "text/csv"
        return [
            ReadResourceContents(
                content=text,
                mime_type=mime,
                meta={"truncated": truncated, "size_bytes": size},
            )
        ]
    except UnicodeDecodeError:
        return [
            ReadResourceContents(
                content=raw,
                mime_type="application/octet-stream",
                meta={"truncated": truncated, "size_bytes": size},
            )
        ]


def build_resource_links_for_run(
    case_id: str,
    run_id: str,
    artifact_run: dict,
) -> list[types.ResourceLink]:
    """Build one ``ResourceLink`` per artifact file in a finished run.

    Includes:
    - ``stdout.txt`` and ``stderr.txt`` at run-dir root (always present when
      the run finished — captured by the dispatcher, hashed via
      ``stdout_sha256`` / ``stderr_sha256``).
    - Every entry in ``output_files`` (files the wrapper wrote to ``out/``).

    The DFIR panel of the round-1 review caught the gap: most tools whose
    "product" is stdout (volatility3 plugins, jq, file_info) never populated
    ``output_files`` because that list only tracks files under ``out/``.
    Without stdout.txt as a resource link, the entire
    ``ResourceLink → resources/read`` chain was dead for those tools.
    """
    links: list[types.ResourceLink] = []

    # stdout.txt — always emitted (the run dir is always created with one,
    # even if empty, by ArtifactStore.finalize_run).
    stdout_sha = artifact_run.get("stdout_sha256")
    if stdout_sha:
        links.append(
            types.ResourceLink(
                type="resource_link",
                name="stdout.txt",
                uri=f"artifact://{case_id}/{run_id}/stdout.txt",
                description=(
                    f"Captured stdout from run {run_id[:8]} (full output; the "
                    f"`stdout_sample` field of the tool response is truncated)."
                ),
                mimeType="text/plain",
            )
        )

    # stderr.txt — same.
    stderr_sha = artifact_run.get("stderr_sha256")
    if stderr_sha:
        links.append(
            types.ResourceLink(
                type="resource_link",
                name="stderr.txt",
                uri=f"artifact://{case_id}/{run_id}/stderr.txt",
                description=f"Captured stderr from run {run_id[:8]}.",
                mimeType="text/plain",
            )
        )

    # out/<relpath> — files the wrapper produced. relpath is POSIX-relative
    # to ``out/``, but resolve_artifact_path uses run-dir root, so we prepend.
    for f in artifact_run.get("output_files") or []:
        relpath = f.get("relpath")
        size = f.get("size")
        if not relpath:
            continue
        full_rel = relpath if relpath.startswith("out/") else f"out/{relpath}"
        uri = f"artifact://{case_id}/{run_id}/{full_rel}"
        links.append(
            types.ResourceLink(
                type="resource_link",
                name=str(Path(relpath).name),
                uri=uri,
                description=f"Artifact from run {run_id[:8]}; size={size} bytes",
                size=size if isinstance(size, int) else None,
            )
        )
    return links


__all__ = [
    "ArtifactRef",
    "MAX_BYTES",
    "build_resource_links_for_run",
    "parse_artifact_uri",
    "read_artifact",
    "resolve_artifact_path",
]
