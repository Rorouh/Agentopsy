"""``resources/read`` handler for MCP `mcp-toolkit` (D5').

URI scheme: ``artifact://<case_id>/<run_id>/<relpath>``.

The MCP client (Claude Desktop) calls ``resources/read`` with one of these
URIs after seeing it as a ``ResourceLink`` content block in a tool response.
The URI is parsed here and the bytes are served THROUGH
``agentopsy.artifacts.lectura`` — the single verified-read boundary — so this
surface applies exactly the same policy as the agent's ``leer_artefacto``, the
REST reader and the timeline: the file has to belong to the run's manifest, the
run has to be sealed, the path has to stay confined after resolving symlinks,
and the bytes have to re-hash to the digest the manifest recorded and the audit
anchored. Until 2026-09-08 this handler opened the resolved path directly, so
altering ``stdout.txt`` and re-reading it through MCP returned the altered text
with no error (auditoría 2026-09-07, F02).

The payload comes back as ``ReadResourceContents`` — the duck-typed dataclass
the SDK's ``@server.read_resource()`` decorator expects (``.content``,
``.mime_type``, ``.meta``). Returning ``TextResourceContents`` directly was a
plan-stage bug: the decorator iterates over our return and reads ``.content``,
which would crash on ``TextResourceContents`` (whose payload is under
``.text``). Verified by the robustness panel — F1 of the round-1 review.

Why a separate handler module:
- Keeps ``toolkit.py`` focused on the tool surface.
- The URI parsing and the mapping onto the verified-read boundary are easier to
  test in isolation (CLAUDE.md security gate 6 — canonicalize paths in the
  backend).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from mcp import types
from mcp.server.lowlevel.helper_types import ReadResourceContents

from agentopsy.artifacts import lectura


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
            f"invalid artifact URI {uri!r}, expected "
            f"artifact://<case-uuid>/<run-uuid>/<relpath>"
        )
    return ArtifactRef(case_id=m["case"], run_id=m["run"], relpath=m["rel"])


def referencia_de(ref: ArtifactRef) -> str:
    """The URI's relpath as the verified-read boundary names an artifact.

    ``stdout.txt`` / ``stderr.txt`` at the run-dir root are the ``stdout`` /
    ``stderr`` channels; anything under ``out/`` is a derived file named by its
    manifest relpath. Anything else (``manifest.json``, a path outside those two
    shapes) is NOT an artifact of the run and is refused here rather than
    resolved: the manifest is custody metadata, not readable content.
    """
    rel = ref.relpath.strip().replace("\\", "/")
    if rel in ("stdout.txt", "stderr.txt"):
        return rel[: -len(".txt")]
    if rel.startswith("out/"):
        return rel[len("out/") :]
    raise ValueError(
        f"artifact URI {ref.relpath!r} does not name an artifact of run "
        f"{ref.run_id}: expected stdout.txt, stderr.txt or out/<relpath>"
    )


@contextmanager
def _abrir(ref: ArtifactRef) -> Iterator[lectura.Lectura]:
    """Open the referenced artifact through the verified-read boundary, mapping
    its domain errors onto the exception contract ``toolkit.py`` handles."""
    referencia = referencia_de(ref)
    try:
        with lectura.abrir_verificado(
            ref.case_id, ref.run_id, referencia, ambito=lectura.AMBITO_MCP
        ) as leida:
            yield leida
    except (lectura.ArtefactoInexistente, lectura.ArtefactoNoSellado) as exc:
        raise FileNotFoundError(str(exc)) from exc
    # La integridad rota (bytes alterados, manifiesto reescrito, cadena que no
    # verifica) NO se traduce aquí: sube con su tipo. Convertirla en «no
    # encontrado» haría creer que el artefacto no está, cuando el problema es que
    # está y ya no vale. Quien la enmarca con su motivo es el servidor MCP, que
    # captura toda la familia (RA05 c y e).
    except (lectura.ArtefactoFueraDeAmbito, lectura.LocalizadorInvalido) as exc:
        raise ValueError(str(exc)) from exc


def resolve_artifact_path(ref: ArtifactRef) -> Path:
    """Return the absolute, canonical filesystem path of the referenced artifact,
    AFTER the verified-read boundary has cleared it.

    Kept as a named entry point because the boundary check is the interesting
    part to test in isolation. It re-hashes the bytes exactly as
    ``read_artifact`` does, so it is never a cheaper "just resolve the path"
    shortcut that a caller could take to skip the gate.

    Raises:
        KeyError: if the case does not exist.
        FileNotFoundError: if the artifact file does not exist, is not declared
            in the run's manifest, or the run is not sealed yet.
        ValueError: if the URI does not name an artifact of the run, or the
            resolved path escapes the run directory.
        ArtifactIntegrityError: if the bytes no longer match the manifest.
    """
    with _abrir(ref) as leida:
        return leida.ruta


def read_artifact(uri: str) -> list[ReadResourceContents]:
    """Resolve + read an ``artifact://`` URI through the verified-read boundary.

    Returns the SDK's expected ``Iterable[ReadResourceContents]`` so the
    ``@server.read_resource()`` decorator can wrap it into the wire-shape
    ``TextResourceContents`` / ``BlobResourceContents`` itself.

    For files larger than ``MAX_BYTES`` we return the first chunk with a
    ``truncated`` flag in the meta so the client knows there is more. The meta
    also carries the VERIFIED provenance (run, tool, evidence, the SHA-256 the
    bytes were checked against, and whether the manifest is anchored in the
    audit chain): the client is reading evidence-derived bytes and has to be
    able to say what they are and what guarantee they carry.
    """
    ref = parse_artifact_uri(uri)
    with _abrir(ref) as leida:
        raw = leida.bytes_(MAX_BYTES)
        truncated = leida.size > MAX_BYTES
        meta = {
            "truncated": truncated,
            "size_bytes": leida.size,
            "verified": True,
            **leida.procedencia(),
        }
        suffix = leida.ruta.suffix.lower()

    # Decide text vs binary on the first chunk.
    try:
        raw[:_TEXT_PROBE].decode("utf-8")
        # If the probe decoded but the rest fails, fall through to text decode
        # with errors="replace" — the artefact is probably text with a single
        # non-utf8 byte; better to return readable text than blob.
        text = raw.decode("utf-8", errors="replace")
        mime = "text/plain; charset=utf-8"
        if suffix == ".json":
            mime = "application/json"
        elif suffix == ".csv":
            mime = "text/csv"
        return [ReadResourceContents(content=text, mime_type=mime, meta=meta)]
    except UnicodeDecodeError:
        return [
            ReadResourceContents(
                content=raw, mime_type="application/octet-stream", meta=meta
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
    "referencia_de",
    "build_resource_links_for_run",
    "parse_artifact_uri",
    "read_artifact",
    "resolve_artifact_path",
]
