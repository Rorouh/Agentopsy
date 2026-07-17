"""aff4imager wrapper — list/extract streams from an AFF4 volume.

Runs `aff4imager` (Velocidex c-aff4 1.0.rc1, in the `base` stage of BOTH
maletines) via the exec-agent. FORENSIA is post-mortem: WinPmem itself (live
RAM acquisition, a Windows kernel driver) never ships here — this tool
consumes its OUTPUT: the `.aff4` volume the perito acquired arrives as
evidence, its streams get listed, and the chosen stream (e.g. the physical
memory image) is exported into the run's output directory so `volatility3`
can consume it as a derived artifact (`{run_id, relpath}`).

Two explicit modes (RULE 2 — the agent never guesses a stream):
- no `stream` param  -> `-l <volume>`: list the stream URNs (inline).
- `stream` = full `aff4://…` URN from a previous listing -> `-e <urn> -D
  <output_dir> <volume>`: export it under the run's `out/` (the binary nests
  the file as `<volume-uuid>/<stream-path>`).
"""

from __future__ import annotations

from typing import Any

ALLOWED_FLAGS = frozenset({"-l", "-e", "-D"})


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for aff4imager.

    params:
        image_path (str, required): path to the `.aff4` volume (the evidence),
            under the maletín's read-only `/evidence` mount.
        output_dir (str, required): run output directory (`-D` in export mode;
            unused when listing).
        stream (str, optional): FULL stream URN (`aff4://…`) exactly as printed
            by a previous listing run. Omit to list the volume's streams.
    """
    image_path = params.get("image_path")
    if not image_path or not isinstance(image_path, str):
        raise ValueError("aff4imager requires params.image_path: str")
    output_dir = params.get("output_dir")
    if not output_dir or not isinstance(output_dir, str):
        raise ValueError("aff4imager requires params.output_dir: str")

    stream = params.get("stream")
    if stream is None:
        return ["-l", image_path]
    if not isinstance(stream, str) or not stream.startswith("aff4://"):
        raise ValueError(
            "aff4imager params.stream must be a full 'aff4://…' stream URN "
            "exactly as printed by a previous listing run (call without "
            "params.stream first to list the volume's streams)"
        )
    return ["-e", stream, "-D", output_dir, image_path]


def parse(stdout: str) -> dict[str, Any]:
    """Listing prints one `aff4://…` URN per line; other runs print sparse
    `Key: value` log lines. Surface both shapes."""
    streams: list[str] = []
    summary: dict[str, str] = {}
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("aff4://"):
            streams.append(line)
            continue
        if ":" in line and not line.endswith(":"):
            key, _, value = line.partition(":")
            key = key.strip().lower().replace(" ", "_").replace("-", "_")
            value = value.strip()
            if key and value and len(key) <= 64:
                summary[key] = value
    return {"streams": streams, "stream_count": len(streams), "summary": summary}
