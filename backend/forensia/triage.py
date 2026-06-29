"""Deterministic OS fingerprint over a registered evidence file.

Pre-flight triage that runs at evidence registration (and lazily on first read
for evidence registered before this module existed). NO LLM, NO external tools,
pure Python over the read-only copy already inside the case dir — chain of
custody intact.

The output (``unix`` | ``windows`` | ``unknown``) is persisted into
``baseline.json`` as ``detected_os`` and surfaced via the evidence handle so:

1. The UI can warn when ``case.os_profile != evidence.detected_os`` (a banner
   asking the operator to reopen the case with the right profile). It NEVER
   auto-switches — that would break CLAUDE.md RULE 2.
2. The ``ForensicAgent`` system prompt receives the value as part of the case
   context, so the model can refuse to invoke tools when the profile and the
   evidence disagree (the «guard rail de perfil» rule in
   ``agentes/forensia-*/prompts/system.md``).

Method: scan a bounded byte window (head + middle + tail of the file, capped
per region) looking for marker byte strings characteristic of each OS family,
tally hits and pick a winner when one family clearly dominates. Ambiguous /
weak signals → ``unknown``. The numbers (window sizes, hit thresholds) are
calibrated for typical disk and memory images; tuning them later is fine,
breaking the contract (always returns one of the three literals) is not.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal

logger = logging.getLogger(__name__)

DetectedOS = Literal["unix", "windows", "unknown"]

# Per-region cap. 8 MiB at head + 4 MiB at middle + 4 MiB at tail covers the
# bootloader/partition table, a chunk of FS structures, and a chunk of
# user/log data without reading multi-GB images in full.
_HEAD_WINDOW = 8 * 1024 * 1024
_MID_WINDOW = 4 * 1024 * 1024
_TAIL_WINDOW = 4 * 1024 * 1024

# Hit thresholds. A profile wins when (a) it has at least MIN_HITS markers and
# (b) it has at least DOMINANCE× the hits of the other profile. Anything else
# (zero hits both, both fire similarly, weak total) → unknown.
_MIN_HITS = 4
_DOMINANCE = 3

# Marker byte strings. Kept conservative on purpose: false positives in either
# direction would surface as a wrong banner / wrong refusal.
#
# Windows markers: bootloader, kernel build strings, paths that only appear on
# NTFS/Windows installs, registry hive names.
_WINDOWS_MARKERS: tuple[bytes, ...] = (
    b"Microsoft Windows",
    b"Windows NT",
    b"BOOTMGR",
    b"NTLDR",
    b"\\Windows\\System32",
    b"\\WINDOWS\\system32",
    b"\\Windows\\system32",
    b"\\Program Files",
    b"AppData\\Roaming",
    b"NTUSER.DAT",
    b"SOFTWARE\\Microsoft",
    b"SYSTEM\\CurrentControlSet",
    b"\\Users\\Default",
    b"win7sp1",
    b"win10",
    b"win11",
    b"amd64fre.win",
)

# Unix markers cover both Linux and macOS — they share the os_profile=unix
# bucket per CLAUDE.md. Conservative set to avoid matching Windows strings
# that happen to contain `/etc/` etc.
_UNIX_MARKERS: tuple[bytes, ...] = (
    b"Linux version",
    b"GNU/Linux",
    b"/etc/passwd",
    b"/etc/shadow",
    b"/etc/fstab",
    b"/bin/bash",
    b"/usr/bin/",
    b"/usr/sbin/",
    b"/var/log/syslog",
    b"/var/log/auth.log",
    b"/lib/x86_64-linux-gnu",
    b"/lib/systemd/",
    b"/sbin/init",
    # macOS
    b"Darwin Kernel",
    b"/System/Library/",
    b"/Library/LaunchDaemons",
    b"/Applications/",
    b"Mach-O",
)


def fingerprint_os(evidence_path: Path) -> DetectedOS:
    """Read bounded regions of ``evidence_path`` and return the detected OS.

    The file is opened ``O_RDONLY`` and never written to. On any I/O failure
    the function returns ``"unknown"`` rather than raising — a missed
    fingerprint should never block evidence registration.
    """
    if not evidence_path.is_file():
        logger.warning("triage: %s is not a file; reporting unknown", evidence_path)
        return "unknown"

    try:
        size = evidence_path.stat().st_size
    except OSError as exc:
        logger.warning("triage: stat failed on %s: %s", evidence_path, exc)
        return "unknown"

    if size == 0:
        return "unknown"

    win_hits = 0
    unix_hits = 0

    try:
        with evidence_path.open("rb") as fh:
            head = fh.read(min(_HEAD_WINDOW, size))
            win_hits += _count_markers(head, _WINDOWS_MARKERS)
            unix_hits += _count_markers(head, _UNIX_MARKERS)

            if size > _HEAD_WINDOW + _MID_WINDOW:
                fh.seek(max(0, size // 2 - _MID_WINDOW // 2))
                mid = fh.read(_MID_WINDOW)
                win_hits += _count_markers(mid, _WINDOWS_MARKERS)
                unix_hits += _count_markers(mid, _UNIX_MARKERS)

            if size > _HEAD_WINDOW + _TAIL_WINDOW:
                fh.seek(max(0, size - _TAIL_WINDOW))
                tail = fh.read(_TAIL_WINDOW)
                win_hits += _count_markers(tail, _WINDOWS_MARKERS)
                unix_hits += _count_markers(tail, _UNIX_MARKERS)
    except OSError as exc:
        logger.warning("triage: read failed on %s: %s", evidence_path, exc)
        return "unknown"

    logger.info(
        "triage: %s → windows_hits=%d unix_hits=%d",
        evidence_path.name, win_hits, unix_hits,
    )

    return _decide(win_hits, unix_hits)


def _count_markers(buf: bytes, markers: tuple[bytes, ...]) -> int:
    return sum(1 for m in markers if m in buf)


def _decide(win_hits: int, unix_hits: int) -> DetectedOS:
    if win_hits >= _MIN_HITS and win_hits >= _DOMINANCE * max(unix_hits, 1):
        return "windows"
    if unix_hits >= _MIN_HITS and unix_hits >= _DOMINANCE * max(win_hits, 1):
        return "unix"
    return "unknown"


__all__ = ["fingerprint_os", "DetectedOS"]
