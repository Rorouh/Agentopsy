"""Deep OS triage — determine the OS family of a CONTAINER image by reading its disk.

``forensia.triage`` (the shallow pass) is pure Python over the bytes of the file
that was registered. That is enough for a ``.raw`` / ``.dd``: the OS markers
(``\\Windows\\System32``, ``/etc/passwd``) sit there in the clear and the marker
scan finds them. It is NOT enough for a **container**: an EWF ``.E01``, a
``.vmdk``, a ``.qcow2``, a ``.vhd(x)`` or a ``.vdi`` stores the disk chunked and
usually compressed, so the marker scan sees compressed noise, ``family`` comes
back ``unknown``, and the case is left without an ``os_profile`` — which used to
mean asking the examiner "which OS is this?", a question the tool is supposed to
answer for them.

This pass closes that gap **without stepping outside the architecture**:

    api → the maletín's exec-agent → ``ewfmount`` / ``qemu-storage-daemon``
    (FUSE, READ-ONLY, BLOCK level — the evidence filesystem is never mounted,
    FORENSIC INVARIANT 3) → TSK ``mmls`` + ``fls`` over the raw block.

What it reads is the **root directory of every filesystem in the image**.
``Windows/``, ``Program Files/``, ``$MFT`` is Windows; ``etc/``, ``usr/``,
``var/``, ``bin/`` is Unix. That is the same determination a examiner makes by
hand, it is deterministic, and the concrete entries that justify it are recorded
in ``signals`` and in the case's hash-chained audit log (INVARIANT 4).

**RULE 2 holds, and this is not a fallback.**

- It runs ONLY when the shallow pass could not route (``routable_profile`` is
  ``None``) and the evidence is a disk-shaped one. A routable evidence is left
  exactly as it was.
- The verdict is still a CONTENT determination: partition table + root
  directories of the actual image, never the host platform, never the extension.
- Ambiguity still escalates. Two OSs in one image (a dual-boot, or evidence
  seeded with foreign directory names by a suspect — SECURITY INVARIANTS) means
  neither side dominates, the family stays ``unknown``, and the operator
  anchors.
- A maletín that is down, an ``ewfmount`` that is missing, an image TSK cannot
  open: all of them leave the record UNCHANGED (still ``unknown``) with the
  reason logged. They never produce a guessed profile.

**Venue.** The probe runs in ``DEEP_TRIAGE_VENUE`` — a DECLARED constant, not a
pick. ``mmls``, ``fls``, ``ewfmount`` and ``qemu-storage-daemon`` all live in the
stage both maletín images share, and this determination happens *before* any
``os_profile`` exists, so it cannot be routed by profile the way a tool run is.
Declaring the venue is what keeps it honest: if that maletín is unreachable the
result is "not determined", and the other maletín is NEVER tried instead (RULE 2
— no cross-maletín fallback).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

from forensia.toolkit import maletin
from forensia.toolkit.wrappers import tsk_fls, tsk_mmls
from forensia.triage import DetectedEvidence, routable_profile

logger = logging.getLogger(__name__)

# The maletín this probe runs in. See the module docstring: a declared policy, not
# a fallback — the profile it would be routed by is precisely what we are trying
# to determine.
DEEP_TRIAGE_VENUE = maletin.TOOLKIT_UNIX

# Evidence shapes worth opening. A memory dump has no partition table and no
# filesystem: TSK would fail on every call and the extra round-trips buy nothing
# (the shallow pass already scored its kernel strings). ``unknown`` kind means we
# could not even name the container format, so there is nothing to de-encapsulate.
_DEEP_KINDS: frozenset[str] = frozenset({"disk", "container_disk"})

# EWF segment extensions (``.E01`` / ``.Ex01`` and their continuations). Mirrors
# ``dispatcher._EWF_SUFFIX_RE`` — the maletín exposes these through ``ewfmount``.
_EWF_SUFFIX_RE = re.compile(r"^\.ex?\d{2}$", re.IGNORECASE)

# Container extension → qemu block-driver name. Mirrors
# ``dispatcher._QEMU_CONTAINER_FORMATS`` (``vpc`` is VHD/conectix). A raw image is
# not a container and maps to nothing — it is read directly.
_QEMU_CONTAINER_FORMATS: dict[str, str] = {
    ".vmdk": "vmdk",
    ".vdi": "vdi",
    ".qcow2": "qcow2",
    ".qcow": "qcow2",
    ".vhd": "vpc",
    ".vhdx": "vhdx",
}

# Wall-clock ceiling per probe call inside the maletín. ``mmls`` is instant;
# ``fls`` on a partition root reads a handful of directory blocks. The de-encapsulation
# (ewfmount / qemu FUSE export) is what can be slow on a big set, and the exec-agent
# caps it on its own side too.
_PROBE_TIMEOUT_S = 300

# How many partitions to open. A real disk has a handful; the cap stops a corrupt
# or hostile partition table from turning triage into hundreds of exec calls.
_MAX_PARTITIONS = 8

# A real partition row in ``mmls`` output carries a ``NNN:NNN`` slot in the meta
# column. ``Meta`` (the table itself) and ``-------`` (unallocated) are not
# filesystems and are skipped — TSK would fail on them by definition.
_PARTITION_SLOT_RE = re.compile(r"^\d{3}:\d{3}$")

# Root-directory names that identify the OS. Both sets are DISCRIMINATIVE on
# purpose: ``Users`` is deliberately in neither (Windows and macOS both have it),
# and ``$OrphanFiles`` is excluded because TSK synthesizes it on ext too — it says
# nothing about the OS. Compared case-insensitively (NTFS is case-preserving).
_ROOT_WINDOWS: frozenset[str] = frozenset({
    "windows", "winnt", "program files", "program files (x86)", "programdata",
    "documents and settings", "$recycle.bin", "recycler", "perflogs", "msocache",
    "pagefile.sys", "hiberfil.sys", "swapfile.sys", "bootmgr", "ntldr",
    "boot.ini", "ntdetect.com", "bootsect.bak", "autoexec.bat", "config.sys",
    # NTFS metafiles — present in the root of every NTFS volume.
    "$mft", "$mftmirr", "$logfile", "$volume", "$attrdef", "$bitmap", "$boot",
    "$badclus", "$secure", "$upcase", "$extend",
})

_ROOT_UNIX: frozenset[str] = frozenset({
    # Linux / *BSD FHS
    "etc", "usr", "var", "bin", "sbin", "lib", "lib32", "lib64", "libx32",
    "opt", "srv", "proc", "sys", "dev", "mnt", "media", "root", "run", "boot",
    "home", "tmp", "vmlinuz", "initrd.img", "lost+found",
    # macOS
    "applications", "library", "system", "private", "volumes", "cores",
    ".ds_store", ".vol", "network",
})

# Same shape as ``forensia.triage._decide_family``: a side must clear ``_MIN_HITS``
# distinct markers AND dominate the other by ``_DOMINANCE``×. The dominance rule IS
# the conflict guard — on a dual-boot image, or one seeded with foreign directory
# names, neither side dominates and the family stays ``unknown`` → escalate.
_MIN_HITS = 3
_DOMINANCE = 3


class DeepTriageUnavailable(RuntimeError):
    """The deep probe could not run (maletín unreachable / not configured, the
    de-encapsulation dependency missing, or the image unreadable by TSK).

    Never a verdict — the caller keeps the shallow record untouched and routing
    stays unresolved until the operator anchors (RULE 2)."""


@dataclass(frozen=True)
class DeepTriageRun:
    """One literal command the probe executed, for the audit log (INVARIANT 4)."""

    argv: list[str]
    exit_code: int

    def to_dict(self) -> dict:
        return {"argv": list(self.argv), "exit": self.exit_code}


@dataclass(frozen=True)
class DeepTriageResult:
    """Outcome of the deep probe: the family it determined (possibly ``unknown``),
    the root entries that justify it, and every command that was run."""

    family: str
    signals: tuple[str, ...]
    runs: tuple[DeepTriageRun, ...]
    venue: str


def _container_mode(image_path: str) -> tuple[str | None, str | None]:
    """``(ewf_image, qemu_format)`` for ``image_path`` — at most one is set.

    A raw image is neither: it is read directly, with no de-encapsulation.
    """
    dot = image_path.rfind(".")
    suffix = image_path[dot:].lower() if dot != -1 else ""
    if _EWF_SUFFIX_RE.match(suffix):
        return image_path, None
    return None, _QEMU_CONTAINER_FORMATS.get(suffix)


def _run(
    argv_tail: list[str], binary: str, image_path: str, *, venue: str
) -> tuple[int, str, list[str]]:
    """Run ``[binary, *argv_tail]`` in the maletín, de-encapsulating ``image_path``
    when it is a container. Returns ``(exit, stdout, literal_argv)``."""
    ewf_image, qemu_format = _container_mode(image_path)
    argv = [binary, *argv_tail]
    exit_code, stdout, _stderr = maletin.run_argv_in_maletin(
        venue,
        argv,
        timeout=_PROBE_TIMEOUT_S,
        ewf_image=ewf_image,
        qemu_image=image_path if qemu_format else None,
        qemu_format=qemu_format,
    )
    return exit_code, stdout, argv


def _partition_offsets(stdout: str) -> list[int]:
    """Start sectors of the real filesystem partitions in ``mmls`` output."""
    parsed = tsk_mmls.parse(stdout)
    offsets = [
        int(part["start_sector"])
        for part in parsed.get("partitions", [])
        if _PARTITION_SLOT_RE.match(str(part.get("meta", "")))
    ]
    return offsets[:_MAX_PARTITIONS]


def _root_names(stdout: str) -> list[str]:
    """Root-directory entry names from ``fls`` output, lowercased."""
    parsed = tsk_fls.parse(stdout)
    if parsed.get("format") != "list":
        return []
    return [str(e["name"]).strip().lower() for e in parsed.get("entries", [])]


def _decide_family(win_hits: int, unix_hits: int) -> str:
    """Same rule as the shallow pass: clear the floor AND dominate, or ``unknown``."""
    if win_hits >= _MIN_HITS and win_hits >= _DOMINANCE * max(unix_hits, 1):
        return "windows"
    if unix_hits >= _MIN_HITS and unix_hits >= _DOMINANCE * max(win_hits, 1):
        return "unix"
    return "unknown"


def probe_image(image_path: str, *, venue: str = DEEP_TRIAGE_VENUE) -> DeepTriageResult:
    """Determine the OS family of the disk image at ``image_path`` (a path as the
    maletín sees it — api and maletines mount the same ``/cases``).

    Procedure, and why each step is a determination rather than a retry:

    1. ``mmls`` maps the partition table. A **non-zero exit is its verdict**, not a
       failure we paper over: "Cannot determine partition type" means the image is
       a bare filesystem with no partition map (a container rootfs, a dumped
       partition — see ``docs/bugs/001``), and the correct next step is to read the
       filesystem at offset 0. Both branches are the same procedure — *enumerate
       the filesystems in this image* — and neither invents anything: if the image
       is unreadable, step 2 finds nothing and the family stays ``unknown``.
    2. ``fls`` lists the ROOT of each filesystem found. A partition that is not a
       readable filesystem (swap, recovery, an empty EFI slot) contributes no
       names; that is information about that partition, not a masked error.
    3. The collected names are scored. Floor + dominance, exactly as the shallow
       pass — a tie escalates.

    Raises ``DeepTriageUnavailable`` when the channel itself could not be used.
    """
    runs: list[DeepTriageRun] = []

    try:
        mmls_exit, mmls_out, mmls_argv = _run(
            tsk_mmls.build_argv({"image_path": image_path}), "mmls", image_path, venue=venue
        )
    except maletin.MaletinExecError as exc:
        raise DeepTriageUnavailable(
            f"el triage profundo no pudo ejecutar 'mmls' en {venue}: {exc}"
        ) from exc
    runs.append(DeepTriageRun(mmls_argv, mmls_exit))

    # ``None`` = read the filesystem at offset 0 (no partition map).
    offsets: list[int | None]
    if mmls_exit == 0:
        found = _partition_offsets(mmls_out)
        offsets = list(found) if found else [None]
    else:
        offsets = [None]

    win_hits: set[str] = set()
    unix_hits: set[str] = set()
    signals: list[str] = []

    for offset in offsets:
        params: dict[str, object] = {"image_path": image_path}
        if offset is not None:
            params["partition_offset"] = offset
        try:
            fls_exit, fls_out, fls_argv = _run(
                tsk_fls.build_argv(params), "fls", image_path, venue=venue
            )
        except maletin.MaletinExecError as exc:
            raise DeepTriageUnavailable(
                f"el triage profundo no pudo ejecutar 'fls' en {venue}: {exc}"
            ) from exc
        runs.append(DeepTriageRun(fls_argv, fls_exit))
        if fls_exit != 0:
            continue
        names = set(_root_names(fls_out))
        win = names & _ROOT_WINDOWS
        unix = names & _ROOT_UNIX
        win_hits |= win
        unix_hits |= unix
        if win or unix:
            where = "fs" if offset is None else f"off={offset}"
            for name in sorted(win | unix):
                signals.append(f"root[{where}]={name}")

    family = _decide_family(len(win_hits), len(unix_hits))
    signals.insert(0, f"deep:win={len(win_hits)} unix={len(unix_hits)}")
    return DeepTriageResult(
        family=family, signals=tuple(signals), runs=tuple(runs), venue=venue
    )


def deepen(
    shallow: DetectedEvidence,
    image_path: Path | str,
    *,
    venue: str = DEEP_TRIAGE_VENUE,
) -> tuple[DetectedEvidence, DeepTriageResult | None, str | None]:
    """Enrich ``shallow`` with a deep determination when — and only when — it is
    needed. Returns ``(record, run_detail, reason)``.

    - Already routable, or not a disk-shaped evidence → ``(shallow, None, None)``.
      Nothing is executed; the record is returned untouched.
    - Probe determined a family → a NEW record with that family, ``confidence``
      pinned to ``"markers"`` (the same tier the shallow content scan earns —
      ``routable_profile`` accepts it) and the shallow signals plus the deep ones.
    - Probe ran but stayed ``unknown`` (a tie, or nothing readable) → the shallow
      record with the deep signals appended, so the audit shows what was looked at.
      Routing stays unresolved; the operator anchors.
    - Probe could not run → ``(shallow, None, reason)``. Never a guess.
    """
    if routable_profile(shallow) is not None:
        return shallow, None, None
    if shallow.kind not in _DEEP_KINDS:
        return shallow, None, None

    try:
        result = probe_image(str(image_path), venue=venue)
    except DeepTriageUnavailable as exc:
        logger.info("deep triage skipped for %s: %s", image_path, exc)
        return shallow, None, str(exc)

    signals = (*shallow.signals, *result.signals)
    if result.family in ("unix", "windows"):
        return (
            DetectedEvidence(
                family=result.family,  # type: ignore[arg-type]
                kind=shallow.kind,
                confidence="markers",
                signals=signals,
            ),
            result,
            None,
        )
    return (
        DetectedEvidence(
            family=shallow.family,
            kind=shallow.kind,
            confidence=shallow.confidence,
            signals=signals,
        ),
        result,
        None,
    )


__all__ = [
    "DEEP_TRIAGE_VENUE",
    "DeepTriageResult",
    "DeepTriageRun",
    "DeepTriageUnavailable",
    "deepen",
    "probe_image",
]
