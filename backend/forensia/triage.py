"""Deterministic OS-family + evidence-kind fingerprint over a registered file.

Pre-flight triage that runs at evidence registration (and lazily on first read
for evidence registered before this module existed). NO LLM, NO external tools,
pure Python over the read-only copy already inside the case dir — chain of
custody intact.

The output is a ``DetectedEvidence(family, kind, confidence, signals)`` record
persisted into ``baseline.json``. Consumers:

1. Routing (auto-detección de SO): ``routable_profile`` turns the record into
   the ``os_profile`` a case is DERIVED to route on
   (``CaseManager.apply_detected_evidence`` at registration). Determination is
   from the evidence CONTENT, never the host platform. On ``unknown`` / low
   confidence / conflict it returns ``None`` → the operator must anchor the
   profile — never a silent pick (RULE 2 enmendada).
2. The ``ForensicAgent`` system prompt: receives both family AND kind and
   routes the model to the right section of the playbook ("disk image" vs
   "memory dump") without it having to fail-and-pivot.

Decision tree (cheap headers first, then markers — see panel write-up in the
commit that introduced this):

    Phase 1: fixed-offset HEADERS at byte 0 / 512 / 1024 / 0x438 / 32 — strong
             signal, near-zero false positive risk. LiME / Windows crash dump
             / EWF (.E01) / AFF / VMDK / VDI / QCOW / VHD / VHDX, and the
             STANDALONE-FILE magics of ``_DOCUMENT_MAGICS`` (PDF, PNG, JPEG,
             OOXML, OLE2, SQLite, EVTX, pcap…) → ``kind=document``.
    Phase 2: MBR boot signature 0x55AA at byte 510 (with a sanity check on the
             partition table) + GPT "EFI PART" at byte 512.
    Phase 3: filesystem boot sectors (NTFS, ext2/3/4, HFS+, APFS) — strong
             "disk image" signal.
    Phase 4: memory-dump scoring over the 8 MiB head + 4 MiB middle + 4 MiB
             tail windows: PE scatter (MZ\\x90\\x00, PE\\x00\\x00, RSDS) +
             kernel/loader strings (ntoskrnl, hal.dll, PsLoadedModuleList,
             linux_banner) + first 4 KiB all-zero ("page 0 unmapped").
             Each signal adds to a score; >= 3 → memory.
    Phase 5: extension hint (.mem/.vmem/.lime/.dmp) — last resort only.
    Phase 6: PLAIN TEXT by content (no NUL bytes + decodes clean) — the .txt /
             .log / .csv / .json a examiner supplies, which carry no magic at
             all → ``kind=document``.

Family classification (unix vs windows) uses the same head+mid+tail windows
already loaded for Phase 4, scoring marker byte-strings. The two axes are
independent: a Windows memdump scores ``family=windows, kind=memory``.

``kind=document`` is the ONE exception to that independence, and it is
deliberate: a supplied file is not a system, so there is no OS it was "taken
from" to determine, and its family is always ``unknown``. A PDF report about a
Windows incident is full of Windows strings; scoring them would let a DOCUMENT
set the case ``os_profile`` — and worse, conflict with the profile the real disk
image determines. ``routable_profile`` refuses to route a document a second
time, so a hand-built record cannot get around it either.

Tuning the thresholds is fine; breaking the contract (always returns a record
with ``family ∈ {unix, windows, unknown}`` and ``kind ∈ {disk, memory,
container_disk, document, unknown}``) is not.
"""

from __future__ import annotations

import codecs
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

logger = logging.getLogger(__name__)

DetectedOS = Literal["unix", "windows", "unknown"]
DetectedKind = Literal["disk", "memory", "container_disk", "document", "unknown"]
DetectedConfidence = Literal["header", "markers", "extension", "none"]

# Per-region cap. 8 MiB at head + 4 MiB at middle + 4 MiB at tail covers the
# bootloader/partition table, a chunk of FS structures, and a chunk of
# user/log data without reading multi-GB images in full.
_HEAD_WINDOW = 8 * 1024 * 1024
_MID_WINDOW = 4 * 1024 * 1024
_TAIL_WINDOW = 4 * 1024 * 1024

# Family thresholds (unchanged from the previous design).
_MIN_HITS = 4
_DOMINANCE = 3

# Memory-dump markers — verified empirically on a 5 GiB Windows 7 raw memdump.
# Symbolic kernel struct names ("_EPROCESS", "_KPRCB") are NOT present as
# literal bytes in Volatility-style raw memdumps (they're metadata in PDBs,
# not strings in memory). What IS reliably present:
#
#   - Scattered PE headers: every loaded module / driver / userland binary
#     leaves an "MZ"+ "PE\0\0" pair in physical memory. A disk image has
#     at most one (the bootloader, if any) and the rest are inside files
#     not at page boundaries. Memdumps have dozens scattered.
#   - "RSDS" PDB signatures embedded in loaded PE files' debug directories.
#     A formatted disk has them too, but inside .exe/.dll files; in a memdump
#     they're sprinkled across the physical page space.
#
# We score these AND require the absence of a disk header (MBR/GPT/FS BPB)
# to call "memory" — see ``_classify_kind_from_markers``.
_MEMORY_PE_MARKERS: tuple[bytes, ...] = (
    b"MZ\x90\x00",       # canonical DOS stub prefix (more specific than bare "MZ")
    b"PE\x00\x00",       # NT/PE header (very specific 4-byte signature)
    b"RSDS",             # PDB debug record signature
)

# Kernel/loader strings that, when found together with PE scatter, strengthen
# the "memory" verdict. Still useful — they confirm we're looking at an OS-
# bearing payload (vs. a random file with happens-to-look-like-PE bytes).
_KERNEL_STRINGS: tuple[bytes, ...] = (
    b"ntoskrnl",
    b"ntkrnlmp",
    b"hal.dll",
    b"PsLoadedModuleList",
    b"NT Kernel & System",
    b"linux_banner",
    b"swapper_pg_dir",
    b"vmlinux",
)

# Family markers (windows / unix) — used over the same head/mid/tail windows.
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
    b"Darwin Kernel",
    b"/System/Library/",
    b"/Library/LaunchDaemons",
    b"/Applications/",
    b"Mach-O",
)

# Extensions that strongly suggest memory (last-resort hint, never decisive).
_MEMORY_EXTENSIONS: frozenset[str] = frozenset({
    ".mem", ".vmem", ".lime", ".dmp", ".raw_mem", ".bin_mem",
})

# ── Ficheros SUELTOS aportados al caso (kind=document) ───────────────────────
# Un perito no siempre recibe un disco entero. Recibe también el PDF de un
# contrato, el Word de una carta de despido, la foto que alguien envió, el CSV
# que exportó un sistema o el `.evtx` que le pasó el cliente. Todo eso es
# evidencia: entra por el MISMO hash-gate y la MISMA cadena de custodia; lo que
# cambia es que no hay sistema de ficheros que recorrer ni memoria que perfilar,
# así que TSK y Volatility no aplican y el agente lee el fichero en sí.
#
# La determinación es por CONTENIDO, no por extensión (una foto renombrada a
# `.txt` sigue siendo un JPEG, y es precisamente el tipo de cosa que un
# investigado hace). Cada entrada es ``(offset, magic, signal)``: el offset fijo
# donde la firma tiene que estar, los bytes literales, y el nombre que queda en
# ``signals`` y por tanto en ``baseline.json`` y en el log de auditoría.
#
# BMP, tar y PE quedan FUERA de esta tabla: sus firmas son de 2-5 bytes y chocan
# con datos corrientes, así que se validan aparte con una comprobación de
# estructura (``_looks_like_bmp`` / ``_looks_like_tar`` / ``_looks_like_pe``).
_DOCUMENT_MAGICS: tuple[tuple[int, bytes, str], ...] = (
    # --- Documentos ofimáticos y de texto enriquecido ---
    (0, b"%PDF-", "pdf"),
    (0, b"{\\rtf", "rtf"),
    (0, b"%!PS", "postscript"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2_office"),  # .doc/.xls/.ppt/.msg
    # --- Imágenes ---
    (0, b"\x89PNG\r\n\x1a\n", "png"),
    (0, b"\xff\xd8\xff", "jpeg"),
    (0, b"GIF87a", "gif"),
    (0, b"GIF89a", "gif"),
    (0, b"II*\x00", "tiff"),
    (0, b"MM\x00*", "tiff"),
    (4, b"ftyp", "iso_bmff"),  # HEIC/HEIF, MP4, MOV: la misma caja ISO-BMFF
    # --- Audio y vídeo ---
    (0, b"ID3", "mp3"),
    (0, b"OggS", "ogg"),
    (0, b"fLaC", "flac"),
    (0, b"\x1a\x45\xdf\xa3", "matroska"),  # MKV / WebM
    # --- Empaquetados ---
    (0, b"7z\xbc\xaf\x27\x1c", "7z"),
    (0, b"Rar!\x1a\x07", "rar"),
    (0, b"\x1f\x8b", "gzip"),
    (0, b"BZh", "bzip2"),
    (0, b"\xfd7zXZ\x00", "xz"),
    # --- Artefactos sueltos que un cliente entrega sin el disco ---
    (0, b"SQLite format 3\x00", "sqlite"),
    (0, b"ElfFile\x00", "evtx"),          # log de eventos de Windows
    (0, b"regf", "registry_hive"),        # hive del registro de Windows
    (0, b"FILE0", "mft_record"),          # registro del $MFT extraído
    (0, b"MAM\x04", "prefetch_compressed"),
    (0, b"SCCA", "prefetch"),
    (0, b"\xd4\xc3\xb2\xa1", "pcap"),
    (0, b"\xa1\xb2\xc3\xd4", "pcap"),
    (0, b"\x0a\x0d\x0d\x0a", "pcapng"),
    (0, b"\x7fELF", "elf"),               # binario Linux: la muestra de malware
)

# Contenedores ZIP: OOXML (docx/xlsx/pptx), OpenDocument (odt/ods/odp), JAR, APK
# y el ZIP a secas comparten la firma ``PK\x03\x04``. Qué hay DENTRO se decide
# leyendo el nombre de las primeras entradas del archivo, que el ZIP guarda en
# claro en sus cabeceras locales, al principio del fichero.
_ZIP_MAGIC = b"PK\x03\x04"
_ZIP_PAYLOAD_MARKERS: tuple[tuple[bytes, str], ...] = (
    (b"word/", "ooxml_word"),
    (b"xl/", "ooxml_excel"),
    (b"ppt/", "ooxml_powerpoint"),
    (b"mimetypeapplication/vnd.oasis.opendocument.text", "odf_text"),
    (b"mimetypeapplication/vnd.oasis.opendocument.spreadsheet", "odf_spreadsheet"),
    (b"mimetypeapplication/vnd.oasis.opendocument.presentation", "odf_presentation"),
    (b"AndroidManifest.xml", "apk"),
)
# Cuánto del principio se mira para resolver el contenido de un ZIP y para
# comprobar las firmas de offset fijo. 64 KiB cubre de sobra las cabeceras
# locales de las primeras entradas de un OOXML.
_MAGIC_WINDOW = 64 * 1024

# Muestra que decide si un fichero SIN firma es texto plano (Phase 6). 64 KiB es
# suficiente para descartar binarios y barato para un log de cientos de MB.
_TEXT_SAMPLE = 64 * 1024
# Proporción mínima de bytes imprimibles para llamar «texto» a algo que no
# decodifica como UTF-8 (un log en latin-1, un CSV exportado por Windows).
_TEXT_PRINTABLE_RATIO = 0.95


@dataclass(frozen=True)
class DetectedEvidence:
    """Triage record persisted to ``baseline.json`` and surfaced on the handle.

    ``signals`` is auditable — when a forensic decision is justified by the
    triage classification, the case file should be able to answer "which
    bytes said so". The list is intentionally short (header magics + marker
    counts) so it fits in a JSON record next to the hash.
    """

    family: DetectedOS
    kind: DetectedKind
    confidence: DetectedConfidence
    signals: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "family": self.family,
            "kind": self.kind,
            "confidence": self.confidence,
            "signals": list(self.signals),
        }


def fingerprint_evidence(evidence_path: Path) -> DetectedEvidence:
    """Classify the evidence file at ``evidence_path`` along (family, kind).

    The file is opened ``O_RDONLY`` and never written to. On any I/O failure
    the function returns an all-``unknown`` record rather than raising —
    a missed fingerprint should never block evidence registration.
    """
    if not evidence_path.is_file():
        logger.warning("triage: %s is not a file; reporting unknown", evidence_path)
        return DetectedEvidence("unknown", "unknown", "none", ())

    try:
        size = evidence_path.stat().st_size
    except OSError as exc:
        logger.warning("triage: stat failed on %s: %s", evidence_path, exc)
        return DetectedEvidence("unknown", "unknown", "none", ())

    if size == 0:
        return DetectedEvidence("unknown", "unknown", "none", ())

    signals: list[str] = []

    try:
        with evidence_path.open("rb") as fh:
            # ---- Phase 1 + 2 + 3: HEAD reads for header/MBR/FS classification.
            head = fh.read(min(_HEAD_WINDOW, size))

            # ---- Family from head (we'll re-score over mid/tail too).
            win_hits = _count_markers(head, _WINDOWS_MARKERS)
            unix_hits = _count_markers(head, _UNIX_MARKERS)

            # ---- Phase 1: fixed-offset headers.
            header_kind, header_signal = _classify_header(head[:_MAGIC_WINDOW])
            if header_kind is not None:
                signals.append(header_signal)
                # Un fichero SUELTO no es un sistema, así que no hay familia que
                # determinar: se devuelve `unknown` sin puntuar marcadores. No es
                # renuncia, es lo contrario — el PDF de un informe sobre un
                # incidente de Windows está LLENO de cadenas de Windows, y
                # puntuarlas dejaría que un documento fijase el `os_profile` del
                # caso (y entrase en conflicto con el que determina el disco de
                # verdad). Ver la nota del docstring del módulo.
                if header_kind == "document":
                    return DetectedEvidence(
                        "unknown", "document", "header", tuple(signals)
                    )
                # Family from head markers still has signal even when kind is
                # decided by header — disk images carry OS strings inside.
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
                family = _decide_family(win_hits, unix_hits)
                return DetectedEvidence(family, header_kind, "header", tuple(signals))

            # ---- Phase 2: MBR / GPT.
            if len(head) >= 512 and head[510:512] == b"\x55\xaa" and _mbr_partitions_sane(head[446:510], size):
                signals.append("mbr_55aa")
                _accumulate_family(fh, size, head, win_hits, unix_hits, _WINDOWS_MARKERS, _UNIX_MARKERS)
                # Re-read for accurate counts (cleaner than threading)
                win_hits, unix_hits, _, _ = _scan_all_windows(fh, size, head)
                family = _decide_family(win_hits, unix_hits)
                return DetectedEvidence(family, "disk", "header", tuple(signals))

            if size > 520 and head[512:520] == b"EFI PART":
                signals.append("gpt_efi_part")
                win_hits, unix_hits, _, _ = _scan_all_windows(fh, size, head)
                family = _decide_family(win_hits, unix_hits)
                return DetectedEvidence(family, "disk", "header", tuple(signals))

            # ---- Phase 3: filesystem boot sectors.
            if len(head) >= 11 and head[3:11] == b"NTFS    ":
                signals.append("ntfs_bpb")
                win_hits, unix_hits, _, _ = _scan_all_windows(fh, size, head)
                family = _decide_family(win_hits, unix_hits)
                return DetectedEvidence(family, "disk", "header", tuple(signals))

            if size > 0x43A and head[0x438:0x43A] == b"\x53\xef":
                signals.append("ext_magic")
                win_hits, unix_hits, _, _ = _scan_all_windows(fh, size, head)
                family = _decide_family(win_hits, unix_hits)
                return DetectedEvidence(family, "disk", "header", tuple(signals))

            # ---- Phase 4: PE/PDB scatter + kernel strings → memory dump.
            # If no disk header survived Phase 1-3 and we see many PE headers
            # scattered through the physical-page window, this is a memdump.
            # The first 4 KiB being all zeros also strongly correlates with
            # memdumps (page 0 of physical memory is typically unmapped).
            win_hits, unix_hits, pe_hits, kernel_hits = _scan_all_windows(fh, size, head)
            first4k_zero = head[:4096] == b"\x00" * 4096
            rsds_count = head.count(b"RSDS")

            # ``pe_hits`` from _scan_all_windows is the unique-per-window count
            # over (MZ\x90\x00, PE\x00\x00, RSDS) summed across 3 windows — so
            # the max possible is 9 (3 markers × 3 regions). >= 4 means at
            # least two of those markers showed up in multiple regions, which
            # only happens when PE files are scattered across physical memory
            # pages (i.e. a memory dump) — a disk image keeps PEs inside files
            # so the page boundaries don't preserve the headers.
            memory_score = 0
            if pe_hits >= 4:
                memory_score += 2
                signals.append(f"pe_scatter={pe_hits}")
            if rsds_count >= 2:
                memory_score += 1
                signals.append(f"rsds_pdb={rsds_count}")
            if kernel_hits >= 1:
                memory_score += 1
                signals.append(f"kernel_strings={kernel_hits}")
            if first4k_zero:
                memory_score += 1
                signals.append("page0_zero")

            if memory_score >= 3:
                family = _decide_family(win_hits, unix_hits)
                return DetectedEvidence(family, "memory", "markers", tuple(signals))

            # ---- Phase 5: extension hint (last resort).
            if evidence_path.suffix.lower() in _MEMORY_EXTENSIONS:
                signals.append(f"extension={evidence_path.suffix.lower()}")
                family = _decide_family(win_hits, unix_hits)
                return DetectedEvidence(family, "memory", "extension", tuple(signals))

            # ---- Phase 6: TEXTO PLANO por contenido.
            # Un .txt, un .log, un .csv o un .json no tienen firma ninguna: lo que
            # los identifica es que TODO lo que hay dentro es texto. Va la última
            # porque es la comprobación más débil de las seis, y llega aquí sólo
            # cuando ni el disco ni la memoria dieron señal — un volcado o una
            # imagen están llenos de bytes nulos y no pasan de la primera línea.
            # La familia es `unknown` por lo mismo que en la fase 1: el log de un
            # servidor Linux está lleno de rutas Unix y no por eso el CASO es
            # Unix; la determinación del SO se hace sobre sistemas, no sobre
            # ficheros aportados.
            text_signal = _looks_like_text(head)
            if text_signal is not None:
                signals.append(text_signal)
                return DetectedEvidence(
                    "unknown", "document", "markers", tuple(signals)
                )

            # Family may still resolve even when kind is unknown.
            family = _decide_family(win_hits, unix_hits)
            return DetectedEvidence(family, "unknown", "none" if family == "unknown" else "markers", tuple(signals))

    except OSError as exc:
        logger.warning("triage: read failed on %s: %s", evidence_path, exc)
        return DetectedEvidence("unknown", "unknown", "none", ())


def fingerprint_os(evidence_path: Path) -> DetectedOS:
    """Backward-compat shim for callers that only need the family axis.

    Kept because ``EvidenceManager.get()`` has a lazy-backfill path that was
    written against the old single-return API. New code should call
    ``fingerprint_evidence`` directly and persist both axes.
    """
    return fingerprint_evidence(evidence_path).family


# ---- internals -------------------------------------------------------------


def _classify_header(head4k: bytes) -> tuple[DetectedKind | None, str]:
    """Return (kind, signal_name) for any Phase-1 magic match, else (None, '').

    Los soportes de SISTEMA (volcado de memoria, contenedor de disco) van
    PRIMERO y las firmas de fichero suelto después: un `.E01` empieza por
    ``EVF\\x09`` y un volcado LiME por ``LiME``, ninguno choca con las de abajo,
    pero el orden deja explícito qué manda si algún día una firma nueva
    solapase.
    """
    if len(head4k) < 8:
        return None, ""
    if head4k[:4] == b"LiME":
        return "memory", "lime_header"
    if head4k[:8] in (b"PAGEDUMP", b"PAGEDU64"):
        return "memory", "windows_crash_dump"
    if head4k[:8] == b"EVF\x09\x0d\x0a\xff\x00":
        return "container_disk", "ewf_e01"
    if head4k[:3] == b"AFF" or head4k[:3] == b"AF4":
        return "container_disk", "aff"
    if head4k[:4] == b"KDMV":
        return "container_disk", "vmdk_sparse"
    if head4k[:7] == b"<<< Ora":  # VirtualBox VDI banner starts "<<< Oracle VM ..."
        return "container_disk", "vdi"
    if head4k[:4] == b"QFI\xfb":
        return "container_disk", "qcow"
    if head4k[:8] == b"conectix":
        return "container_disk", "vhd"
    if head4k[:8] == b"vhdxfile":
        return "container_disk", "vhdx"

    document_signal = _classify_document(head4k)
    if document_signal is not None:
        return "document", document_signal
    return None, ""


def _classify_document(head: bytes) -> str | None:
    """Nombre de la firma de FICHERO SUELTO que encaja en ``head``, o ``None``.

    Sólo firmas de offset FIJO (la tabla ``_DOCUMENT_MAGICS``) más los tres
    formatos que necesitan comprobar estructura porque su firma es demasiado
    corta para fiarse de ella (ZIP, BMP, tar, PE). Nunca mira la extensión: una
    foto renombrada a `.txt` sigue siendo un JPEG, y renombrar es justo lo que
    hace quien esconde algo.
    """
    for offset, magic, signal in _DOCUMENT_MAGICS:
        end = offset + len(magic)
        if len(head) >= end and head[offset:end] == magic:
            return signal
    if head[:4] == _ZIP_MAGIC:
        for marker, signal in _ZIP_PAYLOAD_MARKERS:
            if marker in head:
                return signal
        return "zip"
    if head[:4] == b"RIFF" and len(head) >= 12:
        container = head[8:12]
        if container == b"WEBP":
            return "webp"
        if container == b"WAVE":
            return "wav"
        if container == b"AVI ":
            return "avi"
    if _looks_like_bmp(head):
        return "bmp"
    if _looks_like_tar(head):
        return "tar"
    if _looks_like_pe(head):
        return "pe_executable"
    return None


def _looks_like_bmp(head: bytes) -> bool:
    """``BM`` son dos bytes y aparecen en cualquier sitio, así que además se
    comprueba la estructura: un BMP declara su propio tamaño en los bytes 2-6 y
    el offset de los píxeles en los 10-14, y ambos tienen que ser coherentes."""
    if len(head) < 14 or head[:2] != b"BM":
        return False
    declared_size = int.from_bytes(head[2:6], "little")
    pixel_offset = int.from_bytes(head[10:14], "little")
    return 14 <= pixel_offset < declared_size <= 1 << 32


def _looks_like_tar(head: bytes) -> bool:
    """El tar POSIX pone ``ustar`` en el byte 257 de su primera cabecera."""
    return len(head) >= 262 and head[257:262] == b"ustar"


def _looks_like_pe(head: bytes) -> bool:
    """Un ejecutable de Windows: ``MZ`` al principio Y la cabecera ``PE\\0\\0``
    en el offset que el propio ``e_lfanew`` (bytes 60-64) declara.

    Las dos condiciones juntas, porque ``MZ`` suelto son dos bytes corrientes.
    Esto NO estorba a la detección de volcados de memoria: allí lo que puntúa es
    el REPARTO de cabeceras PE por las tres ventanas del fichero (fase 4), no un
    `MZ` en el byte 0, que en un volcado es página cero y suele ir a ceros.
    """
    if len(head) < 64 or head[:2] != b"MZ":
        return False
    e_lfanew = int.from_bytes(head[60:64], "little")
    end = e_lfanew + 4
    return 64 <= e_lfanew and len(head) >= end and head[e_lfanew:end] == b"PE\x00\x00"


def _looks_like_text(head: bytes) -> str | None:
    """``"text_utf8"`` / ``"text_8bit"`` si ``head`` es texto plano, o ``None``.

    Dos pasadas, de más a menos estricta. UTF-8 primero, con un decodificador
    INCREMENTAL: la muestra corta el fichero por un byte cualquiera, y un
    carácter multibyte partido por la mitad no es un fallo de codificación, es el
    final de la muestra. Si no decodifica, se cuenta la proporción de bytes
    imprimibles, que es lo que separa un log en latin-1 de un binario.

    Un byte NUL descarta de entrada: ningún texto plano los lleva y todos los
    soportes binarios (volcado, imagen de disco, contenedor) están llenos.
    """
    sample = head[:_TEXT_SAMPLE]
    if not sample or b"\x00" in sample:
        return None
    decoder = codecs.getincrementaldecoder("utf-8")()
    try:
        decoder.decode(sample, False)
    except UnicodeDecodeError:
        pass
    else:
        return "text_utf8"
    printable = sum(
        1 for byte in sample if 32 <= byte < 127 or byte in (9, 10, 13) or byte >= 160
    )
    if printable / len(sample) >= _TEXT_PRINTABLE_RATIO:
        return "text_8bit"
    return None


def _mbr_partitions_sane(part_table: bytes, file_size: int) -> bool:
    """Validate that an MBR partition table has at least one entry with a
    non-zero type and an LBA inside the file. Defends against an accidental
    0x55AA at the tail of a memdump that isn't really a boot sector.
    """
    if len(part_table) < 64:
        return False
    max_lba = file_size // 512
    for i in range(4):
        entry = part_table[i * 16 : (i + 1) * 16]
        ptype = entry[4]
        if ptype == 0x00:
            continue
        # LBA of first absolute sector — little-endian u32 at offset 8.
        first_lba = int.from_bytes(entry[8:12], "little")
        sectors = int.from_bytes(entry[12:16], "little")
        if first_lba > 0 and sectors > 0 and (first_lba + sectors) <= max_lba * 2:
            # Allow some slack (× 2) for images smaller than declared.
            return True
    return False


def _count_markers(buf: bytes, markers: tuple[bytes, ...]) -> int:
    return sum(1 for m in markers if m in buf)


def _decide_family(win_hits: int, unix_hits: int) -> DetectedOS:
    # A family is only called when its markers both clear ``_MIN_HITS`` AND
    # dominate the other side by ``_DOMINANCE``×. That dominance requirement is
    # deliberately also the CONFLICT guard: when both sides score high (a
    # dual-boot image, or evidence seeded with foreign OS strings — SECURITY
    # INVARIANTS: a suspect can plant NTFS + ext markers to induce a wrong
    # route) neither dominates, so we fall through to ``unknown``. ``unknown``
    # is what ``routable_profile`` treats as "not auto-routable → escalate to
    # the operator" (RULE 2 enmendada: never a silent pick on a near-tie). No
    # extra magic threshold is introduced — the existing dominance ratio already
    # encodes "close call ⇒ unknown".
    if win_hits >= _MIN_HITS and win_hits >= _DOMINANCE * max(unix_hits, 1):
        return "windows"
    if unix_hits >= _MIN_HITS and unix_hits >= _DOMINANCE * max(win_hits, 1):
        return "unix"
    return "unknown"


# Confidence levels strong enough to auto-route on: a fixed-offset format/FS
# HEADER, or in-image MARKER counts. A bare extension hint ("extension") or no
# signal at all ("none") is NOT enough — those escalate to the operator.
_ROUTABLE_CONFIDENCE: frozenset[DetectedConfidence] = frozenset({"header", "markers"})


def routable_profile(detected: DetectedEvidence) -> DetectedOS | None:
    """Return the ``os_profile`` this evidence can be auto-routed to, or ``None``
    when the determination is not trustworthy enough to route on its own.

    Routable ⇔ a concrete family (``unix``/``windows``) determined from strong
    CONTENT signals (a filesystem/container HEADER or in-image MARKER counts) —
    never from the host platform, never from a bare extension. ``unknown``
    (which also subsumes the conflict / near-tie case, see ``_decide_family``)
    and low-confidence families return ``None`` → the orchestrator must escalate
    to the operator, who anchors the profile manually (RULE 2 enmendada: fail
    loud in ambiguity, never a silent pick).

    This is the SINGLE source of truth for "can we auto-route this evidence?".
    The auto-set / conflict bookkeeping (``CaseManager.apply_detected_evidence``)
    and every routing caller build on it — none re-derive the predicate.

    ``kind=document`` NUNCA enruta. Un fichero aportado (un PDF, un Word, una
    foto, un log) no es el sistema investigado: es material sobre él. Su
    contenido puede nombrar un sistema operativo de mil maneras sin que eso
    determine nada, así que el perfil del caso lo fijan las imágenes y los
    volcados, o lo ancla el operador. ``fingerprint_evidence`` ya devuelve
    ``family=unknown`` para un documento y con eso bastaría; la comprobación de
    aquí es la que hace que siga siendo verdad si alguien construye el registro a
    mano (un test, una migración, un backfill).
    """
    if detected.kind == "document":
        return None
    if detected.family in ("unix", "windows") and detected.confidence in _ROUTABLE_CONFIDENCE:
        return detected.family
    return None


def _accumulate_family(*_args, **_kwargs) -> None:
    """No-op placeholder kept so the read paths above stay symmetric; the real
    scoring uses ``_scan_all_windows``."""
    return None


def _scan_all_windows(
    fh, size: int, head: bytes,
) -> tuple[int, int, int, int]:
    """Score family + PE scatter + kernel strings over head + middle + tail.

    Returns ``(windows_hits, unix_hits, pe_scatter_hits, kernel_string_hits)``.
    ``head`` is passed in already-read to avoid a duplicate read. The middle
    and tail windows are only read when the file is large enough. PE scatter
    counts the unique markers in ``_MEMORY_PE_MARKERS`` per window (a window
    where MZ, PE\\0\\0 and RSDS all appear scores 3 — capturing breadth, not
    raw frequency, which avoids over-weighting a single binary that happens
    to have many ``RSDS`` records).
    """
    win = _count_markers(head, _WINDOWS_MARKERS)
    unx = _count_markers(head, _UNIX_MARKERS)
    pe = _count_markers(head, _MEMORY_PE_MARKERS)
    ker = _count_markers(head, _KERNEL_STRINGS)

    if size > _HEAD_WINDOW + _MID_WINDOW:
        fh.seek(max(0, size // 2 - _MID_WINDOW // 2))
        mid = fh.read(_MID_WINDOW)
        win += _count_markers(mid, _WINDOWS_MARKERS)
        unx += _count_markers(mid, _UNIX_MARKERS)
        pe += _count_markers(mid, _MEMORY_PE_MARKERS)
        ker += _count_markers(mid, _KERNEL_STRINGS)

    if size > _HEAD_WINDOW + _TAIL_WINDOW:
        fh.seek(max(0, size - _TAIL_WINDOW))
        tail = fh.read(_TAIL_WINDOW)
        win += _count_markers(tail, _WINDOWS_MARKERS)
        unx += _count_markers(tail, _UNIX_MARKERS)
        pe += _count_markers(tail, _MEMORY_PE_MARKERS)
        ker += _count_markers(tail, _KERNEL_STRINGS)

    return win, unx, pe, ker


__all__ = [
    "DetectedEvidence",
    "DetectedOS",
    "DetectedKind",
    "DetectedConfidence",
    "fingerprint_evidence",
    "fingerprint_os",
    "routable_profile",
]
