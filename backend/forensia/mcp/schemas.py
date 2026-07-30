"""Pydantic input schemas for every forensic tool published via MCP.

D4 of mcp-toolkit-s1.md: each ``Tool`` in the catalog has a tightly-typed
schema that becomes its MCP ``inputSchema``. The schema enforces the L2 line:
**no raw paths to evidence are accepted as parameters**. Path-bearing fields
are:

- Evidence paths (image_path / dump_path / evtx_path / mft_path / target_path /
  target_dir / evtx_dir): EXCLUDED from the schema. The MCP server injects them
  from the session's selected evidence through the catalog-declared shared path
  policy. A path role that also accepts DERIVED_INPUT may expose only the shared
  ArtifactRef contract, never a free evidence path.
- ``output_dir``: EXCLUDED — injected by the dispatcher from ArtifactStore.
- Auxiliary paths that are NOT evidence (YARA ``rules_path``, jq ``input_path``,
  Chainsaw ``sigma_dir`` / ``rules_dir``) remain typed here, while the shared catalog
  path policy confines them to the active case. The dispatcher repeats that gate for
  every caller, including direct calls.

We keep the schemas under ``forensia.mcp.schemas`` (a sibling of the
catalog) so the catalog stays usable by the existing dispatcher tests that
never touched MCP.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from forensia.artifact_ref import ArtifactRef


class _StrictModel(BaseModel):
    """Common base: reject unknown fields (RULE L2).

    Without ``extra='forbid'`` a malicious or careless caller could pass
    ``{'image_path': '/etc/passwd', ...}`` and Pydantic would silently drop
    it. The shared evidence-injection policy would still
    set the right path, but the request would not have failed loud — and
    RULE 2 demands fail-loud over fail-quiet. Forbid extras and we get an
    explicit ``ValidationError`` the moment someone tries it.
    """

    model_config = ConfigDict(extra="forbid")


# ============================================================================
# 12 SIMPLE TOOLS
# ============================================================================


class FileInfoParams(_StrictModel):
    """``file`` — identify the file format / MIME type of the evidence.

    The evidence path is injected from the session; the operator can choose to
    also emit MIME information via ``also_mime``.
    """

    also_mime: bool = Field(
        default=False,
        description="If true, run with --mime to also report the MIME type.",
    )


class XxdHeadParams(_StrictModel):
    """``xxd`` — hex-dump the first bytes of the evidence."""

    bytes: int = Field(
        default=512,
        ge=1,
        le=16384,
        description="Number of bytes to dump from the start of the evidence (1..16384).",
    )
    skip: int = Field(
        default=0, ge=0, description="Byte offset where to start the dump."
    )
    cols: int = Field(
        default=16,
        ge=1,
        le=256,
        description="Bytes per row in the hex dump (1..256).",
    )


class StringsHeadParams(_StrictModel):
    """``strings`` — extract printable strings near the start of the evidence."""

    min_len: int = Field(
        default=12,
        ge=1,
        le=256,
        description="Minimum length of a string to report (1..256).",
    )
    radix: Optional[Literal["d", "o", "x"]] = Field(
        default=None,
        description="Radix for the byte offset prefix (decimal, octal, hex).",
    )


class TskMmlsParams(_StrictModel):
    """``mmls`` — list partitions of a disk image. Evidence path is injected."""

    type: Optional[Literal["dos", "gpt", "mac", "bsd", "sun"]] = Field(
        default=None,
        description="Partition-table type. Omit to let mmls auto-detect.",
    )
    image_format: Optional[Literal["raw", "ewf", "aff", "vmdk", "vhd"]] = Field(
        default=None,
        description="Container format of the image. Omit to auto-detect.",
    )


class TskFlsParams(_StrictModel):
    """``fls`` — walk the filesystem tree of a partition."""

    partition_offset: Optional[int] = Field(
        default=None,
        ge=0,
        description="Partition start offset in sectors (from `tsk_mmls`).",
    )
    filesystem: Optional[
        Literal[
            "ntfs",
            "fat",
            "fat12",
            "fat16",
            "fat32",
            "ext2",
            "ext3",
            "ext4",
            "hfs",
            "iso9660",
            "ufs",
            "yaffs2",
        ]
    ] = Field(default=None, description="Filesystem type if auto-detect fails.")
    image_format: Optional[Literal["raw", "ewf", "aff", "vmdk", "vhd"]] = Field(
        default=None, description="Container format of the image."
    )
    body_format: bool = Field(
        default=False,
        description="Emit `body` format for downstream `tsk_mactime`.",
    )
    mount_point: str = Field(
        default="/",
        description="Mount point prefix for paths in the body output.",
    )
    recursive: bool = Field(
        default=False, description="Walk recursively. Output can be very large."
    )
    deleted_only: bool = Field(
        default=False, description="Only emit deleted entries."
    )
    allocated_only: bool = Field(
        default=False, description="Only emit allocated entries."
    )
    long_format: bool = Field(default=False, description="Long output format.")


class TskIcatParams(_StrictModel):
    """``icat`` — extract a file's raw bytes by TSK metadata address (inode).

    The image is the injected evidence; the extracted bytes land in the run's
    output as a hashed artifact that a downstream parser can consume.
    """

    inode: str = Field(
        max_length=64,
        pattern=r"^\d+(?:-\d+){0,2}$",
        description="TSK metadata address from `tsk_fls`, e.g. `13552` or `12-128-4`.",
    )
    partition_offset: Optional[int] = Field(
        default=None, ge=0, description="Partition start offset in sectors (from tsk_mmls)."
    )
    filesystem: Optional[
        Literal[
            "ntfs", "fat", "fat12", "fat16", "fat32", "ext2", "ext3",
            "ext4", "hfs", "iso9660", "ufs", "yaffs2",
        ]
    ] = Field(default=None, description="Filesystem type if auto-detect fails.")
    image_format: Optional[Literal["raw", "ewf", "aff", "vmdk", "vhd"]] = Field(
        default=None, description="Container format of the image."
    )
    recover: bool = Field(
        default=False, description="Best-effort recovery of deleted content (-r)."
    )
    slack: bool = Field(default=False, description="Include slack space (-s).")


class HashdeepParams(_StrictModel):
    """``hashdeep`` — multi-algorithm hashing of the evidence or an extracted tree."""

    algorithms: Optional[
        list[Literal["md5", "sha1", "sha256", "sha512", "tiger", "whirlpool"]]
    ] = Field(
        default=None,
        max_length=6,
        description="Algorithms to compute. Default ['md5','sha256'].",
    )
    recursive: bool = Field(
        default=False, description="Recurse into directories (-r)."
    )


class ForemostParams(_StrictModel):
    """``foremost`` — carve files by header/footer signature (evidence injected)."""

    types: Optional[
        list[
            Literal[
                "all", "jpg", "gif", "png", "bmp", "tif", "avi", "exe", "mpg", "wav",
                "riff", "wmv", "mov", "pdf", "ole", "doc", "zip", "rar", "htm", "cpp",
            ]
        ]
    ] = Field(
        default=None,
        max_length=20,
        description="File types to carve. Default: all.",
    )
    quick: bool = Field(
        default=False, description="Quick mode (-q): scan block boundaries only."
    )


class PlasoLog2TimelineParams(_StrictModel):
    """``log2timeline.py`` — build a super-timeline (.plaso) from the evidence.

    HEAVY: on a full disk with every parser this runs for hours. Narrow it with
    ``parsers`` and ``partitions``.
    """

    partitions: str = Field(
        default="all",
        max_length=64,
        pattern=r"^(all|[0-9p,]+)$",
        description="Partition selector: 'all' or e.g. '1', '1,3'.",
    )
    parsers: Optional[str] = Field(
        default=None,
        max_length=256,
        pattern=r"^[A-Za-z0-9_,!*-]+$",
        description="Plaso parser/preset filter, e.g. 'win7' or 'winevtx,winreg,prefetch'.",
    )
    timezone: Optional[str] = Field(
        default=None, max_length=64, description="Time zone of the source system."
    )


class PlasoPsortParams(_StrictModel):
    """``psort.py`` — turn a .plaso storage into a readable timeline.

    ``plaso_path`` is the artifact a previous ``plaso_log2timeline`` run produced,
    not the evidence — same contract as ``tsk_mactime`` with its body file.
    """

    plaso_path: ArtifactRef
    output_format: Literal[
        "l2tcsv", "dynamic", "json", "json_line", "l2ttln", "tln", "kml", "xlsx", "null"
    ] = Field(default="l2tcsv", description="Timeline output format.")
    timezone: Optional[str] = Field(
        default=None, max_length=64, description="Output time zone."
    )


class TskMactimeParams(_StrictModel):
    """``mactime`` — turn a body file (from `tsk_fls -m`) into a timeline."""

    bodyfile_path: ArtifactRef
    iso_dates: bool = Field(
        default=True,
        description="Use ISO-8601 dates instead of locale-dependent strings.",
    )
    timezone: Optional[str] = Field(
        default=None,
        max_length=64,
        description="IANA timezone for date conversion (e.g. `Europe/Madrid`).",
    )
    date_range: Optional[str] = Field(
        default=None,
        description="Filter range as `YYYY-MM-DD..YYYY-MM-DD`.",
        pattern=r"^\d{4}-\d{2}-\d{2}\.\.\d{4}-\d{2}-\d{2}$",
    )


class EwfInfoParams(_StrictModel):
    """``ewfinfo`` — read metadata of an EWF (E01) container. Evidence injected."""

    # No additional parameters — ewfinfo just reads the container.
    pass


class EvtxECmdParams(_StrictModel):
    """``EvtxECmd`` — parse Windows EVTX files to CSV. Evidence path injected."""

    # output_dir injected by dispatcher; no other params for v1.
    pass


class MFTECmdParams(_StrictModel):
    """``MFTECmd`` — parse a NTFS `$MFT` into CSV. Evidence path injected."""

    pass


class LECmdParams(_StrictModel):
    """``lecmd`` — parse Windows shortcut `.lnk` files (file or directory) into
    CSV. Evidence path injected."""

    pass


class JLECmdParams(_StrictModel):
    """``jlecmd`` — parse Jump Lists (`*Destinations-ms`, file or directory)
    into CSV. Evidence path injected."""

    pass


class RECmdParams(_StrictModel):
    """``recmd`` — run a RECmd batch against a registry hive (evidence injected).

    ``batch`` is a batch file NAME from the ``BatchExamples/`` directory the
    maletín ships (e.g. ``Kroll_Batch.reb``) — a bare name, never a path
    (RULE 2: closed contract; the wrapper anchors it to the shipped directory).
    """

    batch: Literal["Kroll_Batch.reb"] = Field(
        description=(
            "RECmd batch file name from the maletín's BatchExamples/ "
            "(e.g. `Kroll_Batch.reb`). A bare name, never a path."
        ),
    )
    is_directory: bool = Field(
        default=False,
        description="Treat the evidence as a directory of hives (-d) instead of a single hive (-f).",
    )


class AmcacheParserParams(_StrictModel):
    """``amcacheparser`` — parse `Amcache.hve` into CSVs (evidence injected)."""

    include_linked: bool = Field(
        default=False,
        description="Also emit file entries linked to program entries (-i).",
    )


class AppCompatCacheParserParams(_StrictModel):
    """``appcompatcacheparser`` — parse the ShimCache from a `SYSTEM` hive into
    CSV. Evidence path injected."""

    pass


class SBECmdParams(_StrictModel):
    """``sbecmd`` — parse ShellBags from the user hives under a directory into
    CSV. Evidence path (a directory) injected."""

    pass


class WxTCmdParams(_StrictModel):
    """``wxtcmd`` — parse a Windows Timeline `ActivitiesCache.db` into CSV.
    Evidence path injected."""

    pass


class RBCmdParams(_StrictModel):
    """``rbcmd`` — parse Recycle Bin `$I` metadata into CSV (evidence injected)."""

    is_file: bool = Field(
        default=False,
        description="Treat the evidence as a single $I file (-f) instead of a $Recycle.Bin directory (-d).",
    )


class RegRipperParams(_StrictModel):
    """``rip`` (RegRipper) — run a registry-analysis plugin against a hive file.

    The hive can be the selected EVIDENCE injected from the session, or an
    ``ArtifactRef`` emitted by a prior producer such as ``tsk_icat``. Either supply a
    single ``plugin`` to run one, a ``profile`` to run a bundle, or set ``list=true``.
    """

    hive_path: Optional[ArtifactRef] = Field(
        default=None,
        description="ArtifactRef emitted by a prior producer such as tsk_icat.",
    )
    list: bool = Field(
        default=False,
        description="If true, list available plugins instead of running.",
    )
    plugin: Optional[str] = Field(
        default=None,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_]+$",
        description="A single RegRipper plugin name (e.g. `userassist`).",
    )
    profile: Optional[str] = Field(
        default=None,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_]+$",
        description="A bundled plugin profile (e.g. `software`, `system`).",
    )


class YaraParams(_StrictModel):
    """``yara`` — match rules against the evidence (target_path injected).

    ``rules_path`` is a path to a YARA rules file or directory. **Confined**
    to the active Agentopsy case by the shared dispatcher policy; the
    operator stages rule bundles under e.g. ``~/.forensia/cases/<case>/rules/``.
    """

    rules_path: str = Field(
        min_length=1,
        max_length=2048,
        description=(
            "Path to a YARA rules file or directory. Must live inside the "
            "active Agentopsy case directory."
        ),
    )
    recursive: bool = Field(
        default=False, description="Walk subdirectories of the target."
    )
    print_strings: bool = Field(
        default=False,
        description="Print matched strings, not just rule names.",
    )
    disable_warnings: bool = Field(
        default=False, description="Suppress YARA compiler warnings."
    )


class Aff4ImagerParams(_StrictModel):
    """``aff4imager`` — list/extract streams from an AFF4 volume (e.g. a
    WinPmem 3.x RAM acquisition; evidence path injected). Call WITHOUT
    ``stream`` to list the volume's stream URNs; call again with the URN to
    export it into the run output for volatility3 to consume."""

    stream: Optional[str] = Field(
        default=None,
        max_length=2048,
        pattern=r"^aff4://.+",
        description=(
            "FULL stream URN (aff4://…) exactly as printed by a previous "
            "listing run. Omit to list the volume's streams."
        ),
    )


class FtkImagerParams(_StrictModel):
    """``ftkimager`` — convert the disk-image evidence between raw/E01/SMART
    formats with MD5/SHA1 verification (evidence path injected; the converted
    image lands in the run's output directory with its acquisition report)."""

    format: Literal["raw", "e01", "s01"] = Field(
        default="raw",
        description="Output image format: raw (dd), E01 (EWF) or S01 (SMART).",
    )
    compress: Optional[int] = Field(
        default=None,
        ge=0,
        le=9,
        description="Compression level for e01/s01 (0=none..9=best). Invalid for raw.",
    )
    verify: bool = Field(
        default=True,
        description="Hash and verify the destination image after writing (MD5+SHA1).",
    )


class JqParams(_StrictModel):
    """``jq`` — query a JSON artifact already on disk (typically a prior run's output).

    ``input_path`` MUST live under the active Agentopsy case directory (SEC-1). Typically
    an artifact at ``~/.forensia/cases/<case>/artifacts/<run>/stdout.txt``
    (or similar) emitted by an earlier tool call.
    """

    filter: str = Field(
        min_length=1,
        max_length=4096,
        description="The jq filter expression (e.g. `.[] | select(.severity==\"high\")`).",
    )
    input_path: str | ArtifactRef = Field(
        description=(
            "Path to the JSON file to query. Confined to the active Agentopsy case "
            "directory; typically an artifact from a "
            "previous run."
        ),
    )
    raw_output: bool = Field(
        default=False, description="Emit raw strings (drop the JSON quotes)."
    )
    compact: bool = Field(default=False, description="One-line output.")
    slurp: bool = Field(
        default=False, description="Read entire input as a JSON array."
    )
    sort_keys: bool = Field(
        default=False, description="Stable-sort object keys in the output."
    )


# ============================================================================
# 4 COMPLEX TOOLS — curated enums, validated input
# ============================================================================


# Volatility3 plugin enum — a curated subset that the wrapper actually
# supports. Adding a new plugin requires extending this list. RULE 2:
# closed enum, no free-text.
_VOLATILITY_WINDOWS_PLUGINS = (
    "windows.info.Info",
    "windows.pslist.PsList",
    "windows.pstree.PsTree",
    "windows.psscan.PsScan",
    "windows.netscan.NetScan",
    "windows.malfind.Malfind",
    "windows.hollowprocesses.HollowProcesses",
    "windows.cmdline.CmdLine",
    "windows.handles.Handles",
    "windows.modules.Modules",
    "windows.modscan.ModScan",
    "windows.registry.hivelist.HiveList",
    "windows.registry.printkey.PrintKey",
    "windows.registry.userassist.UserAssist",
    # Credenciales (E1): SÍ están en el build (vol 2.28.0) — verificado 2026-07-17
    # ejecutando hashdump sobre una RAM Win7 real (6 cuentas, exit 0). Se declaran
    # con el nombre CANÓNICO `windows.registry.*`; los alias `windows.hashdump.*`
    # siguen funcionando pero vol los retira tras 2026-09-25.
    "windows.registry.hashdump.Hashdump",
    "windows.registry.lsadump.Lsadump",
    "windows.registry.cachedump.Cachedump",
    # Historial de consola: existen, pero en Win7 (NT 6.1) ambos abortan con
    # NotImplementedError — su tabla de símbolos de conhost no cubre esa versión
    # (cmdscan reutiliza el mismo código que consoles). Se exponen igualmente para
    # que el agente lo COMPRUEBE y registre el error real en vez de asumirlo.
    "windows.consoles.Consoles",
    "windows.cmdscan.CmdScan",
    "windows.filescan.FileScan",
    "windows.dumpfiles.DumpFiles",
    "windows.envars.Envars",
    "windows.svcscan.SvcScan",
    "timeliner.Timeliner",
)
_VOLATILITY_LINUX_PLUGINS = (
    "linux.banner.Banner",
    "linux.pslist.PsList",
    "linux.pstree.PsTree",
    "linux.psscan.PsScan",
    "linux.sockstat.Sockstat",
    "linux.bash.Bash",
    "linux.proc.Maps",
    "linux.lsmod.Lsmod",
    "linux.check_modules.Check_modules",
    "linux.check_syscall.Check_syscall",
)
_VOLATILITY_MAC_PLUGINS = (
    "mac.psaux.PsAux",
    "mac.proc_maps.Maps",
)
_VOLATILITY_PLUGINS = _VOLATILITY_WINDOWS_PLUGINS + _VOLATILITY_LINUX_PLUGINS + _VOLATILITY_MAC_PLUGINS


class Volatility3Params(_StrictModel):
    """``volatility3`` — memory analysis with a curated plugin enum.

    The plugin name is a closed enum of values that the wrapper supports. Add
    a new plugin to ``_VOLATILITY_PLUGINS`` in ``schemas.py`` to expose it
    via MCP; otherwise the request is rejected at validation.

    ``plugin_args`` is a flat dict mapping flag name → value, matching the
    wrapper contract (see ``forensia.toolkit.wrappers.volatility3``). To
    target a single PID, pass ``{"pid": "1832"}`` — each entry becomes
    ``--<key> <value>`` after the plugin name in the resolved argv.
    """

    plugin: Literal[_VOLATILITY_PLUGINS] = Field(  # type: ignore[valid-type]
        description=(
            "Volatility3 plugin name (module + class). This enum is FORENSIA's "
            "CURATED POLICY, not the capability of the maletín: a name rejected "
            "here may well exist in the build, widen the list in schemas.py. "
            "Never report a rejection as 'the plugin does not exist'."
        ),
    )
    dump_path: Optional[ArtifactRef] = Field(
        default=None,
        description=(
            "OPTIONAL {run_id, relpath} reference to a memdump a prior run "
            "materialised (e.g. the raw stream aff4imager exported from a "
            "WinPmem .aff4). Omit to analyse the selected evidence itself."
        ),
    )
    plugin_args: Optional[dict[str, str]] = Field(
        default=None,
        description=(
            "Extra plugin-specific args as a flat {flag: value} dict. Example "
            "for targeting PID 1234: `{\"pid\": \"1234\"}`. Keys must match "
            "[a-zA-Z][a-zA-Z0-9_-]*; values are strings."
        ),
    )


_BULK_EXTRACTOR_SCANNERS = (
    "accts",
    "aes",
    "base16",
    "base64",
    "elf",
    "email",
    "exif",
    "evtx",
    "facebook",
    "find",
    "gps",
    "gzip",
    "hashdb",
    "hiber",
    "httplogs",
    "json",
    "kml",
    "lightgrep",
    "msxml",
    "net",
    "outlook",
    "pdf",
    "rar",
    "sqlite",
    "vcard",
    "winlnk",
    "winpe",
    "winprefetch",
    "windirs",
    "wordlist",
    "xor",
    "zip",
)


class BulkExtractorParams(_StrictModel):
    """``bulk_extractor`` — carve IoCs from a disk image (target injected)."""

    enable_scanners: Optional[list[Literal[_BULK_EXTRACTOR_SCANNERS]]] = Field(  # type: ignore[valid-type]
        default=None,
        max_length=20,
        description="Specific scanners to enable. If omitted, defaults of bulk_extractor.",
    )
    disable_scanners: Optional[list[Literal[_BULK_EXTRACTOR_SCANNERS]]] = Field(  # type: ignore[valid-type]
        default=None,
        max_length=20,
        description="Scanners to disable.",
    )


class HayabusaParams(_StrictModel):
    """``hayabusa`` — Sigma-rule scan over EVTX dir (injected as evtx_dir)."""

    min_level: Optional[Literal["info", "low", "medium", "high", "critical"]] = Field(
        default=None,
        description="Minimum severity to report.",
    )


class ChainsawParams(_StrictModel):
    """``chainsaw hunt`` — Sigma rules over EVTX dir (target injected).

    ``sigma_dir`` and ``rules_dir`` MUST live under the active Agentopsy case directory
    (SEC-1). Bundled rule sets go under e.g. ``~/.forensia/cases/<case>/rules/``.
    """

    sigma_dir: Optional[str] = Field(
        default=None,
        max_length=2048,
        description=(
            "Path to a Sigma rules directory. Confined to the active Agentopsy "
            "case directory."
        ),
    )
    rules_dir: Optional[str] = Field(
        default=None,
        max_length=2048,
        description=(
            "Path to a Chainsaw rules directory (e.g. mappings). Confined to "
            "the active Agentopsy case directory."
        ),
    )
    ruleset: Optional[Literal["chainsaw-native"]] = Field(
        default=None,
        description="Bundled ruleset id mapped to one exact maletin path.",
    )
    output_format: Literal["csv", "json"]


# ============================================================================
# REGISTRY
# ============================================================================

SCHEMA_BY_TOOL: dict[str, type[BaseModel]] = {
    # 12 simple tools
    "file_info": FileInfoParams,
    "xxd_head": XxdHeadParams,
    "strings_head": StringsHeadParams,
    "tsk_mmls": TskMmlsParams,
    "tsk_fls": TskFlsParams,
    "tsk_mactime": TskMactimeParams,
    "ewf_info": EwfInfoParams,
    "evtxecmd": EvtxECmdParams,
    "mftecmd": MFTECmdParams,
    "regripper": RegRipperParams,
    "yara": YaraParams,
    "jq": JqParams,
    # 4 complex tools
    "volatility3": Volatility3Params,
    "bulk_extractor": BulkExtractorParams,
    "hayabusa": HayabusaParams,
    "chainsaw": ChainsawParams,
    # Conversión de imágenes / volúmenes AFF4 (2026-07-17, extended tier)
    "ftkimager": FtkImagerParams,
    "aff4imager": Aff4ImagerParams,
    # Extended tier que estaba en el maletín y en la allowlist pero SIN schema, así
    # que el agente no podía pedirlas (barrido 2026-07-17). `qemu_nbd` queda fuera
    # DELIBERADAMENTE: es side_effecting (conecta dispositivos de bloque) y no se
    # expone al agente; se opera a mano desde el maletín.
    "tsk_icat": TskIcatParams,
    "hashdeep": HashdeepParams,
    "foremost": ForemostParams,
    "plaso_log2timeline": PlasoLog2TimelineParams,
    "plaso_psort": PlasoPsortParams,
    # EZ Tools absorbidas el 2026-07-07 (extended tier)
    "lecmd": LECmdParams,
    "jlecmd": JLECmdParams,
    "recmd": RECmdParams,
    "amcacheparser": AmcacheParserParams,
    "appcompatcacheparser": AppCompatCacheParserParams,
    "sbecmd": SBECmdParams,
    "wxtcmd": WxTCmdParams,
    "rbcmd": RBCmdParams,
}


__all__ = [
    "SCHEMA_BY_TOOL",
    "FileInfoParams",
    "XxdHeadParams",
    "StringsHeadParams",
    "TskMmlsParams",
    "TskFlsParams",
    "TskMactimeParams",
    "EwfInfoParams",
    "EvtxECmdParams",
    "MFTECmdParams",
    "FtkImagerParams",
    "Aff4ImagerParams",
    "TskIcatParams",
    "HashdeepParams",
    "ForemostParams",
    "PlasoLog2TimelineParams",
    "PlasoPsortParams",
    "LECmdParams",
    "JLECmdParams",
    "RECmdParams",
    "AmcacheParserParams",
    "AppCompatCacheParserParams",
    "SBECmdParams",
    "WxTCmdParams",
    "RBCmdParams",
    "RegRipperParams",
    "YaraParams",
    "JqParams",
    "Volatility3Params",
    "BulkExtractorParams",
    "HayabusaParams",
    "ChainsawParams",
]
