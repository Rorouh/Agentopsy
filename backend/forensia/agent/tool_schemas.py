"""JSON Schemas que describen los params de cada Tool del catálogo en formato
compatible con OpenAI tool-calling.

El LLM ve estos schemas y propone llamadas tipadas. El agent loop intercepta cada
llamada, inyecta los paths reales (evidence handle, output_dir del ArtifactRun)
y luego dispatcha contra el wrapper. El modelo NUNCA elige el path absoluto de
la evidencia — eso lo controla FORENSIA, no el LLM (defensa en profundidad
contra prompt-injection que intente saltar a otro archivo).
"""

from __future__ import annotations

from typing import Any

# Params que se inyectan automáticamente desde el contexto (NO los pide el LLM):
#   - image_path / dump_path / mft_path / hive_path / evtx_path : resolved evidence handle
#   - output_dir : asignado por el ArtifactStore.start_run del dispatcher
AUTO_INJECTED = frozenset(
    {
        "image_path",
        "dump_path",
        "mft_path",
        "hive_path",
        "evtx_path",
        "output_dir",
        "target_path",
        "input_path",
        "bodyfile_path",
    }
)

# Schemas de parámetros por tool_id. Solo los params QUE EL LLM PUEDE ELEGIR.
# Los auto-inyectados se omiten del schema (el LLM no debería decidirlos).
TOOL_PARAM_SCHEMAS: dict[str, dict[str, Any]] = {
    "file_info": {
        "type": "object",
        "properties": {
            "also_mime": {
                "type": "boolean",
                "description": "Also emit MIME info (application/octet-stream; charset=binary).",
            },
        },
        "additionalProperties": False,
    },
    "xxd_head": {
        "type": "object",
        "properties": {
            "bytes": {
                "type": "integer",
                "minimum": 1,
                "maximum": 65536,
                "description": "How many bytes to dump (default 512). Magic numbers fit in 32.",
            },
            "skip": {
                "type": "integer",
                "minimum": 0,
                "description": "Offset to start the dump (default 0).",
            },
            "cols": {"type": "integer", "minimum": 4, "maximum": 64, "default": 16},
        },
        "additionalProperties": False,
    },
    "strings_head": {
        "type": "object",
        "properties": {
            "min_len": {
                "type": "integer",
                "minimum": 4,
                "maximum": 256,
                "description": "Min string length (default 12). Lower it to 6 if you need vendor markers.",
            },
            "radix": {
                "type": "string",
                "enum": ["d", "o", "x"],
                "description": "Emit string offsets in decimal/octal/hex.",
            },
        },
        "additionalProperties": False,
    },
    "tsk_mmls": {
        "type": "object",
        "properties": {
            "type": {
                "type": "string",
                "enum": ["dos", "gpt", "mac", "bsd", "sun"],
                "description": "Partition table type. Omit to auto-detect.",
            },
            "image_format": {
                "type": "string",
                "enum": ["raw", "ewf", "aff", "vmdk", "vhd"],
                "description": "Image container format. Omit to auto-detect.",
            },
        },
        "additionalProperties": False,
    },
    "tsk_fls": {
        "type": "object",
        "properties": {
            "partition_offset": {
                "type": "integer",
                "minimum": 0,
                "description": "Partition offset in sectors (-o).",
            },
            "filesystem": {
                "type": "string",
                "enum": [
                    "ntfs", "fat", "fat12", "fat16", "fat32", "ext2", "ext3",
                    "ext4", "hfs", "iso9660", "ufs", "yaffs2",
                ],
            },
            "image_format": {
                "type": "string",
                "enum": ["raw", "ewf", "aff", "vmdk", "vhd"],
            },
            "recursive": {"type": "boolean", "default": False},
            "deleted_only": {"type": "boolean", "default": False},
            "allocated_only": {"type": "boolean", "default": False},
            "long_format": {"type": "boolean", "default": False},
            "body_format": {
                "type": "boolean",
                "default": False,
                "description": "Emit body file for mactime (-m).",
            },
        },
        "additionalProperties": False,
    },
    "tsk_mactime": {
        "type": "object",
        "properties": {
            "date_range": {
                "type": "string",
                "description": "Optional date range like 2024-01-01..2024-12-31.",
            },
            "timezone": {"type": "string", "description": "Timezone label, e.g. UTC."},
        },
        "additionalProperties": False,
    },
    "ewf_info": {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    },
    "bulk_extractor": {
        "type": "object",
        "properties": {
            "enable_scanners": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Allowlist of scanner names.",
            },
            "disable_scanners": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Disable specific scanners.",
            },
        },
        "additionalProperties": False,
    },
    "yara": {
        "type": "object",
        "properties": {
            "rules_path": {
                "type": "string",
                "description": "Host path to YARA rules file or directory.",
            },
            "recursive": {"type": "boolean", "default": False},
            "print_strings": {"type": "boolean", "default": False},
        },
        "required": ["rules_path"],
        "additionalProperties": False,
    },
    "volatility3": {
        "type": "object",
        "properties": {
            "plugin": {
                "type": "string",
                "description": (
                    "Volatility 3 plugin id (dotted), e.g. windows.pslist.PsList, "
                    "linux.pslist.PsList, windows.netscan.NetScan, "
                    "windows.malfind.Malfind."
                ),
            },
            "plugin_args": {
                "type": "object",
                "description": "Optional plugin args as a flat map of string→string.",
            },
        },
        "required": ["plugin"],
        "additionalProperties": False,
    },
    "hayabusa": {
        "type": "object",
        "properties": {
            "evtx_dir": {
                "type": "string",
                "description": "Directory containing pre-extracted .evtx files.",
            },
            "output_csv": {
                "type": "string",
                "description": "Output CSV path.",
            },
            "min_level": {
                "type": "string",
                "enum": ["info", "low", "medium", "high", "critical"],
            },
        },
        "required": ["evtx_dir", "output_csv"],
        "additionalProperties": False,
    },
    "chainsaw": {
        "type": "object",
        "properties": {
            "target_dir": {"type": "string"},
            "sigma_dir": {"type": "string"},
            "rules_dir": {"type": "string"},
            "output_format": {"type": "string", "enum": ["csv", "json"]},
            "output_path": {"type": "string"},
        },
        "required": ["target_dir", "output_format", "output_path"],
        "additionalProperties": False,
    },
    "regripper": {
        "type": "object",
        "properties": {
            "plugin": {
                "type": "string",
                "description": "RegRipper plugin name (e.g. samparse, run, services).",
            },
            "profile": {"type": "string"},
            "list": {"type": "boolean", "default": False},
        },
        "additionalProperties": False,
    },
    "evtxecmd": {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    },
    "mftecmd": {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    },
    "jq": {
        "type": "object",
        "properties": {
            "filter": {"type": "string", "description": "jq filter expression."},
            "input_path": {"type": "string", "description": "Path to the input JSON file."},
            "raw_output": {"type": "boolean", "default": False},
            "compact": {"type": "boolean", "default": False},
        },
        "required": ["filter", "input_path"],
        "additionalProperties": False,
    },
}


# Descripciones humanas para que el LLM entienda qué hace cada tool.
TOOL_DESCRIPTIONS: dict[str, str] = {
    "file_info": "Identify what KIND of file the evidence actually is. ALWAYS run this FIRST. If it returns generic data, follow up with xxd_head and strings_head before invoking any forensic tool.",
    "xxd_head": "Hex-dump the first bytes of the evidence to read its magic number directly. Use this when file_info returns 'data' (no signature) — most container formats are identifiable from bytes 0..32.",
    "strings_head": "Extract printable strings from the evidence to look for vendor names, kernel banners, format markers (Linux version, LiME, EnCase, VMware, EVTX). Pair with xxd_head when file_info is non-diagnostic.",
    "tsk_mmls": "List partitions of the raw disk evidence. Run this first to discover the partition layout.",
    "tsk_fls": "List files in the partition. Useful for triaging the filesystem and producing bodyfiles for mactime.",
    "tsk_mactime": "Build a chronological timeline from a TSK bodyfile.",
    "ewf_info": "Read EWF/E01 case metadata (examiner, acquisition date, baseline hashes).",
    "bulk_extractor": "Run parallel feature scanners (emails, URLs, IPs, credit cards) across the evidence.",
    "yara": "Match YARA rules against files or directories. Caller provides the rules path.",
    "volatility3": "Run a Volatility 3 plugin against the memory dump. Pick the plugin id appropriate to the host OS.",
    "hayabusa": "Run Hayabusa with Sigma rules over a directory of pre-extracted EVTX files.",
    "chainsaw": "Hunt over EVTX or JSON files with Sigma rules.",
    "regripper": "Run RegRipper against a pre-extracted Windows registry hive.",
    "evtxecmd": "Parse a pre-extracted .evtx file (or directory) into CSV.",
    "mftecmd": "Parse a pre-extracted $MFT into CSV.",
    "jq": "Filter JSON output from other tools.",
}


def openai_tool_spec(tool_id: str) -> dict[str, Any] | None:
    """Return the OpenAI function-calling spec for ``tool_id``, or None if unsupported."""
    if tool_id not in TOOL_PARAM_SCHEMAS:
        return None
    return {
        "type": "function",
        "function": {
            "name": tool_id,
            "description": TOOL_DESCRIPTIONS.get(tool_id, ""),
            "parameters": TOOL_PARAM_SCHEMAS[tool_id],
        },
    }


def openai_tool_specs(tool_ids: list[str] | tuple[str, ...]) -> list[dict[str, Any]]:
    specs = []
    for tid in tool_ids:
        spec = openai_tool_spec(tid)
        if spec is not None:
            specs.append(spec)
    return specs
