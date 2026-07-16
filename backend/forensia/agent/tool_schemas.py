"""JSON Schemas que describen los params de cada Tool del catálogo en el formato
de especificación function-calling (el estándar de facto que los cuatro
ejecutores entienden dentro del prompt estructurado del camino degradado).

El LLM ve estos schemas y propone llamadas tipadas. El agent loop intercepta cada
llamada, inyecta los paths reales (evidence handle, output_dir del ArtifactRun)
y luego dispatcha contra el wrapper. El modelo NUNCA elige el path absoluto de
la evidencia — eso lo controla FORENSIA, no el LLM (defensa en profundidad
contra prompt-injection que intente saltar a otro archivo).
"""

from __future__ import annotations

from typing import Any

from forensia.artifact_ref import artifact_ref_json_schema

# Descripción común del input-de-artefacto derivado de las EZ Tools: como el
# `hive_path` de regripper, aceptan la ArtifactRef {run_id, relpath} que produjo un
# `tsk_icat` previo, para encadenar `tsk_icat.output → tool.input` con custodia del
# derivado (el dispatcher re-hashea el artefacto antes de ejecutar). Omítelo y
# FORENSIA inyecta el path de la evidencia directamente.
_EZ_INPUT_DESC = (
    "ArtifactRef {{run_id, relpath}} emitida por un `tsk_icat` previo que extrajo "
    "{what}. Encadena tsk_icat.output → esta tool. Omítelo para correr sobre la "
    "evidencia que FORENSIA inyecta."
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
    "tsk_icat": {
        "type": "object",
        "properties": {
            "inode": {
                "type": ["integer", "string"],
                "description": (
                    "TSK metadata address (inode) of the file to extract, as located "
                    "by tsk_fls. A number, optionally with -type[-id] suffixes "
                    "(e.g. 13552 or 12-128-4)."
                ),
            },
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
                "description": "Filesystem type hint (-f). Omit to auto-detect.",
            },
            "image_format": {
                "type": "string",
                "enum": ["raw", "ewf", "aff", "vmdk", "vhd"],
                "description": "Image container format hint (-i). Omit to auto-detect.",
            },
            "recover": {
                "type": "boolean",
                "default": False,
                "description": "Recover deleted content best-effort (-r).",
            },
            "slack": {
                "type": "boolean",
                "default": False,
                "description": "Include slack space (-s).",
            },
        },
        "required": ["inode"],
        "additionalProperties": False,
    },
    "tsk_mactime": {
        "type": "object",
        "properties": {
            "bodyfile_path": {
                **artifact_ref_json_schema(),
                "description": "ArtifactStore reference to a body file under a prior run out/.",
            },
            "date_range": {
                "type": "string",
                "description": "Optional date range like 2024-01-01..2024-12-31.",
            },
            "timezone": {"type": "string", "description": "Timezone label, e.g. UTC."},
        },
        "required": ["bodyfile_path"],
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
            "min_level": {
                "type": "string",
                "enum": ["info", "low", "medium", "high", "critical"],
            },
        },
        "additionalProperties": False,
    },
    "chainsaw": {
        "type": "object",
        "properties": {
            "sigma_dir": {"type": "string"},
            "rules_dir": {"type": "string"},
            "ruleset": {"type": "string", "enum": ["chainsaw-native"]},
            "output_format": {"type": "string", "enum": ["csv", "json"]},
        },
        "required": ["output_format"],
        "additionalProperties": False,
    },
    "regripper": {
        "type": "object",
        "properties": {
            "hive_path": {
                **artifact_ref_json_schema(),
                "description": "ArtifactRef emitted by a prior producer such as tsk_icat.",
            },
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
        "properties": {
            "evtx_path": {
                **artifact_ref_json_schema(),
                "description": _EZ_INPUT_DESC.format(what="the .evtx file"),
            },
        },
        "additionalProperties": False,
    },
    "mftecmd": {
        "type": "object",
        "properties": {
            "mft_path": {
                **artifact_ref_json_schema(),
                "description": _EZ_INPUT_DESC.format(what="the $MFT"),
            },
        },
        "additionalProperties": False,
    },
    "lecmd": {
        "type": "object",
        "properties": {
            "target_path": {
                **artifact_ref_json_schema(),
                "description": _EZ_INPUT_DESC.format(what="the .lnk file"),
            },
        },
        "additionalProperties": False,
    },
    "jlecmd": {
        "type": "object",
        "properties": {
            "target_path": {
                **artifact_ref_json_schema(),
                "description": _EZ_INPUT_DESC.format(what="the Jump List file"),
            },
        },
        "additionalProperties": False,
    },
    "recmd": {
        "type": "object",
        "properties": {
            "batch": {
                "type": "string",
                "enum": ["Kroll_Batch.reb"],
                "description": (
                    "RECmd batch file NAME from the BatchExamples/ shipped in the "
                    "maletín (e.g. Kroll_Batch.reb). A bare name — never a path."
                ),
            },
            "is_directory": {
                "type": "boolean",
                "default": False,
                "description": "Treat the evidence as a directory of hives (-d) instead of a single hive (-f).",
            },
        },
        "required": ["batch"],
        "additionalProperties": False,
    },
    "amcacheparser": {
        "type": "object",
        "properties": {
            "include_linked": {
                "type": "boolean",
                "default": False,
                "description": "Also emit file entries linked to program entries (-i).",
            },
        },
        "additionalProperties": False,
    },
    "appcompatcacheparser": {
        "type": "object",
        "properties": {
            "hive_path": {
                **artifact_ref_json_schema(),
                "description": _EZ_INPUT_DESC.format(what="the SYSTEM hive"),
            },
        },
        "additionalProperties": False,
    },
    "sbecmd": {
        "type": "object",
        "properties": {
            "target_path": {
                **artifact_ref_json_schema(),
                "description": _EZ_INPUT_DESC.format(
                    what="the directory of UsrClass.dat/NTUSER.DAT hives"
                ),
            },
        },
        "additionalProperties": False,
    },
    "wxtcmd": {
        "type": "object",
        "properties": {
            "target_path": {
                **artifact_ref_json_schema(),
                "description": _EZ_INPUT_DESC.format(
                    what="the ActivitiesCache.db"
                ),
            },
        },
        "additionalProperties": False,
    },
    "rbcmd": {
        "type": "object",
        "properties": {
            "is_file": {
                "type": "boolean",
                "default": False,
                "description": "Treat the evidence as a single $I file (-f) instead of a $Recycle.Bin directory (-d).",
            },
        },
        "additionalProperties": False,
    },
    "jq": {
        "type": "object",
        "properties": {
            "filter": {"type": "string", "description": "jq filter expression."},
            "input_path": {
                "oneOf": [
                    {"type": "string"},
                    {
                        **artifact_ref_json_schema(),
                    },
                ],
                "description": "Same-case file path or ArtifactStore {run_id, relpath} reference.",
            },
            "raw_output": {"type": "boolean", "default": False},
            "compact": {"type": "boolean", "default": False},
        },
        "required": ["filter", "input_path"],
        "additionalProperties": False,
    },
}


# Descripciones humanas para que el LLM entienda qué hace cada tool.
TOOL_DESCRIPTIONS: dict[str, str] = {
    "file_info": "Identify what KIND of file the evidence actually is. ALWAYS run this FIRST. If it returns generic data, follow up with strings_head before invoking any forensic tool.",
    "xxd_head": "Hex-dump the first bytes of the evidence to read its magic number directly. Use this when file_info returns 'data' (no signature) — most container formats are identifiable from bytes 0..32.",
    "strings_head": "Extract printable strings from the evidence to look for vendor names, kernel banners, format markers (Linux version, LiME, EnCase, VMware, EVTX). Use it when file_info is non-diagnostic.",
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
    "tsk_icat": "Extract a file's raw bytes by inode (from tsk_fls) straight off the image without mounting — allocated or deleted. The extracted artifact can feed a downstream parser (regripper, mftecmd, evtxecmd…) as {run_id, relpath}.",
    "evtxecmd": "Parse a pre-extracted .evtx file (or directory) into CSV.",
    "mftecmd": "Parse a pre-extracted $MFT into CSV.",
    "lecmd": "Parse pre-extracted Windows shortcut .lnk files (file or directory) into CSV — target paths, timestamps, volume info.",
    "jlecmd": "Parse pre-extracted Jump Lists (Automatic/CustomDestinations-ms, from the user's Recent/ folder) into CSV — per-app document access history.",
    "recmd": "Run a RECmd batch (e.g. Kroll_Batch.reb) against a pre-extracted registry hive (or directory of hives) into CSV.",
    "amcacheparser": "Parse a pre-extracted Amcache.hve into CSVs — program/file inventory, evidence of execution.",
    "appcompatcacheparser": "Parse the ShimCache (AppCompatCache) from a pre-extracted SYSTEM hive into CSV — executables present/run on the system.",
    "sbecmd": "Parse ShellBags from UsrClass.dat/NTUSER.DAT hives under a directory into CSV — folders the user browsed, even if deleted.",
    "wxtcmd": "Parse a pre-extracted Windows Timeline ActivitiesCache.db (Win10 1803+) into CSV — app/document activity history.",
    "rbcmd": "Parse Recycle Bin $I metadata (directory or single file) into CSV — original path, size and deletion time of recycled files.",
    "jq": "Filter JSON output from other tools.",
}


# Side-channel tools that the agent loop handles in-process (NOT dispatched
# to a binary). They get exposed to the LLM in the same `tools=[…]` list so
# the model can call them naturally.
_INTERNAL_TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "consultar_actividad": {
        "type": "object",
        "properties": {
            "date_from": {
                "type": "string",
                "description": "Inicio del rango (inclusive): `YYYY-MM-DD` o ISO-8601 UTC.",
            },
            "date_to": {
                "type": "string",
                "description": "Fin del rango (inclusive): `YYYY-MM-DD` o ISO-8601 UTC.",
            },
            "category": {
                "type": "string",
                "enum": [
                    "credenciales", "ssh", "historial", "persistencia",
                    "ejecutable_temporal", "web", "logs", "binario_sistema",
                ],
                "description": "Filtra por categoría de relevancia (p. ej. `web` = artefactos web).",
            },
            "path_contains": {
                "type": "string",
                "description": "Subcadena a buscar en la ruta del evento (case-insensitive).",
            },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 500,
                "description": "Máximo de eventos a devolver (por defecto 100).",
            },
        },
        "additionalProperties": False,
    },
    "record_finding": {
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "minLength": 4,
                "maxLength": 200,
                "description": "Short headline (≤ 80 chars idealmente).",
            },
            "summary": {
                "type": "string",
                "minLength": 4,
                "maxLength": 4000,
                "description": "1–3 frases que explican el hallazgo y CÓMO lo dedujiste.",
            },
            "severity": {
                "type": "string",
                "enum": ["low", "medium", "high", "critical"],
            },
            "tool_id": {
                "type": "string",
                "description": "Tool id que produjo la evidencia para este hallazgo.",
            },
            "run_id": {
                "type": "string",
                "description": (
                    "UUID4 del ArtifactRun que respalda este hallazgo. OBLIGATORIO "
                    "para un hallazgo afirmativo (procedencia): sin él se rechaza el "
                    "registro, salvo que marques finding_kind=\"descarte\"."
                ),
            },
            # Los prompts de los paquetes YA prescriben estos campos («Esquema de
            # hallazgo» en agentes/*/prompts/system.md): confidence, observed_at y la
            # procedencia de artefacto. Sin ellos en el schema,
            # `additionalProperties: False` impedía al modelo emitirlos (mismo bug que
            # `mitre_hints`) y el motor los descartaba en silencio.
            "confidence": {
                "type": "number",
                "minimum": 0,
                "maximum": 1,
                "description": (
                    "Confianza CALIBRADA (0..1) en el hallazgo. 1.0 = evidencia "
                    "directa e inequívoca; valores bajos para inferencias. Opcional."
                ),
            },
            "observed_at": {
                "type": "string",
                "description": (
                    "Marca temporal del ARTEFACTO que sostiene el hallazgo (cuándo "
                    "ocurrió el hecho en la evidencia), ISO-8601 con offset/UTC "
                    "(p. ej. 2026-07-15T13:42:00Z). Distinta de cuándo registras el "
                    "hallazgo. Opcional."
                ),
            },
            "artifact_sha256": {
                "type": "string",
                "pattern": "^[0-9a-fA-F]{64}$",
                "description": (
                    "SHA-256 (64 hex) del output del run que sostiene el hallazgo — "
                    "procedencia a nivel de artefacto. Opcional; el ancla obligatoria "
                    "es run_id."
                ),
            },
            "finding_kind": {
                "type": "string",
                "enum": ["afirmacion", "descarte"],
                "description": (
                    "`afirmacion` (por defecto) afirma algo sobre la evidencia y EXIGE "
                    "run_id. `descarte` documenta que una vía NO aportó (queda exento "
                    "de procedencia). Úsalo solo para descartes reales, no para eludir "
                    "el requisito de run_id de una afirmación."
                ),
            },
            "mitre_hints": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Técnicas ATT&CK que sostiene este hallazgo, p. ej. "
                    "[\"T1547.001\"]. ENUM CERRADA: sólo ids de la semilla "
                    "(_orchestrator/knowledge/mitre_attack_seed.md). Un id fuera de "
                    "la semilla RECHAZA el hallazgo entero — no inventes ids. Mapea "
                    "a sub-técnica cuando la evidencia lo permita; si no, a la "
                    "técnica padre. Omite el campo si el hallazgo no sostiene "
                    "ninguna técnica."
                ),
            },
        },
        "required": ["title", "summary", "severity"],
        "additionalProperties": False,
    },
    "annotate_mitre": {
        "type": "object",
        "properties": {
            "finding_id": {
                "type": "string",
                "description": (
                    "UUID de un hallazgo YA registrado (el `finding_id` que devolvió "
                    "`record_finding`) que sostiene estas técnicas."
                ),
            },
            "mitre_hints": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Técnicas ATT&CK que sostiene el hallazgo, p. ej. [\"T1055\", "
                    "\"T1056.001\"]. ENUM CERRADA: sólo ids de la semilla "
                    "(_orchestrator/knowledge/mitre_attack_seed.md); un id fuera de "
                    "la semilla RECHAZA la anotación. Envía la lista COMPLETA: "
                    "reemplaza la anterior de ese hallazgo (lista vacía la retira)."
                ),
            },
            "note": {
                "type": "string",
                "description": "Por qué el hallazgo sostiene esas técnicas (opcional).",
            },
        },
        "required": ["finding_id", "mitre_hints"],
        "additionalProperties": False,
    },
}

_INTERNAL_DESCRIPTIONS: dict[str, str] = {
    "consultar_actividad": (
        "CONSULTA la super-timeline del sistema de ficheros YA generada de la evidencia "
        "activa, sin re-ejecutar tsk_fls. Úsala para responder «¿qué actividad hubo entre "
        "X e Y?», «¿hubo algún registro el <fecha>?» o «enséñame los artefactos web»: lee "
        "el bodyfile hasheado del run de fls y filtra TODOS sus eventos MACB por rango de "
        "fechas, categoría de relevancia y/o subcadena de ruta. Es una proyección "
        "determinista y exhaustiva — no infiere. Si la super-timeline aún no existe, te lo "
        "dice (status=no_timeline) para que la generes primero en vez de adivinar. Prefiere "
        "esto a re-lanzar tsk_fls/tsk_mactime cuando la timeline ya está construida."
    ),
    "record_finding": (
        "PERSIST a structured finding for this case. Call this BEFORE composing your "
        "final answer for EACH meaningful conclusion (file type identified, kernel "
        "version detected, IOC found, hypothesis confirmed/rejected, etc.). The "
        "findings panel in the UI reads these. severity: low for context, medium for "
        "noteworthy, high for actionable, critical for clear compromise. An "
        "AFFIRMATIVE finding (something you assert about the evidence) REQUIRES "
        "run_id (the ArtifactRun that backs it) — it is rejected without it; set "
        "finding_kind=\"descarte\" when you document a ruled-out lead instead. Attach "
        "confidence (0..1), observed_at (when it happened in the evidence) and "
        "artifact_sha256 when you have them, and mitre_hints when the finding "
        "supports an ATT&CK technique from the seed."
    ),
    "annotate_mitre": (
        "ANCHOR ATT&CK techniques to an ALREADY-recorded finding so they show up as "
        "proposals on the MITRE board. Use it whenever you correlate findings to "
        "techniques (e.g. the examiner asks for the MITRE correlation), or to fill in "
        "hints you didn't attach at record time. finding_id must exist; ids come from "
        "the seed. Idempotent per finding: re-call with the FULL list (it replaces the "
        "previous one). This PERSISTS the correlation — prose in your answer does not "
        "reach the board on its own."
    ),
}


def internal_tool_specs() -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    for tid, schema in _INTERNAL_TOOL_SCHEMAS.items():
        specs.append({
            "type": "function",
            "function": {
                "name": tid,
                "description": _INTERNAL_DESCRIPTIONS.get(tid, ""),
                "parameters": schema,
            },
        })
    return specs


def tool_spec(tool_id: str) -> dict[str, Any] | None:
    """Return the function-calling spec for ``tool_id``, or None if unsupported."""
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


def tool_specs(tool_ids: list[str] | tuple[str, ...]) -> list[dict[str, Any]]:
    specs = []
    for tid in tool_ids:
        spec = tool_spec(tid)
        if spec is not None:
            specs.append(spec)
    return specs
