"""JSON Schemas que describen los params de cada Tool del catálogo en el formato
de especificación function-calling (el estándar de facto que los cuatro
ejecutores entienden dentro del prompt estructurado del camino degradado).

El LLM ve estos schemas y propone llamadas tipadas. El agent loop intercepta cada
llamada, inyecta los paths reales (evidence handle, output_dir del ArtifactRun)
y luego dispatcha contra el wrapper. El modelo NUNCA elige el path absoluto de
la evidencia — eso lo controla Agentopsy, no el LLM (defensa en profundidad
contra prompt-injection que intente saltar a otro archivo).
"""

from __future__ import annotations

from typing import Any

from forensia.artifact_ref import artifact_ref_json_schema
from forensia.knowledge import DOC_ID_PATTERN, MAX_BLOCK_CHARS, MAX_SECTION_CHARS

# Descripción común del input-de-artefacto derivado de las EZ Tools: como el
# `hive_path` de regripper, aceptan la ArtifactRef {run_id, relpath} que produjo un
# `tsk_icat` previo, para encadenar `tsk_icat.output → tool.input` con custodia del
# derivado (el dispatcher re-hashea el artefacto antes de ejecutar). Omítelo y
# Agentopsy inyecta el path de la evidencia directamente.
_EZ_INPUT_DESC = (
    "ArtifactRef {{run_id, relpath}} emitida por un `tsk_icat` previo que extrajo "
    "{what}. Encadena tsk_icat.output → esta tool. Omítelo para correr sobre la "
    "evidencia que Agentopsy inyecta."
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
                    "Volatility 3 plugin id — ALWAYS module + class, e.g. "
                    "windows.pslist.PsList, linux.pslist.PsList, "
                    "windows.netscan.NetScan, windows.malfind.Malfind. "
                    "An 'invalid choice' error means the NAME is malformed (class "
                    "missing), NEVER that the plugin is absent from the build. "
                    "Credentials (verified present): "
                    "windows.registry.hashdump.Hashdump / .lsadump.Lsadump / "
                    ".cachedump.Cachedump. Known REAL limit: "
                    "windows.consoles.Consoles and windows.cmdscan.CmdScan raise "
                    "NotImplementedError on Windows 7 (NT 6.1) — cmdscan shares "
                    "the consoles code, so it is not an alternative."
                ),
            },
            "plugin_args": {
                "type": "object",
                "description": "Optional plugin args as a flat map of string→string.",
            },
            "dump_path": {
                **artifact_ref_json_schema(),
                "description": (
                    "OPTIONAL {run_id, relpath} reference to a memdump a prior run "
                    "materialised (e.g. the raw stream aff4imager exported from a "
                    "WinPmem .aff4). Omit to analyse the selected evidence itself."
                ),
            },
        },
        "required": ["plugin"],
        "additionalProperties": False,
    },
    "aff4imager": {
        "type": "object",
        "properties": {
            "stream": {
                "type": "string",
                "pattern": "^aff4://.+",
                "description": (
                    "FULL stream URN (aff4://…) exactly as printed by a previous "
                    "listing run. OMIT this param first to LIST the volume's "
                    "streams; then call again with the URN of the stream to "
                    "export (e.g. the physical-memory stream of a WinPmem dump)."
                ),
            },
        },
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
    "ftkimager": {
        "type": "object",
        "properties": {
            "format": {
                "type": "string",
                "enum": ["raw", "e01", "s01"],
                "default": "raw",
                "description": "Output image format: raw (dd), E01 (EWF) or S01 (SMART).",
            },
            "compress": {
                "type": "integer",
                "minimum": 0,
                "maximum": 9,
                "description": "Compression level for e01/s01 (0=none..9=best). Invalid for raw.",
            },
            "verify": {
                "type": "boolean",
                "default": True,
                "description": "Hash and verify the destination image after writing (MD5+SHA1).",
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
    "ftkimager": "Convert the disk-image evidence between formats — raw (dd) ↔ E01/SMART — with MD5/SHA1 verification and an acquisition report. E.g. produce a TSK-friendly raw copy from an E01, or a compressed E01 from a raw image.",
    "aff4imager": "List or extract streams from an AFF4 volume (e.g. a WinPmem 3.x RAM acquisition). Call WITHOUT params to list the stream URNs; call again with `stream`=<that URN> to export it into the run output — then feed the exported raw to volatility3 as {run_id, relpath}.",
    "jq": "Filter JSON output from other tools.",
}


# Side-channel tools that the agent loop handles in-process (NOT dispatched
# to a binary). They get exposed to the LLM in the same `tools=[…]` list so
# the model can call them naturally.
_INTERNAL_TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "consultar_conocimiento": {
        "type": "object",
        "properties": {
            "doc_id": {
                "type": "string",
                "description": (
                    "Id de un documento del «Mapa de memoria» del system prompt "
                    "(p. ej. `artefactos-unix`). Devuelve su contenido completo."
                ),
            },
        },
        "required": ["doc_id"],
        "additionalProperties": False,
    },
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
    "declarar_pivote": {
        "type": "object",
        "properties": {
            "via_cerrada": {
                "type": "string",
                "maxLength": 200,
                "description": (
                    "Qué vía das por cerrada, en concreto. P. ej. «tsk_fls sobre el "
                    "disco para fechar los documentos»."
                ),
            },
            "motivo": {
                "type": "string",
                "maxLength": 1000,
                "description": (
                    "Por qué está cerrada, CON el sostén: el exit code y el stderr, o "
                    "el `run_id` que lo demuestra. No vale «no funcionó»."
                ),
            },
            "via_alternativa": {
                "type": "string",
                "maxLength": 1000,
                "description": (
                    "Por dónde vas a seguir y qué esperas obtener. P. ej. «volcar los "
                    "hives desde la RAM con volatility3 hivelist y pasarlos por "
                    "regripper: da huso horario, cuentas y documentos recientes sin "
                    "tocar el disco»."
                ),
            },
        },
        "required": ["via_cerrada", "motivo", "via_alternativa"],
        "additionalProperties": False,
    },
    "leer_artefacto": {
        "type": "object",
        "properties": {
            "run_id": {
                "type": "string",
                "description": (
                    "UUID4 del run cuya salida quieres leer (el que devolvió la "
                    "herramienta al ejecutarse)."
                ),
            },
            "fichero": {
                "type": "string",
                "description": (
                    "`stdout` (por defecto), `stderr`, o el `relpath` de un fichero "
                    "de salida del run. Un binario no se sirve como texto."
                ),
            },
            "buscar": {
                "type": "string",
                "description": (
                    "SUBCADENA literal, sin distinguir mayúsculas. Devuelve solo las "
                    "líneas que la contienen — como un `grep`. Omítela para leer "
                    "secuencialmente."
                ),
            },
            "desde": {
                "type": "integer",
                "minimum": 1,
                "description": (
                    "Línea por la que empezar, 1-based, contando SOLO las relevantes "
                    "(las que casan con `buscar`). Para paginar usa el "
                    "`siguiente_desde` que devuelve la llamada anterior."
                ),
            },
            "lineas": {
                "type": "integer",
                "minimum": 1,
                "maximum": 400,
                "description": "Cuántas líneas devolver (por defecto 200, máximo 400).",
            },
        },
        "required": ["run_id"],
        "additionalProperties": False,
    },
    "anotar_conocimiento": {
        "type": "object",
        "properties": {
            "doc_id": {
                "type": "string",
                "pattern": DOC_ID_PATTERN,
                "description": (
                    "Id del nodo del grafo de ESTE caso. Usa uno del núcleo listado "
                    "en «Conocimiento de este caso» (system prompt) cuando encaje; "
                    "si no, crea uno nuevo en minúsculas-con-guiones. Es un ID, "
                    "NUNCA una ruta: Agentopsy decide dónde se guarda."
                ),
            },
            "section": {
                "type": "string",
                "maxLength": MAX_SECTION_CHARS,
                "description": (
                    "Tema dentro del nodo, p. ej. `zona-horaria`. Es la CLAVE: "
                    "escribir otra vez la misma sección SUSTITUYE su contenido en la "
                    "vista (la versión anterior se conserva en el registro). Úsalo "
                    "para corregirte sin duplicar."
                ),
            },
            "content": {
                "type": "string",
                "maxLength": MAX_BLOCK_CHARS,
                "description": (
                    "La CONCLUSIÓN y el puntero que la sostiene (`run_id`, ruta del "
                    "artefacto, hash). NUNCA el volcado entero de una herramienta: "
                    "si no cabe, resume y cita el run_id."
                ),
            },
        },
        "required": ["doc_id", "section", "content"],
        "additionalProperties": False,
    },
}

_INTERNAL_DESCRIPTIONS: dict[str, str] = {
    "consultar_conocimiento": (
        "LEE bajo demanda un documento de referencia del «Mapa de memoria» (system "
        "prompt): detalle por-herramienta, catálogo de artefactos por SO, etc. NO "
        "cargues todo de antemano — consulta solo el doc que necesites para la tarea "
        "en curso (economía de contexto). `doc_id` debe ser uno de los ids listados en "
        "el Mapa de memoria; un id desconocido se rechaza con la lista de ids válidos."
    ),
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
    "declarar_pivote": (
        "DECLARA que una vía está cerrada y por dónde sigues. Úsala cuando una "
        "herramienta o una cadena entera no puede darte lo que buscabas (formato no "
        "soportado, plugin ausente, el disco no abre) y vas a atacar el mismo objetivo "
        "por OTRO artefacto.\n"
        "No es rendirse ni es cambiar de tema: es la jugada que resuelve casos reales "
        "—«el disco no abre → vuelco los hives desde la RAM y respondo igual»—. Lo que "
        "NO puedes hacer es cambiar de vía en silencio: el perito tiene que ver que "
        "descartaste algo, con qué prueba y qué haces en su lugar. Queda registrado en "
        "el log de custodia.\n"
        "Cita SIEMPRE el sostén (exit code, stderr o `run_id`): un descarte sin prueba "
        "no vale, y podría estar ocultando un fallo puntual en vez de una vía cerrada."
    ),
    "leer_artefacto": (
        "LEE la salida COMPLETA de una herramienta que ya ejecutaste, filtrándola por "
        "líneas — es tu `grep`/`head` sobre tus propios resultados. Lo que ves al "
        "ejecutar una tool es solo una MUESTRA recortada: si la salida importa "
        "(un árbol de `fls`, las cuentas de `regripper`, un CSV de `mftecmd`, las "
        "conexiones de `netscan`), LÉELA con esta tool antes de concluir nada.\n"
        "Úsala también en vez de re-ejecutar una herramienta «para volver a mirar»: "
        "el run ya está en disco, releerlo es gratis y re-ejecutar no lo es.\n"
        "`buscar` filtra por subcadena (una IP, un nombre de usuario, `Confidential`, "
        "un EID). Si `hay_mas` es true, vuelve a llamar con el `siguiente_desde` que "
        "te devuelve. Un fichero binario no se sirve aquí: usa `strings_head`/"
        "`xxd_head` o el parser que corresponda."
    ),
    "anotar_conocimiento": (
        "ESCRIBE en el grafo de conocimiento de ESTE caso: lo que has averiguado, "
        "dónde está y qué queda abierto. Es tu memoria entre turnos — el contexto se "
        "recorta, esto no. Anota EN CALIENTE, en cuanto una herramienta te da algo "
        "que vas a necesitar después: el perfil del sistema y el huso horario, las "
        "cuentas, un hito de la cronología, y sobre todo el `run_id` de un artefacto "
        "que tendrás que citar más tarde (así no dependes de recordarlo ni "
        "re-ejecutas la herramienta). Reescribir la misma `section` te CORRIGE sin "
        "duplicar. Los nodos y sus secciones aparecen en «Conocimiento de este caso» "
        "y se releen con `consultar_conocimiento(doc_id)`.\n"
        "NO es un hallazgo pericial: un hallazgo va a `record_finding` con su "
        "procedencia. Aquí van notas de trabajo. Y NO vuelques salidas enteras: la "
        "conclusión y el puntero."
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


def _with_evidence_selector(
    schema: dict[str, Any], evidence_choices: list[tuple[str, str]]
) -> dict[str, Any]:
    """Inyecta un ``evidence_id`` OPCIONAL en el schema cuando el caso tiene MÁS DE
    UNA evidencia, para que el agente pueda apuntar cada herramienta a la evidencia
    adecuada (memoria → volatility3; disco → tsk_*). Con una sola evidencia no se
    añade nada (Agentopsy inyecta esa por defecto). Devuelve una COPIA — nunca muta
    el schema del módulo."""
    if len(evidence_choices) <= 1:
        return schema
    catalogo = "; ".join(f"{eid} = {label}" for eid, label in evidence_choices)
    props = dict(schema.get("properties", {}))
    props["evidence_id"] = {
        "type": "string",
        "enum": [eid for eid, _ in evidence_choices],
        "description": (
            "Sobre qué evidencia del caso corre esta herramienta. Elígela por su "
            f"tipo: {catalogo}. Omítelo para usar la evidencia primaria. La memoria "
            "se analiza con volatility3; el disco con tsk_*/regripper."
        ),
    }
    return {**schema, "properties": props}


def tool_spec(
    tool_id: str, evidence_choices: list[tuple[str, str]] | None = None
) -> dict[str, Any] | None:
    """Return the function-calling spec for ``tool_id``, or None if unsupported."""
    if tool_id not in TOOL_PARAM_SCHEMAS:
        return None
    schema = TOOL_PARAM_SCHEMAS[tool_id]
    if evidence_choices:
        schema = _with_evidence_selector(schema, evidence_choices)
    return {
        "type": "function",
        "function": {
            "name": tool_id,
            "description": TOOL_DESCRIPTIONS.get(tool_id, ""),
            "parameters": schema,
        },
    }


def tool_specs(
    tool_ids: list[str] | tuple[str, ...],
    evidence_choices: list[tuple[str, str]] | None = None,
) -> list[dict[str, Any]]:
    specs = []
    for tid in tool_ids:
        spec = tool_spec(tid, evidence_choices)
        if spec is not None:
            specs.append(spec)
    return specs
