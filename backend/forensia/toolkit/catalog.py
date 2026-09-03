"""The curated maletín. Each entry is a closed-enum Tool the agent may select.

Tiers (the "kit primeros 30 minutos"; the exact core membership is pinned by
`tests/test_catalog_integrity.py::test_core_tier_matches_expected_kit`):
- `core`: the kit needed for a fast post-mortem. Required for the MVP.
- `extended`: additional tools that ride along once the core is stable (Plaso, hashing,
  carving extras, mount helpers).

Every tool here, and every binary the maletines carry WITHOUT exposing, is documented in
`docker/docs/CATALOGO_MALETIN.md` (one invocation example per tool + pinned versions).

Delivery (CLAUDE.md RULE 1): each tool declares the compose maletín image(s) that
physically carry its binary via `toolkits=` — `toolkit-unix` / `toolkit-windows`. Tools
in the shared `base` stage of `docker/docker/forensic-toolkit/Dockerfile` serve both
OS profiles and live in BOTH maletines (`MALETINES`); Windows-artifact tools (RegRipper,
hayabusa, chainsaw, the Eric Zimmerman .NET tools) live only in `toolkit-windows`.
`forensia.toolkit.maletin` probes those services and `capabilities` reports the result;
RULE 2 forbids resolving a tool against any maletín it does not declare here.

The legacy per-host-OS `delivery` + `container_image` fields are retained for the
not-yet-realigned dispatcher execution path; dropping them is the last item of the
"Remaining" list in CLAUDE.md, section Status.
"""

from __future__ import annotations

from forensia.path_policy import BundledPath, PathKind, PathParameter, PathRole
from forensia.toolkit.maletin import MALETINES, TOOLKIT_WINDOWS
from forensia.toolkit.tool import Tool
from forensia.toolkit.wrappers import (
    aff4imager as _aff4imager,
)
from forensia.toolkit.wrappers import (
    amcacheparser as _amcacheparser,
)
from forensia.toolkit.wrappers import (
    appcompatcacheparser as _appcompatcacheparser,
)
from forensia.toolkit.wrappers import (
    bulk_extractor as _bulk_extractor,
)
from forensia.toolkit.wrappers import (
    file_info as _file_info,
)
from forensia.toolkit.wrappers import (
    foremost as _foremost,
)
from forensia.toolkit.wrappers import (
    ftkimager as _ftkimager,
)
from forensia.toolkit.wrappers import (
    hashdeep as _hashdeep,
)
from forensia.toolkit.wrappers import (
    plaso_log2timeline as _plaso_log2timeline,
)
from forensia.toolkit.wrappers import (
    plaso_psort as _plaso_psort,
)
from forensia.toolkit.wrappers import (
    qemu_nbd as _qemu_nbd,
)
from forensia.toolkit.wrappers import (
    strings_head as _strings_head,
)
from forensia.toolkit.wrappers import (
    xxd_head as _xxd_head,
)
from forensia.toolkit.wrappers import (
    chainsaw as _chainsaw,
)
from forensia.toolkit.wrappers import (
    evtxecmd as _evtxecmd,
)
from forensia.toolkit.wrappers import (
    ewf_info as _ewf_info,
)
from forensia.toolkit.wrappers import (
    hayabusa as _hayabusa,
)
from forensia.toolkit.wrappers import (
    hindsight as _hindsight,
)
from forensia.toolkit.wrappers import (
    jlecmd as _jlecmd,
)
from forensia.toolkit.wrappers import (
    jq as _jq,
)
from forensia.toolkit.wrappers import (
    lecmd as _lecmd,
)
from forensia.toolkit.wrappers import (
    mftecmd as _mftecmd,
)
from forensia.toolkit.wrappers import (
    rbcmd as _rbcmd,
)
from forensia.toolkit.wrappers import (
    recmd as _recmd,
)
from forensia.toolkit.wrappers import (
    regripper as _regripper,
)
from forensia.toolkit.wrappers import (
    sbecmd as _sbecmd,
)
from forensia.toolkit.wrappers import (
    tsk_fls as _tsk_fls,
)
from forensia.toolkit.wrappers import (
    tsk_icat as _tsk_icat,
)
from forensia.toolkit.wrappers import (
    tsk_mactime as _tsk_mactime,
)
from forensia.toolkit.wrappers import (
    tsk_mmls as _tsk_mmls,
)
from forensia.toolkit.wrappers import (
    tsk_recover as _tsk_recover,
)
from forensia.toolkit.wrappers import (
    volatility3 as _volatility3,
)
from forensia.toolkit.wrappers import (
    wxtcmd as _wxtcmd,
)
from forensia.toolkit.wrappers import (
    yara as _yara,
)

# Cross tools ship in the `base` stage inherited by BOTH maletines; Windows artifacts
# only in `toolkit-windows`. (No catalog tool is `toolkit-unix`-exclusive today — the
# unix stage only adds journalctl/lnav/fs helpers that are not in the catalog.)
_BOTH = MALETINES
_WINDOWS = (TOOLKIT_WINDOWS,)

_E = (PathRole.EVIDENCE_INPUT,)
_C = (PathRole.CASE_INPUT,)
_D = (PathRole.DERIVED_INPUT,)
_ED = (PathRole.EVIDENCE_INPUT, PathRole.DERIVED_INPUT)
_CD = (PathRole.CASE_INPUT, PathRole.DERIVED_INPUT)
_O = (PathRole.RUN_OUTPUT,)


def _path(
    name: str,
    roles: tuple[PathRole, ...],
    kind: PathKind,
    *,
    required: bool = True,
) -> PathParameter:
    return PathParameter(name, roles, kind, required=required)


def _output(name: str, relpath: str, kind: PathKind) -> PathParameter:
    return PathParameter(name, _O, kind, output_relpath=relpath)


_OUTPUT_DIR = _output("output_dir", ".", PathKind.DIRECTORY)
_BULK_EXTRACTOR_OUTPUT = _output(
    "output_dir", "bulk_extractor", PathKind.DIRECTORY
)
_CHAINSAW_RULESET = PathParameter(
    "ruleset",
    (PathRole.BUNDLED_RULESET,),
    PathKind.DIRECTORY,
    required=False,
    bundled=(BundledPath("chainsaw-native", "/opt/chainsaw-src/rules"),),
)
_RECMD_BATCH = PathParameter(
    "batch",
    (PathRole.BUNDLED_RULESET,),
    PathKind.FILE,
    bundled=(
        BundledPath(
            "Kroll_Batch.reb",
            "/opt/eztools/RECmd/RECmd/BatchExamples/Kroll_Batch.reb",
        ),
    ),
)
_NBD_DEVICE = PathParameter(
    "nbd_device",
    (PathRole.RUNTIME_DEVICE,),
    PathKind.FILE,
    bundled=(BundledPath("nbd0", "/dev/nbd0"),),
)

# =============================================================================
# INSTALADO EN EL MALETÍN Y FUERA DEL CATÁLOGO, A PROPÓSITO
# =============================================================================
# Las imágenes traen bastantes más binarios de los que el catálogo expone. Un
# binario que está en el maletín y no aquí NO es un olvido: cada uno tiene un
# motivo, y están escritos para que quien audite el maletín encuentre la razón
# sin reabrir el debate ni exponerlos por error. Auditoría 2026-09-03, hecha
# contra las imágenes construidas, no contra el Dockerfile.
#
# Violan el invariante forense 3 (montar el sistema de ficheros de la evidencia):
#   guestmount          Monta el FS de la imagen. El invariante 3 exige leer la
#                       imagen SIN montarla (TSK/Volatility); `mount -o ro` no
#                       basta, el replay del journal escribe en la imagen.
#   guestfish, virt-*   Peor que guestmount: `virt-copy-in`, `virt-customize` y
#                       `virt-sysprep` ESCRIBEN en la imagen. Los arrastra
#                       `libguestfs-tools` sin que nadie los pidiera; quedan
#                       fuera por escrito, no por olvido.
#
# Son el mecanismo interno de Agentopsy, no herramientas del agente:
#   ewfmount            Lo usa `forensia.triage_deep` por el exec-agent para
#   qemu-storage-daemon abrir un contenedor en RO a nivel de BLOQUE. Exponerlos
#                       daría al modelo una vía de abrir la imagen fuera del
#                       control de `EvidenceManager` (invariante forense 1).
#   sha256sum           El hash-gate lo hace `EvidenceManager` en proceso; el
#                       hash de un artefacto lo pone el artifact-store.
#
# Redundan con una tool que ya está en el catálogo (RULE 2: dos caminos para el
# mismo artefacto es justo lo que no queremos que el modelo tenga que elegir):
#   evtx_dump           EVTX -> `evtxecmd` (EvtxECmd, además aplica sus Maps/).
#   lnkparse            .lnk -> `lecmd` (LECmd).
#   regipy-*            Hives -> `recmd` (RECmd) y `regripper`.
#   md5deep, sha1deep,  Hashing recursivo -> `hashdeep`, que es el mismo binario
#   sha256deep, ...     de md5deep con otro nombre.
#   psteal.py           log2timeline + psort en un paso -> ya cubierto por
#                       `plaso_log2timeline` + `plaso_psort`, y más controlable.
#
# No se pueden ejecutar por el canal del exec-agent (argv sin shell, INVARIANTE
# DE SEGURIDAD 4: no hay tuberías ni redirecciones):
#   bstrings            En Linux solo procesa por stdin (`cat f | bstrings`);
#                       sus modos -f/-d no procesan en no-Windows en el build
#                       2026.5.0. Es de uso manual desde el maletín.
#
# Utilidad de operador, interactivas o sin valor pericial propio:
#   rg, less, lnav      Búsqueda y navegación de logs a mano.
#   journalctl          Journals exportados; se leen a mano o vía plaso.
#   qemu-img, dumpe2fs, Inspección de contenedor y de sistema de ficheros a mano.
#   debugfs, xfs_db
#   volshell, yarac     Shell interactiva de Volatility y compilador de reglas.
#
# Candidatas RECONOCIDAS y todavía no expuestas (no son exclusiones, son deuda):
#   fsstat              Tipo de FS, tamaño de sector y clúster, número de serie
#                       del volumen y última vez montado. (La zona horaria del
#                       sistema investigado NO sale de aquí: sale del hive
#                       SYSTEM, TimeZoneInformation, que ya cubre `regripper`.)
#   ewfverify           Verifica el hash interno del EWF contra el que escribió
#                       quien adquirió: una afirmación de custodia citable que
#                       Agentopsy no puede producir por otra vía.
#   ntfsundelete,       Borrados y anti-forense.
#   usnjls, ils
# =============================================================================
CATALOG: tuple[Tool, ...] = (
    # ====== CORE TIER — kit "primeros 30 minutos" ======

    # --- "Primer vistazo": characterize the file BEFORE invoking forensic tools ---
    Tool(
        "file_info",
        "file",
        ("unix", "windows"),
        tier="core",
        toolkits=_BOTH,
        path_parameters=(_path("image_path", _E, PathKind.FILE),),
        allowed_flags=_file_info.ALLOWED_FLAGS,
        build_argv=_file_info.build_argv,
        parse=_file_info.parse,
    ),
    Tool(
        "xxd_head",
        "xxd",
        ("unix", "windows"),
        tier="core",
        toolkits=_BOTH,
        path_parameters=(_path("image_path", _E, PathKind.FILE),),
        allowed_flags=_xxd_head.ALLOWED_FLAGS,
        build_argv=_xxd_head.build_argv,
        parse=_xxd_head.parse,
    ),
    Tool(
        "strings_head",
        "strings",
        ("unix", "windows"),
        tier="core",
        toolkits=_BOTH,
        path_parameters=(_path("image_path", _E, PathKind.FILE),),
        allowed_flags=_strings_head.ALLOWED_FLAGS,
        build_argv=_strings_head.build_argv,
        parse=_strings_head.parse,
    ),

    # --- Sistema de ficheros / particiones (TSK, en el stage base de ambos maletines) ---
    Tool(
        "tsk_mmls",
        "mmls",
        ("unix", "windows"),
        tier="core",
        toolkits=_BOTH,
        image_param="image_path",
        path_parameters=(_path("image_path", _E, PathKind.FILE),),
        allowed_flags=_tsk_mmls.ALLOWED_FLAGS,
        build_argv=_tsk_mmls.build_argv,
        parse=_tsk_mmls.parse,
    ),
    Tool(
        "tsk_fls",
        "fls",
        ("unix", "windows"),
        returns="artifact",
        tier="core",
        toolkits=_BOTH,
        image_param="image_path",
        # In `-m` (body_format) mode fls's stdout IS the bodyfile mactime consumes; capture
        # it to a hashed out/ artifact so it is referenceable as {run_id, relpath} (else the
        # fls→mactime chain has no resolvable input). Inline listing mode is unaffected.
        stdout_artifact_param="body_format",
        path_parameters=(_path("image_path", _E, PathKind.FILE),),
        allowed_flags=_tsk_fls.ALLOWED_FLAGS,
        build_argv=_tsk_fls.build_argv,
        parse=_tsk_fls.parse,
    ),
    Tool(
        "tsk_mactime",
        "mactime",
        ("unix", "windows"),
        returns="artifact",
        tier="core",
        toolkits=_BOTH,
        input_artifact_params=("bodyfile_path",),
        path_parameters=(_path("bodyfile_path", _D, PathKind.FILE),),
        allowed_flags=_tsk_mactime.ALLOWED_FLAGS,
        build_argv=_tsk_mactime.build_argv,
        parse=_tsk_mactime.parse,
    ),

    # --- Imagen (libewf, stage base de ambos maletines) ---
    Tool(
        "ewf_info",
        "ewfinfo",
        ("unix", "windows"),
        tier="core",
        toolkits=_BOTH,
        path_parameters=(_path("image_path", _E, PathKind.FILE),),
        allowed_flags=_ewf_info.ALLOWED_FLAGS,
        build_argv=_ewf_info.build_argv,
        parse=_ewf_info.parse,
    ),

    # --- Carving / IoCs (stage base de ambos maletines) ---
    Tool(
        "bulk_extractor",
        "bulk_extractor",
        ("unix", "windows"),
        returns="artifact",
        tier="core",
        toolkits=_BOTH,
        path_parameters=(
            _path("image_path", _E, PathKind.FILE),
            _BULK_EXTRACTOR_OUTPUT,
        ),
        allowed_flags=_bulk_extractor.ALLOWED_FLAGS,
        build_argv=_bulk_extractor.build_argv,
        parse=_bulk_extractor.parse,
    ),
    Tool(
        "yara",
        "yara",
        ("unix", "windows"),
        returns="artifact",
        tier="core",
        toolkits=_BOTH,
        path_parameters=(
            _path("rules_path", _C, PathKind.FILE_OR_DIRECTORY),
            _path("target_path", _E, PathKind.FILE_OR_DIRECTORY),
        ),
        allowed_flags=_yara.ALLOWED_FLAGS,
        build_argv=_yara.build_argv,
        parse=_yara.parse,
    ),

    # --- Memoria RAM (Volatility 3, stage base de ambos maletines) ---
    Tool(
        "volatility3",
        "vol",
        ("unix", "windows"),
        returns="artifact",
        tier="core",
        toolkits=_BOTH,
        # Derived handoff: además del memdump registrado como evidencia, acepta el
        # raw que un run previo materializó (p. ej. el stream de memoria física que
        # aff4imager exportó de un volcado WinPmem .aff4) como ArtifactRef
        # (re-hasheado antes del run — custodia de derivados).
        input_artifact_params=("dump_path",),
        path_parameters=(_path("dump_path", _ED, PathKind.FILE),),
        allowed_flags=_volatility3.ALLOWED_FLAGS,
        build_argv=_volatility3.build_argv,
        parse=_volatility3.parse,
    ),

    # --- EVTX / Sigma (Rust, solo en el maletín windows) ---
    Tool(
        "hayabusa",
        "hayabusa",
        ("windows",),
        returns="artifact",
        tier="core",
        toolkits=_WINDOWS,
        path_parameters=(
            _path("evtx_dir", _E, PathKind.DIRECTORY),
            _output("output_csv", "hayabusa.csv", PathKind.FILE),
        ),
        allowed_flags=_hayabusa.ALLOWED_FLAGS,
        build_argv=_hayabusa.build_argv,
        parse=_hayabusa.parse,
    ),
    Tool(
        "chainsaw",
        "chainsaw",
        ("windows",),
        returns="artifact",
        tier="core",
        toolkits=_WINDOWS,
        path_parameters=(
            _path("target_dir", _E, PathKind.DIRECTORY),
            _path("sigma_dir", _C, PathKind.DIRECTORY, required=False),
            _path("rules_dir", _C, PathKind.DIRECTORY, required=False),
            _CHAINSAW_RULESET,
            _output("output_path", "chainsaw", PathKind.DIRECTORY),
        ),
        allowed_flags=_chainsaw.ALLOWED_FLAGS,
        build_argv=_chainsaw.build_argv,
        parse=_chainsaw.parse,
    ),

    # --- Eric Zimmerman .NET tools: viven en el maletín windows (EvtxECmd/MFTECmd,
    #     .dll net9 sobre el runtime .NET absorbido en su Dockerfile), ejecutados por
    #     el exec-agent como el resto (2026-07-04). ---
    Tool(
        "evtxecmd",
        "EvtxECmd",
        ("windows",),
        returns="artifact",
        tier="core",
        toolkits=_WINDOWS,
        # Derived handoff: the .evtx it parses is normally the byte-exact file a prior
        # TSK `icat` run extracted, so `evtx_path` accepts an ArtifactRef the dispatcher
        # resolves + re-hashes (custody of the derivative). A literal evidence path
        # (or Agentopsy-injected evidence) still works when omitted.
        input_artifact_params=("evtx_path",),
        path_parameters=(
            _path("evtx_path", _ED, PathKind.FILE_OR_DIRECTORY),
            _OUTPUT_DIR,
        ),
        allowed_flags=_evtxecmd.ALLOWED_FLAGS,
        build_argv=_evtxecmd.build_argv,
        parse=_evtxecmd.parse,
    ),
    Tool(
        "mftecmd",
        "MFTECmd",
        ("windows",),
        returns="artifact",
        tier="core",
        toolkits=_WINDOWS,
        # Derived handoff: the $MFT it parses is normally the file a prior TSK `icat`
        # run extracted, so `mft_path` accepts an ArtifactRef (re-hashed before run).
        input_artifact_params=("mft_path",),
        path_parameters=(
            _path("mft_path", _ED, PathKind.FILE),
            _OUTPUT_DIR,
        ),
        allowed_flags=_mftecmd.ALLOWED_FLAGS,
        build_argv=_mftecmd.build_argv,
        parse=_mftecmd.parse,
    ),

    # --- Registry (Perl): vive en el maletín windows, ejecutado por el exec-agent ---
    Tool(
        "regripper",
        "rip.pl",
        ("windows",),
        returns="artifact",
        tier="core",
        toolkits=_WINDOWS,
        # Derived handoff: the hive it parses is normally the byte-exact file a prior
        # TSK `icat` run extracted, so `hive_path` accepts an artifact ref ({run_id,
        # relpath}) the dispatcher resolves + re-hashes before running (custody of the
        # derivative). A literal path still works for a hive already under /evidence.
        input_artifact_params=("hive_path",),
        path_parameters=(
            _path("hive_path", _ED, PathKind.FILE, required=False),
        ),
        allowed_flags=_regripper.ALLOWED_FLAGS,
        build_argv=_regripper.build_argv,
        parse=_regripper.parse,
    ),

    # --- Helper de filtrado JSON para el agente (stage base de ambos maletines) ---
    Tool(
        "jq",
        "jq",
        ("unix", "windows"),
        tier="core",
        toolkits=_BOTH,
        input_artifact_params=("input_path",),
        path_parameters=(_path("input_path", _CD, PathKind.FILE),),
        allowed_flags=_jq.ALLOWED_FLAGS,
        build_argv=_jq.build_argv,
        parse=_jq.parse,
    ),

    # ====== EXTENDED TIER — se añaden tras estabilizar el core ======

    # Extracción puntual de ficheros (TSK, stage base)
    Tool(
        "tsk_icat",
        "icat",
        ("unix", "windows"),
        returns="artifact",
        # icat streams a file's RAW BYTES to stdout; capture them to a hashed artifact
        # file, never decode as text (would corrupt hives/EVTX/$MFT/executables).
        binary_stdout=True,
        image_param="image_path",
        toolkits=_BOTH,
        path_parameters=(_path("image_path", _E, PathKind.FILE),),
        allowed_flags=_tsk_icat.ALLOWED_FLAGS,
        build_argv=_tsk_icat.build_argv,
        parse=_tsk_icat.parse,
    ),

    # Extracción de un ÁRBOL de ficheros (TSK, stage base). Es el productor que le
    # faltaba al catálogo: `tsk_icat` saca UN fichero a `out/stdout.bin`, así que
    # ninguna tool podía construir un DIRECTORIO derivado. Lee la imagen sin montar
    # el sistema de ficheros, igual que el resto de la familia TSK.
    Tool(
        "tsk_recover",
        "tsk_recover",
        ("unix", "windows"),
        returns="artifact",
        toolkits=_BOTH,
        image_param="image_path",
        path_parameters=(
            _path("image_path", _E, PathKind.FILE),
            _OUTPUT_DIR,
        ),
        allowed_flags=_tsk_recover.ALLOWED_FLAGS,
        build_argv=_tsk_recover.build_argv,
        parse=_tsk_recover.parse,
    ),

    # Super-timeline (Plaso, stage base) — lento, kit "primera tarde"
    Tool(
        "plaso_log2timeline",
        "log2timeline.py",
        ("unix", "windows"),
        returns="artifact",
        toolkits=_BOTH,
        path_parameters=(
            _path("image_path", _E, PathKind.FILE_OR_DIRECTORY),
            _OUTPUT_DIR,
        ),
        allowed_flags=_plaso_log2timeline.ALLOWED_FLAGS,
        build_argv=_plaso_log2timeline.build_argv,
        parse=_plaso_log2timeline.parse,
    ),
    Tool(
        "plaso_psort",
        "psort.py",
        ("unix", "windows"),
        returns="artifact",
        toolkits=_BOTH,
        input_artifact_params=("plaso_path",),
        path_parameters=(
            _path("plaso_path", _D, PathKind.FILE),
            _OUTPUT_DIR,
        ),
        allowed_flags=_plaso_psort.ALLOWED_FLAGS,
        build_argv=_plaso_psort.build_argv,
        parse=_plaso_psort.parse,
    ),

    # Hashing / carving extra (stage base)
    Tool(
        "hashdeep",
        "hashdeep",
        ("unix", "windows"),
        returns="artifact",
        toolkits=_BOTH,
        path_parameters=(_path("image_path", _E, PathKind.FILE_OR_DIRECTORY),),
        allowed_flags=_hashdeep.ALLOWED_FLAGS,
        build_argv=_hashdeep.build_argv,
        parse=_hashdeep.parse,
    ),
    # Talla por FIRMAS (cabecera/pie), así que el SO de la evidencia le es indiferente:
    # declara los dos perfiles, como el resto de las cross. Hasta 2026-09-03 declaraba
    # solo `unix` con `toolkits=_BOTH`, así que estaba instalada en los dos maletines
    # pero un caso Windows no podía pedirla (los tipos que talla —exe, doc, ole, zip—
    # son justamente de Windows). `test_cross_tools_declare_both_os_profiles` lo fija.
    Tool(
        "foremost",
        "foremost",
        ("unix", "windows"),
        returns="artifact",
        toolkits=_BOTH,
        path_parameters=(
            _path("image_path", _E, PathKind.FILE),
            _OUTPUT_DIR,
        ),
        allowed_flags=_foremost.ALLOWED_FLAGS,
        build_argv=_foremost.build_argv,
        parse=_foremost.parse,
    ),

    # Conversión de imágenes (FTK Imager CLI 3.1.1, stage base — 2026-07-17):
    # raw↔E01/SMART con verificación MD5/SHA1 y reporte de adquisición. Lee los
    # contenedores de forma NATIVA, por eso NO declara image_param: la reescritura
    # ewfmount le daría la vista raw y perdería los metadatos EWF de la fuente.
    Tool(
        "ftkimager",
        "ftkimager",
        ("unix", "windows"),
        returns="artifact",
        toolkits=_BOTH,
        path_parameters=(
            _path("image_path", _E, PathKind.FILE),
            _OUTPUT_DIR,
        ),
        allowed_flags=_ftkimager.ALLOWED_FLAGS,
        build_argv=_ftkimager.build_argv,
        parse=_ftkimager.parse,
    ),

    # Volúmenes AFF4 (Velocidex c-aff4, stage base — 2026-07-17): consumir la
    # SALIDA de WinPmem 3.x (volcados de RAM .aff4). Dos modos explícitos (RULE 2):
    # sin `stream` lista los URNs del volumen; con `stream` (URN literal de un
    # listado previo) exporta ese stream al out/ del run — que volatility3 puede
    # consumir como derivado. WinPmem en sí NO se empaqueta (adquisición en vivo).
    Tool(
        "aff4imager",
        "aff4imager",
        ("unix", "windows"),
        returns="artifact",
        toolkits=_BOTH,
        path_parameters=(
            _path("image_path", _E, PathKind.FILE),
            _OUTPUT_DIR,
        ),
        allowed_flags=_aff4imager.ALLOWED_FLAGS,
        build_argv=_aff4imager.build_argv,
        parse=_aff4imager.parse,
    ),

    # Montaje auxiliar (side-effecting; qemu-utils en el stage base)
    Tool(
        "qemu_nbd",
        "qemu-nbd",
        ("unix",),
        side_effecting=True,
        toolkits=_BOTH,
        path_parameters=(
            _path("image_path", _E, PathKind.FILE),
            _NBD_DEVICE,
        ),
        allowed_flags=_qemu_nbd.ALLOWED_FLAGS,
        build_argv=_qemu_nbd.build_argv,
        parse=_qemu_nbd.parse,
    ),

    # --- EZ Tools (Eric Zimmerman, .NET): los parsers de los Modules de KAPE
    #     absorbidos en el maletín windows el 2026-07-07 (wrappers en minúsculas
    #     en su PATH; ver docker/docs/CATALOGO_MALETIN.md § EZ Tools). PECmd y
    #     SrumECmd NO existen en el maletín (Windows-only: ntdll/ESENT) y
    #     bstrings queda fuera del catálogo: en Linux solo procesa por stdin y
    #     el canal exec-agent ejecuta argv sin shell (sin tuberías) — es una
    #     herramienta de uso manual del maletín. ---
    Tool(
        "lecmd",
        "lecmd",
        ("windows",),
        returns="artifact",
        toolkits=_WINDOWS,
        # Derived handoff: accepts the .lnk a prior TSK `icat` extracted as an
        # ArtifactRef (re-hashed before run); a literal/injected evidence path when omitted.
        input_artifact_params=("target_path",),
        path_parameters=(
            _path("target_path", _ED, PathKind.FILE_OR_DIRECTORY),
            _OUTPUT_DIR,
        ),
        allowed_flags=_lecmd.ALLOWED_FLAGS,
        build_argv=_lecmd.build_argv,
        parse=_lecmd.parse,
    ),
    Tool(
        "jlecmd",
        "jlecmd",
        ("windows",),
        returns="artifact",
        toolkits=_WINDOWS,
        # Derived handoff: accepts the Jump List a prior TSK `icat` extracted as an
        # ArtifactRef (re-hashed before run); a literal/injected evidence path when omitted.
        input_artifact_params=("target_path",),
        path_parameters=(
            _path("target_path", _ED, PathKind.FILE_OR_DIRECTORY),
            _OUTPUT_DIR,
        ),
        allowed_flags=_jlecmd.ALLOWED_FLAGS,
        build_argv=_jlecmd.build_argv,
        parse=_jlecmd.parse,
    ),
    Tool(
        "recmd",
        "recmd",
        ("windows",),
        returns="artifact",
        toolkits=_WINDOWS,
        path_parameters=(
            _path("hive_path", _E, PathKind.FILE_OR_DIRECTORY),
            _OUTPUT_DIR,
            _RECMD_BATCH,
        ),
        allowed_flags=_recmd.ALLOWED_FLAGS,
        build_argv=_recmd.build_argv,
        parse=_recmd.parse,
    ),
    Tool(
        "amcacheparser",
        "amcacheparser",
        ("windows",),
        returns="artifact",
        toolkits=_WINDOWS,
        path_parameters=(
            _path("hive_path", _E, PathKind.FILE),
            _OUTPUT_DIR,
        ),
        allowed_flags=_amcacheparser.ALLOWED_FLAGS,
        build_argv=_amcacheparser.build_argv,
        parse=_amcacheparser.parse,
    ),
    Tool(
        "appcompatcacheparser",
        "appcompatcacheparser",
        ("windows",),
        returns="artifact",
        toolkits=_WINDOWS,
        # Derived handoff: accepts the SYSTEM hive a prior TSK `icat` extracted as an
        # ArtifactRef (re-hashed before run); a literal/injected evidence path when omitted.
        input_artifact_params=("hive_path",),
        path_parameters=(
            _path("hive_path", _ED, PathKind.FILE),
            _OUTPUT_DIR,
        ),
        allowed_flags=_appcompatcacheparser.ALLOWED_FLAGS,
        build_argv=_appcompatcacheparser.build_argv,
        parse=_appcompatcacheparser.parse,
    ),
    Tool(
        "sbecmd",
        "sbecmd",
        ("windows",),
        returns="artifact",
        toolkits=_WINDOWS,
        # Derived handoff: accepts a directory of hives a prior TSK `icat`/carve run
        # produced as an ArtifactRef (re-hashed before run); injected evidence when omitted.
        input_artifact_params=("target_path",),
        path_parameters=(
            _path("target_path", _ED, PathKind.DIRECTORY),
            _OUTPUT_DIR,
        ),
        allowed_flags=_sbecmd.ALLOWED_FLAGS,
        build_argv=_sbecmd.build_argv,
        parse=_sbecmd.parse,
    ),
    Tool(
        "wxtcmd",
        "wxtcmd",
        ("windows",),
        returns="artifact",
        toolkits=_WINDOWS,
        # Derived handoff: accepts the ActivitiesCache.db a prior TSK `icat` extracted
        # as an ArtifactRef (re-hashed before run); injected evidence when omitted.
        input_artifact_params=("target_path",),
        path_parameters=(
            _path("target_path", _ED, PathKind.FILE),
            _OUTPUT_DIR,
        ),
        allowed_flags=_wxtcmd.ALLOWED_FLAGS,
        build_argv=_wxtcmd.build_argv,
        parse=_wxtcmd.parse,
    ),
    # --- Artefactos de navegador (pyhindsight, Python, maletín windows) ---
    #     La ÚNICA tool de navegador del catálogo: el ejemplo canónico del encargo
    #     («toda la navegación web del usuario entre dos fechas») no tenía ninguna.
    #     Consume el DIRECTORIO de perfil, así que su ruta es DERIVED_INPUT y solo
    #     eso: llega como ArtifactRef del `tsk_recover` que lo extrajo, y el
    #     dispatcher lo re-hashea entero antes de ejecutar. Nunca una ruta libre.
    #     El envoltorio fija además `-l` y `--temp_dir`, que por defecto escriben
    #     junto al propio script, fuera del caso.
    Tool(
        "hindsight",
        "hindsight.py",
        ("windows",),
        returns="artifact",
        toolkits=_WINDOWS,
        input_artifact_params=("profile_dir",),
        path_parameters=(
            _path("profile_dir", _D, PathKind.DIRECTORY),
            _OUTPUT_DIR,
        ),
        allowed_flags=_hindsight.ALLOWED_FLAGS,
        build_argv=_hindsight.build_argv,
        parse=_hindsight.parse,
    ),
    Tool(
        "rbcmd",
        "rbcmd",
        ("windows",),
        returns="artifact",
        toolkits=_WINDOWS,
        path_parameters=(
            _path("target_path", _E, PathKind.FILE_OR_DIRECTORY),
            _OUTPUT_DIR,
        ),
        allowed_flags=_rbcmd.ALLOWED_FLAGS,
        build_argv=_rbcmd.build_argv,
        parse=_rbcmd.parse,
    ),
)

BY_ID = {tool.id: tool for tool in CATALOG}


def for_profile(os_profile: str) -> tuple[Tool, ...]:
    return tuple(t for t in CATALOG if os_profile in t.os_profiles)


def by_tier(tier: str) -> tuple[Tool, ...]:
    return tuple(t for t in CATALOG if t.tier == tier)
