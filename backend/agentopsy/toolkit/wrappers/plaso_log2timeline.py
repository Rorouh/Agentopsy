"""plaso `log2timeline.py` wrapper — build a super-timeline (.plaso storage) from a source.

Runs plaso's parsers over a disk image / partition / directory and writes a `.plaso`
storage file (the artifact) that `plaso_psort` then post-processes. Heavy: on a full disk
it runs dozens of parsers — bound it with `partitions` and/or `parsers` when testing.
"""

from __future__ import annotations

import re
from typing import Any

ALLOWED_FLAGS = frozenset(
    {
        "--storage_file",
        "--partitions",
        "--parsers",
        "--status_view",
        "--vss_stores",
        "-z",
        "--single_process",
        "--workers",
        "--unattended",
        "--volumes",
    }
)

#: Selector de volúmenes (LVM/APFS), misma gramática que `--partitions`.
_VOLUMES_RE = re.compile(r"^(all|[0-9,.]+)$")

#: Número de workers que desactiva el motor multiproceso pidiendo `--single_process`.
_SINGLE_PROCESS = 1

# Parser filter expression (plaso preset/parser names, with ! and , and *). Kept as an
# allowlist pattern so the argv never carries an arbitrary token.
_PARSERS_RE = re.compile(r"^[A-Za-z0-9_,!*-]+$")
# Partition selector: "all" or comma/range of numbers (e.g. "1", "1,3", "p1").
_PARTITIONS_RE = re.compile(r"^(all|[0-9p,]+)$")


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for log2timeline.py.

    params:
        image_path (str, required): SOURCE (disk image / partition / dir). Injected.
        output_dir (str, required): run dir injected by the dispatcher; the .plaso goes to
            `<output_dir>/timeline.plaso`.
        partitions (str, optional): partition selector (`all` default, or `1`, `1,3`…).
        volumes (str, optional): LVM/APFS volume selector (`all` default).
        parsers (str, optional): plaso parser/preset filter (e.g. `filestat`, `linux`).
        timezone (str, optional): time zone (`-z`).
        workers (int, optional): worker processes. SIN este parámetro se corre
            `--single_process`; ver la nota de abajo antes de subirlo.

    **Tres banderas están puestas para que la corrida NO se cuelgue.** Las tres
    salen de una misma sesión medida el 2026-08-05, sobre una imagen de 8 GB con
    LVM (Metasploitable) y con el maletín EMULADO (los maletines van fijados a
    `linux/amd64` porque el PPA GIFT no publica arm64, así que en un host arm64
    corren bajo QEMU):

    1. ``--volumes`` (por defecto ``all``) y 2. ``--unattended``: plaso encontró
       dos volúmenes LVM y se quedó PREGUNTANDO por teclado cuál procesar
       («Volume identifier(s):»), bloqueado leyendo un stdin que el exec-agent no
       le da. Se comió los 1800 s del techo sin parsear un solo byte. Con stdin
       cerrado el fallo es aún peor: lee EOF, no procesa NINGÚN volumen y termina
       diciendo «Processing completed» con un `.plaso` vacío, es decir un
       resultado falso que parece un éxito. ``--unattended`` hace que plaso
       TERMINE CON ERROR en vez de preguntar (RULE 2: fallar alto, nunca esperar
       a un humano que no existe).
    3. ``--single_process``: ya sin el prompt, el motor multiproceso se colgaba
       igual, en `futex_wait_queue`, con 4 SEGUNDOS de CPU en 20 minutos y sin
       levantar un solo worker. El `multiprocessing` de plaso deadlockea bajo
       emulación. Con las tres banderas la misma corrida pasa a 100 % de CPU y el
       `.plaso` crece a 72 MB en 100 segundos.

    El monoproceso es más lento en x86 nativo, pero termina en los tres hosts: una
    herramienta colgada es infinitamente más lenta que una lenta, y el perito no
    puede diagnosticar un deadlock de QEMU desde el chat. Quien corra en x86
    nativo y quiera el motor multiproceso lo pide EXPLÍCITAMENTE con ``workers``
    (RULE 2: volver al modo que se cuelga es decisión del operador, nunca un
    default silencioso).
    """
    image_path = params.get("image_path")
    if not image_path or not isinstance(image_path, str):
        raise ValueError("plaso_log2timeline requires params.image_path: str")
    output_dir = params.get("output_dir")
    if not output_dir or not isinstance(output_dir, str):
        raise ValueError("plaso_log2timeline requires params.output_dir: str")

    partitions = params.get("partitions", "all")
    if not isinstance(partitions, str) or not _PARTITIONS_RE.match(partitions):
        raise ValueError("plaso_log2timeline partitions must be 'all' or a partition selector")

    # Volúmenes LVM/APFS: sin esto plaso PREGUNTA por teclado cuál procesar y se
    # cuelga hasta el techo de ejecución. `--unattended` cierra la misma puerta
    # para cualquier otra pregunta: termina con error en vez de esperar.
    volumes = params.get("volumes", "all")
    if not isinstance(volumes, str) or not _VOLUMES_RE.match(volumes):
        raise ValueError("plaso_log2timeline volumes must be 'all' or a volume selector")

    storage = output_dir.rstrip("/") + "/timeline.plaso"
    argv: list[str] = [
        "--status_view",
        "none",
        "--vss_stores",
        "none",
        "--unattended",
        "--partitions",
        partitions,
        "--volumes",
        volumes,
    ]

    if (parsers := params.get("parsers")):
        if not isinstance(parsers, str) or not _PARSERS_RE.match(parsers):
            raise ValueError("plaso_log2timeline parsers must be a plaso parser filter expression")
        argv += ["--parsers", parsers]
    if (tz := params.get("timezone")):
        if not isinstance(tz, str):
            raise ValueError("plaso_log2timeline timezone must be a str")
        argv += ["-z", tz]

    # Motor de ejecución: monoproceso salvo que el operador pida workers a propósito.
    workers = params.get("workers")
    if workers is None:
        argv.append("--single_process")
    else:
        if isinstance(workers, bool) or not isinstance(workers, int) or workers < 1:
            raise ValueError("plaso_log2timeline workers must be an int >= 1")
        argv += ["--single_process"] if workers == _SINGLE_PROCESS else ["--workers", str(workers)]

    argv += ["--storage_file", storage, image_path]
    return argv


def parse(stdout: str) -> dict[str, Any]:
    """log2timeline con `--status_view none` imprime poco; el resultado es el `.plaso`
    (artefacto). Extrae cualquier resumen que aparezca y reporta si terminó."""
    lower = stdout.lower()
    completed = "processing completed" in lower or "log2timeline" in lower
    return {
        "completed": completed,
        "note": "el resultado es <output_dir>/timeline.plaso (artefacto); procésalo con plaso_psort",
        "tail": [ln for ln in stdout.splitlines() if ln.strip()][-8:],
    }
