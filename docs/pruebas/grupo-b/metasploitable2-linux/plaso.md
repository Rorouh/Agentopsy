# `plaso_log2timeline` + `plaso_psort` — sobre `metasploitable2-linux`

- **Grupo:** B · **Imagen:** Metasploitable 2 · **Estado:** ✅ **INTEGRADAS** (wrappers implementados esta sesión)
- **Binarios:** `log2timeline.py` + `psort.py` (plaso 20240308) · **Maletín:** `toolkit-unix`
- **run_ids:** log2timeline `5ef3afbd` · psort `50748d14`

## Objetivo (máxima expresión)

**Super-timeline multi-fuente.** A diferencia de `tsk_mactime` (solo tiempos de FS de un
bodyfile), plaso corre **decenas de parsers** (filestat, syslog, navegadores, registro,
EVTX…) y consolida todo en un `.plaso`, que `psort` exporta a CSV/JSON con filtros. Es la
columna vertebral cronológica más rica.

## ✅ Integración (fix de Bug 003 — pareja de tools)

Ambas eran stubs. Integradas: `wrappers/plaso_log2timeline.py` (SOURCE + `--storage_file`,
`--partitions`, `--parsers`, `--no_vss`, `--status_view none`) y `wrappers/plaso_psort.py`
(`-o <formato>` `-w <csv>` PATH). Catálogo, `_EVIDENCE_INJECTION`
(`plaso_log2timeline→image_path`, `plaso_psort→plaso_path` como `mactime→bodyfile`) y tests
`TestPlasoLog2timeline`/`TestPlasoPsort`.

## Cómo las usé (encadenado)

```
# 1) log2timeline: SOURCE → .plaso  (acotado a /boot, partición 1, por tiempo)
execute("plaso_log2timeline", {"image_path": <raw>, "partitions": "1"}, …)
→ exit 0, run 5ef3afbd, "Processing completed" · artefacto <run>/out/timeline.plaso

# 2) psort: .plaso → CSV l2tcsv
execute("plaso_psort", {"plaso_path": <.plaso>, "output_format": "l2tcsv"}, …)
→ exit 0, run 50748d14 · artefacto <run>/out/timeline.csv
```

## Resultado obtenido — exit 0 en las dos

**60 eventos** del `/boot` en formato `l2tcsv`, **enriquecidos**: fecha/hora/TZ, **MACB**,
source, inode, y **SHA-256 por fichero**. Ejemplos:
- `vmlinuz-2.6.24-16-server` — modificado `2008-04-10` (build del kernel).
- `grub/*_stage1_5` — `2010-03-16` (instalación de grub).

Acotado a `/boot` a propósito (partición pequeña); el super-timeline **del disco completo**
daría **cientos de miles** de eventos multi-fuente (logs, historiales, etc.), pero es MUY
lento bajo emulación.

## Veredicto de eficacia

- **Muy eficaz e integradas**: el encadenado log2timeline→psort funciona por el dispatcher con
  cadena de custodia; el CSV supera a mactime (añade hashes, source types, filtrable).
- **Coste alto**: en disco completo es la tool más lenta; acótala con `partitions`/`parsers` o
  lánzala en background.

## Lecciones para entrenar al agente

1. **plaso es un flujo de 2 pasos**: `log2timeline` (→ `.plaso`) y luego `psort` (→ CSV/JSON).
   El `.plaso` es un artefacto intermedio; pásalo como `plaso_path` a psort.
2. **Acota o resérvalo**: en disco completo es lentísimo; usa `partitions`/`parsers`
   (`filestat`, `linux`, `webhist`…) para dirigirlo, o anúncialo como paso largo.
3. **Prefiere plaso a mactime cuando necesites multi-fuente** (logs + FS + registro + …) o
   hashes por evento; usa mactime para un timeline de FS rápido.
4. **`psort` filtra**: rango temporal / formato (l2tcsv, dynamic, json_line) para no volcar
   todo — encadénalo con `jq` si sacas JSON.

## Registro en el caso

- **Finding:** `c7bf7a5b` — "Super-timeline plaso con hashes por evento" (low), run `50748d14`.
- **Evidencia recopilada:** [`plaso/timeline-boot.csv`](plaso/timeline-boot.csv) (60 eventos
  l2tcsv). El `.plaso` intermedio en el `ArtifactRun` `5ef3afbd`.
