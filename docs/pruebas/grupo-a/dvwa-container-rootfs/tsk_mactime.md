# `tsk_mactime` — sobre `dvwa-container-rootfs/dvwa-disk.raw`

- **Grupo:** A · **Imagen:** DVWA docker rootfs (ext4 plano) · **Estado:** ✅ eficaz (matiz de parse)
- **Binario:** `mactime` (Sleuthkit) · **Maletín:** `toolkit-unix` (Cross)
- **run_id:** `da7134af-8c83-4a8f-a3d1-b73e7782b535`
- **Entrada:** bodyfile de `tsk_fls -m` (run `4ff7bdf2`, 14.234 líneas) — no la imagen.

## Objetivo (máxima expresión)

`mactime` convierte un **bodyfile** (de `fls -m`) en una **línea temporal MAC(b)** ordenada
(Modified / Accessed / Changed / Birth). Es la columna vertebral cronológica del caso.
Esperaba ver la actividad del sistema ordenada en el tiempo y poder distinguir ventanas
(instalación vs manipulación vs uso).

## Cómo la usé (params + argv)

Wrapper `tsk_mactime.py`. Params: `bodyfile_path` (req.), `iso_dates` (`-y`, def true),
`timezone` (`-z`), `date_range`. **No toma la imagen**: consume el bodyfile del paso `fls -m`.

```
argv = ["mactime", "-b", <bodyfile>, "-d", "-y"]   # -d CSV, -y fechas ISO
```

## Resultado obtenido — exit 0

- **43.604 eventos** de timeline (más que las 14.234 entradas de `fls`: cada fichero aporta
  varias marcas M/A/C/B).
- **Rango:** `1996-07-28` → `2026-07-03T18:16:44Z`.
- **Lectura forense clave** (top marcas por nº de eventos):
  - `2026-07-03T18:16:31Z` → **9.324 eventos**, y varios miles más en los segundos siguientes:
    es la **ráfaga de nacimiento** de casi todo el árbol = **cuándo fabricamos la imagen**
    (`mkfs.ext4 -d`).
  - `2018-06-10` / `2018-05-04` → miles de eventos = **instalación de paquetes** del build del
    contenedor (Debian/DVWA).
  - Último evento: `/var/www/html/vulnerabilities/xss…` (estructura de la app DVWA).

Esto separa **"cuándo se instaló el sistema"** (2018) de **"cuándo se creó esta evidencia"**
(2026-07-03) — justo lo que un perito quiere anclar.

## Matiz de parse (no bug grave, pero a saber)

Con `iso_dates=true` (`-y`), las fechas usan `T` como separador (`2026-07-03T18:16:31Z`). El
`parse` agrupa el histograma con `parts[0].split(" ")[0]` (espera un espacio), así que
**`top_days` agrupa por marca de segundo, no por día**, y `days_count` (805) cuenta segundos
distintos, no días. Útil igual (localiza la ráfaga), pero el nombre "days" engaña.

## Veredicto de eficacia

- **Muy eficaz**: produjo el timeline completo y la ráfaga de creación saltó a la vista.
- **Depende del paso previo** (`fls -m`): sin bodyfile no hay mactime — el encadenado
  `fls -m` → `mactime` es obligado.
- Parse mejorable (agrupación por día con ISO).

## Lecciones para entrenar al agente

1. **`mactime` NO lee la imagen**: necesita el `bodyfile_path` de un `tsk_fls` con
   `body_format:true` previo. Encadénalos siempre.
2. **La ráfaga de nacimiento delata la fabricación de la evidencia**: en una imagen "creada"
   (contenedor, dd reciente) verás miles de eventos B en un mismo segundo. No lo confundas con
   actividad del usuario — es artefacto de creación.
3. **Ancla los hallazgos a marcas del timeline**, no a la hora de ejecución de la tool.
4. Para acotar, usa `date_range` (`YYYY-MM-DD..YYYY-MM-DD`) y `timezone` — en una imagen real
   con actividad, esto separa la ventana del incidente del ruido.

## Registro en el caso

- **Finding:** `f4073ad3` — "Timeline MAC(b): ráfaga de creación 2026-07-03 sobre base de 2018" (low), procedencia `tsk_mactime` / run `da7134af`.
- **Evidencia recopilada:** [`tsk_mactime/timeline-resumen.txt`](tsk_mactime/timeline-resumen.txt)
  (primeros/últimos + timeline de `/var/www/html`). El CSV completo (43.604 filas) vive en el
  `ArtifactRun` `da7134af`.
