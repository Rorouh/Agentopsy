# `strings_head` — sobre `dvwa-container-rootfs/dvwa-disk.raw`

- **Grupo:** A · **Imagen:** DVWA docker rootfs (ext4 plano) · **Estado:** ✅ muy eficaz (con matices de uso)
- **Binario:** `strings` · **Maletín:** `toolkit-unix` (Cross)
- **run_id:** `dbbaa423-f328-4fc8-a304-5bb340dd8703`

## Objetivo (qué se espera de la tool en su máxima expresión)

Segundo "primer vistazo" tras `file_info`: sacar **strings imprimibles** que desambiguan un
blob — banners de versión, rutas embebidas, nombres de vendor, y con suerte **secretos en
claro** (credenciales, tokens) que quedaron en el FS. Esperaba paths `/var/www`, versiones
del stack LAMP y, en un DVWA, las credenciales de su `config.inc.php`.

## Cómo la usé (params + porqué + argv real)

Wrapper `strings_head.py`. Params: `image_path`, `min_len` (`-n`, 4..256, def 12), `radix`
(`-t d|o|x`, muestra offsets). `ALLOWED_FLAGS` incluye `-e` y `-a`, **pero `build_argv` NO
los emite** (limitación, ver abajo).

```
argv = ["strings", "-n", "12", "-t", "x", <img>]
```
Elegí `radix='x'` (offsets hex) para poder **localizar** cada hallazgo dentro de la imagen,
y `min_len=12` (default) como equilibrio ruido/señal.

## Resultado obtenido — exit 0

- **Volumen:** `stdout.txt` de **99 MB**, **2 064 158 líneas**. (El `parse` reenvía al LLM
  solo 200 de cabeza + 50 de cola; el resto vive en el artefacto.)
- **Criba del artefacto** (grep sobre `stdout.txt`) — hallazgos reales:
  - **Credenciales DVWA en claro**, con offset:
    - `1b2c95a1  $_DVWA[ 'db_user' ] = 'root';`
    - `1b2c95c0  $_DVWA[ 'db_password' ] = 'p@ssw0rd';`
  - Config: `config/config.inc.php` (offset `1b2bb000`).
  - Versiones: `Apache/2.4.25`, `MySQL 5.0.x`.
  - Rutas/markers: `/var/www/html`, `shell_execve`.

Nota: los hallazgos jugosos están en offset `~0x1b2c95xx` (≈ 453 MB dentro de la imagen) —
**muy lejos** de las primeras 200 líneas.

## Veredicto de eficacia

- **Muy eficaz como fuente de intel**: sacó credenciales, versiones y rutas de un vistazo.
- **Pero el modo "imagen entera" es traicionero para un LLM**: 99 MB / 2 M líneas no caben
  en contexto, y el `head` parseado (primeras 200) **no contiene** lo importante. Sin cribar
  el artefacto, el agente "no ve" las credenciales.

## Lecciones para entrenar al agente

1. **`strings` sobre la imagen COMPLETA genera un artefacto enorme** (aquí 99 MB). NO leas el
   `head` crudo esperando el hallazgo: casi nunca está en las primeras líneas.
2. **Filtra el artefacto, no lo vuelques:** tras `strings_head`, encadena `jq`/grep por
   patrones (credenciales `db_password|password|token`, versiones `Apache/|MySQL|PHP/`,
   IOCs `http|@|[0-9]{1,3}(\.[0-9]{1,3}){3}`) sobre el `stdout.txt` del `run_id`.
3. **Usa `radix='x'`** siempre que quieras poder **anclar el hallazgo por offset** dentro de
   la imagen (y luego mapearlo a un fichero con `tsk_fls`/`tsk_icat`).
4. **Mucho mejor dirigido:** exprime `strings` sobre **ficheros extraídos** concretos (p. ej.
   `config.inc.php` recuperado con `tsk_icat`) en vez de sobre la imagen entera — señal
   altísima, artefacto minúsculo.
5. **`min_len`:** súbelo (20-30) para reducir ruido en imágenes grandes; bájalo (6-8) solo
   sobre ficheros pequeños concretos.
6. **Limitación real:** el wrapper **no capta strings de 16/32-bit** (`-e l/b`) → en
   evidencia **Windows** (UTF-16) `strings` de 8-bit se pierde media película. Para Windows,
   no confíes solo en esta tool.

## Acciones de mejora sugeridas (producto)

- **Exponer `-e` (encoding) en `build_argv`** (ya está en `ALLOWED_FLAGS`): permite
  `-e l`/`-e b` para UTF-16 — imprescindible para artefactos Windows.
- Considerar un **filtro server-side** (patrón/grep en el exec-agent) para no materializar
  99 MB cuando solo interesan las coincidencias.

## Registro en el caso

- **Findings:**
  - `6b07b440` — "Credenciales de BD DVWA en claro en la imagen" (medium) — `root`/`p@ssw0rd`
    (offset `0x1b2c95a1`) y `app`/`vulnerables` (offset `0x1b2cd2f9`).
  - `c4d9b3de` — "Stack web identificado: Apache 2.4.25 / MySQL 5.x" (low).
  - Ambos con procedencia `strings_head` / run `dbbaa423`.
- **Evidencia recopilada:** [`strings_head/hallazgos.txt`](strings_head/hallazgos.txt) (criba con
  offsets). El artefacto completo (99 MB) vive en el `ArtifactRun` del caso
  (`artifacts/dbbaa423-…/stdout.txt`), no se duplica aquí.
