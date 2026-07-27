# `file_info` — sobre `dvwa-container-rootfs/dvwa-disk.raw`

- **Grupo:** A · **Imagen:** DVWA docker rootfs (ext4 plano) · **Estado:** ✅ con matices
- **Binario:** `file` · **Maletín:** `toolkit-unix` (Cross)
- **run_ids:** `72ea3c8c-1145-4e74-8865-c1221f0f38cf` (con `--mime`), `4d…` (descripción)

## Objetivo (qué se espera de la tool en su máxima expresión)

`file` identifica el tipo de un fichero por *magic bytes* (no por extensión). En el flujo
forense es el **"primer vistazo"**: caracterizar la evidencia **antes** de invocar tools
pesadas, para no equivocar la herramienta (p. ej. no lanzar Volatility contra un disco).
Esperaba que dijera *"ext4 filesystem"* con algún metadato (UUID, volumen, features).

## Cómo la usé (params + porqué + argv real)

El wrapper (`backend/forensia/toolkit/wrappers/file_info.py`) expone:
- `image_path` (req.) — lo inyecta Agentopsy.
- `also_mime` (bool) — añade info MIME. Flags permitidos: `-b -i -z -L --brief --mime`.

Probé **las dos pasadas** para exprimirla y comparar:

1. `also_mime=false` → `argv = ["file", "-b", <img>]`  (modo descripción)
2. `also_mime=true`  → `argv = ["file", "-b", "--mime", <img>]`  (modo MIME)

## Resultado obtenido

**Pasada 1 — descripción (`file -b`)** — exit 0:
```
Linux rev 1.0 ext4 filesystem data, UUID=b632c5f5-a170-4dec-990e-c17ae97874af,
volume name "DVWA" (extents) (64bit) (large files) (huge files)
```
Excelente: identifica **ext4**, la **UUID**, el **nombre de volumen "DVWA"** y las features
del superblock. Muy informativo.

**Pasada 2 — MIME (`file -b --mime`)** — exit 0:
```
application/octet-stream; charset=binary
```
Genérico e inútil aquí: `--mime` **sustituye** la descripción por el MIME, y el MIME de una
imagen de disco cruda es siempre `octet-stream`.

**Contraste con TSK** (`fsstat -t`): devuelve `ext4`. Confirma el FS; `file` en modo
descripción ya daba eso y más.

## Veredicto de eficacia

- **En modo descripción: muy eficaz** sobre esta imagen — identifica el FS y metadatos
  ricos con una sola llamada barata.
- **`also_mime=true` es una trampa en imágenes de disco:** el `parsed.description` quedó
  como `application/octet-stream`, perdiendo toda la información útil. Es un **límite del
  wrapper**: `also_mime` usa `file -b --mime`, que reemplaza la descripción en vez de
  añadirla. Para tener descripción **y** MIME hoy hacen falta dos invocaciones.

## Lecciones para entrenar al agente

1. **Para caracterizar una IMAGEN DE DISCO, usa `file_info` sin `also_mime`** (modo
   descripción): identifica el FS (ext4/ntfs/…), UUID y volumen de un vistazo y barato.
2. **No uses `also_mime=true` sobre imágenes de disco/volcados:** el MIME de un `.raw` es
   `octet-stream` y además *oculta* la descripción. `also_mime` solo aporta valor sobre
   **ficheros extraídos** (un `.docx`, un ELF, un log) cuando quieres su clasificación MIME.
3. **`file` mira los primeros bytes:** funciona bien aquí porque el superblock ext deja
   *magic* reconocible; para confirmar el FS de forma canónica, la tool forense es `fsstat`
   (no en catálogo hoy) o inferirlo con `tsk_fls`/`tsk_mmls`.
4. **Encadenado típico:** `file_info` → si es imagen de disco → `tsk_mmls` (si hay
   particiones) o directamente `tsk_fls` (FS plano); si es un fichero suelto extraído →
   `file_info(also_mime)` + `strings_head` + `yara`.

## Acción de mejora sugerida (producto, no bloqueante)

Que `also_mime` **añada** el MIME en vez de reemplazar la descripción: dos invocaciones
internas (`file -b` + `file -bi`) fundidas en `parsed.description` + `parsed.mime`. Candidato
a issue/mejora del wrapper `file_info`.

## Registro en el caso

- **Finding:** `6cadfda6` — "Evidencia = sistema de ficheros ext4 (volumen DVWA)" (low) →
  panel Hallazgos, procedencia `file_info` / run `72ea3c8c`.
- **Evidencia recopilada:** [`file_info/tipo.txt`](file_info/tipo.txt) (salida de ambos modos).
