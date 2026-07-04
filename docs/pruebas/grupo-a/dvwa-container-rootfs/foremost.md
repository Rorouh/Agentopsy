# `foremost` — sobre `dvwa-container-rootfs/dvwa-disk.raw`

- **Grupo:** A · **Imagen:** DVWA docker rootfs (ext4 plano) · **Estado:** ✅ **INTEGRADA** (wrapper implementado esta sesión) + eficaz
- **Binario:** `foremost` · **Maletín:** `toolkit-unix` (Cross)
- **run_id (dispatcher):** `f907b737-1c98-4055-96c4-5d13008909ba`

## Objetivo (máxima expresión)

`foremost` hace **carving por cabecera/pie**: recupera ficheros cuyos metadatos ya no
existen, casando *magic* a lo largo de la imagen. Su terreno natural es el **espacio no
asignado** de un disco usado. Quería ver qué recupera y con qué fidelidad.

## ✅ Integración (fix de Bug 003 para esta tool)

Era stub. Aplicando la **regla de sesión**, la integré antes de probar: wrapper
`wrappers/foremost.py` (build_argv con allowlist de tipos + `parse`), catálogo,
`_EVIDENCE_INJECTION` (`foremost→image_path`) y test `TestForemost`.

**Detalle de diseño:** el artifact-store **pre-crea** `<run>/out/`, pero foremost **rechaza
un dir de salida existente**. El wrapper carva en un subdir **fresco** `<output_dir>/foremost`
para no chocar. (Lección de integración reutilizable para cualquier tool que cree su propio
dir.)

## Cómo la usé (params + argv)

```
execute("foremost", {"image_path": <img>, "types": ["jpg","png","gif","pdf","zip"], "quick": True}, …)
argv = foremost -t jpg,png,gif,pdf,zip -q -o <output_dir>/foremost -i <img>
→ exit 0, run f907b737
```

## Resultado obtenido — exit 0

**277 ficheros carveados**: `png=160`, `gif=111`, `jpg=5`, `pdf=1` (del `audit.txt`).
Son **assets embebidos** del sistema de ficheros — iconos de paquetes, imágenes de
documentación, 1 PDF — **no ficheros borrados** (el rootfs no tenía deleted, lo vimos con
`fls -d`). Demuestra que el carving opera por **firma sobre datos asignados** también.

## Matiz de producto: `parse` no ve el resumen

`parsed` salió `{finished:false, foundat_markers:0}` porque foremost escribe su resumen en
**`audit.txt` (fichero), no en stdout**, y `parse` solo recibe stdout. El desglose real vive
en el **artefacto** (`output_dir/foremost/audit.txt` + carpetas por tipo). El agente debe
**leer el `audit.txt`** del artefacto para el conteo, no fiarse del `parsed`.

## Veredicto de eficacia

- **Muy eficaz**: 277 ficheros recuperados y clasificados por tipo, con offset.
- **Integrada** y corriendo por el dispatcher con cadena de custodia.
- El `parse` es ciego al resumen (limitación estructural: la señal está en un fichero, no en
  stdout).

## Lecciones para entrenar al agente

1. **foremost carva por firma, no solo lo borrado**: en una imagen "limpia" recupera los
   assets embebidos; en un **disco usado** recupera ficheros realmente eliminados. Interpreta
   el resultado según el tipo de evidencia.
2. **El resultado está en el artefacto, no en `parsed`**: tras `foremost`, lee
   `output_dir/foremost/audit.txt` (o cuenta ficheros por carpeta de tipo). No concluyas
   "no encontró nada" por un `parsed` vacío.
3. **Acota con `types` y usa `quick`** para no carvear todo en imágenes grandes.
4. **Complementa a `tsk_fls -d`**: `fls -d` recupera por metadatos (rápido, con nombre);
   `foremost` recupera por firma (sin nombre, incluso sin metadatos). Úsalos juntos.

## Registro en el caso

- **Finding:** `1f4765c2` — "foremost carveó 277 ficheros por firma…" (low), run `f907b737`.
- **Evidencia recopilada:** [`foremost/audit.txt`](foremost/audit.txt) (resumen + offsets).
  Los 277 ficheros carveados viven en el `ArtifactRun` `f907b737/out/foremost/`.
