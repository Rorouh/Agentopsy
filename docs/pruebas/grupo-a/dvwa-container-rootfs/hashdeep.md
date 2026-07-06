# `hashdeep` — sobre `dvwa-container-rootfs/dvwa-disk.raw`

- **Grupo:** A · **Imagen:** DVWA docker rootfs (ext4 plano) · **Estado:** ✅ **INTEGRADA** (wrapper implementado esta sesión) + eficaz
- **Binario:** `hashdeep` · **Maletín:** `toolkit-unix` (Cross)
- **run_id (dispatcher):** `a2a8925b-8059-40a8-9b00-bc330b6d0c76` (integridad) · antes por binario directo

## Objetivo (máxima expresión)

`hashdeep` calcula **múltiples hashes** (MD5/SHA-1/SHA-256) de forma **recursiva** y, sobre
todo, **audita** un árbol contra un set conocido (modo `-a -k`, p. ej. NSRL) para separar
"ficheros conocidos" de "desconocidos/sospechosos". Quería (1) corroborar la integridad de la
imagen con un tercero independiente y (2) producir el hash set de los artefactos extraídos.

## ✅ Integración (fix de Bug 003 para esta tool)

Empezó siendo un stub (sin `build_argv`/`parse`). Aplicando la **nueva regla de la sesión**,
la **integré** antes de probar: wrapper `wrappers/hashdeep.py` (build_argv con allowlist de
algoritmos + parse del CSV `%%%%`), cableado en `catalog.py`, añadida a `_EVIDENCE_INJECTION`
(`hashdeep→image_path`) y test `TestHashdeep` en `test_wrappers.py`. Ahora corre por el
**dispatcher** como el resto:

```
execute("hashdeep", {"image_path": <img>, "algorithms": ["md5","sha1","sha256"]}, case_id=…, os_profile="unix")
→ exit 0, run a2a8925b, parsed: {files_count:1, algorithms:[md5,sha1,sha256],
   files:[{size:1189085184, hashes:{md5:5038e35c…, sha1:68f0ab16…, sha256:d9d08eab…}}]}
```
El `parse` devuelve los hashes **estructurados** (no texto crudo). Queda en el `ArtifactRun`
+ audit del caso.

## Cómo la usé y resultado

**1) Integridad de la imagen (multi-algoritmo):**
```
hashdeep -c md5,sha1,sha256 <img>
→ 1189085184, md5=5038e35c…, sha1=68f0ab16…, sha256=d9d08eab…
```
El **SHA-256 coincide EXACTO** con el baseline que FORENSIA registró al ingerir la evidencia
(`d9d08eabe8008bccc1c6252364fff6c5f2685257f727d12e2dfa2bdda609f8f9`). → **verificación de
integridad independiente** de la cadena de custodia. Y aporta MD5/SHA-1 que el baseline no
tiene (útil para cotejar con sets antiguos MD5).

**2) Hash set recursivo de los ficheros extraídos** (`hashdeep -r -c md5,sha256 <dir>`):
`config.inc.php` (1859 B), `main.sh` (231 B), `/etc/passwd` (975 B), `/etc/shadow` (528 B),
cada uno con su MD5 + SHA-256 — el set que iría al informe.

## Veredicto de eficacia

- **Muy eficaz y directo**: multi-algoritmo + recursivo sin fricción; el cotejo SHA-256 con el
  baseline refuerza la cadena de custodia.
- **Inutilizable por el agente** hoy (stub, Bug 003).
- **No probé el modo audit** (`-a -k <known_set>`): necesita un set conocido (NSRL) que no
  tenemos aquí — es su capacidad más potente (filtrar lo conocido y resaltar lo desconocido).

## Lecciones para entrenar al agente

1. **hashdeep hashea FICHEROS, no una imagen de disco por dentro**: sobre la imagen cruda da
   el hash del fichero-imagen (útil para integridad). Para hashear ficheros del sistema,
   extráelos antes (`tsk_icat`) o trabaja sobre un montaje/derivados.
2. **Úsalo para cerrar la cadena de custodia**: coteja su SHA-256 con el baseline de FORENSIA;
   si difieren, la evidencia se alteró.
3. **El oro está en el modo audit** (`-a -k NSRL`): en un disco real, filtra los miles de
   ficheros conocidos del SO y deja solo los desconocidos (candidatos a malware/artefactos).
   Requiere un set conocido — consíguelo antes.
4. **Multi-algoritmo** (`-c md5,sha1,sha256`): calcula todos de una pasada; incluye MD5 para
   compatibilidad con sets/hashsets antiguos.

## Registro en el caso

- **Finding:** `a28a818a` — "Integridad verificada por hashdeep: SHA-256 == baseline FORENSIA" (low).
- **Evidencia recopilada:** [`hashdeep/hashes.txt`](hashdeep/hashes.txt) (hashes de la imagen + set de los ficheros extraídos).
