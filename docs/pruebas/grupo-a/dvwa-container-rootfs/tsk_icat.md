# `tsk_icat` — sobre `dvwa-container-rootfs/dvwa-disk.raw`

- **Grupo:** A · **Imagen:** DVWA docker rootfs (ext4 plano) · **Estado:** ✅ **INTEGRADA** (wrapper implementado esta sesión) + eficaz
- **Binario:** `icat` (Sleuthkit) · **Maletín:** `toolkit-unix` (Cross)
- **run_id (dispatcher):** `6f352052-36fe-4154-8587-c9822661b15c` (config.inc.php, inode 13552) · antes por binario directo

## Objetivo (máxima expresión)

`icat` extrae el **contenido de un fichero por su inode**, sin montar el FS — la herramienta
quirúrgica que sigue a `tsk_fls`: localizas el inode y sacas el fichero (log, config, binario)
como artefacto. Quería recuperar los 4 objetivos de alto valor del mapeo previo.

## ✅ Integración (fix de Bug 003 para esta tool)

Empezó siendo un stub (`NotImplementedError`). Aplicando la **regla de sesión**, la
**integré**: wrapper `wrappers/tsk_icat.py` (`build_argv` con validación estricta del inode
`^\d+(-\d+){0,2}$` + `-o/-f/-i/-r/-s`, y `parse` con heurística texto/binario + preview),
cableado en `catalog.py`, añadida a `_EVIDENCE_INJECTION` (`tsk_icat→image_path`) y test
`TestTskIcat`. Ahora corre por el **dispatcher** con `ArtifactRun` + audit:

```
execute("tsk_icat", {"image_path": <img>, "inode": 13552}, case_id=…, os_profile="unix")
→ exit 0, run 6f352052, parsed {content_length:1812, is_text:True, preview:"<?php … db_server …"}
```

> Nota: `parse` decodifica stdout como texto; para artefactos **binarios** puede venir con
> caracteres de reemplazo (limitación del exec-agent, que devuelve texto) — para binarios,
> usa el fichero del `ArtifactRun`, no el `preview`.
>
> **Actualización (posterior a esta corrida).** `icat` es ya `binary_stdout=True`: sus bytes
> van íntegros a `out/stdout.bin` (hasheado) y el `parsed` **no** es `content_length:…` sino
> una referencia al artefacto `{artifact:{run_id, relpath:"stdout.bin", sha256, size}}` —
> lista para pasarse como input derivado a la tool aguas abajo (ver `docs/storage.md`
> § Relevo derivado). El `content_length:1812` de arriba es del canal de texto antiguo.

## Qué extraje (y resultado)

| Inode | Fichero | Bytes | Contenido clave |
|-------|---------|-------|-----------------|
| 13552 | `config.inc.php` | 1859 | Config **activo**: db `app`/`vulnerables` @127.0.0.1:5432, `default_security_level='low'`, PHPIDS disabled |
| 1030 | `main.sh` | 231 | Entrypoint del contenedor: arranca MySQL + Apache2, tail de logs |
| 549 | `/etc/passwd` | 249 | 20 cuentas; solo `root` con `/bin/bash` |
| 726 | `/etc/shadow` | 528 | `root:*` (bloqueado); **sin hashes crackeables** |

> Matiz importante: el config **activo** (`config.inc.php`) usa `app`/`vulnerables`; el
> `root`/`p@ssw0rd` que vio `strings` estaba en el `.dist` (ejemplo). `icat` desambigua.

## Trampa encontrada (lección de oro para el agente)

Primero cogí inodes 375 (`passwd`) y 726 por nombre desde el árbol de `fls -r`, y **375 no era
`/etc/passwd`** sino un script de cron `passwd` (había >100 ficheros llamados "passwd":
man-pages, locales, cron…). El `/etc/passwd` real era el inode **549**.

**Lección:** `fls -r` lista nombres **sin ruta**; elegir un inode por nombre es peligroso.
Para el fichero correcto, **navega el directorio padre** (`fls <img> <inode_de_/etc>`; aquí
`/etc` = inode 107) y toma el inode del hijo exacto.

## Veredicto de eficacia

- **El binario `icat` es muy eficaz** (extracción limpia, sin montar).
- **Inutilizable por el agente hoy** por el stub del wrapper (Bug 003) → prioridad de arreglo
  alta: `tsk_icat` es el paso natural tras `tsk_fls` y su argv es trivial.

## Lecciones para entrenar al agente

1. **Encadena `tsk_fls` → `tsk_icat`**: mapea, localiza inode, extrae. No intentes leer un
   fichero desde el listado de `fls` — `fls` da metadatos, no contenido.
2. **No elijas inode por nombre a ciegas** (ver trampa): navega el directorio padre para el
   inode exacto.
3. **`icat` sobre config/entrypoint/logs** es donde está la señal; combínalo con `file_info`/
   `strings_head` sobre el fichero extraído (pequeño) — señal máxima, artefacto mínimo.
4. **Cuando el wrapper sea un stub, falla con error accionable**, no con `NotImplementedError`
   (mejora de producto — Bug 003).

## Registro en el caso

- **Findings:** `486d5e68` (config activo, security low — medium) · `7b052854` (entrypoint
  main.sh) · `a432d075` (passwd/shadow sin hashes). Sin `run_id` (extracción por binario).
- **Evidencia recopilada:** [`tsk_icat/config.inc.php`](tsk_icat/config.inc.php) ·
  [`main.sh`](tsk_icat/main.sh) · [`passwd`](tsk_icat/passwd) · [`shadow`](tsk_icat/shadow).
