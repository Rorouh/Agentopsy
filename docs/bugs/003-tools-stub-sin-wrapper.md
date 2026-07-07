# Bug 003 — 6 tools del catálogo son *stubs* (declaradas sin wrapper)

- **Severidad:** alta para la campaña de pruebas (esas tools **no se podían ejecutar** por el
  dispatcher/agente, aunque el binario existe en el maletín)
- **Estado:** ✅ **resuelto** (2026-07-04) — las 6 integradas con wrapper + catálogo + test
- **Componente:** `backend/forensia/toolkit/catalog.py` + `wrappers/` (faltan)
- **Detectado:** 2026-07-04, probando `tsk_icat` sobre `dvwa-container-rootfs`

## Síntoma

`execute("tsk_icat", …)` (y las otras 5) lanza:

```
NotImplementedError: tool wrapper not implemented yet (skeleton)
```

Porque en el catálogo se declaran **sin `build_argv` ni `parse`**, y el default de `Tool` es
`_not_built`, que lanza esa excepción.

## Tools afectadas (las 6, TODAS integradas)

`hashdeep` (run `a2a8925b`) · `foremost` (`f907b737`) · `tsk_icat` (`6f352052`) ·
`plaso_log2timeline` + `plaso_psort` (`5ef3afbd`/`50748d14`) · `qemu_nbd` (wrapper integrado).

Cada una con wrapper + catálogo + `_EVIDENCE_INJECTION` + test. `_EXTENDED_STILL_STUB` queda
**vacío**. Cinco se probaron por el dispatcher; **`qemu_nbd`** tiene el wrapper listo pero su
**runtime** (módulo `nbd` + privilegios) no está disponible en el maletín del compose — es una
limitación de entorno **aparte** del stub, documentada en
`docs/pruebas/grupo-b/.../qemu_nbd.md`.

(Las otras 16 del catálogo **sí** tenían wrapper real desde el principio.)

## Impacto

- El **agente no puede invocarlas** (ni el dispatcher, ni el MCP): cualquier intento peta con
  `NotImplementedError`, no con un error accionable.
- Bloquea probar en la campaña: `tsk_icat` (extracción por inode), `foremost` (carving),
  `hashdeep` (hashing), `plaso_*` (super-timeline), `qemu_nbd` (montaje).
- **El binario SÍ funciona** en el maletín: p. ej. `icat <img> <inode>` extrae el fichero sin
  problema (verificado: `config.inc.php` inode 13552, `main.sh` inode 1030, `/etc/passwd`
  inode 549). Lo que falta es el **wrapper** (build_argv con allowlist de flags + parse).

## Fix propuesto (no aplicado)

Implementar los 6 wrappers en `wrappers/` con su `build_argv` (allowlist de flags) y `parse`,
y cablearlos en `catalog.py`. El más urgente para el flujo de disco es **`tsk_icat`**
(`icat [-o off] [-f fs] <img> <inode>` → bytes del fichero como artefacto); es de una línea de
argv. Le siguen `foremost`, `hashdeep`, `plaso_log2timeline`/`plaso_psort` y `qemu_nbd`.

## Workaround mientras tanto

Ejecutar el binario directamente en el maletín para prueba/recolección:
`docker compose exec toolkit-unix icat <img> <inode>`. No deja `ArtifactRun`/audit (no pasa
por el dispatcher), así que la cadena de custodia hay que anotarla a mano.
