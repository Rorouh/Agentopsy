# Grupo B — tools sobre disco PARTICIONADO real (sistema usado)

Segundo grupo de la campaña. La diferencia con el Grupo A (rootfs plano de contenedor) es
que aquí hay un **disco real con tabla de particiones** y un **sistema usado** — así que se
desbloquean y brillan las tools que el rootfs no ejercitaba:

- **`tsk_mmls`** (¡por fin hay tabla de particiones!) → offsets que alimentan `-o` en fls/icat.
- **`tsk_fls -d`** con **ficheros borrados reales** (un sistema usado sí los tiene).
- **`foremost`** carveando eliminados de verdad (no solo assets embebidos).
- **`plaso`** super-timeline sobre múltiples fuentes.

Plan general: [`../matriz-tools-evidencia.md`](../matriz-tools-evidencia.md). Misma
metodología y organización que el Grupo A (bitácora por imagen y por tool, findings del caso,
evidencia recopilada en `<tool>/`).

## Imágenes en este grupo

| Imagen | Qué es | Estado |
|--------|--------|--------|
| [`metasploitable2-linux/`](metasploitable2-linux/README.md) | VM Linux vulnerable (Metasploitable 2), disco convertido VMDK→raw, particionado | ✅ completado (7 tools: mmls, fls, mactime, foremost, bulk_extractor, icat, ewf_info) |

## Nota de preparación (VMDK → raw)

El build de TSK del maletín **no** trae libvmdk (`mmls -i vmdk` → *"Unsupported image type"*).
En esta prueba la VMDK se convirtió **a mano** a `.raw` con `qemu-img convert -O raw` (8 GiB
virtuales). Sobre el `.raw`, `mmls` lee la tabla DOS sin problema.

> **Actualización (2026-07-17): ya no hace falta convertir a mano.** El dispatcher detecta el
> contenedor (vmdk/vdi/qcow2/vhd/vhdx) y el exec-agent lo **desencapsula al vuelo, sin copia**,
> con el FUSE export de `qemu-storage-daemon` (RO a nivel de bloque, espejo del `ewfmount` de
> EWF). El agente ejecuta TSK sobre el VMDK directamente y el backend enruta el raw expuesto.
> Ver `docs/operacion/exec-agent.md` (routing contenedor qemu) y Bug 4 en
> `docs/agentes/notas-rediseno-agentes.md`.
