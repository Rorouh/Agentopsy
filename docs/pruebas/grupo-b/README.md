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
La VMDK se convirtió a `.raw` con `qemu-img convert -O raw` (8 GiB virtuales). Sobre el `.raw`,
`mmls` lee la tabla DOS sin problema. Lección: para VMDK/VDI/QCOW, **convertir a raw con
`qemu-img`** antes de TSK (o usar `qemu_nbd` cuando su wrapper esté integrado).
