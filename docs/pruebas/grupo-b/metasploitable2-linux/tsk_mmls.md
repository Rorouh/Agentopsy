# `tsk_mmls` — sobre `metasploitable2-linux/Metasploitable.raw`

- **Grupo:** B · **Imagen:** Metasploitable 2 (disco particionado real) · **Estado:** ✅ eficaz
- **Binario:** `mmls` (Sleuthkit) · **Maletín:** `toolkit-unix` (Cross)
- **run_id:** `cbb72b13-29e2-4491-b89e-b41ed817e220`

## Objetivo (máxima expresión)

`mmls` lista la **tabla de particiones** (DOS/GPT): slots, offsets en sectores y tipos. Es el
primer paso obligado en un **disco** (a diferencia del rootfs plano del Grupo A, donde `mmls`
daba exit 1). Su salida da los `partition_offset` que alimentan `-o` en `fls`/`icat`.

## Cómo la usé (params + argv)

Antes hubo que **convertir el VMDK a raw** (`qemu-img convert -O raw`) — TSK del maletín no
lee VMDK. Sobre el raw:

```
execute("tsk_mmls", {"image_path": <raw>}, case_id=…, os_profile="unix")
argv = mmls <raw>   →   exit 0, run cbb72b13
```

## Resultado obtenido — exit 0, 8 slots

| slot | start (sector) | length | tipo |
|------|----------------|--------|------|
| 2 | 63 | 481887 | **Linux (0x83)** — `/boot` (~235 MB) |
| 3 | 481950 | 16289910 | DOS Extended (0x05) |
| 6 | 482013 | 16289847 | **Linux LVM (0x8e)** — raíz (~7,7 GB) |

(+ slots Meta/Unallocated). Tabla DOS bien formada, dos zonas de datos: `/boot` plano y la
raíz dentro de **LVM**.

## Veredicto de eficacia

- **Muy eficaz**: leyó la tabla completa y entregó los offsets — exactamente su función.
- Confirma la utilidad de `mmls` en un disco real (vs el exit 1 del FS plano del Grupo A → Bug
  001 / regla del playbook).

## Lecciones para entrenar al agente

1. **En un disco, empieza por `mmls`**: da los offsets de cada partición para el resto de TSK
   (`fls -o <offset>`, `icat -o <offset>`). Sin esto, `fls` sobre el disco entero falla o lee
   la partición equivocada.
2. **VMDK/VDI/QCOW → desencapsulado automático (2026-07-17)**: el TSK del maletín no trae
   libvmdk, pero ya **no hay que convertir a mano**. El exec-agent expone el contenedor como
   raw al vuelo (sin copia) con el FUSE export de `qemu-storage-daemon`; el dispatcher lo
   enruta solo. El agente le pasa el `.vmdk` a TSK y funciona. Ver `docs/operacion/exec-agent.md`.
3. **Ojo con LVM (tipo 0x8e)**: la partición existe pero el FS está en un volumen lógico. `fls
   -o 482013` **no** lo lee directo; hay que activar el LV (kpartx/losetup + vgchange) y dar el
   offset del LV. Distínguelo de una partición ext plana (0x83), que `fls -o` sí lee directo.
4. **El offset es en SECTORES** (512 bytes), no bytes — pásalo tal cual a `partition_offset`.

## Registro en el caso

- **Finding:** `0203fe21` — "Layout de disco: /boot ext + raíz en LVM (Metasploitable 2)" (medium), run `cbb72b13`.
- **Evidencia recopilada:** [`tsk_mmls/particiones.txt`](tsk_mmls/particiones.txt).
