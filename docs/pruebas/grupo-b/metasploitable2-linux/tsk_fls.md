# `tsk_fls` — sobre `metasploitable2-linux/Metasploitable.raw`

- **Grupo:** B · **Imagen:** Metasploitable 2 (disco particionado real) · **Estado:** ✅ eficaz (con hallazgo de oro sobre LVM)
- **Binario:** `fls` (Sleuthkit) · **Maletín:** `toolkit-unix`
- **run_ids:** `/boot` `ee94eeae` · raíz recursiva `76af7acf` · raíz borrados `7d994db4`

## Objetivo (máxima expresión)

Recorrer un **disco real particionado y usado**: listar `/boot` (partición ext plana) y la
**raíz dentro de LVM**, y sobre todo sacar los **ficheros borrados** (que un sistema usado sí
tiene — a diferencia del rootfs plano del Grupo A, con 0 borrados).

## Parte 1 — `/boot` (offset 63, ext plano)

```
execute("tsk_fls", {"image_path": <raw>, "partition_offset": 63, "recursive": True}, …)
→ exit 0, run ee94eeae
```
Contenido: `grub`, `vmlinuz-2.6.24-16-server`, `initrd.img-…`, `System.map-…`, `memtest86+`.
Revela el **kernel 2.6.24-16-server** (Ubuntu 8.04 Hardy — muy antiguo/vulnerable).

## Parte 2 — la raíz está en LVM (el reto)

`mmls` mostró que la raíz es un **Linux LVM (0x8e)**, no una partición plana → `fls -o 482013`
(inicio de la partición LVM) **no** lee el FS. Dos caminos:

### Camino A — activar LVM (correcto pero pesado, privilegiado)
En un contenedor **privilegiado** (el maletín del compose no puede: sin `/dev/loop`):
```
losetup --find --show <raw>; kpartx -av <loop>            # mapea loopNp5 (el PV)
vgchange -ay --config 'devices/global_filter=["a|<PV>|","r|.*|"]'   # evita PVs duplicados
vgmknodes; dmsetup mknodes                                # crea /dev/mapper/* (sin udev)
fls /dev/mapper/metasploitable-root                       # → Ext3, raíz real
```
Da la raíz **Ext3** y **7.100 borrados**. Pero **no** es reproducible por el dispatcher
(necesita loop + privilegios que la imagen del maletín no tiene).

### Camino B — offset lineal del LV (elegante, por el dispatcher) ✅
El LV es un **único segmento lineal**: `dmsetup table metasploitable-root` →
`0 14680064 linear 253:2 384`. Es decir, la raíz empieza en el PV (partición 482013) **+ 384
sectores** = **sector 482397**. Entonces, sin LVM ni privilegios:
```
execute("tsk_fls", {"image_path": <raw>, "partition_offset": 482397, "recursive": True}, …)
fsstat/fls -o 482397 <raw>  → Ext3, raíz: home, bin, root, usr, etc, lib, mnt, dev…
```
**Funciona por el dispatcher.** (Solo válido para LVs lineales de un segmento; un LV
fragmentado necesitaría el camino A.)

## Resultado — exit 0

- Raíz **Ext3** montable por offset 482397.
- **7.100 ficheros borrados** (`fls -rd`), incluyendo `home/msfadmin/.lesshst` (historial less
  borrado) y toda la app vulnerable **TWiki** (`twiki20030201`). vs **0** en el DVWA.

## Veredicto de eficacia

- **Muy eficaz**: recorrió `/boot` y la raíz LVM, y destapó 7.100 borrados — la señal estrella
  de un disco usado.
- **LVM es el gran matiz** del disco real: hay que resolverlo (offset lineal o activación).

## Lecciones para entrenar al agente

1. **Disco real → `mmls` primero** para los offsets; si ves **LVM (0x8e)**, la raíz NO se lee
   con el offset de la partición.
2. **LVM lineal de un segmento → offset directo:** `dmsetup table <lv>` da `linear <dev>
   <offset>`; suma `offset` al inicio de la partición LVM y pásalo a `partition_offset`. Lee
   el FS por el dispatcher sin activar LVM.
3. **LVM complejo (varios segmentos / striped) → activación** con loop+kpartx+vgchange en un
   entorno privilegiado (el maletín del compose no lo permite hoy — gap).
4. **`fls -d` en un disco USADO es oro**: aquí 7.100 borrados recuperables; encadénalo con
   `tsk_icat` (por inode) para recuperar los que interesen.

## Registro en el caso

- **Findings:** `5b801681` (raíz Ext3 por offset lineal 482397) · `2979ad4e` (7.100 borrados).
- **Evidencia recopilada:** [`tsk_fls/borrados.txt`](tsk_fls/borrados.txt) (7.100 entradas) ·
  [`tsk_fls/_lv-table.txt`](tsk_fls/_lv-table.txt) (tabla dmsetup del LV, el offset 384).
