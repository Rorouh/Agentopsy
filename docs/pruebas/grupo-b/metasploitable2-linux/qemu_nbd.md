# `qemu_nbd` — caso especial (mount helper, side-effecting)

- **Grupo:** B · **Binario:** `qemu-nbd` · **Maletín:** `toolkit-unix`
- **Estado:** ✅ **wrapper integrado** (último stub de Bug 003) · ⛔ **no ejecutable por el
  dispatcher en el compose** (necesita privilegios + módulo `nbd`)

## Qué es y para qué

`qemu-nbd` **no es una tool de análisis** que produzca un resultado: es un **helper de
montaje**. Expone una imagen de disco (raw/qcow2/**vmdk**/**vdi**) como **dispositivo de
bloque** en `/dev/nbdX`, para que otras herramientas que necesitan un *device* (no un fichero)
puedan leerla: activar **LVM**, montar un FS, o dar a TSK un device.

**Read-only a nivel de BLOQUE** (`-r`): es la forma *sound* de exponer una imagen — un
`mount -o ro` puede disparar *journal replay* y escribir en la imagen; el block-RO **no**
(FORENSIC INVARIANTS §3, soundness-forense.md). Por eso `qemu-nbd -r` es preferible a montar.

## Integración (fix de Bug 003)

Wrapper `wrappers/qemu_nbd.py`: `build_argv` valida el device (`/dev/nbdN`), el formato
(raw/qcow2/vmdk/vdi/vhdx/vpc) y fuerza `-r` por defecto → `qemu-nbd -r -f <fmt> -c <dev>
<img>`. Cableado en catálogo (`side_effecting=True`), `_EVIDENCE_INJECTION`
(`qemu_nbd→image_path`) y test `TestQemuNbd`. Con esto **`_EXTENDED_STILL_STUB` queda vacío**:
todas las tools extended integradas.

## ⛔ Por qué NO se prueba por el dispatcher (limitación de runtime)

`qemu-nbd -c /dev/nbd0` requiere:
1. El **módulo de kernel `nbd`** cargado (`modprobe nbd`).
2. Nodos `/dev/nbdX` presentes.
3. **Privilegios** (CAP_SYS_ADMIN real / `--privileged`).

El maletín del compose **no es privilegiado** y no tiene `nbd` ni `/dev/nbdX` (igual que no
puede activar LVM — ver `tsk_fls.md`). Así que el exec-agent no puede ejecutarlo. Es el mismo
motivo por el que en el Grupo B la activación LVM se hizo en un contenedor **privilegiado
aparte**, no por el dispatcher.

## Cómo se usaría (en un entorno privilegiado)

De hecho, ya usamos qemu-nbd *de facto* en el Grupo B para el reto del LVM (ver `tsk_fls.md`),
con `losetup`+`kpartx` en un contenedor `--privileged`. El equivalente con `qemu-nbd`:
```
modprobe nbd max_part=16
qemu-nbd -r -f raw -c /dev/nbd0 Metasploitable.raw   # o -f vmdk sobre el VMDK sin convertir
kpartx -av /dev/nbd0 ; vgchange -ay                  # LVM
fls /dev/mapper/metasploitable-root
qemu-nbd -d /dev/nbd0                                # desconectar al terminar
```
Ventaja sobre nuestro flujo: `-f vmdk`/`-f vdi` permite exponer **VMDK/VDI directamente**, sin
convertir a raw con `qemu-img` (que duplica 8 GB).

## Veredicto / lecciones para el agente

1. **`qemu_nbd` es infraestructura, no análisis**: su "resultado" es un device conectado; no
   lo esperes en `parsed`.
2. **Requiere entorno privilegiado**: en el compose actual no corre. Si Agentopsy se despliega
   con un maletín privilegiado + `nbd`, se activa esta capacidad (montar/LVM/VMDK directo).
3. **Preferir block-RO (`-r`) a `mount -o ro`** por soundness.
4. **Mejora futura**: dar a los maletines la capacidad `nbd`/privilegios de forma controlada
   desbloquearía qemu_nbd, la activación LVM por el dispatcher y el acceso directo a VMDK/VDI
   (evitando la conversión a raw del Grupo B). Es una decisión de seguridad (como el socket
   Docker §A) — documentarla antes de habilitarla.

## Registro

- **Sin finding** (no produce hallazgo sobre la evidencia; es helper de infraestructura).
- **Sin evidencia recopilada** (no genera artefacto ejecutable en el compose).
