# Acceso al disco `.vmdk` · murcielago · ejecución 16 — ⛔ BLOQUEADO POR ENTORNO

Intentos de abrir `IE11-Win7-VMWare-disk1.vmdk` (monolithicSparse, 20 GB) para analizarlo con
TSK. **Ninguna vía funciona en este host** (Apple Silicon, Docker con imágenes amd64
**emuladas**, sin KVM). Documentado porque es un límite del ENTORNO, valioso para el flujo.

| Vía intentada | Comando | Resultado |
|---|---|---|
| **TSK directo** | `mmls /in/…vmdk` | exit 1, sin salida → el TSK del maletín **no lee VMDK** (sin libvmdk). |
| **qemu-nbd** | `qemu-nbd --read-only --connect=/dev/nbd0 …` | `Failed to set NBD socket` → el módulo **`nbd` no está operativo** en la VM de Docker Desktop. |
| **convertir a raw** | `qemu-img convert -O raw` | **Sin espacio**: el vmdk ocupa 20 GB reales y solo quedan ~17 GB libres. |
| **libguestfs** | `virt-filesystems -a …vmdk` | `supermin exited with error status 1` → el appliance **no arranca bajo emulación** (necesita KVM). |

## Diagnóstico

Las cuatro vías de montaje de disco del maletín (`toolkit-unix` amd64) dependen de algo que
este host no da: soporte VMDK en TSK, módulo `nbd` en el kernel, espacio para convertir, o
KVM para libguestfs. **No es un fallo del caso ni del `.vmdk`** (que abrirá bien donde el
maletín corra nativo). Es incompatibilidad **host de desarrollo (Mac/ARM) ↔ toolkit amd64**.

## Salidas para desbloquear (decisión del usuario)

1. **Liberar ~15–20 GB** en el Mac y **convertir el vmdk a raw** (`qemu-img convert -O raw`);
   TSK/plaso leen el raw sin problema. Es la vía más fiable aquí.
2. **Ejecutar el análisis de disco donde el maletín corre nativo** (Linux con KVM / el
   despliegue real de Forensia): allí `nbd`/libguestfs funcionan y no hace falta convertir.
3. **Cerrar el informe con lo de memoria** (que ya es mucho) y dejar el disco como fase 2.

## Nota de custodia

El `.vmdk` quedó en `444` (solo lectura) antes de cualquier intento. Ningún intento escribió
en la evidencia (todo `ro` / `--read-only`).
