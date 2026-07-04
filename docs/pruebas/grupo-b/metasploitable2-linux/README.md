# Imagen: `metasploitable2-linux` (VM vulnerable, disco particionado)

Bitácora de pruebas del Grupo B sobre un **disco real particionado y usado**.

## Identidad de la evidencia

| Campo | Valor |
|-------|-------|
| Origen | `evidence/metasploitable2-linux/Metasploitable.vmdk` (VM VirtualBox/VMware) |
| Preparación | **VMDK → raw** con `qemu-img convert -O raw` (TSK del maletín no trae libvmdk) |
| Fichero | `evidence/metasploitable2-linux/Metasploitable.raw` (8 GiB virtuales, ~2,7 GB reales) |
| Layout | tabla DOS: `/boot` **ext (0x83)** sector 63 + **LVM (0x8e)** sector 482013 (raíz) |
| SHA-256 baseline | `f922408675a51f17236707de8d3c4727a98f57241c6847549b7cec2e0e9e2a3b` |
| Caso | `69b31984-1045-4a6d-bb23-0f507fca0c32` ("Metasploitable2", perfil `unix`) |
| evidence_id | `f7c927be-fcf5-44f4-bd72-a239953927de` |
| Triage | `detected_os=unknown` (lee el MBR, no el ext interno), `detected_kind=disk` |
| Ruta interna | `/cases/cases/69b31984-…/evidence/f7c927be-…/original.raw` |

## Nota forense: la raíz está en LVM

El sistema de ficheros raíz vive dentro de un **Linux LVM (0x8e)**, no de una partición
plana. TSK lee `/boot` (ext, offset 63) directamente; para el root FS hay que **activar el
volumen lógico** (kpartx / losetup + vgchange) o dar el offset del LV a `-o`. Es la diferencia
grande con el rootfs plano del Grupo A.

## Checklist de tools (Grupo B)

| Tool | Estado | Veredicto corto |
|------|--------|-----------------|
| [`tsk_mmls`](tsk_mmls.md) | ✅ | 8 particiones; /boot ext + raíz en LVM; da los offsets |
| [`tsk_fls`](tsk_fls.md) | ✅ | /boot (kernel 2.6.24) + raíz Ext3 en LVM leída por **offset lineal 482397** (sin activar LVM); **7.100 borrados** recuperables |
| [`tsk_icat`](tsk_icat.md) | ✅ | Recuperó `/etc/shadow` con **7 hashes MD5 crackeables** (root, msfadmin, postgres…) + `/etc/passwd`; vs DVWA (cuentas bloqueadas) |
| [`tsk_mactime`](tsk_mactime.md) | ✅ | 228.514 eventos; ventanas reales 2008→2010→2012; destapó y arregló **Bug 004** (exec-agent crash con no-UTF-8) |
| [`foremost`](foremost.md) | ✅ | **3.967 ficheros** carveados (1738 png, 388 htm web, zip/jar…) — ~14× más que el DVWA; disco usado |
| [`bulk_extractor`](bulk_extractor.md) | ✅ | 496k dominios/350k emails + **artefactos de uso real**: 160 httplogs, 91 sesiones utmp, 5 ccn |
| [`ewf_info`](ewf_info.md) | ✅ | Leyó la ficha de adquisición del E01 (caso, examiner, EnCase 6) + MD5 embebido `1cd5cd2f…` |
