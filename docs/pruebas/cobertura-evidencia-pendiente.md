# Cobertura de evidencia para las tools pendientes

Qué tools de la campaña se pueden probar **con la evidencia que ya tenemos** y cuáles
**requieren descargar** evidencia nueva. Complementa la [matriz](matriz-tools-evidencia.md).

## Inventario de evidencia (a 2026-07-04)

**Todo lo que hay es DISCO (VMs Linux). No hay volcado de memoria ni evidencia Windows
confirmada.**

| Evidencia | Tipo | SO | Estado |
|-----------|------|----|--------|
| `dvwa-container-rootfs` | disco (ext4 plano) | Linux | ✅ probado (Grupo A) |
| `metasploitable2-linux` | disco particionado + E01 | Linux | ✅ probado (Grupo B) |
| `lab26-virtualbox` | disco VDI (VM) | **Debian** (`OSType="Debian_64"` del `.vbox`) | sin usar |
| `owasp-bwa` | disco VMDK (VM) | Linux | sin usar |
| `hackable-secret-hacker` | **OVA** (VM) | ? (sin extraer; nombre de CTF, probable Linux) | sin usar |
| `dvwa-installer-iso` | ISO óptica | — | sin usar |

> **Pista sobre Hackable:** el `.rar` contiene `Hackable - Secret Hacker.ova` → es otra
> **VM (disco)**, no memoria. (Los `.dd` que salían en `strings` del rar eran ruido
> comprimido, falsos positivos.)

## Tools pendientes: ¿tenemos evidencia?

| Tool | ¿Evidencia? | Qué falta |
|------|-------------|-----------|
| `plaso_log2timeline` / `plaso_psort` | ✅ **PROBADO** (Metasploitable) | ✅ integradas + probadas (runs `5ef3afbd`/`50748d14`) |
| `qemu_nbd` | ✅ integrado (wrapper) | ⚠️ runtime bloqueado en el compose (nbd+privilegios); documentado |
| `yara` | ✅ **PROBADO** (DVWA) | ✅ binario instalado + regla propia matchea (run `177b21da`) |
| `xxd_head` | ✅ **PROBADO** (DVWA) | ✅ binario instalado; hex del superbloque (run `cc56b3e9`) |
| `volatility3` | ❌ no (no hay RAM) | **descargar** un volcado de memoria |
| `hayabusa` / `chainsaw` | ❌ no (no hay Windows) | **descargar** `.evtx` (samples pequeños de GitHub) |
| `regripper` / `evtxecmd` / `mftecmd` | ❌ no (no hay Windows) | **descargar** hives/`$MFT` o imagen Windows (+ arreglar catálogo `rip`→`rip.pl` / absorber .NET) |

## Resumen

- **Sin descargas grandes:** `plaso`, `qemu_nbd`, `yara`, `xxd` corren sobre lo que ya
  tenemos; es sobre todo **integrar wrappers / instalar binarios**.
- **Sí hay que descargar:** un **volcado de RAM** (Volatility3) y **evidencia Windows**
  (EVTX/registro). Los EVTX son **samples pequeños** (repos GitHub), no una imagen de 8 GB.
- **Comodín:** el **OVA de Hackable** podría ser Windows (probable Linux por el nombre). Si al
  extraerlo resulta Windows, nos daría EVTX/registro **sin descargar más**.

## Orden recomendado

1. **Ahora, sin descargas:** integrar y probar **`plaso`** (super-timeline sobre
   Metasploitable) → **`qemu_nbd`** → **`yara`** → **`xxd`**. Cierra 4-5 tools con lo que hay.
2. **Descarga pequeña:** `.evtx` samples → **`hayabusa`** / **`chainsaw`**.
3. **Descarga media:** un volcado RAM → **`volatility3`**.
4. **Opcional:** extraer el OVA de Hackable; si es Windows, cubre la parte Windows sin más
   descargas (hives/EVTX/$MFT desde su disco).

## Fuentes de descarga (cuando toque)

Ver la [matriz](matriz-tools-evidencia.md) §"Fuentes de evidencia real": volcados de memoria
(Volatility Memory Samples), EVTX (hayabusa-sample-evtx / EVTX-ATTACK-SAMPLES), reglas YARA
(signature-base).
