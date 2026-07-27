# `hayabusa` — sobre `windows-evtx-hayabusa-samples` (16 EVTX)

- **Grupo:** C (Windows) · **Estado:** ✅ (tras **2 fixes**: Bug 005 glibc + Bug 006 wizard)
- **Binario:** `hayabusa` 3.9.0 (musl) · **Maletín:** `toolkit-windows`
- **run_id:** `6a2607e9-ffb2-4c42-b990-20d0c905b1d8`

## Objetivo (máxima expresión)

Aplicar **reglas Sigma** (4.947) a los logs de eventos Windows (`.evtx`) para **detectar
ataques** y mapearlos a **MITRE ATT&CK** — la tool estrella para triage de EVTX.

## Dos fixes necesarios para que arrancara

1. **Bug 005 — glibc:** el binario `gnu` exigía glibc 2.38 (base Ubuntu 22.04 = 2.35) →
   `GLIBC_2.38 not found`. Fix: usar el build **musl** (static-pie). Ver
   [Bug 005](../../../bugs/005-hayabusa-glibc-gnu-build.md).
2. **Bug 006 — wizard interactivo:** sin `-w/--no-wizard`, hayabusa lanza un "Scan wizard"
   que lee del terminal → por el exec-agent (sin TTY) **panica** (`"not a terminal"`, exit
   101). Fix: el wrapper añade `-w -q`. Ver
   [Bug 006](../../../bugs/006-hayabusa-wizard-no-tty.md).

## Cómo la usé (params + argv)

```
execute("hayabusa", {"evtx_dir": "/evidence/windows-evtx-hayabusa-samples",
                     "output_csv": "…/hayabusa.csv"}, case_id=…, os_profile="windows")
argv = hayabusa csv-timeline -d <evtx_dir> -o <csv> --no-color -w -q   →   exit 0, run 6a2607e9
```

## Resultado obtenido — exit 0

**129 alertas Sigma**: 1 critical, 17 high, 25 medium, 9 low, 77 info. Detecciones reales con
técnica MITRE, hashes y línea de comandos:
- **Compile-after-delivery + proxy exec (T1059 / T1218.004):** `csc.exe` compila
  `zoom-update.cs` → `InstallUtil.exe /U zoom-update.exe` (usuario `CYBERCAT\pc1-user`).
- **Log Cleared (T1070, anti-forense):** `Administrator` limpia el Security log (EventID 1102)
  en `dc1.test.local`.
- **LOLBIN download (T1105):** `desktopimgdownldr.exe` baja `calc.exe` de
  `http://192.168.158.128:8000`.
- + Kerberoasting, RDP Hijacking/Zerologon, BITS jobs, timestomping.

## Veredicto / lecciones para el agente

- **Muy eficaz** para triage EVTX: de logs crudos a **detecciones con técnica MITRE + IOCs**
  (hashes, IPs, cmdlines) en una pasada.
- **Da `evtx_dir` (un directorio de .evtx), no un fichero**: Agentopsy lo inyecta como
  `evtx_dir`; hayabusa recorre todos los `.evtx`.
- **Prioriza por nivel** (`--min-level high`) para no ahogarte en los 77 "info".
- **Binarios de terceros → build estático** (musl) y **flags non-interactive** (`-w`): dos
  trampas que solo se ven al ejecutar (Bugs 005/006).

## Registro en el caso

- **Findings:** `6628e7f9` (129 detecciones Sigma) · `6a896ac6` (cadena de ataque compile+InstallUtil+LogCleared+LOLBIN — high).
- **Evidencia recopilada:** [`hayabusa/hayabusa-timeline.csv`](hayabusa/hayabusa-timeline.csv) (129 alertas).
