# `evtxecmd` — sobre `windows-evtx-hayabusa-samples` (16 EVTX)

- **Grupo:** C (Windows) · **Estado:** ✅ (tras **absorber .NET + realinear al maletín**)
- **Binario:** `EvtxECmd` (Eric Zimmerman, .NET net9 sobre runtime en el maletín) · **Maletín:** `toolkit-windows`
- **run_id:** `b3d9efb8-2c90-480f-ad17-71787ecb829c`

## Objetivo (máxima expresión)

**Normalizar** los logs de eventos Windows (`.evtx`) a un **CSV estructurado y uniforme**:
todos los eventos, un esquema común (RecordNumber, TimeCreated, EventId, Provider, Channel,
PayloadData, MapDescription). No detecta — **extrae y ordena** para pivotar o alimentar una
timeline.

## Qué hizo falta para arrancarla (el bloque .NET)

`EvtxECmd`/`MFTECmd` eran el último modelo legacy container-por-tool y **sus binarios no
estaban** en el maletín. Se hizo:
1. **Dockerfile:** instalar el **runtime .NET 9** (script oficial `dotnet-install`) + `libicu`,
   descargar los builds **net9** de `EvtxECmd`/`MFTECmd` (CDN oficial, SHA pinneado) y envolverlos
   en scripts `/usr/local/bin/EvtxECmd`·`MFTECmd` que hacen `dotnet <tool>.dll "$@"`.
2. **W^X:** el JIT de .NET **segfaultaba bajo emulación QEMU** (linux/amd64 en Apple Silicon).
   Fix: `ENV DOTNET_EnableWriteXorExecute=0` en el maletín (inocuo en amd64 nativo).
3. **Catálogo/wrapper:** retirado `delivery`/`container_image`/`host_mounts`; `build_argv` usa la
   ruta real (`-f`/`-d <evtx>`, `--csv <out>`), no `/in/evtx`·`/out` (idéntico patrón a regripper).

## Cómo la usé (params + argv)

```
execute("evtxecmd", {"evtx_path": "/evidence/windows-evtx-hayabusa-samples"},
        case_id=…, os_profile="windows")   # output_dir lo inyecta el dispatcher
argv = EvtxECmd -d <evtx_dir> --csv <out_dir> --csvf evtx.csv   →   exit 0, run b3d9efb8
```

## Resultado obtenido — exit 0

**279 eventos** normalizados a un CSV. Distribución:

| Canal / EventID | N | Qué |
|-----------------|--:|-----|
| RDP LocalSessionManager / 34 | 30 | sesiones RDP |
| Security / 4624·4672·4634 | 78 | logons / privilegios / logoff |
| Windows PowerShell / 600 | 20 | arranque de proveedor PS |
| Sysmon / 1 · 11 · 5 | 34 | process create · file create · network |

## Veredicto / lecciones para el agente

- **Complementa, no duplica, a hayabusa/chainsaw.** Aquéllos dan **alertas** Sigma/MITRE;
  EvtxECmd da **todos los eventos crudos normalizados** en una tabla — para pivotar por
  proceso/usuario/hora o construir una timeline, no para "dame las alertas".
- **Un solo esquema** para EVTX heterogéneos: los `Maps/` de EZ traducen los payloads propios de
  cada Provider/EventID a campos legibles (MapDescription, PayloadData).
- **Da un fichero o un directorio** (`-f`/`-d`); el wrapper elige por extensión.
- **Trampa de infra (.NET bajo emulación):** sin `DOTNET_EnableWriteXorExecute=0` casca — patrón
  a recordar para cualquier tool .NET en el maletín amd64 emulado.

## Registro en el caso

- **Findings:** `60056430` (279 eventos normalizados — low).
- **Evidencia recopilada:** [`evtxecmd/evtx.csv`](evtxecmd/evtx.csv) (279 eventos).
