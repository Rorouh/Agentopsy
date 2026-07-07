# Ground-truth — `lonewolf-2018` (2018 Lone Wolf Scenario)

Traza dorada del escenario **2018 Lone Wolf** (DigitalCorpora). Cubre las dos
entradas del manifiesto que comparten host: `lonewolf-2018-disk` (imagen FTK/E01)
y `lonewolf-2018-memory` (`memdump.mem`). Reglas de este fichero:
[ground-truth/README.md](README.md).

## Metadatos

| Campo | Valor (disco) | Valor (memoria) |
|---|---|---|
| id de imagen | `lonewolf-2018-disk` | `lonewolf-2018-memory` |
| SHA-256 baseline | variante (a) E01: **9 segmentos verificados** (ver [corpus-windows.md](../corpus-windows.md)); variante (b) imagen única: `<pendiente>` | `<pendiente: computar con scripts/hash-evidence.py>` |
| hash de adquisición (FTK) | MD5 `7af48fa65519e84246b1729e5b68f140` · SHA-1 `694e26624d1ea029eb50d793b198edf85be4b4fc` (verificados en `FTK Imager Log.txt`, 2018) | — (no aplica) |
| tipo | `disk` | `memory` |
| formato | `.E01` (multi-segmento) | `.mem` (raw, Volatility3) |
| SO/build | Windows 10 | Windows 10 |
| fuente/URL | [2018 Lone Wolf Scenario](https://digitalcorpora.org/corpora/scenarios/2018-lone-wolf-scenario/) | (misma) |
| entrada en el manifiesto | [corpus-windows.md](../corpus-windows.md) | [corpus-windows.md](../corpus-windows.md) |

## Contexto

Escenario **insider**: planificación de un tiroteo. El material es una imagen
forense **FTK de un portátil Windows 10** (adquirida con FTK Imager 3.1.1.8 en
2018; ver el log de adquisición) más un volcado de RAM del mismo host. La
investigación es de **actividad de usuario** (documentos, búsquedas, dispositivos
extraíbles, sesiones), no de intrusión: no hay atacante externo ni malware.

## Fuentes de la traza dorada

- **`Forensic Outputs.zip`** — outputs forenses oficiales del propio escenario.
- **`0 README.pdf`** — descripción/guía pública del escenario.
- Write-ups públicos del caso (revisar autoría/licencia antes de citar).

Estos ficheros de referencia se guardan **fuera de git** en
`evidence-corpus/lonewolf-2018/ground-truth-refs/` (cubierto por el ignore de
`evidence-corpus/`).

> **NO se usa** la *Teacher's Guide* oficial: está restringida a profesorado. La
> traza dorada se construye solo con fuentes públicas + los outputs del escenario.

## Limitaciones documentadas

Este caso **NO contiene** malware, inyección de procesos, C2 ni borrado de logs.
Por tanto **no** sirve para validar técnicas de intrusión. Sirve para validar:

- **Playbook de disco**: registro (persistencia, cuentas, USB), EVTX de logon,
  `$MFT`, super-timeline, dispositivos USB.
- **Enum de procesos en RAM**: listado/árbol de procesos con Volatility3.

Las técnicas de intrusión **`T1055`** (Process Injection), **`T1071`** (Application
Layer Protocol / C2) y **`T1070.001`** (Clear Windows Event Logs) se cubrirán con
una **imagen de memoria de CTF de malware** en el paso **A2** del
[plan de ruta](../plan-ruta-forensia-win.md) — no aquí.

## Hallazgos esperados

> Cada `hallazgo esperado` está `<verificar>` hasta confirmarlo con su artefacto al
> analizar la imagen (RULE 2: no inventar). Los `tool_id` provienen de la allowlist
> [`policy/tools.yaml`](../../../agentes/forensia-windows/policy/tools.yaml); la
> columna «cómo verificar» describe la metodología manual (eso sí es fijo). La mayoría
> de la actividad de este caso (insider) cae **fuera** de la semilla de técnicas de
> ataque, por eso la columna MITRE va mayormente `<verificar>`.

### Disco (`lonewolf-2018-disk`)

| hallazgo esperado | artefacto que lo sostiene | `tool_id` | técnica MITRE (semilla) | severidad | cómo verificarlo manualmente |
|---|---|---|---|---|---|
| `<verificar>` (persistencia / programas de inicio) | `NTUSER.DAT` / `SOFTWARE` → claves `Run`/`RunOnce` | `regripper` | `<verificar>` (candidata `T1547.001` solo si hay autostart real) | `<verificar>` | Extraer los hives con `tsk_icat`, correr RegRipper `run`/`soft_run`; contrastar rutas contra binarios presentes en `$MFT`. |
| `<verificar>` (cuentas de usuario del sistema) | `SAM` → usuarios y último logon | `regripper` | `<verificar>` | `<verificar>` | RegRipper `samparse`; anotar RIDs, nombres y fechas de último acceso. |
| `<verificar>` (dispositivos USB conectados) | `SYSTEM` → `USBSTOR` / `MountedDevices` + `setupapi.dev.log` | `regripper` | `<verificar>` (exfil por medio físico está fuera de la semilla actual) | `<verificar>` | RegRipper `usbstor`/`mountdev`; correlacionar VID/PID y primera/última conexión con la timeline. |
| `<verificar>` (sesiones de logon) | `Security.evtx` → eventos 4624/4625 | `evtxecmd` | `<verificar>` (candidata `T1078` solo si hay acceso anómalo) | `<verificar>` | Pre-extraer el EVTX con `tsk_icat`, normalizar con EvtxECmd; filtrar 4624/4625 por usuario y tipo de logon. |
| `<verificar>` (documentos / ficheros relevantes y sus tiempos) | `$MFT` (`$SI` vs `$FN`) | `mftecmd` | `<verificar>` | `<verificar>` | MFTECmd → CSV; revisar rutas de interés (Documentos, Descargas), comparar timestamps `$SI`/`$FN` por si hubiera anomalías. |
| `<verificar>` (línea temporal de actividad) | bodyfile MAC(b) del sistema de ficheros | `tsk_mactime` | `<verificar>` | `<verificar>` | Generar bodyfile con `tsk_fls` y ordenar con `tsk_mactime`; acotar la ventana temporal del escenario. |

### Memoria (`lonewolf-2018-memory`)

| hallazgo esperado | artefacto que lo sostiene | `tool_id` | técnica MITRE (semilla) | severidad | cómo verificarlo manualmente |
|---|---|---|---|---|---|
| `<verificar>` (procesos en ejecución en el volcado) | lista/árbol de procesos del volcado RAM | `volatility3` | `<verificar>` (sin intrusión conocida en este caso) | `<verificar>` | `volatility3 -f memdump.mem windows.pslist` / `windows.pstree`; anotar procesos de usuario relevantes y sus tiempos de arranque. |
