# `volatility3` — sobre `windows7-x64-ram-dump` (5 GB de RAM)

- **Grupo:** C (Windows) · **Estado:** ✅ (sin fixes — ya estaba instalado y cableado)
- **Binario:** `vol` (Volatility 3, Python) · **Maletines:** ambos (`_BOTH`); aquí `toolkit-windows`
- **Evidencia:** `ram.raw` (5,0 GB) — **Windows 7 SP1 x64**, build `7601.24384.amd64fre.win7sp1`, SystemTime 2021-03-23 19:24:35Z

## Objetivo (máxima expresión)

Analizar la **memoria RAM** de una máquina Windows: qué procesos estaban vivos, su árbol
padre/hijo, líneas de comando, conexiones de red y **código inyectado** — cosas que no se ven
en el disco. Es la tool de *memory forensics* (procesos ocultos, malware fileless, C2, hooks).

## Sin fix: ya operativa

A diferencia de regripper/hayabusa/chainsaw, `volatility3` no necesitó nada: el binario `vol`
ya está en ambos maletines y el wrapper (`dump_path` + `plugin` FQ + `plugin_args`, salida
`-r json`) estaba cableado. El **único** bloqueo era la evidencia (un volcado de RAM), que
aportó el analista. vol3 **descarga los símbolos del kernel on-demand** (el maletín tiene
salida a internet al symbol server) — resolvió Win7 SP1 x64 sin intervención.

## Cómo la usé (params + argv)

```
execute("volatility3", {"dump_path": "/evidence/windows7-x64-ram-dump/ram.raw",
                        "plugin": "windows.pslist.PsList"}, case_id=…, os_profile="windows")
argv = vol -f <dump> -r json --quiet <plugin>
```

Plugins ejecutados (todos exit 0, por el dispatcher → audit + run_id):

| Plugin | run_id | Resultado |
|--------|--------|-----------|
| `windows.info` | (directo) | Win7 SP1 x64, build 7601, SystemTime 2021-03-23 |
| `windows.pslist.PsList` | `0a2973f4` | 52 procesos |
| `windows.pstree.PsTree` | `1072bb1a` | árbol padre/hijo |
| `windows.cmdline.CmdLine` | `7ebed730` | líneas de comando de los 52 |
| `windows.netscan.NetScan` | `cf79a306` | 56 artefactos de red |
| `windows.malfind.Malfind` | `54bb3265` | 8 regiones RWX (inyección) |

## Resultado / hallazgos

**1. Posible keylogger `key.exe` en el Escritorio (high).** `pslist`+`cmdline`: dos instancias
de `key.exe` desde `C:\Users\IEUser\Desktop\key.exe` — PID 3856 lanzado por `explorer.exe`
(1272) y PID 3184 hijo de 3856. Nombre de keylogger + ubicación en el Escritorio (fuera de
rutas de sistema) → binario a volcar y pasar por yara/hashdeep.

**2. Código inyectado RWX (high).** `malfind`: 8 regiones `PAGE_EXECUTE_READWRITE`. En
`explorer.exe` una región contiene el patrón trampolín `mov r10,imm; mov rax,<addr>; jmp rax`
(`41 ba .. 48 b8 .. 48 ff 20`), típico de hooking/shellcode; `key.exe` (3184) también tiene
región RWX. El proceso de shell del usuario está enganchado → host comprometido.

**3. Superficie/servicios y salida externa (medium).** `netscan`: `hMailServer` (1832)
escuchando SMTP/25, POP3/110, IMAP/143, submission/587; `OpenSSH sshd` (948, vía Cygwin
`cygrunsrv`) en 22; SMB 445/139, RPC 135. Artefacto de red **CLOSED hacia 200.228.36.6**
(rango brasileño) sin proceso asociado → posible C2/exfil residual.

*(Nota: `MagnetRamCapture.exe` en el Escritorio es la herramienta de adquisición del propio
volcado — artefacto esperado, no IOC.)*

## Veredicto / lecciones para el agente

- **Empieza siempre por `windows.info`**: fija SO/arquitectura y fuerza la descarga de símbolos;
  si eso falla, ningún otro plugin funcionará (la imagen no es un volcado válido o faltan símbolos).
- **La tríada de triage de memoria:** `pslist`/`pstree` (qué corre y de quién cuelga) →
  `cmdline` (desde dónde) → `netscan` (con quién habla) → `malfind` (qué está inyectado).
- **PPID + ruta = oro:** un `key.exe` colgando de `explorer.exe` y corriendo desde el Escritorio
  salta a la vista frente a un `svchost.exe` colgando de `services.exe`.
- **RWX = bandera roja.** `malfind` marca memoria ejecutable-y-escribible; el patrón trampolín en
  `explorer` es inyección casi segura.
- **Vol3 necesita internet la primera vez** (símbolos). En un despliegue aislado hay que
  pre-sembrar el pack de símbolos Windows en la imagen.

## Registro en el caso

- **Findings:** `9ec2e5ea` (keylogger key.exe — high) · `538294f3` (código inyectado RWX — high)
  · `0e631604` (servicios expuestos + salida a IP externa — medium).
- **Evidencia recopilada:** [`volatility3/`](volatility3/) (`pslist`, `pstree`, `cmdline`,
  `netscan`, `malfind` en JSON).
