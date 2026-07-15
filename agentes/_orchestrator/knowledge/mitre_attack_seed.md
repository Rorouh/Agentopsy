# MITRE ATT&CK — Semilla (Enterprise)

Subconjunto curado para FORENSIA. **Enum cerrada** que `mitre.md` puede emitir hoy
(el orquestador no debe inventar ids fuera de esta lista hasta que el corpus
completo aterrice en S5). Cada entrada: id, nombre, táctica(s) y qué artefacto
forense suele sostenerla. Referencia: ATT&CK Enterprise (revisar versión al
ampliar).

## TA0002 — Execution
| Técnica | Nombre | Se sostiene con |
|---|---|---|
| T1059 | Command and Scripting Interpreter | historiales de shell, EVTX 4688, Sysmon 1 |
| T1059.001 | PowerShell | EVTX PowerShell/Operational, ScriptBlock logging |
| T1059.003 | Windows Command Shell | 4688 con cmd.exe, Prefetch |
| T1059.004 | Unix Shell | `~/.bash_history`, `auth.log`, artefactos `/tmp` |
| T1053 | Scheduled Task/Job | tareas programadas, `cron`, EVTX 4698 |
| T1053.003 | Cron | `/etc/cron*`, `/var/spool/cron`, syslog |
| T1053.005 | Scheduled Task | `\Windows\Tasks`, registro TaskCache, EVTX 4698 |

## TA0003 — Persistence
| Técnica | Nombre | Se sostiene con |
|---|---|---|
| T1547 | Boot or Logon Autostart Execution | hives de registro, ASEP |
| T1547.001 | Registry Run Keys / Startup Folder | RegRipper `run`, `NTUSER.DAT`, carpeta Inicio |
| T1543 | Create or Modify System Process | servicios, daemons |
| T1543.003 | Windows Service | RegRipper `services`, EVTX 7045, Amcache |
| T1505.003 | Server Software Component: Web Shell | ficheros en `/var/www`/`inetpub`, YARA, logs web |
| T1136 | Create Account | SAM, EVTX 4720, `/etc/passwd` |
| T1098 | Account Manipulation | EVTX 4738/4724, `authorized_keys` |
| T1133 | External Remote Services | servicios de acceso remoto expuestos (SSH/RDP/VPN) en `netscan` LISTENING, EVTX/`auth.log` de acceso, servicios residentes |

## TA0004 — Privilege Escalation
| Técnica | Nombre | Se sostiene con |
|---|---|---|
| T1548 | Abuse Elevation Control Mechanism | sudoers, UAC, setuid |
| T1078 | Valid Accounts | 4624/4625 logon, accesos anómalos |

## TA0005 — Defense Evasion
| Técnica | Nombre | Se sostiene con |
|---|---|---|
| T1055 | Process Injection | Volatility3 `malfind`, regiones RWX, hollowing |
| T1070 | Indicator Removal | `$UsnJrnl`, EVTX 1102 (clear log), `wtmp` truncado |
| T1070.001 | Clear Windows Event Logs | EVTX 1102, huecos en secuencia de eventos |
| T1027 | Obfuscated/Compressed Files or Information | FLOSS/strings, entropía, packers |
| T1036 | Masquerading | nombre vs ruta (svchost fuera de System32), doble extensión |
| T1140 | Deobfuscate/Decode Files or Information | scripts codificados, base64 en artefactos |

## TA0006 — Credential Access
| Técnica | Nombre | Se sostiene con |
|---|---|---|
| T1003 | OS Credential Dumping | acceso a LSASS, SAM/SECURITY hives, `/etc/shadow` |
| T1003.001 | LSASS Memory | Volatility3, handles a lsass, minidumps |
| T1110 | Brute Force | EVTX 4625 en ráfaga (logon fallido), 4771, `auth.log` |

## TA0007 — Discovery
| Técnica | Nombre | Se sostiene con |
|---|---|---|
| T1057 | Process Discovery | historiales de comando, Sysmon |
| T1082 | System Information Discovery | comandos de enumeración en historiales |
| T1083 | File and Directory Discovery | ShellBags (`UsrClass.dat`/`NTUSER.DAT`), LNK/Jump Lists, historiales |

## TA0008 — Lateral Movement
| Técnica | Nombre | Se sostiene con |
|---|---|---|
| T1021 | Remote Services | 4624 type 3/10, RDP/SMB, `lastlog` |
| T1021.001 | Remote Desktop Protocol | EVTX TerminalServices, 4624 type 10 |
| T1021.004 | Remote Services: SSH | `netscan` 22/tcp + `sshd` residente, `auth.log`, `lastlog`, `~/.ssh/authorized_keys` |

## TA0011 — Command and Control
| Técnica | Nombre | Se sostiene con |
|---|---|---|
| T1071 | Application Layer Protocol | conexiones en RAM (`netscan`), IOCs en no-asignado |
| T1095 | Non-Application Layer Protocol | sockets anómalos, beaconing |

## TA0009 — Collection
| Técnica | Nombre | Se sostiene con |
|---|---|---|
| T1005 | Data from Local System | documentos/imágenes recopilados del sistema; `$MFT`, `filescan`/`dumpfiles` en RAM |
| T1056 | Input Capture | proceso de captura residente, región RWX (`malfind`), fichero de log de pulsaciones |
| T1056.001 | Keylogging | binario keylogger (nombre/ruta de usuario, no firmado), `SetWindowsHookEx` en `handles`/`dlllist`, log de teclas, región RWX en `malfind` |
| T1074 | Data Staged | ficheros reunidos en ubicación intermedia antes de exfiltrar |
| T1074.001 | Local Data Staging | carpeta de staging local (p.ej. `Pics\Hidden`), `filescan`/`$MFT`, timeline |
| T1114 | Email Collection | almacén de correo local, cliente de email residente en RAM |
| T1114.001 | Local Email Collection | `.pst`/`.dbx` (Outlook/Outlook Express), `filescan`/`dumpfiles`, `$MFT` |

## TA0010 — Exfiltration
| Técnica | Nombre | Se sostiene con |
|---|---|---|
| T1041 | Exfiltration Over C2 Channel | volumen saliente, IOCs, artefactos de staging |
| T1048 | Exfiltration Over Alternative Protocol | exfil por email/FTP/DNS fuera del canal C2; cabeceras de correo, logs, PCAP |
| T1052 | Exfiltration Over Physical Medium | USBSTOR + acceso a ficheros en medio extraíble |
| T1052.001 | Exfiltration over USB | USBSTOR/`mountdev` (SYSTEM), `setupapi.dev.log`, LNK/ShellBags |
| T1567 | Exfiltration Over Web Service | proceso de sincronización/cliente cloud en RAM (`pslist`/`psscan`) + `netscan` ESTABLISHED :443 a rangos cloud en la misma ventana |
| T1567.002 | Exfiltration to Cloud Storage | cliente de almacenamiento cloud (S3, Dropbox, Drive, OneDrive) activo + documento/fichero abierto en la misma ventana (`filescan`/`dumpfiles`, timeline) |

## TA0040 — Impact
| Técnica | Nombre | Se sostiene con |
|---|---|---|
| T1486 | Data Encrypted for Impact | notas de rescate, extensiones masivas, YARA ransomware |
| T1490 | Inhibit System Recovery | borrado de shadow copies, EVTX, comandos vssadmin |

---

> **Uso:** `mitre.md` solo correlaciona técnicas de esta tabla y SIEMPRE con
> `relatedFindingIds` no vacío. Mapea a sub-técnica cuando la evidencia lo permita;
> si no, a la técnica padre. La atribución a grupos/APT no se hace desde esta
> semilla (requiere el corpus de grupos de S5 y, aun así, con cautela).

> **Ampliación 2026-07 (ATT&CK Enterprise v16):** añadidas para las guías de
> interpretación de artefactos (`knowledge/artefactos-windows.md`) sin duplicar
> ids: `T1110` (Brute Force, 4625 en ráfaga), `T1083` (File and Directory
> Discovery, ShellBags), `T1052` + `T1052.001` (Exfiltration Over Physical
> Medium / over USB, USBSTOR). Al aterrizar el corpus completo en S5 se revisa la
> versión y estas filas se reconcilian con él.

> **Ampliación 2026-07, segunda tanda (corridas LoneWolf memoria):** añadidas
> `T1567` + `T1567.002` (Exfiltration Over Web Service / to Cloud Storage), sin
> duplicar ids. Motivo: el patrón recurrente del corpus de memoria (clientes
> cloud tipo S3 Browser/Dropbox/OneDrive activos + conexiones establecidas a
> rangos cloud) quedaba sin técnica citable en la enum cerrada, y las
> investigaciones lo dejaban sin mapear u obligaban a un id fuera de semilla.
> Sostienen la cadena de correlación «Exfiltración a nube (memoria)» del
> playbook y la guía correspondiente en `artefactos-windows.md`.

> **Ampliación 2026-07, tercera tanda (corrida M57-Patents, memoria de Jo):**
> añadidas la táctica **TA0009 — Collection** (`T1005`, `T1074`/`T1074.001`,
> `T1114`/`T1114.001`) y `T1048` (Exfiltration Over Alternative Protocol) en
> TA0010, sin duplicar ids. Motivo: el vector de M57 es **exfil de propiedad
> intelectual por email** (Outlook Express) con **staging en carpeta oculta**
> (`Pics\Hidden`); ese patrón no tenía técnica citable (la exfil de la semilla era
> solo física/USB o cloud/web-service), y la corrida zero-shot 11-24 lo dejó
> correctamente sin mapear. Sostiene el hilo Jo del ground-truth
> `docs/agentes/ground-truth/m57-patents.md`. Derivado de fuentes públicas; a
> validar con el packet oficial si el tutor lo obtiene.
