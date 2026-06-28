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

## TA0007 — Discovery
| Técnica | Nombre | Se sostiene con |
|---|---|---|
| T1057 | Process Discovery | historiales de comando, Sysmon |
| T1082 | System Information Discovery | comandos de enumeración en historiales |

## TA0008 — Lateral Movement
| Técnica | Nombre | Se sostiene con |
|---|---|---|
| T1021 | Remote Services | 4624 type 3/10, RDP/SMB, `lastlog` |
| T1021.001 | Remote Desktop Protocol | EVTX TerminalServices, 4624 type 10 |

## TA0011 — Command and Control
| Técnica | Nombre | Se sostiene con |
|---|---|---|
| T1071 | Application Layer Protocol | conexiones en RAM (`netscan`), IOCs en no-asignado |
| T1095 | Non-Application Layer Protocol | sockets anómalos, beaconing |

## TA0010 — Exfiltration
| Técnica | Nombre | Se sostiene con |
|---|---|---|
| T1041 | Exfiltration Over C2 Channel | volumen saliente, IOCs, artefactos de staging |

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
