# windows.pslist — procesos (legible + leads)

Cruda: [`raw.txt`](raw.txt). 52 procesos. Todas las horas en **UTC** (volcado 19:24:35 UTC).

## Procesos con peso forense

| PID | Proceso | PPID | Creado (UTC) | Por qué importa | Pregunta |
|---|---|---|---|---|---|
| 948 | **sshd.exe** | 1168 (cygrunsrv) | 17:15:47 | **Servidor SSH (Cygwin)** en la máquina → canal de exfiltración SCP/SFTP y acceso remoto. | **P2** |
| 2016/1168 | cygrunsrv.exe | 488/2016 | 17:15:46 | Cygwin como servicio: es lo que arranca el `sshd`. | P2 |
| 1832 | **hMailServer.exe** | 488 | 17:15:45 | **Servidor de correo local** (Wow64). Correo saliente = vector de fuga. | **P4/P2** |
| 3856 | **key.exe** | 1272 (explorer) | **19:08:10** | Nombre sospechoso, lanzado desde el explorador. | **P2** |
| 3184 | **key.exe** | 3856 (key.exe) | 19:08:10 | Segunda instancia, hija de la primera. Patrón raro. | **P2** |
| 1600 | **cmd.exe** | 1272 (explorer) | **19:22:55** | Consola abierta **100 s antes del volcado** → aquí puede estar el borrado (E2). | **E2** |
| 1388 | conhost.exe | 396 | 19:22:55 | Host de consola de ese `cmd.exe`. | E2 |
| 1524 | **StikyNot.exe** | 1272 | 17:15:32 | Sticky Notes: el `.snt` suele guardar notas y **a veces contraseñas**. | **E1?** |
| 1816 | msedge.exe | 1272 | 17:49:22 → †17:50:33 | Navegador abierto ~1 min → URLs/webmail en memoria. | **P4** |
| 2324 | MagnetRamCaptu | 1272 | 19:24:25 | **MagnetRAMCapture**: la herramienta que hizo ESTE volcado. Artefacto de **adquisición**, no del atacante — se anota para no confundirlo con actividad sospechosa. | — |

## Lectura rápida

- La máquina no es un PC de oficina "pelado": tiene **SSH server y servidor de correo**
  levantados. Eso abre dos vías de exfiltración muy concretas que hay que perseguir (P2/P4).
- **`key.exe` y el `cmd.exe` de las 19:22** son las dos pistas más calientes para P2 y E2:
  ambas cerca del final, justo antes de capturar la RAM.
- **No dar por hecho nada del nombre** `key.exe`: hay que ver su **línea de comandos**
  (`cmdline`, ejec. 04) y si tiene inyección (`malfind`) antes de llamarlo malicioso.
