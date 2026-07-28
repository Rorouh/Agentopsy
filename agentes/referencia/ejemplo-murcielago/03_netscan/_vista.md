# windows.netscan — conexiones de red (legible + leads)

Cruda: [`raw.txt`](raw.txt). Todas las horas **UTC**.

## Lo caliente

| Qué | Detalle | Pregunta |
|---|---|---|
| **⭐ Conexión externa** | `200.228.36.6` — TCPv4 **CLOSED**, sin PID (offset `0x13e099530`). IP **pública** (rango brasileño 200.x). Resto de una conexión saliente ya cerrada. **Primer candidato a destino de exfiltración.** | **P4 / P2** |
| **SSH abierto** | `sshd.exe` (PID 948) **LISTENING en 0.0.0.0:22**. Canal de exfiltración SCP/SFTP + acceso remoto. | **P2** |
| **Servidor de correo** | `hMailServer` (PID 1832) **LISTENING en 25, 110, 143, 587** (SMTP/POP3/IMAP/submission). Correo saliente = fuga. | **P4 / P2** |
| Máquina en LAN | IP local `192.168.65.135`; SMB (139/445), LLMNR (5355), WSD (3702). Normal en Win7. | contexto |

## Lectura

- **No se ve la conexión "en vivo" hacia una nube conocida** (Drive/Dropbox/webmail) en este
  netscan — la mayoría son puertos en escucha locales. Lo único que apunta afuera es
  **`200.228.36.6`**, y ya estaba **CLOSED**: hay que perseguir esa IP en las URLs/strings de
  memoria (ejec. siguiente con `strings`/`bulk_extractor`) para saber **qué** se mandó.
- Los dos servicios de fuga (SSH, correo) **estaban levantados**; falta ver si se **usaron**
  para sacar datos (logs, sesiones) → eso ya pide el disco.
