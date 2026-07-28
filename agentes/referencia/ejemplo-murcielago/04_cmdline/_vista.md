# windows.cmdline — líneas de comando (legible + leads)

Cruda: [`raw.txt`](raw.txt).

## Lo relevante

| PID | Proceso | Línea de comando | Lectura |
|---|---|---|---|
| 3856 / 3184 | **key.exe** | `"C:\Users\IEUser\Desktop\key.exe"` | ⭐ Ejecutable **en el escritorio del usuario `IEUser`**, dos instancias anidadas. Nombre y ubicación sospechosos. **P2.** |
| 1600 | cmd.exe | `"C:\Windows\system32\cmd.exe"` | Consola sin args aquí — **los comandos tecleados** están en el historial (`cmdscan`, ejec. 06), no en `cmdline`. **E2.** |
| 1524 | StikyNot.exe | `"C:\Windows\System32\StikyNot.exe"` | Sticky Notes activo → mirar `StickyNotes.snt` (posible nota con credenciales). **E1?** |
| 2016 / 948 | cygrunsrv / sshd | `C:\Program Files\OpenSSH\...` | **OpenSSH (Cygwin)** instalado y sirviendo. Canal de exfiltración. **P2.** |
| 1832 | hMailServer | `"...\hMailServer.exe" RunAsService` | Servidor de correo como servicio. **P4/P2.** |
| 2324 | MagnetRamCapture | `"C:\Users\IEUser\Desktop\MagnetRamCapture.exe"` | Herramienta de **adquisición** de la RAM, en el Desktop de IEUser. No es del atacante. |

## Dato de identidad

- **El usuario del equipo es `IEUser`** (perfil `C:\Users\IEUser`). Es "el empleado" del
  enunciado, salvo que aparezcan más cuentas al listar usuarios/hives.
- ⚠️ **`key.exe` todavía NO es "malicioso"**: es un ejecutable con nombre y sitio raros. Para
  afirmar qué hace falta ver `malfind` (inyección) y, idealmente, extraerlo del disco y
  analizarlo. Se anota como **sospechoso a confirmar**, no como hallazgo cerrado.
