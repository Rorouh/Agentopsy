# E1 — pass.txt (leído del disco) · icat inode 1194

Contenido de `C:\Users\IEUser\Desktop\pass.txt` (offset 2048, inode 1194):

> "La contraseña de usuario la tienes que dumpear con volatility, así podrás acceder a la
> máquina, el hash obtenido es fácil de romper :)"

## Lectura
- `pass.txt` **NO contiene la contraseña**: es una **pista** del ejercicio → la vía prevista es
  **volcar el hash NTLM con volatility (hashdump) y crackearlo**.
- ⚠️ Este build de vol del maletín **no trae `hashdump`** (a6), así que la contraseña **no se
  ha podido obtener** con las herramientas disponibles. Vía pendiente: extraer SAM+SYSTEM y
  pasarlos por `samdump2`/`secretsdump` (fuera del maletín) y crackear con hashcat/john.
- `leeme.txt.bak` trae un **César/ROT13**: "creo que deberás de buscar el correo" → apunta al
  **correo** (hMailServer/Thunderbird) como vía de exfiltración.
