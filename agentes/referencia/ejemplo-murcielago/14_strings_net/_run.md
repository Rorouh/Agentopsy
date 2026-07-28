# strings (nube/IP) · murcielago · ejecución 14 · P4
- **Tool:** `strings` (ASCII + UTF-16LE) del `toolkit-unix` · imagen `forensia/toolkit-unix:1.0`
- **Comando:** `{ strings -a -t d ram.raw; strings -a -e l -t d ram.raw; } | grep -iE "<ip>|<dominios nube/webmail>"`
- **Exit / líneas:** 0 · 1951 · **Fecha:** 2026-07-28
- **Salidas:** `raw.txt` · `_vista.md`
- **Observado:** IP `200.228.36.6` **no aparece**; sí un **enlace a fichero de Google Drive** repetido; resto, ruido de navegador. Responde parcialmente **P4**.
