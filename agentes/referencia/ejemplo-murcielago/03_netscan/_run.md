# volatility3 windows.netscan · murcielago · ejecución 03
- **Tool:** volatility3 2.28.0 · `windows.netscan` · imagen `forensia/toolkit-unix:1.0`
- **Comando:** `vol -f /in/ram.raw windows.netscan` (lote, cache en volumen `forensia-vol-cache`)
- **Exit / bytes:** 0 · 4190 · **Fecha:** 2026-07-28
- **Salidas:** `raw.txt` · `_vista.md`
- **Observado:** conexión externa **CLOSED a 200.228.36.6** (candidato a exfiltración); `sshd`:22 y `hMailServer`:25/110/143/587 en escucha. Responde parcialmente **P4** y da vectores **P2**.
