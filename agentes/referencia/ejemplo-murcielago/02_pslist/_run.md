# volatility3 windows.pslist · murcielago · ejecución 02

- **Fecha:** 2026-07-28
- **Tool:** `volatility3` 2.28.0 — `windows.pslist`
- **Imagen Docker:** `forensia/toolkit-unix:1.0`
- **Comando exacto:** `vol -f /in/ram.raw windows.pslist` (dentro del lote del contenedor
  efímero; cache de símbolos en volumen `forensia-vol-cache`).
- **Entrada:** `input/murcielago/ram.raw` (ro)
- **Duración / exit code:** rápido (cache caliente) · 0 · 5045 bytes
- **Salidas:** `raw.txt` (cruda) · `_vista.md` (legible, con los leads).
- **Observado:** 52 procesos. Lista coherente con un Win7 SP1. **Varios procesos con peso
  forense fuerte** (ver `_vista.md`): SSH (Cygwin), servidor de correo, `key.exe`,
  `cmd.exe` justo antes del volcado, Sticky Notes.
- **Responde a:** contexto para P2, P4, E1, E2 (da PIDs, tiempos y árbol para dirigir el
  resto de plugins).
