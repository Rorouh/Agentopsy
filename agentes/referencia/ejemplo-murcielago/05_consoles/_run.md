# volatility3 windows.consoles · murcielago · ejecución 05 — ⚠️ NO SOPORTADO
- **Tool:** volatility3 2.28.0 · `windows.consoles` · imagen `forensia/toolkit-unix:1.0`
- **Comando:** `vol -f /in/ram.raw windows.consoles` (lote)
- **Exit:** ≠0 (abortó el lote por `set -e`) · **Fecha:** 2026-07-28
- **Salidas:** `raw.txt` (solo cabecera) · `stderr.txt` (traza).
- **Observado / FALLO:** `NotImplementedError: This version of Windows is not supported: 6.1 15.7601!`.
  El plugin `consoles` de esta versión de vol **no soporta Win7**. Limitación de la TOOL, no del caso.
- **Mitigación:** el historial de consola se persigue con `windows.cmdscan` (ejec. 06), que usa otro mecanismo.
- **Lección de método:** no usar `set -e` en un lote de plugins — un plugin no soportado no debe tumbar los demás. Corregido en el relanzamiento (batch 2).
