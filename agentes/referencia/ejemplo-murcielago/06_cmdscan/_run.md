# volatility3 windows.cmdscan · murcielago · ejecución 06 — ⚠️ NO SOPORTADO
- **Tool:** volatility3 2.28.0 · `windows.cmdscan` · `forensia/toolkit-unix:1.0`
- **Comando:** `vol -f /in/ram.raw windows.cmdscan`
- **Exit:** 1 · bytes 77 (solo cabecera) · **Fecha:** 2026-07-28
- **FALLO:** mismo `NotImplementedError: This version of Windows is not supported: 6.1 15.7601!`
  que `consoles` — `cmdscan` reutiliza el código de `consoles`. → **historial de consola NO
  disponible desde esta RAM con esta versión de vol.**
- **Impacto:** bloquea la vía "memoria" de **E2** (comandos tecleados). Alternativas: `$UsnJrnl`/
  `ConsoleHost_history` en **disco**; o `strings`/`bstrings` sobre la RAM buscando el comando.
