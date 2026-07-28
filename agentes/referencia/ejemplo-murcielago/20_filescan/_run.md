# volatility3 windows.filescan · murcielago · ejecución 20
- **Tool:** volatility3 2.28.0 · `windows.filescan` · `forensia/toolkit-unix:1.0`
- **Comando:** `vol -f /in/ram.raw windows.filescan`
- **Exit / líneas:** 0 · 9990 · **Fecha:** 2026-07-28
- **Salidas:** `raw.txt` (todos los file objects) · `_vista.md`
- **Observado:** localiza `Documentacion empresa\CLIENTES DEL BANCO.xls` y `Plan_de_cuentas.xls` (P1), `Desktop\pass.txt` (E1), `Prefetch\KEY.EXE-*.pf` (P2). Da los offsets para dumpfiles.
