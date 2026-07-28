# volatility3 windows.dumpfiles · murcielago · ejecución 21
- **Tool:** volatility3 2.28.0 · `windows.dumpfiles --physaddr <off>` · `forensia/toolkit-unix:1.0`
- **Comando:** `vol -f /in/ram.raw -o /dump windows.dumpfiles --physaddr {0x13d6be070,0x13d0bb070,0x13d337dd0}`
- **Fecha:** 2026-07-28
- **Salidas:** `file.*.CLIENTES DEL BANCO.xls.dat` (16 KB) · `file.*.Plan_de_cuentas.xls.dat` (72 KB). **pass.txt: no extraído** (sin páginas de datos residentes).
- **Observado:** los 2 XLS confidenciales **recuperados de RAM** (P1 confirmado). pass.txt sin contenido en memoria → E1 requiere disco.
- **Nota:** los `.dat` son artefactos DERIVADOS (contienen datos personales de clientes bancarios) → tratar con la misma cautela que la evidencia.
