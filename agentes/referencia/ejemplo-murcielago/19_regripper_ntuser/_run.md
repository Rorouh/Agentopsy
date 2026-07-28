# regripper (NTUSER IEUser) · murcielago · ejecución 19
- **Tool:** regripper (rip.pl) · imagen `forensia/toolkit-windows:1.0` · plugins userassist, recentdocs, comdlg32, runmru, typedpaths
- **Comando:** `rip.pl -r /hives/registry.ntuserdat.0xf8a0025e5410.hive -p <plugin>` (con `timeout 60`)
- **Entrada:** NTUSER.dat de IEUser volcado de RAM. **Fecha:** 2026-07-28 · exits 0
- **Salidas:** `raw.txt` · `_vista.md`
- **Observado:** RecentDocs incluye **"Documentacion empresa"**, pass.txt, passwords.txt (P1 + lead E1); key.exe ejecutado 3× por el usuario (P2); mucho tooling de adquisición (perito). ram.raw guardado en F:\RAM\.
