# volatility3 windows.registry.hivelist --dump · murcielago · ejecución 10
- **Tool:** volatility3 2.28.0 · `windows.registry.hivelist --dump` · `forensia/toolkit-unix:1.0`
- **Comando:** `vol -o /out/10_hivelist -f /in/ram.raw windows.registry.hivelist --dump`
- **Exit / bytes:** 0 · 1546 (listado) · **Fecha:** 2026-07-28
- **Salidas:** `raw.txt` (lista de hives) + **16 hives volcados** `registry.*.hive` (SAM, SYSTEM, SOFTWARE, SECURITY, Amcache, DEFAULT, NTUSER de IEUser y sshd_server, UsrClass, BCD…).
- **Observado:** aparece la cuenta **`sshd_server`** (`C:\Users\sshd_server\ntuser.dat`) → segundo usuario además de IEUser. Los hives volcados habilitan E1 (SAM/SYSTEM → regripper, ejec.15) y P2/ejecución (Amcache).
- **Nota:** los hives son artefactos DERIVADOS de la RAM (no la evidencia original); se guardan en output, no en input.
