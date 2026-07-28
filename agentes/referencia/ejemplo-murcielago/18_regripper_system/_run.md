# regripper (SYSTEM) · murcielago · ejecución 18
- **Tool:** regripper (rip.pl) · imagen `forensia/toolkit-windows:1.0` · plugins timezone, compname, shutdown, usbstor, mountdev
- **Comando:** `rip.pl -r /hives/registry.SYSTEM.0xf8a000024010.hive -p <plugin>` (con `timeout 60`)
- **Entrada:** hive SYSTEM volcado de RAM (`../10_hivelist/`). **Fecha:** 2026-07-28 · exits 0
- **Salidas:** `raw.txt` · `_vista.md`
- **Observado:** TZ = Pacific (UTC−7 con DST); equipo IEWIN7; varias USB Kingston DataTraveler (2 del perito el 23-03, 2 previas del 20/22-03). Responde **P3** y fija la **zona horaria**.
- **Nota:** las USB del 23-03 (F:, E:) son de ADQUISICIÓN (contienen el kit del perito y el propio ram.raw) — no exfiltración.
