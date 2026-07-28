# volatility3 windows.hashdump · murcielago · ejecución 07 — ⚠️ PLUGIN AUSENTE
- **Tool:** volatility3 2.28.0 · `windows.hashdump` · `forensia/toolkit-unix:1.0`
- **Comando:** `vol -f /in/ram.raw windows.hashdump`
- **Exit:** 2 · bytes 0 · **Fecha:** 2026-07-28
- **FALLO:** `argument PLUGIN: invalid choice windows.hashdump` — **este build de vol NO incluye los
  plugins de credenciales** (hashdump/lsadump/cachedump no están en la lista de plugins).
- **Impacto:** bloquea la vía directa de **E1** (volcar hashes/secretos de la RAM).
- **Alternativas (E1):** (1) volcar los hives `SAM`+`SYSTEM` de memoria (`windows.registry.hivelist`
  + dump) y pasarlos por `regripper`/`samdump2` fuera; (2) `SAM` del **disco** cuando llegue;
  (3) buscar contraseña en claro (Sticky Notes, `strings`).
