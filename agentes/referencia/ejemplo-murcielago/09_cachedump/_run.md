# volatility3 windows.cachedump · murcielago · ejecución 09 — ⚠️ CONCLUSIÓN RECTIFICADA

> **RECTIFICACIÓN 2026-07-17.** Acta conservada; conclusión no sostenida. `cachedump` **sí
> está** en el maletín actual — id canónico `windows.registry.cachedump.Cachedump`
> (`vol -h`). El `invalid choice` corresponde al nombre invocado sin la clase. Ver
> [`FLUJO-destilado.md`](../../FLUJO-destilado.md) § heurística 1.
- **Tool:** volatility3 2.28.0 · `windows.cachedump` · `forensia/toolkit-unix:1.0`
- **Comando:** `vol -f /in/ram.raw windows.cachedump`
- **Exit:** 2 · bytes 0 · **Fecha:** 2026-07-28
- **FALLO:** `argument PLUGIN: invalid choice windows.cachedump` — **este build de vol NO incluye los
  plugins de credenciales** (hashdump/lsadump/cachedump no están en la lista de plugins).
- **Impacto:** bloquea la vía directa de **E1** (volcar hashes/secretos de la RAM).
- **Alternativas (E1):** (1) volcar los hives `SAM`+`SYSTEM` de memoria (`windows.registry.hivelist`
  + dump) y pasarlos por `regripper`/`samdump2` fuera; (2) `SAM` del **disco** cuando llegue;
  (3) buscar contraseña en claro (Sticky Notes, `strings`).
