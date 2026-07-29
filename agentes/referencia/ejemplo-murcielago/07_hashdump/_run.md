# volatility3 windows.hashdump · murcielago · ejecución 07 — ⚠️ CONCLUSIÓN RECTIFICADA

> **RECTIFICACIÓN 2026-07-17.** El acta de abajo se conserva íntegra (es el registro de lo
> ejecutado), pero **su conclusión no se sostiene**: re-verificado contra el maletín actual
> (`volatility3 2.28.0`), `windows.registry.hashdump.Hashdump` sobre una RAM Win7 real
> devuelve **6 cuentas con su NT hash y exit 0**. `lsadump` y `cachedump` también están
> (`vol -h` los lista, con alias `windows.*` y canónico `windows.registry.*`).
> El `invalid choice` que se observó corresponde al **nombre invocado sin la clase**
> (`windows.hashdump` en vez de `…​.Hashdump`); no se ha podido reproducir la ausencia.
> **Impacto:** E1 SÍ tiene vía directa. Ver la heurística 1 corregida en
> [`FLUJO-destilado.md`](../../FLUJO-destilado.md).
- **Tool:** volatility3 2.28.0 · `windows.hashdump` · `forensia/toolkit-unix:1.0`
- **Comando:** `vol -f /in/ram.raw windows.hashdump`
- **Exit:** 2 · bytes 0 · **Fecha:** 2026-07-28
- **FALLO:** `argument PLUGIN: invalid choice windows.hashdump` — **este build de vol NO incluye los
  plugins de credenciales** (hashdump/lsadump/cachedump no están en la lista de plugins).
- **Impacto:** bloquea la vía directa de **E1** (volcar hashes/secretos de la RAM).
- **Alternativas (E1):** (1) volcar los hives `SAM`+`SYSTEM` de memoria (`windows.registry.hivelist`
  + dump) y pasarlos por `regripper`/`samdump2` fuera; (2) `SAM` del **disco** cuando llegue;
  (3) buscar contraseña en claro (Sticky Notes, `strings`).
