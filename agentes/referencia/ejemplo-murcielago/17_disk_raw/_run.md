# qemu-img convert vmdk→raw + mmls · murcielago · ejecución 17 (reintento OK)
- **Tool:** qemu-img + TSK mmls · `forensia/toolkit-unix:1.0`
- **Comando:** `qemu-img convert -p -f vmdk -O raw -S 4096 …vmdk /out/disk.raw` ; `mmls /out/disk.raw`
- **Fecha:** 2026-07-28 · convert exit 0 · mmls exit 0
- **Espacio:** con **51,8 GB reales libres** (antes ~22 disfrazados de 82 por purgable) cupo sin problema; raw = 20,5 GB, quedaron 31 GB.
- **Salidas:** `disk.raw` (derivado, 40 GiB aparente / 20,5 GiB real, en 444) — NO es la evidencia original, es su forma analizable.
- **mmls:** 1 partición **NTFS** en **sector 2048** (offset para todo `fls/icat`). Longitud 83881984 sectores (~40 GB).
- **Observado:** el disco **abre limpio y estructurado** → apoya que el desajuste de hash es **errata del PDF**, no descarga corrupta (no se puede probar al 100%, pero es coherente).
- ⚠️ El 1er intento (a8) llenó el disco por el espejismo del purgable; documentado allí.
