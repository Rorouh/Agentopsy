# volatility3 windows.info · murcielago · ejecución 01

- **Fecha:** 2026-07-28
- **Tool:** `volatility3` 2.28.0 — plugin `windows.info`
- **Imagen Docker:** `forensia/toolkit-unix:1.0` (linux/amd64, emulado en arm64)
- **Comando exacto:**
  ```
  docker run --rm -v <input/murcielago>:/in:ro forensia/toolkit-unix:1.0 \
    vol -f /in/ram.raw windows.info
  ```
- **Entrada:** `input/murcielago/ram.raw` (read-only)
- **Parámetros:** ninguno (vol detecta el layout solo).
- **Duración / exit code:** varios min (primera vez: construyó la caché de símbolos de 110
  ficheros; las siguientes ejecuciones de vol serán más rápidas) · 0
- **Salidas:** `01__raw.txt` (cruda) · `01__vista.md` (legible) · `_stderr.txt` (progreso de
  la caché de símbolos — ruido de vol, no hallazgo).
- **Observado:**
  - Perfil: **Win7 SP1 x64**, build `7601.24384`, 1 CPU, hora del volcado **2021-03-23
    19:24:35 UTC**.
  - vol trae los símbolos de ntkrnlmp: **no necesita red** (bien para un maletín offline).
  - El `_stderr.txt` se llena de `Progress … Updating caches` — es normal la primera vez;
    no es un error.
- **Responde a:** paso 1 del flujo. Falta la **zona horaria** (registro) para cerrar el
  marco temporal.
