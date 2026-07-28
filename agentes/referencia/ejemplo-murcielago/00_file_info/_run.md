# file_info · murcielago · ejecución 00

- **Fecha:** 2026-07-28
- **Tool:** `file` + `stat` + `xxd` (utilidades base del maletín `toolkit-unix`)
- **Imagen Docker:** `forensia/toolkit-unix:1.0` (linux/amd64, emulado en arm64)
- **Comando exacto:**
  ```
  docker run --rm -v <input/murcielago>:/in:ro forensia/toolkit-unix:1.0 \
    sh -c 'file /in/ram.raw; stat /in/ram.raw; xxd -l 512 /in/ram.raw'
  ```
- **Entrada:** `input/murcielago/ram.raw` (montada **read-only**)
- **Parámetros:** ninguno relevante.
- **Duración / exit code:** ~2 s · 0
- **Salidas:** `00__raw.txt` (cruda). No se generó `__vista` — la cruda ya es legible.
- **Observado:**
  - `file` devuelve `data`: el volcado **no tiene cabecera reconocible** → coherente con un
    dump **raw lineal** (LiME-style), no un crash dump ni hibernación (esos sí llevan firma).
  - Primeros bytes a cero: normal, el arranque de la RAM física suele ser reservado.
  - **Nota de método:** el `WARNING` de plataforma es de Docker (emulación amd64), no de la
    tool; se deja constar aquí, no contamina el hallazgo.
- **Responde a:** paso 1 del flujo (formato del volcado). Confirma que `volatility3` puede
  tratarlo como raw.
