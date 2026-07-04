# `jq` — sobre `dvwa-container-rootfs/dvwa-disk.raw`

- **Grupo:** A · **Imagen:** DVWA docker rootfs · **Estado:** ✅ eficaz (utilidad *downstream*)
- **Binario:** `jq` · **Maletín:** `toolkit-unix` (Cross)
- **run_id:** `300a1787-11bf-4692-a29d-8417c59de746`

## Objetivo (máxima expresión)

`jq` NO analiza evidencia: **filtra/consulta el JSON que producen otras tools** (Volatility
`-r json`, plaso CSV→json, etc.) para no volcar artefactos gigantes al contexto — extrae
top-N, campos concretos, agregados. Su valor real es *downstream*. Aquí lo valido sobre un
JSON que ya tenemos.

## Cómo la usé (params + argv)

Wrapper `jq.py`. Params: `filter` (req.), `input_path` (req. — **no** es evidencia; lo da el
caller), `raw_output` (-r), `compact` (-c), `slurp` (-s), `sort_keys` (-S).

Lo apliqué al **`baseline.json`** de la evidencia (el registro de cadena de custodia):

```
execute("jq", {"filter": "{sha256, size, detected_os, detected_kind, triage_signals}",
               "input_path": ".../evidence/<eid>/baseline.json"}, …)
argv = jq '{sha256, size, detected_os, detected_kind, triage_signals}' <baseline.json>
```

## Resultado obtenido — exit 0

```json
{ "sha256": "d9d08eab…", "size": 1189085184,
  "detected_os": "unix", "detected_kind": "disk", "triage_signals": ["ext_magic"] }
```
El `parse` lo envuelve como `{"json": {…}}` (salida JSON parseada, no texto). Confirma de
paso que el triage marcó `ext_magic` al ingerir la evidencia.

## Veredicto de eficacia

- **Eficaz y limpio** como filtro. `parse` devuelve el JSON estructurado.
- **No produce hallazgos forenses por sí solo** (es utilidad): no se registra finding — no
  aporta intel nueva sobre la evidencia, solo reformatea/filtra.
- Su **máxima expresión** llega con salidas JSON grandes (p. ej. `volatility3 -r json` con
  miles de procesos/conexiones): ahí `jq` es imprescindible para top-N y proyección.

## Lecciones para entrenar al agente

1. **Usa `jq` para NO volcar artefactos JSON enteros:** tras un tool que devuelve JSON grande,
   filtra con `jq` (`input_path` = el artefacto) por campo / top-N en vez de leer todo.
2. **Encadenado:** `volatility3 (-r json)` → `jq` `.[] | select(.PID==…)`; `plaso_psort`
   (json) → `jq` por rango; etc.
3. **`slurp` (-s)** para reunir varios documentos JSON en un array antes de agregarlos.
4. **`input_path` es un artefacto, no la evidencia:** FORENSIA no lo inyecta — hay que
   pasarle el path del JSON que quieres consultar.

## Registro en el caso

- **Sin finding** (utilidad de filtrado, sin hallazgo nuevo). run `300a1787` en el audit.
- **Evidencia recopilada:** [`jq/custody-extract.json`](jq/custody-extract.json) (extracto de
  custodia vía jq).
