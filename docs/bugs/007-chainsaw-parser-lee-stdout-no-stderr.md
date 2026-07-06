# Bug 007 — el parser de `chainsaw` leía stdout, pero chainsaw resume por stderr

- **Severidad:** media (el artefacto es correcto; el resumen estructurado reportaba 0)
- **Estado:** ✅ **resuelto** (2026-07-04)
- **Componente:** `backend/forensia/toolkit/wrappers/chainsaw.py` + `backend/forensia/toolkit/dispatcher.py`
- **Detectado:** 2026-07-04, al ejecutar chainsaw por el dispatcher (campaña Grupo C)

## Síntoma

`execute("chainsaw", …)` → **exit 0**, los 7 CSV de detección **se escriben bien**
(148 filas reales), pero el resultado estructurado decía `parsed = {'detections': 0,
'lines': 0}`. El `stdout_sample` venía **vacío**.

## Causa raíz

Dos cosas se juntan:

1. **chainsaw escribe a stderr, no a stdout.** El banner ASCII, el progreso y la línea de
   resumen `[+] N Detections found on N documents` salen por **stderr**; con `--output DIR`
   las tablas por regla van a **ficheros CSV**. Así que stdout queda vacío.
2. **El dispatcher solo pasaba stdout al parser** (`tool.parse(stdout)`), y el parser de
   chainsaw contaba líneas que empiezan por `[+]` en stdout → 0.

Contrasta con `hayabusa`, que imprime su resumen (`Total detections: N`) por **stdout** y
por eso sí parseaba (129). Mismo canal exec-agent, distinto stream de salida de la tool.

## Fix aplicado

- **Dispatcher (`_build_result`):** ahora elige por **aridad** del `parse`. Los wrappers que
  necesitan stderr declaran `parse(stdout, stderr)`; el resto sigue con `parse(stdout)` sin
  cambios (`_parse_wants_stderr` inspecciona la firma). No rompe el contrato de ningún
  wrapper existente.
- **`chainsaw.parse(stdout, stderr="")`:** extrae `N` de `(\d+)\s+Detections?\s+found`
  (busca en stdout+stderr), lista las categorías de las líneas `Created X.csv`, y mantiene
  el conteo legacy de `[+]` como *fallback*. Tras el fix: `{'detections': 56,
  'categories': [...7 csv...]}`.

## Lección (reusable)

**No asumir que una CLI resume por stdout.** Muchas herramientas forenses mandan el
progreso/resumen a **stderr** y el resultado real a **ficheros** (`--output`). Al integrar
un wrapper: (1) mirar por qué stream sale el resumen, (2) si el dato vive en los ficheros de
salida, el parser debe contar sobre ellos o sobre stderr, no sobre un stdout que estará
vacío. Relacionado con el Bug 002 (parser que subcuenta): en ambos el **exit code y el
artefacto eran correctos**, lo que fallaba era la *lectura* del resultado — un fallo silencioso
más peligroso que un crash.
