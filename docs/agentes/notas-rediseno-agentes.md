# Notas — Rediseño de los agentes (borrador de conversación)

> Documento de trabajo. Recoge la conversación con el perito sobre cómo rediseñar
> los agentes para reducir ineficiencia y gasto de tokens. **No es diseño cerrado**;
> se irá puliendo. Fecha de inicio: 2026-07-16.

## Problema de partida

Los agentes actuales se manejan con:

- un **playbook casi hardcodeado**,
- un **`identity.md`**,
- un **`system.md`**,

todos en formato Markdown. El resultado es **ineficiente y gasta demasiados tokens**:
se carga un prompt masivo al LLM y se lee toda la memoria de golpe, en lugar de ir
a buscar solo lo que hace falta según el caso.

## Objetivo

Reorientar los prompts hacia un **mapa de memoria**: el agente, según lo que necesite,
acude a un fichero u otro en vez de arrastrar todo el contexto en cada turno. Más
libertad para el perito, menos prompt masivo, ejecución más dirigida.

---

## 1. `identity.md` — pulir

Partir de esta base (FORENSIA-UNIX) e ir refinando:

- **Identidad:** analista forense post-mortem especializada en UNIX/Linux y macOS.
  Tono profesional, pausado, preciso, en español. Sin emojis. Nunca promete lo que
  no puede ejecutar.
- **Mensaje de presentación** (primer turno del chat): se presenta como FORENSIA-UNIX,
  agente forense post-mortem para imágenes Linux/macOS; trabaja en solo lectura sobre
  la evidencia ya registrada y verificada; pide qué reconstruir (accesos, persistencia,
  ejecución, exfiltración, ventana temporal) o propone un barrido inicial con plan.
- **Tono y hábitos:**
  - Habla del **caso** y la **evidencia** por su `id`, no por rutas de fichero.
  - Anuncia los pasos lentos **antes** de lanzarlos (p. ej. `bulk_extractor` sobre la
    imagen completa puede tardar; pregunta si lanzarlo o acotar primero).
  - Distingue **hecho** (lo que un artefacto demuestra) de **hipótesis** (lo que
    sugiere) y **etiqueta la confianza**.
  - Cuando algo no concluye, lo dice sin rodeos y sugiere agregar la herramienta X
    apropiada para ese caso concreto.

Se irá puliendo.

## 2. `system.md` — reorientar a mapa de memoria

- **Ineficiencia detectada:** de la línea 3 a la 9 casi le da una **segunda identidad**,
  redundante con `identity.md`. Eso debe salir del system.
- **Reglas no negociables:** no parecen mal. **Duda abierta:** dónde colocarlas —
  probablemente **se quedan en el `system.md`**.
- **Nuevo enfoque — mapa de memoria:** el system pasa a **trazar un mapa** de a qué
  fichero acudir según lo que se necesite. Ejemplo de redacción:

  ```
  Dependiendo de las instrucciones del perito vas a usar este mapa a modo de memoria.

  ## Ubicación de memoria según caso
  Si te piden X cosa, revisa la ruta X con el fin de ver Y.
  ```

## 3. Playbook — de hardcodeado a más libre

- Hoy está **completamente hardcodeado**.
- Debe ser **más libre**, para que el perito pueda usar las tools que sean más útiles
  según el caso concreto.
- **Añadir algún `.md` más** para mapear mejor la información, de modo que **no se
  cargue un prompt masivo** al LLM ni se lea toda la memoria de golpe.

## 4. Mapa de hallazgos y evidencias (nuevo)

- Crear **otro mapa**, dedicado a **hallazgos y evidencias**.
- Objetivo: ante peticiones específicas (ver el historial web, qué actividad se realizó
  del X al Y, etc.) la ejecución sea **más dirigida y eficiente**.
- **Se construye a medida que el agente avanza** (mapa vivo), no de golpe al inicio.

---

## Bugs de backend a arreglar en paralelo (no los resuelve ningún prompt)

Verificado en el código a partir de los transcripts reales del caso (contenedor Docker
DVWA, `original.raw`). El rediseño de prompts/mapas **reduce la frecuencia** con que el
agente tropieza con estos fallos (deja de re-lanzar herramientas), pero **no los arregla**:
son defectos de backend. Si solo tocamos prompts, `record_finding` seguirá guardando como
*hallazgo* lo que en realidad es una *inferencia no verificada* — inaceptable en forense.

Los ejes 1 y 4 los cubre el rediseño del agente (memoria/mapa vivo). Los ejes 2 y 3 exigen
tocar el backend.

> **Estado (2026-07-17):** Bugs 1 y 2 **ARREGLADOS** y con test de regresión; Bug 3
> sigue pendiente de repro. Suite backend: 990 passed, 6 skipped; `ruff` limpio.

### Bug 1 — El bodyfile de `fls -m` nunca llega a ser artefacto referenciable (pipeline `tsk_fls → tsk_mactime` roto de raíz) — ARREGLADO

- `fls -m` escribe el bodyfile a **stdout**, no a un fichero.
- `tsk_fls` (`backend/forensia/toolkit/catalog.py:225`) está declarado `returns="artifact"`
  pero **no** es `binary_stdout` y **no** tiene ningún parámetro `RUN_OUTPUT` que capture
  stdout a un fichero dentro de `out/`.
- Por eso `ArtifactStore._scan_out_dir` (`backend/forensia/artifacts/store.py:132`) no
  encuentra nada → `output_files: []`.
- `tsk_mactime` pide su `bodyfile_path` como ArtifactRef `{run_id, relpath}`, que
  `resolve_output_file` (`store.py:386`) exige que esté registrado como output file.
  Al no estarlo → `KeyError: produced no output file 'bodyfile.txt'`. **Es el error literal
  del transcript.**
- Agravante: el `stdout_sample` que el agente sí ve va recortado a 2000 chars
  (`backend/forensia/agent/agent.py:812`), así que tampoco puede reconstruir el bodyfile
  leyéndolo inline. Resultado: el agente **infiere** la timeline en vez de materializarla.
- **Arreglado:** nuevo campo `Tool.stdout_artifact_param` (dual-mode). `tsk_fls` lo declara
  `="body_format"`: en modo `-m` su stdout se captura byte-exacto y hasheado a
  `out/stdout.bin` (mismo canal que `binary_stdout`/icat), que `tsk_mactime` resuelve como
  `{run_id, relpath}`. El modo listado normal sigue inline (sin desviar stdout). El builder
  determinista `run_filesystem_timeline` (`_read_run_stdout`) ahora lee el bodyfile de
  `out/stdout.bin`. Ficheros: `toolkit/tool.py`, `toolkit/dispatcher.py`
  (`_stdout_to_artifact`), `toolkit/catalog.py`, `timeline/builder.py`. Regresión:
  `tests/test_binary_stdout_channel.py::test_fls_body_mode_materialises_referenceable_bodyfile`
  y `::test_fls_listing_mode_stays_inline_no_stdout_artifact`.

### Bug 2 — Al agente se le muestran `run_id` truncados que luego reutiliza → `invalid run_id (expected UUID4)` — ARREGLADO

- El ledger de runs que se persiste en el contexto del modelo renderiza `run={run_id[:8]}`
  (`backend/forensia/agent/history.py:168` y `backend/forensia/agent/context.py:98`).
- El `run_id` completo solo viaja en el payload del resultado del **mismo turno**
  (`backend/forensia/agent/agent.py:809`). Turnos después el agente solo tiene el prefijo de
  8 chars (`7e2b9d14`, `99def13e`…) y lo copia como referencia.
- `ArtifactStore._run_dir` (`store.py:128`) lo rechaza por validación UUID4 estricta →
  `invalid run_id (expected UUID4)`. **Es el otro error del transcript.**
- Es un footgun de diseño: se le enseña un id *lossy* que no puede round-trippear.
- **Arreglado:** el ledger (`history.py`) y el stub de resultado elidido (`context.py`)
  ahora imprimen el `run_id` completo (`run={run_id}`), no el prefijo `[:8]`. Coste en
  tokens despreciable (~28 chars extra por entrada, tope 30) frente a que sea la clave de
  recuperación del artefacto.

### Bug 3 — Fallo de Codex CLI (`Reading additional input from stdin...`, exit 1)

- Real (aparece en el transcript), independiente de los prompts. El ejecutor pasa
  `stdin=subprocess.DEVNULL` en el run real (`backend/forensia/executors/base.py:378`;
  la `:282` es el probe de auth, no el run) y el prompt como argv posicional
  (`backend/forensia/executors/codex.py:89`).
- Como el prompt **sí** se pasa como posicional, la teoría "cae a stdin por falta de
  prompt" se debilita: con prompt presente, `Reading additional input from stdin...` es
  probablemente un mensaje informativo (stdin=DEVNULL) y el exit 1 vendría de otra causa
  (sandbox `read-only`, versión de Codex).
- **NO clavado solo leyendo código** — necesita repro en vivo. Pendiente de reproducir, no
  es diagnóstico cerrado.

### Eje 4 — Repetición / coste (lo cubre el rediseño)

- tsk_fls ×15, 207.978 tok, $9.89, 36 ejecuciones re-descubriendo lo ya establecido.
- No es un bug: es la ausencia de memoria persistente que el mapa vivo de hallazgos/evidencias
  viene a resolver. Ver secciones 2 y 4 de arriba.

---

## Pendiente de decidir

- Ubicación definitiva de las **reglas no negociables** (¿`system.md`?).
- Estructura concreta de ficheros del **mapa de memoria** y del **mapa de hallazgos**.
- Cómo se **actualiza** el mapa de hallazgos conforme avanza el análisis.
- Redacción final de `identity.md`, `system.md` y el nuevo esquema de playbook.
