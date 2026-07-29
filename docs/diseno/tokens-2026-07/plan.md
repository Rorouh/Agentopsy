# Plan de corrección del consumo de tokens

> **Entrega 2 de 2.** Depende del [`diagnostico.md`](diagnostico.md), que aporta
> las mediciones.
>
> **Fecha:** 2026-07-29 · **Rama:** `tools`

> **ESTADO (2026-07-29).** Las **Fases 0-2 están aprobadas e implementadas**;
> lo ejecutado, las mediciones y los dos hallazgos que aparecieron por el camino
> están en [`implementacion-fases-0-2.md`](implementacion-fases-0-2.md)
> (validación A/B: **−79,1 %**). Las **Fases 3 y 4 NO se han implementado** por
> decisión explícita, y la [fase de turnos](fase-turnos.md) se entrega
> **diagnosticada y sin implementar**. Las secciones que siguen conservan la
> propuesta original; donde una medición posterior la corrige, hay una nota.
>
> **ACTUALIZACIÓN (2026-07-30, rama Rama-Enrique).** La **Fase 3 está
> implementada**: con backend capaz de sesión el tránscrito viaja íntegro
> (`window_messages` queda solo para ejecutores stateless), todo envío de
> contexto completo se renderiza desde la lista canónica (un stub jamás siembra
> una sesión) y el recorte por umbral (`FORENSIA_SESSION_CONTEXT_MAX_CHARS`,
> default 400.000) se audita (`context_window_trimmed`). De la fase de turnos se
> implementaron los puntos 1-3 de su §6: cierre del bucle de relectura, timeout
> por defecto 120 → 300 s, y auditoría del turno perdido con coste ESTIMADO en
> campos etiquetados. Además se corrigió el tercer hallazgo de la Fase 4 que no
> era de esa fase: los CLI corren ahora en un **cwd neutro vacío** (auditado),
> así que el `CLAUDE.md` de Agentopsy ya no entra en ninguna llamada (−8.870
> tokens/turno). La **Fase 4 sigue fuera de alcance** (impacto en calidad sin
> medir). Gates: `tests/test_session_windowing.py` + tests de ejecutores.

---

## Resumen

1. **Qué encontré.** El gasto no está en lo que el agente hace, sino en el suelo
   fijo de cada turno: 34.491 tokens antes de que el modelo piense nada, de los
   que el 61,6 % es texto idéntico byte a byte que nunca entra en caché.
2. **Cuánto cuesta.** 12,97 USD y 34 minutos por corrida de 22 turnos. Con la
   caché rota, Agentopsy paga además un recargo del 100 % (tarifa de escritura
   1 h = 2×) sobre ~28.000 tokens por turno que jamás vuelve a leer.
3. **Qué propongo.** Cinco fases ordenadas por ratio ahorro/riesgo. Las dos
   primeras (instrumentar + reutilizar sesión) concentran el ~72 % medido y no
   tocan ninguna invariante. Las tres restantes son incrementales y una de ellas
   es hipótesis sin medir, marcada como tal.

---

## Orden de ejecución y ratio

| Fase | Qué | Ahorro | Riesgo | Ratio | Invariantes |
|---|---|---:|---|---|---|
| **0** | Instrumentar tokens de caché | 0 % | **Mínimo** | *habilitante* | ninguna tocada |
| **1** | Reutilizar sesión + enviar delta | **~72 %** medido | Medio | **★★★★★** | ninguna tocada |
| **2** | Reordenar el prompt (estable delante) | incluido en F1 | **Mínimo** | ★★★★☆ | ninguna tocada |
| **3** | Retirar el windowing cuando hay sesión | ~5-10 % | Medio | ★★★☆☆ | roza RULE 2 → §3 |
| **4** | Recortar el andamiaje del ejecutor | ~15 % *sin medir* | Medio-alto | ★★☆☆☆ | ninguna tocada |
| **5** | Extender a Codex / Gemini / Ollama | — | Medio | ★★★☆☆ | RULE 2 (degradar explícito) |

**Las fases 0-2 son un bloque.** La 2 sin la 1 no ahorra nada (medido: variante
B, +4 %); la 1 sin la 0 no se puede verificar. Recomiendo aprobarlas juntas y
tratar 3-5 como decisiones posteriores con datos de la 1 en la mano.

---

## Fase 0 — Instrumentación (habilitante, sin ahorro)

**Por qué primero.** Hoy no se puede afirmar nada sobre coste desde dentro del
producto: `Usage` solo registra el resto no cacheado, y eso subestima la entrada
real ~15× (diagnóstico §1.1). Sin esto, la Fase 1 no es verificable y
`estimate.py` seguirá mintiéndole al perito.

**Qué se toca**

- `forensia/executors/base.py` — añadir a `Usage` los campos
  `cache_creation_input_tokens`, `cache_read_input_tokens` y un `total_input_tokens`
  derivado. Extenderlos en `as_audit_fields()`.
- `forensia/executors/claude_code.py` — parsear `usage.cache_*` del envelope.
- `codex.py` / `gemini.py` / `ollama.py` — parsear lo que cada envelope traiga.
  **Lo que un ejecutor no reporte se queda en `None`** (RULE 2: nunca un número
  inventado; el campo `source` ya distingue un 0 real de un «no lo informó»).
- `forensia/agent/estimate.py` — anclar en `total_input_tokens`, no en
  `input_tokens`. La heurística `HEUR_TOKENS_PER_ITER = 5000` está un orden de
  magnitud por debajo de lo medido (~34.500 de suelo): recalibrarla con el dato
  real y dejar constancia de la fecha de calibración.

**Riesgo:** mínimo. Telemetría aditiva; `_extract_usage` ya está envuelto en un
`try` que garantiza que un fallo de parseo no hunde la corrida.

**Verificación:** una corrida corta enseña `cache_read` plano en 9.051 — es
decir, reproduce desde dentro el hallazgo del diagnóstico. Ese es el criterio de
aceptación de la fase.

---

## Fase 1 — Reutilización de sesión y envío por delta ★

**El cambio que importa.** Medido: **0,2143 USD frente a 0,7740 USD sobre los
mismos 8 turnos, −72 %**, con `cache_read` creciendo de 24.692 a 55.206.

**Diseño**

El turno 1 abre sesión y manda el contexto completo. Los turnos siguientes
reanudan esa sesión y mandan **solo lo nuevo** (los resultados de herramienta
que se acaban de producir):

```
turno 1 : claude -p <contexto completo> --output-format json   → session_id
turno N : claude -p <solo el delta> --resume <session_id>       → session_id
```

`session_id` ya viene en el envelope JSON de Claude Code; hoy se descarta.

**Qué NO cambia — y es deliberado**

- **Agentopsy sigue siendo el dueño de la conversación** (RULE 3). La lista
  canónica `messages` se mantiene íntegra en memoria y en `ChatStore`. La sesión
  del CLI es una *optimización de transporte*, no la fuente de verdad.
- **El audit sigue registrando el argv literal** de lo que realmente se envía
  (FORENSIC INVARIANT 4). Cambia el contenido —ahora es el delta— y **se añade
  `session_id` y un `resume: true`**, de modo que la cadena de custodia gana
  precisión: queda registrado exactamente qué cruzó el cable en cada turno.
- **`prompt_sha256` y `prompt_chars` siguen ahí.** La reconstrucción de la
  corrida completa desde el audit sigue siendo posible: turno 1 + deltas.
- **Los `run_id` y hashes siguen viajando.** Un `Finding` puede seguir citando
  su `run_id` y el SHA-256 de su artefacto, porque los resultados de herramienta
  se mandan **íntegros una sola vez** en lugar de elididos muchas.

**El punto delicado — y cómo se resuelve sin romper RULE 2**

El riesgo real es mandar un delta a una sesión que **no** tiene el historial: el
modelo concluiría sobre evidencia que cree haber visto y no vio. Eso es
exactamente lo que la restricción prohíbe, y es peor que gastar tokens.

Regla propuesta: **la reanudación tiene que ser verificable, y si no lo es se
falla fuerte.**

- Si `--resume` devuelve error o el `session_id` no se puede confirmar, **no** se
  manda el delta. Se reabre sesión con el **contexto completo** y se registra en
  el audit `resume_failed` con el motivo. Es un fallback de *contenido*
  (mandar de más, nunca de menos), y va **anotado**, no en silencio.
- Nunca al revés: jamás un delta contra una sesión no confirmada.
- La respuesta se sigue parseando con el contrato estricto de
  `ExecutorBackend._parse_action`. Si la reanudación hubiera perdido contexto,
  el modelo no puede «rellenar» sin que el JSON lo delate.

**Qué se toca**

- `forensia/executors/base.py` — `CliPromptExecutor.run()` acepta
  `context['session_id']`; `ExecutorResult` lo devuelve.
- `forensia/executors/claude_code.py` — `_build_argv` añade `--resume` cuando
  hay sesión; `_extract_session_id` del envelope.
- `forensia/models/base.py` — `ExecutorBackend` guarda el `session_id`, y
  `next_action` decide entre prompt completo (turno 1) y delta (resto).
- `forensia/agent/agent.py` — el bucle expone qué mensajes son nuevos desde la
  iteración anterior. Cambio pequeño: ya sabe qué acaba de añadir.

**Riesgo:** medio. Toca el contrato del ejecutor y la relación del bucle con el
tránscrito. Mitigación: el camino de contexto completo se conserva íntegro como
comportamiento del turno 1 y como recuperación ante fallo, así que el modo
actual sigue siendo un camino de código vivo y probado.

**Verificación:** con la Fase 0 dentro, una corrida A/B sobre el mismo caso y el
mismo prompt. Criterio de aceptación: `cache_read` **creciente** turno a turno y
`cache_creation` acotado al tamaño del delta.

---

## Fase 2 — Reordenar el prompt (va con la Fase 1)

Hoy `_render_prompt` (`models/base.py:155`) coloca **40.532 caracteres de
contenido estable detrás del bloque variable**:

```
actual:     SISTEMA │ tránscrito (variable) │ ESQUEMAS │ contrato
propuesto:  SISTEMA │ ESQUEMAS │ contrato   │ tránscrito (variable)
```

Para una caché que hace *prefix match*, el orden actual condena los esquemas:
nunca pueden formar parte de un prefijo reutilizable.

**Honestidad sobre el ahorro:** **medido en aislamiento, esto no ahorra nada**
(variante B: +4 %, dentro del ruido). No es un cambio inútil — es la condición
previa para que el prefijo estable *exista*. Su valor se realiza dentro de la
Fase 1 y se extiende a los cuatro ejecutores, incluido Ollama, donde la ventana
de contexto es el recurso escaso.

**Riesgo:** mínimo. Reordenar bloques de una función de render pura. El
contenido enviado al modelo es idéntico; cambia el orden. Requiere revisar que
el contrato de respuesta siga siendo lo último que el modelo lee (es lo que
sostiene el parseo estricto), lo cual se cumple si el tránscrito va detrás y el
contrato se repite al final o se ancla en SISTEMA.

---

## Fase 3 — Retirar el windowing cuando hay sesión

> **NOTA (2026-07-29, tras medir).** Esta fase estaba infravalorada. El
> diagnóstico de [`fase-turnos.md`](fase-turnos.md) demuestra que el windowing no
> solo rompe la caché: **fabrica turnos**. 32 de las 71 llamadas de la corrida
> fueron `leer_artefacto` y **las 32 apuntaban a un resultado que la ventana
> había elidido** (uno se releyó 16 veces). 12 de 21 turnos productivos no
> hicieron otra cosa que releer: ≈ 414.000 tokens, el 42 % de la entrada. El
> ahorro estimado abajo (5-10 %) es, por tanto, **muy bajo**. Sigue sin
> implementar a la espera de decisión.

Con la Fase 1 dentro, `window_messages()` deja de tener sentido: reescribe el
historial en cada turno, que es precisamente lo que rompe el prefijo
(diagnóstico §4/H2). Con sesión reanudada, cada resultado cruza el cable **una
vez** y después se lee a 0,1×.

**Dimensionamiento:** el tránscrito sin windowing del turno 22 son 110.886
caracteres (~51.000 tokens). La ventana de `opus` es de 1M. No hay riesgo de
desbordar en corridas realistas.

**Dónde roza RULE 2 — y la línea que no cruzo.** Si el contexto llegara alguna
vez al límite, hay que recortar. La restricción dice que un recorte silencioso
es peor que gastar tokens. Propuesta:

- Sin sesión → se conserva el windowing actual tal cual.
- Con sesión → no se recorta, salvo que se alcance un umbral de ventana. Si se
  alcanza, **el mensaje de recorte le dice al agente qué falta y cómo
  recuperarlo** (el stub actual ya lo hace bien: nombra `tool_id`, `exit_code`
  y el `run_id` completo, y apunta al artefacto). Ese contrato se mantiene.
- El recorte se registra en el audit. Hoy no se registra.

**Descartado explícitamente:** comprimir resultados antiguos con un resumen
generado por el modelo. Ahorraría tokens, pero un resumen con pérdida puede
dejar caer un `run_id` o un SHA-256, y entonces un `Finding` no puede anclar su
procedencia. **Roza la línea de «la procedencia de los hallazgos sobrevive», así
que lo descarto.**

---

## Fase 4 — Recortar el andamiaje del ejecutor (hipótesis, sin medir)

> **NOTA (2026-07-29, tras medir el coste aislado).** El andamiaje es MAYOR de lo
> que decía esta sección: `--disallowed-tools` quita **7.114** tokens y
> `--system-prompt` otros **6.602** (13.716, el 50,6 % de un arranque en frío),
> no 6.733. Además apareció un tercer componente que no es de esta fase: **8.870
> tokens por llamada del propio `CLAUDE.md` de Agentopsy**, heredados por el
> directorio de trabajo del subproceso. Sigue **sin implementar**: el criterio
> que el encargo puso por delante —¿analiza igual de bien?— no está medido.

Cada `claude -p` arrastra **6.733 tokens** de system prompt y esquemas de
herramienta **propios de Claude Code** (Read, Bash, Grep, Task…), que Agentopsy
ni usa ni quiere: solo pide una decisión JSON. Son el 14,9 % de la entrada de la
corrida.

`claude --help` confirma que existen las palancas: `--system-prompt` (sustituye
el system prompt por completo), `--disallowed-tools` y
`--exclude-dynamic-system-prompt-sections` (secciones dinámicas del system
prompt — candidatas naturales a romper caché).

**No lo doy por bueno.** La variante D usó `--system-prompt` y solo rindió un
11 %, con lecturas contaminadas por iteraciones internas del modelo. Antes de
implementar hay que medirlo aislado, con `num_turns` normalizado. Además hay una
pregunta de comportamiento que no es de coste: sustituir el system prompt de
Claude Code cambia cómo se comporta el modelo, y eso hay que evaluarlo sobre
calidad de análisis, no solo sobre factura.

**Riesgo:** medio-alto, y es riesgo de *calidad*, no de coste. Va al final por
eso.

---

## Fase 5 — Extender a los otros tres ejecutores

Lo común (Fases 0, 2 y 3) los beneficia a los cuatro por construcción, porque
vive en `forensia/agent/` y `forensia/models/base.py`. Lo específico de la Fase
1 hay que verificarlo uno a uno:

| Ejecutor | A verificar | Si no lo soporta |
|---|---|---|
| Codex CLI | `codex exec resume` | Se queda en contexto completo. `capabilities` lo reporta con motivo accionable |
| Gemini CLI | checkpointing / sesión | Igual |
| Ollama | campo `context` de `/api/generate`, o migrar a `/api/chat` | Es local: el ahorro es de latencia y ventana, no monetario. Prioridad baja |

**RULE 2 aquí es literal:** si un ejecutor no soporta continuidad de sesión, eso
es una capacidad no disponible que se reporta con motivo accionable — **nunca un
silencioso «con este ejecutor sale más caro»**. El operador tiene que poder ver
por qué su corrida cuesta lo que cuesta antes de lanzarla.

---

## Efecto combinado esperado

| Escenario | Coste/corrida 22 turnos | Base |
|---|---:|---|
| Hoy | **12,97 USD** | medido |
| Tras Fases 0-2 | **~3,6 USD** | extrapolado del −72 % medido |
| Tras Fases 0-4 | **~2,9 USD** | incluye la Fase 4 sin medir |

**Marco el estatus:** el −72 % está medido sobre 8 turnos con `haiku`; llevarlo
a 22 turnos con `opus` es extrapolación. El mecanismo (prefijo cacheado que
crece) no depende del modelo, pero la cifra exacta sí. La validación es la
corrida A/B de la Fase 1.

El componente que **no** baja es la salida: 121.594 tokens, ~3,04 USD. Es el
trabajo del modelo, y reducirlo es una conversación distinta (menos turnos vía
`tool_batch`, que el contrato de respuesta ya promueve y que es la otra palanca
disponible: cada turno ahorrado son ~34.500 tokens de suelo).

---

## Lo que este plan NO hace

Por si alguna de estas parecía tentadora:

- **No reduce lo que se audita.** `audit.jsonl` sigue guardando el argv literal,
  la versión de la herramienta, los hashes de salida y los códigos de salida.
  Vive en disco, no en el contexto del modelo; optimizar tokens no lo toca. La
  Fase 1 de hecho **añade** campos (`session_id`, `resume`).
- **No recorta contexto en silencio.** Todo recorte sigue siendo visible para el
  agente, con `run_id` completo y puntero al artefacto.
- **No comprime resultados con resúmenes generados por el modelo.** Descartado
  en §3 por la procedencia.
- **No mete claves de API en ninguna parte.** Las sesiones de CLI siguen en el
  volumen `forensia-cli-auth`; `--resume` usa la misma sesión OAuth.
- **No introduce un ejecutor por defecto.** La selección sigue siendo explícita
  del operador.

---

## Precondiciones antes de cualquier push (RULE 6 / RULE 4)

- Desde `backend/`: `pip install -e ".[dev,mcp]"`, `ruff check .`, `pytest -q`.
- Desde `web/`: `npm ci && npm run typecheck && npm run build` si se toca el
  frontend (la Fase 0 lo toca si se muestra el desglose de caché en la UI de
  estimación).
- Documentación en sintonía antes de commitear: `CLAUDE.md` (§Status),
  `docs/agentes/contrato-paquetes.md` y `tools/graph/CONTEXT.md` si cambia el
  contrato del ejecutor.

---

## Decisión que te pido

1. ¿Apruebo las **Fases 0-2 como bloque**? Es donde está el ~72 % medido y no
   toca ninguna invariante.
2. ¿La **Fase 3** (retirar windowing con sesión) la quieres en el mismo bloque o
   como decisión aparte con los datos de la Fase 1 delante?
3. ¿Mido la **Fase 4** aisladamente antes de decidir, o la dejamos fuera de
   alcance por el riesgo de calidad?

Me detengo aquí hasta tu aprobación.
