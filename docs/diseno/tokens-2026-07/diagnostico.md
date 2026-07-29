# Diagnóstico de consumo de tokens — Investigación de Agentopsy

> **Fecha:** 2026-07-29 · **Rama:** `tools` · **Corrida analizada:** caso
> `fe00dad1-c4d7-46ff-a9aa-e7655cc19850` (22 turnos, ejecutor `claude-code`,
> modelo `opus`, 2026-07-28 23:04→23:38 UTC).
>
> **Entrega 1 de 2.** El plan de corrección va en [`plan.md`](plan.md).

---

## Resumen

1. **Qué encontré.** Cada turno del bucle reenvía **60.513 caracteres de texto
   idéntico byte a byte** (system + esquemas + contrato) y **no consigue ni un
   solo token de caché**: medido, `cache_read` del payload de Agentopsy = 0 en
   todos los turnos. El 61,6 % de todos los tokens de entrada de la corrida son
   contenido invariable recobrado 22 veces, y se paga a **tarifa de escritura de
   caché (2×)**, que es *peor* que no cachear.
2. **Cuánto cuesta.** La corrida real: **12,97 USD y 34 minutos para 22 turnos**
   (~0,62 USD/turno). ~992.000 tokens de entrada, de los que ~611.000 son
   estáticos. El **76 % del gasto es entrada**, no salida.
3. **Qué propongo.** Reutilizar sesión del ejecutor y mandar solo el delta.
   Medido en una réplica controlada de los mismos 8 primeros turnos:
   **0,2143 USD frente a 0,7740 USD — un 72 % menos**, con `cache_read`
   creciendo turno a turno como debe. Detalle y fases en `plan.md`.

---

## 1. Método — qué está medido y qué está derivado

Marco explícitamente la frontera, porque parte de esto **no se puede medir hoy
desde dentro de Agentopsy**.

| Dato | Origen | Estatus |
|---|---|---|
| `prompt_chars`, argv literal, `exit_code`, `duration_ms`, `cost_usd` por turno | `audit.jsonl` de la corrida real | **Medido** (FORENSIC INVARIANT 4: el audit guarda el argv literal, prompt incluido) |
| Composición por bloques de cada prompt | Reparto del argv auditado por sus separadores `## SISTEMA` / `## USUARIO` / … | **Medido** (exacto, byte a byte) |
| Prefijo común entre turnos consecutivos | Comparación byte a byte de los prompts auditados | **Medido** |
| `cache_creation_input_tokens` / `cache_read_input_tokens` por turno | **Réplica** de los prompts auditados contra `claude -p --output-format json` (modelo `haiku`, para acotar coste) | **Medido en réplica**, no en la corrida original |
| Tokens de entrada por turno de la corrida original | chars ÷ 2,18 + 6.733 de sobrecarga fija | **Derivado**, reconciliado contra el coste real (ver §1.2) |

### 1.1 Por qué hubo que medir por réplica

El `Usage` de `forensia/executors/base.py:93` tiene tres campos:
`input_tokens`, `output_tokens`, `cost_usd`. **No captura
`cache_creation_input_tokens` ni `cache_read_input_tokens`**, que es
exactamente donde vive el problema. Ningún ejecutor los captura
(`claude_code.py:97`, `codex.py:124`, `gemini.py:128`, `ollama.py:214`).

La consecuencia es peor que un hueco de telemetría. Según la documentación de la
API, `input_tokens` es **únicamente el resto no cacheado**: el total real es
`input_tokens + cache_creation + cache_read`. Por eso el audit de la corrida
registra un `input_tokens` **plano en ~2.302 tokens durante los 22 turnos**
mientras el prompt crecía de 61.595 a 95.210 caracteres:

```
turno  1: prompt  61.595 chars → input_tokens registrado 2.302
turno 22: prompt  95.210 chars → input_tokens registrado 2.302
```

El número auditado **subestima la entrada real en un factor ~15×**. Y
`forensia/agent/estimate.py:186` construye toda su proyección sobre
`total_tokens / runs_with_tokens` a partir de ese campo — de modo que la
estimación previa al análisis que se le enseña al perito está mal por el mismo
factor. Instrumentarlo es la Fase 0 del plan; no lo he hecho aquí porque el
encargo pedía no escribir código todavía, y el audit ya guarda el prompt literal,
que es lo que permitió medirlo por fuera sin tocar nada.

### 1.2 Reconciliación de la conversión chars→tokens

Convertir caracteres a tokens es derivación, así que la ato a un dato duro. La
regresión sobre la réplica (8 puntos, tokenizador de `haiku`) da:

```
tokens_entrada_totales = 6.733 + 0,41638 × chars      (R² > 0,999)
   → 2,40 chars/token, y 6.733 tokens fijos por invocación
```

Los 6.733 tokens fijos son el **propio andamiaje de Claude Code** (su system
prompt y sus herramientas), no de Agentopsy. Comprobación independiente: un
`claude -p "Responde solo: OK" --model haiku` cuesta **0,0151 USD** y consume
10 + 6.589 + 11.609 = 18.208 tokens para devolver `OK`.

Aplicando esa curva a la corrida real (tokenizador de `opus`, más denso) sale
992.152 tokens de entrada. Verificación cruzada contra el gasto realmente
facturado:

```
salida:  121.594 tok × 25 USD/Mtok  =  3,040 USD
total facturado (audit)             = 12,974 USD
⇒ lado entrada                      =  9,934 USD
⇒ a 10 USD/Mtok (escritura de caché 1h = 2× sobre 5 USD/Mtok):  993.400 tokens
```

**992.152 estimados frente a 993.400 derivados del coste: 0,13 % de desviación.**
La conversión usada en las tablas (2,18 chars/token para `opus`) queda anclada a
un número facturado, no a una intuición.

---

## 2. Tokens por turno, desglosados (corrida real, 22 turnos)

Los cuatro primeros bloques son **caracteres exactos** leídos del argv auditado.

| # | SISTEMA (agent.md) | historial | ESQUEMAS tools | contrato | chars | tok entrada | tok salida | USD |
|---|--------:|-----------:|---------:|---------:|------:|-------------:|--------:|----:|
| 1 | 19.981 | 1.082 | 39.520 | 1.012 | 61.595 | 34.988 | — | *timeout 120 s* |
| 2 | 19.981 | 2.318 | 39.520 | 1.012 | 62.831 | 35.555 | 544 | 0,338 |
| 3 | 19.981 | 7.793 | 39.520 | 1.012 | 68.306 | 38.066 | 2.802 | 0,427 |
| 4 | 19.981 | 20.486 | 39.520 | 1.012 | 80.999 | 43.889 | 6.590 | 0,597 |
| 5 | 19.981 | 16.996 | 39.520 | 1.012 | 77.509 | 42.288 | 4.323 | 0,517 |
| 6 | 19.981 | 23.856 | 39.520 | 1.012 | 84.369 | 45.434 | 8.133 | 0,658 |
| 7 | 19.981 | 14.905 | 39.520 | 1.012 | 75.418 | 41.328 | 6.906 | 0,571 |
| 8 | 19.981 | 20.721 | 39.520 | 1.012 | 81.234 | 43.996 | 8.072 | 0,631 |
| 9 | 19.981 | 25.918 | 39.520 | 1.012 | 86.431 | 46.380 | 5.727 | 0,706 |
| 10 | 19.981 | 22.551 | 39.520 | 1.012 | 83.064 | 44.836 | 6.496 | 0,605 |
| 11 | 19.981 | 20.370 | 39.520 | 1.012 | 80.883 | 43.835 | 3.774 | 0,605 |
| 12 | 19.981 | 20.960 | 39.520 | 1.012 | 81.473 | 44.106 | 5.726 | 0,673 |
| 13 | 19.981 | 26.894 | 39.520 | 1.012 | 87.407 | 46.828 | 4.150 | 0,570 |
| 14 | 19.981 | 32.879 | 39.520 | 1.012 | 93.392 | 49.573 | 5.727 | 0,652 |
| 15 | 19.981 | 28.993 | 39.520 | 1.012 | 89.506 | 47.791 | 10.941 | 0,760 |
| 16 | 19.981 | 26.043 | 39.520 | 1.012 | 86.556 | 46.438 | 5.423 | 0,675 |
| 17 | 19.981 | 27.446 | 39.520 | 1.012 | 87.959 | 47.081 | 5.608 | 0,608 |
| 18 | 19.981 | 34.488 | 39.520 | 1.012 | 95.001 | 50.311 | 3.967 | 0,609 |
| 19 | 19.981 | 35.802 | 39.520 | 1.012 | 96.315 | 50.914 | 7.244 | 0,699 |
| 20 | 19.981 | 30.327 | 39.520 | 1.012 | 90.840 | 48.403 | 9.358 | 0,807 |
| 21 | 19.981 | 33.165 | 39.520 | 1.012 | 93.678 | 49.705 | 5.776 | 0,647 |
| 22 | 19.981 | 34.697 | 39.520 | 1.012 | 95.210 | 50.407 | 4.307 | 0,618 |
| | | | | | **1.839.976** | **992.152** | **121.594** | **12,974** |

### Lo que dice la tabla

- **SISTEMA, ESQUEMAS y contrato son constantes exactas** en los 22 turnos.
  60.513 caracteres — el **64 %** del prompt del turno 22 y el **98 %** del
  turno 1 — son idénticos byte a byte.
- **Los esquemas de herramienta son el bloque más grande: 39.520 caracteres**
  (~18.128 tokens), más que `agent.md` (19.981). Por sí solos son el **40,2 %**
  de toda la entrada de la corrida.
- **El andamiaje de Claude Code** (6.733 tok × 22) es otro **14,9 %** — es
  system prompt y herramientas propias de Claude Code (Read, Bash, Grep…) que
  Agentopsy no usa ni necesita, porque solo quiere una decisión JSON.
- **Reparto del gasto: 76 % entrada / 24 % salida.** Optimizar la entrada es
  optimizar la factura.

---

## 3. Cómo crece con las iteraciones

**No es cuadrático. Es lineal con una constante enorme.**

El coste acumulado de N turnos es `N × (E + H) + Σ tránscrito_i`, donde
`E + H` = 27.758 + 6.733 = **34.491 tokens fijos por turno**. El historial sí
crece, pero está acotado por el windowing (§4, H4), así que el término
cuadrático que la teoría predice está **ya amortiguado**: el tránscrito solo va
de 1.082 a 34.697 caracteres, y se estabiliza a partir del turno ~14.

Curva medida (tokens de entrada por turno):

```
50k │                                      ▄▄  ▄▄▄▄  ▄▄▄▄
    │                        ▄▄  ▄▄  ▄▄▄▄▄▄██▄▄████▄▄████
45k │              ▄▄  ▄▄▄▄▄▄██▄▄██▄▄██████████████████████
    │      ▄▄  ▄▄▄▄██▄▄██████████████████████████████████
40k │  ▄▄▄▄██▄▄████████████████████████████████████████████
    │████████████████████████████████████████████████████
35k ├────────────────────────────────────────────────────
    │   ← 34.491 tokens de suelo fijo por turno (E + H) →
 0  └─────────────────────────────────────────────────────
     1  2  3  4  5  6  7  8 ... 14 ...            22
```

**El diagnóstico importante:** entre el turno 1 y el turno 22 el consumo solo
sube un 44 % (34.988 → 50.407). El problema no es la pendiente, **es la
ordenada en el origen**. Aunque el agente no hiciera absolutamente nada, cada
turno arrancaría en ~34.500 tokens.

Corolario: **atacar el crecimiento del historial es la palanca equivocada.** Ya
está acotado, y acotarlo más (bajar `keep_last_tool_results`) empeora las cosas
por la razón de §4/H2.

---

## 4. Las hipótesis, contrastadas

### H1 — Sin caché de prompt · **CONFIRMADA, y peor de lo previsto**

Los cuatro ejecutores arrancan en frío en cada turno. Ninguno reutiliza sesión:

| Ejecutor | argv / llamada por turno | ¿reutiliza sesión? |
|---|---|---|
| Claude Code | `claude -p <prompt> --model opus --output-format json` (`claude_code.py:58`) | **No** — sin `--resume`, sin `--continue` |
| Codex CLI | `codex exec --json … <prompt>` (`codex.py:68`) | **No** |
| Gemini CLI | `gemini -p <prompt> --output-format json` (`gemini.py:97`) | **No** |
| Ollama | `POST /api/generate` con `stream:false` (`ollama.py:111`) | **No** — no propaga el campo `context` |

`forensia/agent/context.py:1` ya lo documenta: *«The executor is stateless:
Agentopsy re-sends the whole conversation on every iteration»*. Lo que faltaba
era el número.

**Medición** — réplica de los 8 primeros turnos reales, orden de producción:

| turno | chars | `input` | `cache_creation` | `cache_read` |
|---|---:|---:|---:|---:|
| 1 | 61.595 | 10 | 27.320 | 5.033 |
| 2 | 62.831 | 10 | 23.890 | **9.051** |
| 3 | 68.306 | 10 | 26.144 | **9.051** |
| 4 | 80.999 | 10 | 31.647 | **9.051** |
| 5 | 77.509 | 10 | 30.006 | **9.051** |
| 6 | 84.369 | 10 | 32.801 | **9.051** |
| 7 | 75.418 | 10 | 28.830 | **9.051** |
| 8 | 81.234 | 10 | 31.357 | **9.051** |

`cache_read` está **clavado en 9.051** — que es exactamente el prefijo propio de
Claude Code. **De los ~28.000 tokens de payload de Agentopsy que se escriben en
caché cada turno, se vuelven a leer cero.**

Y aquí está el matiz que no esperaba: no es solo que no haya ahorro. La caché
1 h se factura a **2× la tarifa base de entrada**. Agentopsy paga un **recargo
del 100 % sobre ~28.000 tokens por turno por una caché que jamás lee**. Salir
del todo del régimen de caché sería más barato que el estado actual.

Que la caché *funciona* está comprobado: en la variante C, los turnos 1 y 2
resultaron byte-idénticos a los de la variante B lanzada minutos antes, y
dieron `cache_creation=0, cache_read=32.353` — coste 0,0327 USD frente a
0,0754 USD, **un 57 % menos**. El mecanismo está disponible; Agentopsy nunca le
presenta un prefijo reutilizable.

### H2 — Prefijo inestable · **CONFIRMADA — y la causa es `window_messages()`**

El prefijo común entre turnos consecutivos es solo el **28–54 %** del prompt:

| par | chars(N) | chars(N+1) | prefijo común | % |
|---|---:|---:|---:|---:|
| 1→2 | 61.595 | 62.831 | 21.066 | 33,5 % |
| 4→5 | 80.999 | 77.509 | 25.352 | 32,7 % |
| 10→11 | 83.064 | 80.883 | 36.406 | 45,0 % |
| 15→16 | 89.506 | 86.556 | 41.582 | 48,0 % |
| 21→22 | 93.678 | 95.210 | 51.806 | 54,4 % |

Localicé el punto exacto de divergencia. **Es siempre el límite del stub de
`window_messages()`** (`context.py:105`). En el par 21→22, el carácter 51.806:

```
turno 21 → {"error": "ToolExecutionError: input derivado para 'hive_path'…
turno 22 → [resultado de tool elidido para acotar el contexto; el detalle…
```

Un mensaje que en el turno N viajaba íntegro, en el turno N+1 se convierte en
stub. **Eso reescribe la mitad del prompt e invalida la caché de todo lo que
viene detrás** — incluidos los 39.520 caracteres de esquemas, que están al
final.

Es un hallazgo incómodo porque **`window_messages()` se escribió justamente
para ahorrar tokens** (Bug 008), y con caché de por medio hace lo contrario:
ahorra el 90 % de unos tokens que se pagarían al 0,1× y a cambio fuerza a
reescribir a 2× todo lo que va después. **Windowing y caché son sustitutos, y la
caché es ~10× mejor.**

Los sospechosos que el encargo señalaba quedan **descartados**: no hay
marcas de tiempo ni `run_id` en el prefijo (`_system_prompt()` se computa una
vez por `run()`, no por iteración), el `structural nudge` se **añade al final**
del historial (no muta lo anterior) y `json.dumps` no interviene en el orden del
prompt. El único desestabilizador es el windowing.

### H3 — Salidas crudas inlineadas · **REFUTADA para esta corrida**

`_bounded_json` (`agent.py:165`) está bien hecho: acota a 8.000 caracteres
degradando por capas (muestras → previews de stdout/stderr → esqueleto),
**nunca corta JSON a mitad** y **siempre conserva el puntero `artifact_run`**,
así que la procedencia sobrevive. En esta corrida los resultados vivos ocupaban
192–574 caracteres: nada explotó.

Dicho eso, el tope teórico sí es alto: 8.000 × 4 resultados conservados =
32.000 caracteres. Sobre un `bulk_extractor` o un `tsk_fls` de disco real ese
techo se toca. **No es el problema de hoy, pero es una bomba armada.**

Dato relevante para el plan: reconstruí el tránscrito sin windowing y en el
turno 22 serían **110.886 caracteres frente a 34.693**. Ese es exactamente el
material que la reutilización de sesión mandaría **una sola vez** en lugar de
elidirlo y reescribir el resto.

### H4 — Presupuesto de contexto mal calibrado · **REFUTADA**

`keep_last_tool_results` = 4 (`context.py:41`), `_MAX_TOOL_RESULT_CHARS` = 8.000,
`MAX_REPLAY_CHARS` = 8.000, `MAX_REPLAY_TURNS` = 6. Los límites son razonables y
están puestos con criterio, no heredados de una prueba. **El problema no es que
los límites estén mal, es que el mecanismo entero es contraproducente cuando hay
caché.** Bajar `keep_last_tool_results` empeoraría el coste, no lo mejoraría:
mueve el punto de divergencia *más hacia el principio* del prompt.

### H5 — Reenvío íntegro de conducta y esquemas · **CONFIRMADA**

Sí, viajan enteros los 22 turnos: `agent.md` dentro de los 19.981 caracteres de
SISTEMA y los 39.520 de esquemas.

Sobre el filtrado por perfil: **`catalog.for_profile` sí se aplica**
(`agent.py:322` → `available_tool_ids()` → `tool_specs(list(allowed), …)`), así
que los esquemas ya son solo los del perfil `windows`. El filtrado funciona.
**El problema no es que se manden esquemas de más, es que los que corresponden
se mandan 22 veces y colocados en el peor sitio posible.**

Porque este es el detalle estructural clave de `_render_prompt`
(`models/base.py:155`), el orden en que se arma el prompt:

```
## SISTEMA          19.981   ← estable
## USUARIO / ASISTENTE / RESULTADO DE TOOL …   ← VARIABLE, crece y se reescribe
## HERRAMIENTAS DISPONIBLES   39.520   ← estable, pero DESPUÉS de lo variable
## FORMATO DE RESPUESTA        1.012   ← estable, también al final
```

**40.532 caracteres de contenido perfectamente estable están colocados detrás
del bloque que cambia en cada turno.** Para una caché que hace *prefix match*,
eso los condena: nunca pueden entrar en un prefijo reutilizable.

### H6 — Rehidratación excesiva · **REFUTADA**

`build_replay_messages` (`history.py:58`) está acotado a 6 pares de turnos y
8.000 caracteres, con ledgers de 30 runs y 10 hallazgos. Es modesto y no aparece
como término significativo en ningún turno medido.

---

## 5. El diferencial contra la terminal: qué es recuperable

Pediste honestidad en este punto, así que separo las tres capas.

Lancé cinco variantes sobre **los mismos 8 turnos reales**, reconstruidos desde
el audit, con ajustes idénticos (`--model haiku`, mismas herramientas
deshabilitadas). Solo cambia una variable: cómo se arma y se manda el prompt.

| Variante | Qué cambia | Coste 8 turnos | Solo entrada | Δ vs producción |
|---|---|---:|---:|---:|
| **A** | Producción tal cual | **0,7740** | 0,4709 | — |
| **B** | Esquemas movidos al principio | 0,8065 | 0,5041 | **+4 %** |
| **C** | Reordenado + sin windowing (6 turnos) | 0,5229 | 0,2926 | *no comparable* |
| **D** | Estáticos a `--system-prompt` | 0,6919 | 0,5008 | **−11 %** |
| **E** | **Sesión reutilizada + solo delta** | **0,2143** | **0,1541** | **−72 %** |

Y el perfil de caché de la variante E, que es lo que confirma que el mecanismo
por fin engrana:

| turno | chars enviados | `cache_creation` | `cache_read` |
|---|---:|---:|---:|
| 3 | 5.473 | 4.054 | 24.692 |
| 4 | 17.884 | 8.453 | 28.746 |
| 5 | 11.136 | 6.129 | 37.199 |
| 6 | 16.471 | 8.147 | 43.328 |
| 7 | 5.155 | 3.731 | 51.475 |
| 8 | 6.641 | 3.930 | **55.206** |

`cache_read` **crece monótonamente** — el tránscrito acumulado se está leyendo a
0,1× — y `cache_creation` se desploma a solo el delta. Es exactamente el perfil
de una sesión de terminal.

### Reparto del diferencial

**Recuperable (~72 % del gasto, medido).** Reutilización de sesión + delta.
No toca ninguna invariante: el bucle sigue siendo de Agentopsy, el audit sigue
guardando el argv literal, los `run_id` y hashes siguen viajando.

**Recuperable con reservas (~15 % adicional, no medido aisladamente).** El
andamiaje propio de Claude Code (6.733 tok/turno). `claude -p` acepta
`--system-prompt` y `--disallowed-tools`; se puede sustituir su system prompt
por el de Agentopsy y apagar sus herramientas, que Agentopsy no usa. **No lo he
medido por separado** y no lo doy por bueno hasta hacerlo: la variante D, que
usaba `--system-prompt`, solo rindió un 11 %, y su lectura quedó contaminada por
iteraciones internas del modelo. Va al plan como hipótesis a validar, no como
ahorro comprometido.

**Estructural (no recuperable, y no debe serlo).** Lo que queda es el producto:

- **`agent.md`, 19.981 caracteres.** Es la conducta pericial. En terminal yo no
  cargo un fichero de conducta forense; aquí es la razón de ser de la
  herramienta.
- **Esquemas del toolkit, 39.520 caracteres.** Ya filtrados por `os_profile`.
  Mis Read/Grep/Bash caben en una fracción de eso porque son tres herramientas
  genéricas; aquí son ~30 herramientas forenses con contratos de argv tipados y
  `PathParameter` — que es justamente lo que hace que el modelo emita un
  `tool_id` de enum cerrada y nunca un comando (SECURITY INVARIANT 5).
- **Los delimitadores anti-inyección** de cada resultado de tool.

Cacheados a 0,1×, esos ~27.800 tokens estáticos cuestan ~2.780 tokens
equivalentes por turno. **El coste intrínseco del producto no es el problema;
el problema es pagarlo 22 veces a tarifa doble.**

---

## 6. Los cuatro ejecutores

Lo que es común y lo que es específico, porque un arreglo que solo sirva para
Claude Code es media solución:

**Común a los cuatro** (vive en `forensia/agent/` y `forensia/models/base.py`):
- Reordenar `_render_prompt` para que todo lo estable vaya delante y lo variable
  detrás. Es un cambio de una función y beneficia a los cuatro por igual.
- Revisar el windowing: con reutilización de sesión deja de tener sentido
  reescribir el historial.
- Instrumentar `Usage` con los campos de caché (los que el ejecutor reporte;
  los que no, `None` — RULE 2, nunca un número inventado).

**Específico por ejecutor** (vive en `forensia/executors/*`):

| Ejecutor | Mecanismo de continuidad | Estado |
|---|---|---|
| Claude Code | `--resume <session_id>` / `--continue`; `session_id` ya viene en el JSON de respuesta | **Verificado en `claude --help` y medido (variante E)** |
| Codex CLI | `codex exec resume` | Documentado; **sin verificar** |
| Gemini CLI | sesión/checkpointing | Documentado; **sin verificar** |
| Ollama | `context` de `/api/generate`, o migrar a `/api/chat` con `messages` | **Sin verificar**; además es local, así que el ahorro es de latencia y de ventana, no monetario |

Solo puedo afirmar el de Claude Code con datos. Los otros tres son
comprobaciones de la Fase 2 del plan. **Si alguno no soporta continuidad de
sesión, la degradación tiene que ser explícita** (RULE 2: capacidad no
disponible con motivo accionable, nunca un silencioso «va más caro»).

---

## 7. Límites de este diagnóstico

Lo que **no** puedo afirmar, y por qué:

1. **Los números de caché son de una réplica con `haiku`, no de la corrida
   original con `opus`.** La corrida original no registró los campos de caché
   porque el código no los captura. Las proporciones entre variantes son
   sólidas (misma variable independiente, mismos ajustes); las cifras absolutas
   de la corrida `opus` están derivadas y reconciliadas contra el coste real
   (§1.2), no medidas directamente.
2. **La extrapolación de −72 % a 22 turnos con `opus` es una extrapolación.**
   Está medida sobre 8 turnos con `haiku`. El mecanismo (prefijo cacheado que
   crece) no depende del modelo, pero el número exacto sí. La validación real
   es una corrida A/B tras la Fase 1.
3. **Las variantes B y D salieron ruidosas**: el modelo hizo un número variable
   de iteraciones internas por turno (`num_turns` entre 1 y 6), lo que infla
   `cache_read` y salida de forma no atribuible al ordenamiento. Por eso su
   lectura es «no ayuda de forma clara», no un porcentaje afinado.
4. **No he medido el coste de una corrida equivalente en terminal.** El
   diferencial de §5 está construido comparando Agentopsy consigo mismo bajo
   distintos regímenes de caché, que es la comparación que aísla la variable.

---

## Anexo — cómo reproducir

Los scripts de medición están en el scratchpad de la sesión (no se versionan:
son instrumental de análisis, no producto — RULE 1). Reproducción:

1. `build_variants.py` — reconstruye los prompts desde `audit.jsonl` y genera
   las variantes. Recupera el tránscrito **sin** windowing aprovechando que el
   cuerpo íntegro de cada resultado aparece en el turno en que todavía estaba
   dentro de la ventana.
2. `run_variants.py A|B|C 8 haiku` — reproduce la variante contra `claude -p` y
   vuelca `results.jsonl`.
3. `run_sysprompt.py` — variante D. `run_resume.py` — variante E.

Coste total de la instrumentación de este diagnóstico: **~2,80 USD** en
`haiku`.
