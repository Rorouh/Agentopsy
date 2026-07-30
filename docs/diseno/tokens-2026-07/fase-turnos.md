# Fase nueva — el número de turnos

> **Diagnóstico, sin implementar.** Encargado tras aprobar las Fases 0-2.
> Sustrato: la corrida `fe00dad1`, 22 turnos, 12,97 USD, la misma que sostiene
> [`diagnostico.md`](diagnostico.md).
>
> **Fecha:** 2026-07-29 · **Rama:** `tools`
>
> **ACTUALIZACIÓN (2026-07-30, rama Rama-Enrique).** Los puntos **1-3** de la
> propuesta (§6) están implementados: el windowing se retira con sesión activa
> (y el envío de apertura/reapertura se renderiza del canónico — el bug que este
> diagnóstico no vio: un stub sembrado en la sesión perpetuaba el bucle),
> `DEFAULT_TIMEOUT_S` sube a 300 s, y el turno perdido por timeout audita su
> coste estimado en campos etiquetados (`estimated_input_tokens`,
> `estimate_basis`). El punto 4 (¿por qué ningún `final`?) queda pendiente de
> re-medir con el bucle de relectura cerrado.
>
> **ACTUALIZACIÓN 2 (2026-07-30).** El punto 4 también está atacado por código,
> no solo pendiente de re-medición: el bucle inyecta un **nudge de
> presupuesto** — a 2 iteraciones del límite avisa de que cierre («tu siguiente
> respuesta deberá ser `final`») y en la última exige el `final` consolidando
> lo ya persistido. El agente no conocía su presupuesto: agotarlo sin responder
> era el desenlace por defecto de cualquier análisis largo. Pinado por
> `test_budget_nudges_demand_a_final_before_exhaustion`. La re-medición de si
> 21 iteraciones bastan sigue pendiente, pero el modo de fallo «12,97 USD sin
> respuesta» ya no existe.

---

## Resumen

1. **Qué encontré.** El bucle no gasta turnos por falta de `tool_batch` —lo usa
   en el 100 % de sus respuestas, 3,4 herramientas por turno—. Los gasta
   **releyendo lo que el propio windowing acababa de borrar**: 32 de las 71
   llamadas del run son `leer_artefacto`, y **las 32 apuntan a un resultado que
   la ventana había elidido**. Un artefacto se releyó **16 veces**.
2. **Cuánto cuesta.** 12 de los 21 turnos productivos no hicieron otra cosa que
   releer. A 34.491 tokens de suelo por turno son **≈ 414.000 tokens, el 42 % de
   la entrada de la corrida**, gastados en recuperar información que ya se había
   pagado. Y la corrida agotó el presupuesto de iteraciones **sin emitir un solo
   `final`**.
3. **Qué propongo.** No es una fase de "reducir turnos": es la misma causa raíz
   que la Fase 3. El windowing no solo rompe la caché (H2) — **fabrica turnos**.
   Retirarlo con sesión activa cierra el bucle de relectura; el resto de palancas
   sobre el número de turnos son menores y las dejo enumeradas.

---

## 1. ¿Se está usando `tool_batch`?

**Sí, exclusivamente.** De las 21 respuestas del asistente en la corrida:

| Acción | Veces |
|---|---:|
| `tool_batch` | **20** |
| `tool_call` | 0 |
| `final` | **0** |

71 llamadas en 20 lotes = **3,38 herramientas por turno**, con lotes de hasta 8.
El contrato de respuesta funciona: la hipótesis de que el modelo lo ignoraba
queda **refutada**.

El dato que sí alarma es el **cero en `final`**. La corrida nunca concluyó: se
quedó sin iteraciones. El perito pagó 12,97 USD por un análisis que no emitió
respuesta final.

## 2. ¿En qué se van los turnos?

Composición de cada turno (`C` = herramienta forense del catálogo, `i` =
herramienta interna en proceso):

```
turno  2: CC          turno  9: ii          turno 16: iii
turno  3: iCiCCCC     turno 10: iii         turno 17: ii
turno  4: iCCC        turno 11: ii          turno 18: iii
turno  5: iCiiii      turno 12: ii          turno 19: iii
turno  6: iCiCiCii    turno 13: iii         turno 20: CCCCCC
turno  7: iii         turno 14: iii         turno 21: iii
turno  8: iiC         turno 15: CCC
```

**12 de 21 turnos (7, 9-14, 16-19, 21) no tocaron la evidencia en absoluto**: son
turnos enteros de lectura interna. Y el desglose por `tool_id` dice de qué:

| `tool_id` | Llamadas | |
|---|---:|---|
| **`leer_artefacto`** | **38** | 54 % de todas las llamadas |
| `volatility3` | 12 | |
| `regripper` | 6 | |
| `record_finding` | 5 | |
| `consultar_actividad` | 3 | |
| `tsk_mmls` / `tsk_fls` | 2 / 2 | |
| `file_info` / `bulk_extractor` / `anotar_conocimiento` | 1 cada uno | |

## 3. La causa: el windowing fabrica turnos

`window_messages()` sustituye los resultados antiguos por un stub:

```
[resultado de tool elidido para acotar el contexto (tool=volatility3, exit=0,
 run=7a8e363c-…); el detalle sigue en el artefacto del run — recupéralo con `jq`]
```

El stub está **bien escrito**: nombra la herramienta, el `exit_code`, el `run_id`
completo y cómo recuperar el detalle. Cumple exactamente lo que RULE 2 exige —
el agente sabe que se recortó y qué falta. El problema no es que engañe al
modelo. **El problema es que el modelo le hace caso.**

Contraste medido sobre la corrida:

| | |
|---|---:|
| `run_id` distintos nombrados en stubs de elisión | 11 |
| Peticiones de `leer_artefacto` | 32 |
| **De las cuales apuntan a un run elidido** | **32 (100 %)** |

Y las relecturas se repiten, porque el resultado de `leer_artefacto` **también**
acaba elidido en la siguiente pasada de ventana:

| Veces releído | `run_id` |
|---:|---|
| **16×** | `803d03c0-d2f8-42dd-8a65-5fedbfd4f0a2` |
| 7× | `3b58fe0b-e2de-4fc2-a321-2b200c1a8c7a` |
| 4× | `b3040d00-10b4-4d2e-afd9-fb3b03f9b659` |
| 3× | `b2e7e0ce-05d9-4e1a-afcc-2b802745354d` |

Es un **bucle cerrado**: elidir → releer → elidir la relectura → releer otra vez.
El mecanismo escrito para ahorrar contexto consume el presupuesto de iteraciones
hasta que la corrida muere sin concluir.

### Lo que esto cuesta

Elidir un resultado ahorra los tokens de ese resultado. Provocar el turno que lo
relee cuesta **34.491 tokens de suelo** (§2 del diagnóstico) más el resultado
otra vez. Con resultados de 192-574 caracteres —lo medido en esta corrida— el
intercambio es de dos órdenes de magnitud a favor de **no elidir**.

```
12 turnos de relectura × 34.491 tokens = 413.892 tokens ≈ 42 % de la entrada
```

## 4. Reintentos, correcciones de formato y el nudge

- **Reintentos de parseo: 0.** Las 21 respuestas se parsearon a la primera. El
  contrato estricto de `_parse_action` está haciendo su trabajo — razón de más
  para mantenerlo al final del prompt (Fase 2).
- **Structural nudge:** no se disparó ni una vez. La regla es "≥3 herramientas
  de catálogo sin hallazgo", y el agente registró `record_finding` 5 veces
  intercaladas. No contribuye al número de turnos.
- **Un solo fallo de herramienta reportado al modelo:** `regripper` agotó sus 3
  intentos y el bucle se lo dijo con un mensaje accionable. Correcto.

## 5. El turno 1: 120 s de timeout que el diagnóstico no comentó

```
turno  1  exit=None  dur=120,1 s  in=None  out=None  error="timeout tras 120s"
```

Qué pasó y qué hace el bucle, verificado en el código:

- `CliPromptExecutor.run` captura `subprocess.TimeoutExpired`, audita el
  `executor_run_finish` con el error y lanza `ExecutorError`.
- `ForensicAgent.run` captura la excepción de `next_action` y **devuelve una
  respuesta de error al operador**. **No reintenta**: no hay reenvío automático
  del prompt completo. Ese punto de la pregunta se responde con un no.
- El coste: el prefijo entero (~35.000 tokens) pagado a cambio de nada. No
  aparece en `input_tokens` porque el envelope nunca llegó, así que **el audit
  registra ese gasto como cero** — otra consecuencia de medir por
  `input_tokens`, y una razón más para la Fase 0.

Los 22 `executor_run_start` son por tanto **1 turno perdido + 21 productivos**,
repartidos en dos mensajes del usuario (el audit contiene 2 bloques `## USUARIO`):
el primero murió en el timeout, el segundo consumió las 21 iteraciones.

El timeout por defecto es de 120 s y **11 de los 21 turnos productivos tardaron
más de 85 s**, tres de ellos por encima de 111 s. La corrida estuvo rozando el
límite todo el rato: el turno 15 tardó 162 s y solo sobrevivió porque el
operador tenía configurado un timeout mayor. Un análisis real con lotes de 6-8
herramientas necesita más de 120 s por turno, y hoy el primer síntoma de que no
los tiene es perder el turno entero.

## 6. Propuesta (sin implementar)

Ordenada por ratio, como el plan:

1. **Retirar el windowing cuando hay sesión activa** — es la Fase 3, y este
   análisis le añade el argumento que le faltaba: no solo ahorra el coste de
   reescribir el prefijo, **elimina 12 de 21 turnos**. Con transporte por sesión
   cada resultado viaja íntegro una vez y permanece en la sesión, así que no hay
   nada que releer. Es la misma palanca, no una segunda.
2. **Revisar el timeout por defecto** (120 s) contra la duración real medida
   (media 89 s, máximo 162 s en turnos productivos). No es un cambio de tokens
   sino de fiabilidad: un turno perdido por timeout cuesta el prefijo entero y
   no deja rastro de coste en el audit.
3. **Auditar el turno perdido con su coste estimado.** Hoy un timeout registra
   `input_tokens: None` y desaparece de `executor_cost`. La corrida costó más de
   lo que el audit puede demostrar.
4. **Investigar por qué no hubo `final`.** Con el bucle de relectura cerrado
   habrá que volver a medir si 21 iteraciones bastan; ahora mismo no sabemos si
   el problema era el presupuesto o la relectura.

**Lo que NO propongo:** tocar el contrato de `tool_batch`. Funciona, y el dato lo
respalda —3,38 herramientas por turno, cero `tool_call` sueltos—. Cualquier
esfuerzo ahí sería optimizar lo que ya está bien mientras el bucle de relectura
sigue abierto.
