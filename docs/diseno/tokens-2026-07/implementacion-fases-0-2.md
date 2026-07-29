# Implementación de las Fases 0-2 y mediciones asociadas

> Ejecuta lo aprobado del [`plan.md`](plan.md): **Fase 0** (instrumentación +
> guardia de regresión + corrección de `estimate.py`), **Fase 1** (sesión y
> delta, con guardia de divergencia) y **Fase 2** (reordenar el prompt).
> Las Fases 3, 4 y la [fase de turnos](fase-turnos.md) quedan **medidas y sin
> implementar**, a la espera de decisión.
>
> **Fecha:** 2026-07-29 · **Rama:** `tools`

---

## Resumen

1. **Qué implementé.** Las Fases 0-2. El transporte por sesión solo envía el
   delta cuando un guardia puede **dar cuenta** de la sesión con tres
   comprobaciones deterministas; cualquier duda —incluida "no se puede
   verificar"— reenvía el contexto completo y lo audita.
2. **Qué midió la validación.** Contra el código real, 8 turnos:
   **0,5491 → 0,1150 USD, −79,1 %**, con `cache_read` creciendo turno a turno
   (38.133 → 48.500) y `cache_creation` desplomado de ~23.000 a ~1.500.
3. **Qué apareció por el camino.** Dos hallazgos no previstos: la sesión del CLI
   **puede divergir de verdad** (medido) y **Agentopsy inyecta su propio
   `CLAUDE.md` en cada llamada** (8.870 tokens por turno) por heredar el
   directorio de trabajo.

---

## 1. El estudio empírico de `--resume` que exigía el encargo

Antes de escribir código, contra `claude` 2.1.220 el 2026-07-29:

| Pregunta | Respuesta medida |
|---|---|
| ¿`--resume` devuelve el mismo `session_id` o uno nuevo? | **El mismo.** Tres turnos encadenados conservaron `32b4168c-…` |
| ¿Reenvía su system prompt en cada resume? | **No.** `cache_creation` cae de 6.068 a 69 y a 301; el prefijo se lee, no se reescribe |
| ¿Los turnos internos (`num_turns` > 1) quedan en la sesión? | **Sí** — ver §2 |
| ¿Hay compactación interna? ¿Es observable? | **Sí a las dos** — ver §2 |

### La identidad contable que lo sostiene

Tres turnos consecutivos sobre una sesión reanudada:

| Turno | `cache_creation` | `cache_read` | |
|---|---:|---:|---|
| 1 | 6.068 | 5.033 | |
| 2 | 69 | **11.101** | = 5.033 + 6.068 ✓ |
| 3 | 301 | **11.170** | = 11.101 + 69 ✓ |

`cache_read(N+1) = cache_read(N) + cache_creation(N)`, exacta al token. El
envelope también expone `cache_creation.ephemeral_1h_input_tokens`, lo que
**confirma** el supuesto del diagnóstico: Claude Code escribe en la caché de 1
hora, tarifa **2×**. Con la caché rota, Agentopsy pagaba ese recargo por un
prefijo que jamás releía.

## 2. Los dos modos de divergencia — medidos, no supuestos

El plan cubría "resume falla → contexto completo". Faltaba el caso peligroso:
**resume que funciona sobre una sesión que ya no es la nuestra**. Existe, y de
dos formas:

**a) El CLI añade turnos propios.** Una sola llamada con una herramienta
habilitada devolvió `num_turns=3` y dejó en la sesión:

```
user:text → assistant:thinking → assistant:tool_use → user:tool_result
          → assistant:tool_use → user:tool_result → assistant:text
```

Cuatro filas que Agentopsy no escribió. Al reanudar, el modelo las enumeró como
contexto vivo. La identidad contable **también se rompe** ahí (`cache_read` 9.065
donde la suma predecía 28.539), así que la divergencia se delata sola.

**b) El CLI compacta.** Las sesiones reales en disco llevan filas
`{"type":"system","subtype":"compact_boundary"}` con
`compactMetadata.cumulativeDroppedTokens` de **1,8 millones**. Compactar
**sustituye el historial por un resumen generado por el modelo**: exactamente la
compresión con pérdida que el plan descartó por diseño —puede dejar caer un
`run_id` o un SHA-256 y romper la procedencia de un hallazgo— con la diferencia
de que **el CLI puede imponerla unilateralmente**.

### El guardia

`forensia/executors/session_guard.py`. Un delta sale **solo** si las tres pasan:

1. **`num_turns == 1`** — el CLI no añadió turnos propios.
2. **Sin `compact_boundary`** en la transcripción — no hubo resumen con pérdida.
3. **La transcripción en disco contiene lo que Agentopsy escribió, y solo eso** —
   número de prompts propios y cero `tool_use` del CLI.

La transcripción es un JSONL en `~/.claude/projects/<slug>/<session_id>.jsonl`
—bajo el compose, dentro del volumen `forensia-cli-auth`, que es el HOME del
contenedor—. Se localiza por **glob del `session_id`** (un UUID, único) en vez de
recalcular el slug del directorio, que es un detalle interno del CLI.

**No hay rama "asumimos que va bien".** Una sesión que no se puede verificar se
trata igual que una divergida: contexto completo y `reopen_reason` en el audit.
Responde literalmente a lo pedido — es imposible que un delta llegue a una sesión
de la que Agentopsy no pueda dar cuenta, y la política queda en el audit.

## 3. Coste y corrección: separados a propósito

Una lectura de las mediciones obligó a partir en dos lo que el plan trataba
junto. La identidad contable se rompe también cuando la caché simplemente
**caduca** (TTL de 1 h) — y eso cuesta dinero, pero **no corrompe nada**.
Confundir ambas cosas sería el error que este encargo persigue:

| | `session_guard` | `cache_health` |
|---|---|---|
| Vigila | Integridad del contenido | Coste |
| Falla cuando | La sesión no es la nuestra | El prefijo se reescribe |
| Consecuencia | El modelo razonaría sobre evidencia que no vio | La factura se multiplica |
| Reacción | **Bloquea el delta**, reabre, audita | **Avisa**, no bloquea nada |

El guardia de regresión permanente pedido en la Fase 0 es el segundo: con sesión
activa, si `cache_read` no crece durante **≥3 turnos consecutivos**, emite un
aviso accionable que va al log y al audit (`executor_cache_regression`), y
nombra la causa más probable —una subida de versión del CLI que ha movido sus
puntos de corte de caché—. Solo avisa con sesión activa: sin ella cada turno es
un arranque en frío por construcción y un `cache_read` plano es lo esperado.

## 4. `estimate.py`: el bug de corrección

`input_tokens` es **solo el resto no cacheado**. La estimación previa al análisis
se anclaba en él, así que enseñaba al perito un número ~15× por debajo de lo que
iba a pagar.

- `Usage` gana `cache_creation_input_tokens`, `cache_read_input_tokens` y
  `total_input_tokens` (derivado). `executor_cost` construye `total_tokens` sobre
  el total real; los eventos anteriores al 2026-07-29 no traen campos de caché y
  **caen a `input_tokens`, conservando exactamente el significado que tenían**
  (el log es append-only: nada se reescribe).
- `HEUR_TOKENS_PER_ITER`: **5.000 → 50.000**, calibrado contra la corrida real
  (992.152 entrada + 121.594 salida) / 22 iteraciones = 50.625. Con fecha y
  origen en el propio comentario del código.
- `INPUT_FRACTION_DEFAULT`: 0,8 → **0,89** (992.152 / 1.113.746 medido).
- Tests de regresión propios, incluido uno que fija que la heurística no vuelva a
  bajar de escala y otro que comprueba que los eventos antiguos siguen contando
  lo mismo.

**Ojo con la tarifa:** `TARIFFS["claude-code"]` sigue asumiendo precio
Sonnet (3/15 USD por MTok) y la corrida medida fue con **opus** (5/25). No lo he
tocado —está declarado como supuesto y el modelo lo elige el operador— pero la
estimación en USD sigue siendo baja por ese lado.

## 5. Fase 2 — reordenar

```
antes:  SISTEMA │ tránscrito (variable) │ ESQUEMAS │ contrato
ahora:  SISTEMA │ ESQUEMAS │ tránscrito (variable) │ contrato
```

El contrato de respuesta **sigue siendo lo último que lee el modelo**, con test
que lo fija. La comprobación pedida se sostiene con dato: en la corrida
`fe00dad1` hubo **0 fallos de parseo en 21 respuestas**, así que la estrictez que
protege el contrato está funcionando y no había margen para arriesgarla por
~1.000 caracteres.

## 6. Validación A/B contra el código real

Misma conversación de 8 turnos, mismo `agent.md` real, mismos esquemas reales
filtrados por perfil, mismo `ExecutorBackend`. Única variable: el transporte.

| | A (transporte OFF) | B (Fases 0-2) |
|---|---:|---:|
| Caracteres de prompt por turno (2-8) | 35.018 → 38.024 | **1.513** |
| `cache_read` | **clavado en 16.021** | **38.133 → 48.500** |
| `cache_creation` por turno | 22.368 → 23.904 | **1.403 – 2.160** |
| Turnos enviados como delta | 0/8 | **7/8** |
| **Coste** | **0,5491 USD** | **0,1150 USD** |
| | | **−79,1 %** |

Los cuatro criterios de aceptación del encargo, sobre esta corrida:

1. ✅ `cache_read` crece turno a turno en vez de quedarse clavado.
2. ✅ `cache_creation` queda acotado al tamaño del delta.
3. ✅ Coste muy por debajo del umbral (extrapolado a 22 turnos opus: ~2,7 USD).
4. ⏳ **Sin verificar** — ver §8.

### La lectura contraintuitiva, y por qué importa

**Los tokens de entrada SUBEN un 13,5 % (312.525 → 354.760) mientras el coste
baja un 79 %.** No es una contradicción: con sesión, el historial completo
permanece en contexto (ya no se eliden resultados) — hay *más* tokens — pero casi
todos se leen de caché a 0,1× en vez de reescribirse a 2×. En equivalentes de
token base: **389.834 → 57.911**.

La consecuencia práctica es que **contar tokens no mide el coste**. Cualquier
métrica futura tiene que ponderar por régimen de caché o mentirá en la dirección
contraria a la de antes.

## 7. Hallazgo no previsto: Agentopsy inyecta su propio `CLAUDE.md`

Medido aislando el mismo prompt mínimo, cambiando solo el directorio de trabajo:

| Configuración | `total_input` |
|---|---:|
| CWD = repo, arnés completo | **27.087** |
| CWD neutro, arnés completo | 18.217 |
| CWD neutro + `--disallowed-tools` | 11.314 |
| CWD neutro + `--system-prompt` (Fase 4) | 4.778 |

**8.870 tokens por llamada** son el `CLAUDE.md` de Agentopsy y el contexto de
proyecto, que el CLI carga porque `subprocess.run` **hereda el directorio de
trabajo** y ningún ejecutor fija `cwd=`. En la corrida medida son ~195.000
tokens, **el 20 % de la entrada**.

No es solo coste. `CLAUDE.md` son las normas de desarrollo de Agentopsy —RULE 0,
RULE 2, invariantes— y están entrando en el contexto del agente forense como si
fueran instrucciones suyas. Eso **contradice el contrato documentado** de que
`agentes/agent.md` es *el ÚNICO fichero de conducta que el agente lee*.

**No lo he arreglado**, por dos razones: está fuera de las fases aprobadas, y
—más importante— cambiar el CWD **mueve el directorio donde el CLI guarda las
sesiones**, que es justo lo que el guardia de divergencia inspecciona. Las dos
cosas hay que medirlas juntas, no encadenarlas a ciegas.

> **ACTUALIZACIÓN (2026-07-30, rama Rama-Enrique): arreglado.** Los CLI corren
> ahora en un **cwd neutro y vacío** (`CONFIG_DIR/executor-cwd`, fijado en
> `CliPromptExecutor.run` y auditado en cada `executor_run_start`). La objeción
> del guardia estaba resuelta por diseño: `session_guard.find_transcript`
> localiza la transcripción por **glob del `session_id`** en todos los
> directorios de proyecto — deliberadamente NO recalcula el slug por-cwd — así
> que mover el cwd no lo ciega; y al ser un directorio FIJO, todas las sesiones
> de Agentopsy quedan bajo un único proyecto estable. Gate:
> `tests/test_executors.py::test_run_uses_neutral_cwd_and_audits_it`.

## 8. Lo que esta validación NO demuestra

- **El criterio 4 (calidad equivalente) no está verificado.** La A/B usó una
  conversación sintética y `haiku`: mide transporte, no análisis. Comparar
  hallazgos, procedencia y técnicas propuestas exige reejecutar `fe00dad1` con
  las evidencias reales y los toolkits levantados. **Ese es el paso que falta y
  manda sobre los otros tres.**
- **El −79 % es sobre 8 turnos con `haiku`.** El mecanismo no depende del
  modelo, la cifra exacta sí.
- **Solo Claude Code.** Codex, Gemini y Ollama siguen a contexto completo. Lo
  común (Fases 0 y 2, más el reordenado) los beneficia por construcción;
  `supports_session_resume` queda en `False` para los tres, explícitamente y con
  el motivo en el código, hasta verificar cada CLI contra su binario real.
- **Fase 4 medida solo en coste:** `--disallowed-tools` quita 7.114 tokens y
  `--system-prompt` otros 6.602 (13.716 en total, el 50,6 % del arranque en
  frío). Pero **el efecto sobre la calidad del análisis sigue sin medir**, y ese
  era el criterio que el encargo puso por delante.
