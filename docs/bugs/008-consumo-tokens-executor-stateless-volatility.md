# Bug 008 — un volcado de Volatility funde ~50 % del presupuesto de tokens en una sola pasada

- **Severidad:** alta (deja el executor cloud inservible en un `/query`; agota la cuenta del operador)
- **Estado:** 🟡 **mitigado** (2026-07-07 — #1–#5 implementados y testeados; #6 estructural opcional/pendiente)
- **Componente:** `backend/forensia/agent/agent.py` + `backend/forensia/executors/models/base.py`
  (bucle ReAct + render del prompt); secundarios: `agentes/*/agent.yaml`, `toolkit/wrappers/volatility3.py`
- **Detectado:** 2026-07-07, ejecutando un volcado simple de Volatility desde el chat (executor cloud);
  reportado por el equipo («50 % en una pasada», «se ha fundido el 100 %»)
- **Método:** investigación multi-agente con debate adversarial (6 ángulos → 35 hipótesis → 29 confirmadas / 5 refutadas)

## Síntoma

Una única llamada a `/api/agent/query` que solo lanza un plugin de Volatility (p. ej. `pslist`)
consume ~50 % del presupuesto de tokens del executor, y en el peor caso lo agota al 100 %.
No es la salida de la tool: el volcado ya está capado aguas abajo.

## Causa raíz

Los ejecutores son **subprocesos stateless sin prompt caching** (`claude -p <prompt>`,
`ollama /api/generate`). En **cada** iteración del bucle ReAct se re-renderiza y re-factura
íntegro el prefijo fijo enorme **más todo el transcript acumulado**, con `max_iterations: 18`
como multiplicador. Nada amortiza ese prefijo.

Cadena verificada en código:

- `_render_prompt` reconstruye TODO el prompt en cada `next_action` y lo pasa a un subproceso
  nuevo sin `--resume`/caché — el `session_id` del envelope se descarta
  (`models/base.py:121-153`; `claude_code.py:51,70`; `ollama.py:126`). **[crítico]**
- El system prompt gigante viaja íntegro cada iteración: `pkg_parts = [system, identity, playbook]`
  con el **playbook completo (21.914 B)** aunque `kind_routing` ya sepa la sección; solo *añade*
  un párrafo, nunca recorta (`agent.py:508-513`, `agent.py:233-238`, `agent.py:539-565`). **[alto]**
- El loop no tiene ventana ni poda: `messages` es append-only y se re-envía completo cada vuelta
  → crecimiento **O(N²)** intra-run. Los caps de `history.py` (`MAX_REPLAY_CHARS=8000`) solo
  actúan *entre* turnos, no dentro del loop (`agent.py:266,271,287-289`). **[alto]**
- `max_iterations: 18` amplifica linealmente el coste fijo por turno (~12 K tok × 18 ≈ 216 K solo
  de prefijo) (`agentes/forensia-windows/agent.yaml:14`, `forensia-unix/agent.yaml:14`). **[alto, multiplicador]**
- Las tool specs se serializan con `json.dumps(..., indent=2)` cada iteración; ~4.7 KB/iter son
  solo whitespace del pretty-print (`models/base.py:148`). **[medio, lossless]**
- `parsed` de Volatility sin cota + `json.dumps(body)[:8000]` ciego que corta a media fila
  (→ JSON inválido) y descarta el puntero `artifact_run` por el orden de claves
  (`volatility3.py:68` → `agent.py:646,650-658`). **[medio + bug de correctness]**

### El multiplicador

`supports_native_tools=False` (`base.py:106`) fuerza el «camino degradado» para los cuatro
ejecutores: los specs viajan como texto inline, nunca por la API con caching. En cada una de
hasta 18 vueltas se re-emite por el cable, sin caché ni sesión:

- **Prefijo fijo ~12 K tok**: system.md (9.815 B) + identity.md (1.365 B) + **playbook.md
  (21.914 B)** + specs `indent=2` (~3.3 K tok).
- **Transcript acumulado**: cada tool-result (~2 K tok) permanece en `messages` y se re-envía en
  todas las vueltas siguientes → término triangular O(N²).

Peor caso `Σ(12K + 2K·i)` para i∈[0,17] ≈ **>300 K tokens de input** en un solo `/query`. Con un
executor de contexto pequeño o cuenta cloud, eso es «50 % en una pasada / funde el 100 %».

## Estrategia: gestión de contexto **nativa de Agentopsy** (provider-agnóstica)

La decisión de diseño (2026-07-07): Agentopsy **no** debe apoyarse en mecanismos
del proveedor (prompt caching de Anthropic, `claude --resume`, context caching de
Gemini/OpenAI) para amortizar el coste. Esos mecanismos difieren por proveedor,
son opacos detrás del harness del CLI y su uso rompería la agnosticidad del
executor (`supports_native_tools=False`, «una sola variable independiente»,
`base.py:104-110`) y RULE 2 (no fallbacks específicos por CLI).

Corolario: la **única palanca uniforme** para los cuatro executors es **enviar
menos por iteración**. Agentopsy ya es *stateful* (posee `messages` canónico); el
fallo es que re-envía toda esa memoria cada vuelta. La solución es una **capa de
proyección propia** en `forensia/*` que produce el `outbound` (lo que va por el
cable) a partir del `messages` canónico, minimizándolo — exactamente el patrón que
ya usa `redact_messages` (`agent.py:271`): el canónico se conserva crudo para
replay/audit/custodia; solo se poda la copia que viaja. Como no hay `cache_read` a
0.1×, cada byte del prefijo fijo que se mande se paga a precio completo en cada
iteración → recortar el prefijo importa **más**, no menos.

## Plan de arreglo (por ratio impacto/esfuerzo)

1. **Recortar el playbook que viaja en el system** (`agent.py:508-513`) — el código ya calcula
   `detected_kind`/`kind_routing`; trocear `playbook.md` por secciones (disco / memoria / comunes)
   e inyectar solo la que casa. Para un memdump elimina ~2/3 de los 21.914 B. **RULE 2:** si
   `kind == unknown`, índice compacto, nunca el playbook entero como *fallback*. Mayor impacto, ~1 commit.
2. **Whitespace de las specs** (`models/base.py:148`) — `separators=(",",":")` en vez de `indent=2`.
   Lossless, 1 línea, −1.2 K tok/iteración.
3. **Ventana/poda del transcript dentro de `run()`** (`agent.py:~271`, antes de construir `outbound`)
   — colapsar tool-results antiguos a un stub de una línea, conservando siempre `messages[0]` +
   `prior_messages` + últimos K pares verbatim. **RULE 3/custodia:** podar *solo* la copia `outbound`
   que va por el cable (mismo patrón que `redact_messages`); mantener el `messages` canónico crudo
   para replay/redaction. El argv literal auditado no se toca; el detalle vive en el `ArtifactRun`/audit.
   Corta la O(N²).
4. **Compactar `parsed` + reordenar el body** (raíz en `volatility3.py:parse`, RULE 3) — devolver
   `{row_count, columns, sample: rows[:50]}` y volcar el array completo a artefacto hasheado; colocar
   `artifact_run` antes de `parsed` para que un recorte nunca lo descarte. Arregla tokens **y** el bug
   de JSON inválido.
5. **Bajar `max_iterations` 18 → 8-10** (`agentes/*/agent.yaml:14`) — mitigación barata del techo del
   escenario runaway; no arregla el derroche por iteración (por eso va después de 1-4).
6. **Continuidad de contexto propia** (el equivalente Agentopsy de un «resume», provider-agnóstico) — la
   forma fuerte de #3. En vez de re-serializar el transcript, Agentopsy mantiene su `messages` canónico y,
   por encima del umbral de ventana, **resume los turnos viejos a un running summary que genera y controla
   él mismo** (no el CLI). Lo que viaja es delta + resumen, idéntico para los cuatro executors. El estado
   sigue viviendo en Agentopsy (custodia/replay intactos). Va después de #1–#4 porque #3 (ventana + stubs)
   ya corta la O(N²); la compactación con resumen es el siguiente escalón si aún hace falta.

## Implementación (2026-07-07)

Capa de gestión de contexto **nativa** en `forensia/agent/context.py` (funciones puras, sin I/O, no mutan
la entrada — mismo contrato que `redact_messages`), proyectando el `messages` canónico al `outbound`. Todo
provider-agnóstico. Reducciones medidas (bytes reales, no estimaciones):

| Fix | Cambio | Fichero | Reducción medida |
|---|---|---|---|
| #1 | Playbook por `kind` (`select_playbook_section`) | `context.py` + `agent.py:_system_prompt` | disk → 70 % del playbook; memory → 91 % (en windows la sección grande es la de memoria, que se conserva) |
| #2 | Specs sin whitespace de `indent=2` | `models/base.py:_render_prompt` | 12.259 → 7.520 B/iter (**−4.7 KB por iteración**) |
| #3 | Ventana del transcript (`window_messages`, `keep_last=4`) | `context.py` + `agent.py` loop | transcript de 12 iter: 98 KB → 35 KB (**35 %**), y se re-envía cada vuelta |
| #4 | `volatility3.parse` acotado + `artifact_run` antes de `parsed` + truncado seguro (`_bounded_json`) | `wrappers/volatility3.py`, `agent.py` | filescan de 5.000 filas: `parsed` 517 KB → **2 KB**; el JSON nunca se corta a media estructura |
| #5 | `max_iterations` 18 → 12 | `agentes/*/agent.yaml` | acota el techo del runaway |

Tests: `backend/tests/test_agent_context_budget.py` (nuevo) + actualizaciones en `test_wrappers.py` y
`test_agent_registry.py`. Suite: 530 passed. El `messages` canónico se conserva crudo → replay/audit/custodia
intactos; el egreso cloud audita el SHA-256 del payload realmente enviado (windowed + redactado).

Pendiente (opcional): #6 (continuidad de contexto propia con running summary) si el transcript aún crece
en investigaciones muy largas; y afinar #1 troceando también el Anexo por herramienta (hoy común).

## Descartado por diseño (provider-específico)

- **Apoyarse en `claude -p --resume <session_id>`** (el `session_id` que hoy se descarta en
  `claude_code.py:70`): reanudar la conversación del lado del CLI delegaría el estado en el proveedor, no
  sería uniforme (Codex usa `exec resume`, Gemini checkpoints, Ollama `/api/chat`) y sacaría parte del
  contexto fuera de Agentopsy, complicando la reproducibilidad y la auditoría del argv literal (INVARIANTE
  4). Rechazado a favor de la continuidad de contexto **nativa** (#6 arriba). Mismo motivo para no
  depender del **prompt caching del proveedor**: opaco tras el harness del CLI y no fiable de forma
  uniforme → la estrategia es minimizar bytes enviados, no cachearlos.

## Descartado (refutado en el debate)

- **«El wrapper/dispatcher manda el volcado completo al LLM»** (`volatility3.py:68`, `dispatcher.py:250`,
  `maletin.py:145`) — falso como causa de *tokens*: hay un cap duro aguas abajo (`agent.py:646` `[:8000]`).
  El array grande se construye en RAM pero al LLM le llegan ~8 KB (~2 K tok). Es coste de CPU/RAM (y el
  bug de JSON inválido de arriba), no el inflador.
- **«num_ctx de Ollama / la redacción inflan el prompt»** — Ollama es `is_local=True` (sin presupuesto
  facturado) y sin `num_ctx` *topa* el contexto, no lo multiplica; la redacción (`agent.py:271`) solo corre
  si `is_cloud` y sus reemplazos son más cortos que el match. Red herrings.
- **«Los ficheros de conocimiento (`artefactos-windows.md`, `mitre_attack_seed.md`) se inyectan»** —
  `grep -rn knowledge backend/forensia/` = 0; el loader solo lee `system`/`identity`/`playbook`
  (`loader.py:157-165`). Nunca se cargan en el prompt.

## Lección (reusable)

Con ejecutores **stateless y agnósticos de proveedor** (la salida de tool ya se capa), el coste lo
domina **el prefijo fijo re-facturado en cada iteración** × el número de iteraciones, más el crecimiento
O(N²) del transcript. El presupuesto se gasta en *re-enviar lo que no cambia*. Como la caché del
proveedor no se puede aprovechar de forma uniforme (rompería la agnosticidad), la única regla de diseño
válida es **enviar menos**: todo lo estático y grande (playbook, specs) se recorta a lo relevante al
`kind` de la evidencia, y el transcript que va por el cable necesita una **ventana** propia — una
proyección lossy del `messages` canónico, que se conserva crudo para la cadena de custodia. La caché,
si el proveedor la aplica, es una optimización gratuita encima; nunca la dependencia.
