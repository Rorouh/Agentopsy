# Prompt para Claude Code — diagnóstico de consumo de tokens

> Pegar en la terminal, en la raíz del repo, con la rama `tools` activa.
> El prompt está redactado para que Claude Code **mida antes de tocar** y **pare a que
> apruebes el plan** antes de implementar.

---

Trabajamos en el repositorio Agentopsy, rama `tools`. Antes de nada: `git pull` (RULE 5)
y lee `CLAUDE.md` y `tools/graph/CONTEXT.md` — las invariantes de ese fichero mandan
sobre cualquier optimización que propongas.

## El síntoma

Con **el mismo prompt y el mismo modelo (Opus 5)**, una investigación lanzada desde el
apartado «Investigación» de Agentopsy consume **muchos más tokens** que ejecutar un
trabajo equivalente contigo directamente en mi terminal. El consumo actual es
insostenible. El objetivo es que investigar desde Agentopsy se parezca, en coste de
tokens, a trabajar contigo en la terminal.

## Lo que quiero de ti, en dos tiempos

**No escribas código todavía.** Este encargo tiene dos entregas y la segunda depende de
que yo apruebe la primera.

### Entrega 1 — Diagnóstico con números

Un documento en `docs/diseno/tokens-2026-07/diagnostico.md` que responda, **con
mediciones, no con intuiciones**:

1. **Cuántos tokens se envían por turno del bucle del agente y por qué.** Desglosa cada
   turno en: prompt de sistema, `agentes/agent.md`, esquemas de herramienta, historial de
   mensajes, resultados de herramienta. Quiero una tabla turno a turno de una corrida
   real, no una estimación teórica.
2. **Cómo crece ese consumo con el número de iteraciones.** Si es cuadrático, dímelo con
   la curva medida.
3. **Cuánto del diferencial contra la terminal es recuperable y cuánto es estructural.**
   Sé honesto aquí: yo en terminal tengo herramientas ligeras (Read/Grep/Bash) y mi
   propia compactación; Agentopsy carga un catálogo forense y un fichero de conducta.
   Parte de la diferencia es intrínseca al producto. Quiero saber qué parte NO lo es.

Para medir: `claude -p --output-format json` devuelve un bloque `usage` con
`input_tokens`, `output_tokens`, `cache_creation_input_tokens` y
`cache_read_input_tokens`. Comprueba si `forensia.executors` ya lo captura; si no, la
primera tarea es instrumentarlo y registrar el uso por turno. **Un `cache_read` de cero
turno tras turno es el hallazgo más probable y el más caro.**

### Entrega 2 — Plan, y paras

Un plan de corrección por fases, ordenado por ratio ahorro/riesgo, en
`docs/diseno/tokens-2026-07/plan.md`. **Te detienes ahí y esperas mi aprobación antes de
implementar nada.**

## Hipótesis a confirmar o refutar

Son hipótesis, no conclusiones: si los datos dicen otra cosa, sigue los datos y dímelo.

- **H1 — Sin caché de prompt.** Cada iteración del bucle podría estar lanzando un
  `claude -p` nuevo con la transcripción completa reenviada desde cero. En terminal yo
  mantengo una sesión con caché sobre el prefijo estable; si Agentopsy no reutiliza
  sesión ni caché, paga el prefijo entero en cada turno y el coste crece de forma
  cuadrática con el número de herramientas ejecutadas. Mira `forensia/executors/`
  (`CliPromptExecutor`, `ClaudeCodeExecutor`) y comprueba si existe reutilización de
  sesión (`--resume` / `--continue` / session id) o si cada turno es un arranque en frío.
- **H2 — Prefijo inestable que invalida la caché.** Aunque haya caché, cualquier cosa
  variable al **principio** del prompt la rompe entera: marcas de tiempo, `run_id`,
  ids de caso, el *structural nudge* que `agent.py` inyecta tras 3 herramientas sin
  hallazgo, o un orden no determinista de claves. Verifica que el prefijo (sistema +
  `agent.md` + esquemas) sea **byte a byte idéntico** entre turnos, y que todo lo
  variable vaya al final.
- **H3 — Salidas crudas inlineadas.** Agentopsy tiene `ArtifactStore`: la salida de cada
  herramienta ya se persiste y se hashea en disco. Comprueba si además se está metiendo
  entera en el contexto. El patrón correcto es que el modelo reciba una **vista acotada
  más la referencia al artefacto** y pueda pedir más si lo necesita. Un `bulk_extractor`
  o un `tsk_fls` sobre un disco real inlineado es una bomba de tokens.
- **H4 — Presupuesto de contexto mal calibrado.** Revisa `window_messages()`,
  `keep_last_tool_results` y `bounded_json` en `forensia/agent/`: qué se conserva, cuánto,
  y si los límites son los adecuados o se quedaron de una prueba.
- **H5 — Reenvío íntegro de conducta y esquemas.** `agentes/agent.md` (~215 líneas) y el
  catálogo completo de esquemas de herramienta, ¿viajan enteros en cada turno? Si el
  catálogo se filtra por `os_profile` (`catalog.for_profile`), ¿se está aprovechando ese
  filtrado en lo que realmente se envía al modelo?
- **H6 — Rehidratación excesiva.** `build_replay_messages()`: al reanudar un chat, ¿cuánto
  del historial se reconstruye y se reenvía?

## Restricciones que ninguna optimización puede romper

- **RULE 2 — sin fallbacks ni truncados silenciosos.** Si recortas contexto, el agente
  tiene que **saber** que se recortó y qué falta. Un contexto podado en silencio produce
  conclusiones sobre evidencia que el modelo cree haber visto y no vio: en una
  herramienta forense eso es peor que gastar tokens.
- **FORENSIC INVARIANT 4 — la auditoría no se toca.** `audit.jsonl` guarda el argv
  literal, la versión de la herramienta, los hashes de salida y los códigos de salida.
  Eso vive en disco, no en el contexto del modelo: optimizar tokens **no puede** reducir
  lo que se audita. Si alguna propuesta tuya roza esa línea, descártala y dilo.
- **La procedencia de los hallazgos sobrevive.** Un `Finding` debe seguir pudiendo citar
  su `run_id` y el SHA-256 de su artefacto. Si el modelo deja de ver la salida completa
  de una herramienta, tiene que seguir pudiendo anclar el hallazgo a ella.
- **RULE 3** — la lógica va en `forensia/*`; routers y frontend siguen siendo adaptadores
  finos.
- **RULE 7** — sin claves de API en ninguna parte. Los ejecutores siguen siendo los
  cuatro que selecciona explícitamente el operador, sin default (RULE 2).
- **Los cuatro ejecutores.** Cualquier arreglo que solo funcione para Claude Code y deje
  a Codex CLI, Gemini CLI y Ollama igual de caros es media solución: dime explícitamente
  qué parte del arreglo es común y qué parte es específica de cada ejecutor.

## Método

- Mide primero. Si no puedes medir algo, dilo en vez de estimarlo como si lo hubieras
  medido.
- Prioriza por ratio ahorro/riesgo: un cambio que recorte el 70 % del gasto sin tocar
  ninguna invariante va antes que uno que recorte el 5 % y toque el bucle del agente.
- Cuando termines cada entrega, resume en tres líneas: qué encontraste, cuánto cuesta y
  qué propones.
- Antes de cualquier push futuro (RULE 6): desde `backend/`, `pip install -e ".[dev,mcp]"`,
  `ruff check .` y `pytest -q`; desde `web/`, `npm ci && npm run typecheck && npm run build`
  si tocas el frontend. Y documentación en sintonía antes de commitear (RULE 4).
