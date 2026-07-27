# `harness/` — Runner single-shot agnóstico de motor (Agentopsy-WIN)

Mide la **DECISIÓN** del sub-agente `windows` —qué herramientas planifica y qué
hallazgos propone— frente a la traza dorada de un `case-win-*.yaml`, usando
**cualquier motor**: un modelo local de **Ollama** o un **CLI agéntico**
(claude / codex / gemini). Es la **Vía 1** del plan de entrenamiento
(`docs/agentes/plan-entrenamiento-validacion.md`): entrena la decisión del agente
sin ejecutar herramientas forenses reales ni tocar el motor del backend.

> **Single-shot.** El modelo responde el plan + los hallazgos **de una sola
> tirada** (no hay loop tool-use ni ejecución real de herramientas). La versión
> interactiva E2E con MCP y dispatcher real es la **Vía 2**, y llegará cuando el
> motor exponga `run()` (ver el plan). El scoring y el formato de casos son los
> mismos, así que este harness no es trabajo tirado.

## Qué NO hace (por diseño)

- No lee ni ejecuta evidencia real (las fixtures `case-win-*` son sintéticas y ni
  siquiera se abren aquí; solo se usa su traza dorada para puntuar).
- No ejecuta herramientas forenses. El "dispatcher" es implícito: el modelo emite
  el plan de golpe y el harness lo compara con lo esperado.
- No toca `backend/`. Vive entero bajo `agentes/forensia-windows/evals/harness/`.

## Uso

```bash
cd agentes/forensia-windows/evals/harness

# Ollama local (modelo por defecto del bloque en motors.yaml):
python run_eval.py --motor ollama --cases 002,005,010

# Ollama con un modelo concreto:
python run_eval.py --motor ollama --model qwen2.5:3b --cases 002

# Un CLI agéntico (cuando esté instalado y con ready:true en motors.yaml):
python run_eval.py --motor claude --cases 002
python run_eval.py --motor gemini --model gemini-2.5-flash --cases 005
```

`--cases` es una lista separada por comas de sufijos `case-win-<id>.yaml`
(p.ej. `002,005,010`). `--timeout` (s, por corrida) es opcional.

## Cómo AÑADIR un motor nuevo (cero código)

Añadir un motor es **solo** un bloque en [`motors.yaml`](motors.yaml). No se toca
`run_eval.py`. Cada bloque declara cómo invocar el motor en modo **no
interactivo**:

```yaml
motors:
  mi_cli:
    ready: true                          # false => run_eval falla en seco (RULE 2)
    argv: ["mi_cli", "--headless", "{prompt}"]
    prompt_via: arg                      # stdin | arg | file
    default_model: "modelo-x"            # opcional
```

- `prompt_via: stdin` → el prompt entra por la entrada estándar del proceso.
- `prompt_via: arg`   → se sustituye `{prompt}` dentro de `argv`.
- `prompt_via: file`  → se escribe el prompt a un fichero temporal y se sustituye
  `{prompt_file}` en `argv`.
- `{model}` se sustituye en `argv` por `--model` (o `default_model`).

Todo se ejecuta con **`subprocess` `shell=False` y `argv` en lista** (gate 4):
nunca se construye una cadena de comando ni se usa `shell=True`.

`ready: false` deja el motor **cableado pero inactivo**: seleccionarlo aborta con
un error explícito (no hay defaults silenciosos, RULE 2). Se pone `ready: true`
cuando el motor se ha instalado y probado de verdad en la máquina.

## Qué mide (métricas)

Una fila por `(motor, modelo, caso)` en `results/summary.md`:

| Métrica | Qué mide |
|---|---|
| `json` | si la respuesta del motor trajo un JSON `{plan, findings}` parseable |
| `tool_recall` | de los `provenance_tool` esperados, cuántos aparecen en el **plan** |
| `find_recall` | hallazgos esperados (por `title_glob`) presentes en la salida |
| `find_prec` | fracción de hallazgos emitidos que casan con alguno esperado |
| `mitre_recall` | técnicas esperadas presentes en los `mitre` de los hallazgos |
| `mitre_ok` | fracción de técnicas emitidas que son correctas (esperadas) |
| `fuera_semilla` | técnicas emitidas que **no** están en la semilla MITRE (inventadas; deben ser `—`) |
| `allowlist_viol` | `tool_id` emitidos fuera de `policy/tools.yaml` (debe ser `—`) |
| `iters` | iteraciones (single-shot ⇒ 1) |
| `tokens` | coste, si el motor lo reporta (`n/a` en Ollama por stdout) |

El modelo **nunca** ve la traza dorada ni los `expected_findings`: solo recibe los
prompts del paquete (`system`+`identity`+`playbook`), la allowlist de tools y un
prompt de escenario neutro por tipo de evidencia (disco / memoria). El scoring es
externo.

## Robustez frente a la salida de los CLI

Los CLI (Ollama incluido) hacen *word-wrap* en streaming con secuencias de cursor
(`ESC[<n>D`, `ESC[K`) que parten un valor de cadena e insertan restos que
invalidarían el JSON. `run_eval.py` incluye un **emulador de terminal** mínimo que
aplica esos movimientos y reconstruye el texto visible (JSON limpio) antes de
extraerlo por conteo de llaves. Así el harness tolera cualquier motor con render
de terminal, no solo Ollama.

## Salidas

- `results/<motor>-<modelo>-<caso>-<timestamp>.json` — scores + `raw_stdout` de
  cada corrida (para auditar la decisión del modelo).
- `results/summary.md` — tabla acumulada; **una fila por corrida**, pensada para
  comparar **varios motores lado a lado** (p.ej. Ollama vs un CLI, o dos modelos).

Ambos son **artefactos generados** y no se versionan (`results/.gitignore`).

## Estado verificado (prueba de generalidad)

La abstracción se ha ejercitado **de verdad** con más de una configuración:

- `ollama` (adapter `stdin`) y `ollama_arg` (adapter `arg`) — **dos caminos de
  adapter distintos**, ambos con subprocess real y JSON parseado (`json ok`).
- Dos modelos: `qwen2.5:3b` (produce el JSON del contrato) y `lse_rayo:latest`
  (fine-tune de chat que **no** cumple el contrato single-shot ⇒ fila `FALLO`,
  medición honesta de un modelo no apto).
- Casos `002` (disco), `005` (memoria) y `010` (prompt-injection).

`claude` y `codex` no están instalados aquí; `gemini` está instalado pero su
cuenta ya no es elegible (free-tier discontinuado). Los tres quedan como bloques
`ready: false` en `motors.yaml`: activarlos es **solo** poner `ready: true` cuando
la herramienta esté disponible — sin tocar código.
