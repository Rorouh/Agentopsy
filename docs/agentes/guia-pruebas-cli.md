# Agentopsy — Guía de pruebas con CLI / Ollama (mientras el motor no está)

Cómo hacer pruebas útiles con Codex CLI, Gemini CLI o modelos Ollama **sin** el
front ni el orquestador completos, y qué entregar para análisis. Hay **dos vías**
distintas; no las confundas.

---

## 0. Las dos vías (qué mide cada una)

| Vía | Qué prueba | Ejecuta herramientas reales | Estado |
|---|---|---|---|
| **1 · Harness single-shot** | La **decisión** del agente (¿elige la tool correcta?, ¿respeta allowlist?, ¿mapea MITRE?) sobre casos sintéticos | NO (mock, sin evidencia) | **listo** (`evals/harness/`) |
| **2 · Análisis real de LoneWolf** | El **playbook completo** sobre evidencia real: el CLI agéntico ejecuta las tools forenses y produce hallazgos | SÍ (tools reales sobre la imagen) | requiere instalar tools |

La Vía 1 mide *razonamiento*; la Vía 2 valida *el producto* sobre LoneWolf. Ambas
alimentan el entrenamiento (ajustar prompts con lo que falle).

---

## 1. Modelos: sí, baja más potentes

`qwen2.5:3b` es insuficiente (acierta tools pero `find_recall 0`, alucina MITRE).
Recomendación:
- **Ollama local:** mínimo `qwen2.5:7b`; mejor `qwen2.5:14b` o `llama3.1:8b`. Si
  tienes GPU potente, `qwen2.5:32b`. Descarga: `ollama pull qwen2.5:14b`.
- **CLIs cloud** (codex = GPT, gemini, claude): son la referencia fuerte; no bajas
  nada, son la columna "potente" de la comparativa.

El experimento del TFM es precisamente **CLI potente vs Ollama local**: cuánto se
acerca lo local (privado) a lo cloud (fuerte).

---

## 2. VÍA 1 — Harness con más motores (sintético, mide decisión)

Prerrequisitos: activar los motores en `evals/harness/motors.yaml`
(`ready: true`) y tenerlos invocables.

Pasos:
1. **Ollama grande:** `ollama pull qwen2.5:14b`. Corre:
   `python run_eval.py --motor ollama --model qwen2.5:14b --cases 001,002,003,004,005,006,007,008,009,010`
2. **Codex CLI:** instálalo, confirma el comando no interactivo (`codex exec "..."`
   o `--help`), ajústalo en `motors.yaml`, `ready: true`, y corre:
   `python run_eval.py --motor codex --cases 001..010`
3. **Gemini CLI:** arregla la auth (la free-tier daba `IneligibleTierError`; usa una
   cuenta elegible), `ready: true`, y corre igual con `--motor gemini`.
4. Cada corrida añade filas a `results/summary.md`. **Ese fichero es lo que me
   pasas** para comparar motores/modelos.

Qué mirar tú de pasada: `tool_recall` alto = elige bien las tools; `find_recall`
alto = deduce los hallazgos; `fuera_semilla` = alucinación MITRE (malo);
`allowlist_viol` = pidió una tool prohibida (malo).

---

## 3. VÍA 2 — Análisis real de LoneWolf con un CLI agéntico

Aquí el CLI (codex/gemini) actúa **como Agentopsy-WIN**: le das los prompts del
paquete como instrucciones y deja que ejecute las herramientas forenses sobre la
evidencia. Es la validación cualitativa del playbook.

### 3.1 Prerrequisito: herramientas forenses instaladas
Empieza por lo de menor fricción:
- **Memoria (más fácil):** `pip install volatility3`. Con eso analizas
  `memdump.mem` directamente (`vol -f memdump.mem windows.pslist`, etc.). Es
  **read-only** por naturaleza. (Necesita que hayas bajado `memdump.mem`.)
- **Disco (más setup):** necesitas TSK + libewf + RegRipper + EvtxECmd. En Windows
  lo más limpio es el **toolkit en Docker del propio repo** (`docker/docker/
  forensic-toolkit/`) o WSL con `sleuthkit`. El disco `LoneWolf.E01` ya lo tienes.

### 3.2 Ensamblar el "prompt de agente"
Concatena, en un fichero de texto, en este orden:
1. `agentes/forensia-windows/prompts/system.md`
2. `agentes/forensia-windows/prompts/identity.md`
3. `agentes/forensia-windows/prompts/playbook.md`
4. La tarea, p.ej.: *"Analiza esta evidencia Windows. Para memoria: procesos,
   inyección, conexiones, credenciales. Registra cada hallazgo con la tool y el
   artefacto que lo sostiene. No inventes."*

### 3.3 Ejecutar
1. Abre el CLI (codex o gemini) en la carpeta que tenga la evidencia + las tools.
2. Pégale el prompt de agente ensamblado.
3. Déjalo conducir la investigación (ejecuta `vol ...`, etc.).
4. **Captura TODO:** la transcripción, los comandos que ejecutó, y su lista final
   de hallazgos. Guárdalo en un `.md`/`.txt` por CLI (p.ej.
   `lonewolf-memoria-codex.md`, `lonewolf-memoria-gemini.md`).

### 3.4 Soundness (no rompas la evidencia)
- Trabaja sobre una **copia**; nunca dejes que una tool **escriba** en la imagen.
- Volatility sobre memoria = read-only. TSK lee sin montar el FS. Para registro/
  EVTX, extrae el artefacto y procesa el fichero derivado (nunca la imagen cruda).
- No montes el NTFS en modo lectura-escritura.

---

## 4. Qué me entregas para que lo analice en detalle

Cuando vuelvas, pásame:
1. **`results/summary.md`** del harness (Vía 1) con los motores que hayas corrido.
2. **Las transcripciones/hallazgos** de LoneWolf por cada CLI (Vía 2).
3. Si tienes el `Forensic Outputs.zip` de LoneWolf a mano, dímelo (es el
   ground-truth de referencia).

Yo audito en detalle: qué motor razona mejor, dónde falla el playbook (tools que no
elige, hallazgos que se pierde, técnicas que alucina), precision/recall real frente
al ground-truth de LoneWolf, y qué prompts ajustar en la siguiente iteración de
entrenamiento.

---

## 5. Checklist (orden recomendado)

- [ ] Commit + push del harness (4 ficheros) a `tools`.
- [ ] `ollama pull qwen2.5:14b` (o 7b si vas justo de RAM).
- [ ] Vía 1: correr el harness con ollama-14b + codex + gemini sobre los 10 casos → guardar `summary.md`.
- [ ] `pip install volatility3` (+ bajar `memdump.mem` si no lo tienes).
- [ ] Vía 2: ensamblar el prompt de agente y correr LoneWolf-memoria con codex y con gemini → guardar transcripciones.
- [ ] (Opcional) Vía 2 sobre el disco con el toolkit Docker del repo.
- [ ] Traerme `summary.md` + transcripciones para el análisis detallado.

> Nota de tokens: todo esto lo haces con codex/gemini/ollama, **sin gastar Claude**.
> El análisis detallado de resultados lo hago yo cuando me los traigas.
