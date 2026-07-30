# Contrato del agente — archivo único `agentes/agent.md`

> **Cambio 2026-07-28.** El contrato de *paquetes entrenados* por directorio
> (`agentes/<id>/` con `agent.yaml` + `prompts/` + `policy/` + `objetivos` +
> `knowledge/`) fue **retirado**. El agente se configura ahora con **un único archivo
> de comportamiento**. Este documento describe el contrato vigente; para el histórico
> del esquema anterior, ver el registro de commits.

## Qué carga Agentopsy

De la carpeta `agentes/` (o la que fije `FORENSIA_AGENTS_DIR`) Agentopsy carga **un
solo archivo**:

- **`agent.md`** — las instrucciones de comportamiento del agente, comunes a todos los
  proveedores de IA (Claude Code, Codex CLI, Gemini CLI, Ollama). Por eso se llama
  `agent.md` y no `CLAUDE.md`.

Al arrancar, `forensia.agent.loader.load_packages()` lee ese texto y construye **un
`AgentPackage` por perfil de SO** (`unix`, `windows`) que comparten el mismo `agent.md`
como `prompts.system` y difieren solo en la allowlist de herramientas. La registry
(`forensia.agent.registry`) los indexa por `os_profile`.

El apartado 9 de `agent.md` («Cómo se escribe») fija además la **tipografía del producto**: ni el signo `§`, ni el guion largo, ni emojis. No es cosmética: ese texto es el que el modelo imita, y el `title` y el `summary` de cada `record_finding` viajan tal cual al informe pericial (`forensia.reports.writer`).

Si `agent.md` no existe o está vacío, la registry arranca **vacía** y
`/api/agent/query` devuelve 503 para cualquier perfil: la UI degrada explícitamente,
sin agente fallback (CLAUDE.md RULE 2).

## Qué se deriva en código (ya no se declara por paquete)

| Antes (paquete declarativo) | Ahora (derivado, sin defaults silenciosos) |
|---|---|
| `policy/tools.yaml` (`allowed:`) | **catálogo filtrado por `os_profile`** — `forensia.toolkit.catalog.for_profile`. Un tool es invocable ⇔ el catálogo lo declara para ese perfil. Imposible desalinearla. |
| `policy/redaction.yaml` | `DEFAULT_REDACTION_PATTERNS` en `forensia.agent.loader` — secretos que nunca sirven al análisis y siempre son peligrosos de filtrar (claves privadas, tokens). No se redacta nada que ciegue al agente. |
| `prompts/system.md` + `identity.md` + `playbook.md` | el texto de `agent.md` (todo en `prompts.system`; `identity`/`playbook` vacíos). |
| `objetivos:` (mapa pregunta→artefacto→herramienta) | va **dentro** de `agent.md` (apartado 4 del propio archivo). |
| `knowledge/` (docs estáticos del paquete) | retirado. El **grafo de conocimiento POR CASO** (`forensia.knowledge`) lo escribe el agente en runtime con `anotar_conocimiento` — es la «FICHA/REGISTRO» del caso. |
| `case_knowledge:` (núcleo del grafo) | retirado. El grafo empieza vacío y el agente crea los nodos que necesite (`ficha`, `cronologia`, `registro`, `pendientes`). |
| `model:` (name/temperature/max_iterations) | constantes por defecto en el loader (el ejecutor real lo elige el operador en runtime — RULE 2). |

## La telaraña del caso vive en las stores por caso

El «spiderweb» de documentos enlazados se mapea sobre las stores de
`~/.forensia/cases/<id>/`:

| Papel | Store | Tool del agente |
|---|---|---|
| FICHA / REGISTRO-DECISIONES | grafo de conocimiento (`knowledge/<doc_id>.md`, append-only, legible) | `anotar_conocimiento` / `consultar_conocimiento` |
| Hallazgos con evidencia | `findings.jsonl` + audit encadenado | `record_finding` |
| Salida cruda por herramienta (`output/NN_tool/__raw`, `_run.md`) | artefactos del caso (cada corrida guarda su salida entera + hash + el argv literal en el audit) | `leer_artefacto` |
| Entregables (informe) | `documents/` | subsistema de documentos |

## Otros ficheros bajo `agentes/`

- **`_orchestrator/knowledge/mitre_attack_seed.md`** — la enum cerrada de técnicas
  ATT&CK que el agente puede proponer (`forensia.mitre.catalog` la parsea). No es parte
  del contrato de comportamiento del agente; es un recurso del subsistema MITRE que
  también se monta en el contenedor `api`.
- **`referencia/`** — material de solo lectura (el banco de pruebas destilado del que
  sale `agent.md`): no se carga en runtime.

## Cómo editar el comportamiento

Edita `agentes/agent.md`. No hace falta reiniciar nada en desarrollo salvo reinstanciar
la registry (reiniciar el proceso `api`). El texto es la base del system prompt; en cada
corrida Agentopsy le añade el contexto del caso (evidencia anclada, triage, allowlist).
