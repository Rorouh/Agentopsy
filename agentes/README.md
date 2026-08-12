# `agentes/` — el agente forense de Agentopsy

Desde 2026-07-28 el agente se configura con **un único archivo de comportamiento**:

- **[`agent.md`](agent.md)** — las instrucciones que lee el agente para saber **cómo
  comportarse**. Es lo único que Agentopsy carga de esta carpeta. Vale para cualquier
  proveedor de IA (Claude Code, Codex CLI, Gemini CLI, Ollama): por eso se llama
  `agent.md` y no `CLAUDE.md`.

Ya **no hay** el contrato de paquetes anterior (`agent.yaml`, `prompts/`, `policy/`,
`objetivos`, `knowledge/`). Fue retirado: masticaba demasiada estructura declarativa
para lo que aporta, y el método real cabe en un solo documento.

## Cómo lo consume Agentopsy

Al arrancar, el `api` lee `agent.md` (o el que fije `FORENSIA_AGENTS_DIR`) y construye
**un agente por perfil de SO** (`windows`, `unix`) que comparten ese texto como base de
su system prompt. En cada corrida, Agentopsy añade el contexto del caso:

- La **evidencia anclada** (verificada por hash, montada solo lectura a nivel de bloque).
- El **triage** (`detected_os`, `detected_kind`) — determinado por el contenido, no por
  el host. `detected_kind` marca el SOPORTE y con él qué herramientas aplican:
  `disk` / `container_disk` (TSK), `memory` (Volatility3) y `document`, que es un
  fichero aportado (un PDF, una foto, un correo, un log, un artefacto suelto, una
  muestra) sobre el que no aplica ninguna de las dos y se lee el fichero en sí.
  Un `document` **nunca** enruta el perfil del caso: no es el sistema investigado.
- La **allowlist de herramientas**, que es el **catálogo filtrado por el `os_profile`**
  del caso (`forensia.toolkit.catalog`). El agente elige por id; Agentopsy resuelve el
  argv real desde el allowlist (SECURITY INVARIANT 5) y le inyecta el path de la
  evidencia (nunca lo pone el modelo).

El perfil de SO **no lo elige el cliente**: lo determina el triage por el contenido de
la evidencia y el orquestador enruta al agente de ese perfil. En `unknown` / baja
confianza / señales en conflicto, **el operador ancla** el perfil (RULE 2 — nunca un
default silencioso).

## La telaraña del caso vive en las stores del caso

El «spiderweb» de documentos que en el banco de pruebas eran ficheros markdown, aquí lo
persisten las stores por caso (`~/.forensia/cases/<id>/`), y el agente las escribe con
sus tools internas. La correspondencia:

| Papel (banco de pruebas) | En Agentopsy |
|---|---|
| `FICHA` / `REGISTRO-DECISIONES` | grafo de conocimiento del caso (`knowledge/<doc_id>.md`, append-only, legible) — `anotar_conocimiento` / `consultar_conocimiento` |
| Hallazgos con evidencia | `findings.jsonl` + audit encadenado — `record_finding` |
| `output/NN_tool/__raw` + `_run.md` | artefactos del caso (cada corrida guarda su salida entera + hash + el argv literal en el audit) — se releen con `leer_artefacto` |
| `entregables/` (informe) | subsistema de documentos (`documents/`) |
