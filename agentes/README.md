# `agentes/` — el agente forense de Agentopsy

El agente se configura con **un único archivo de comportamiento**, y hay **uno por
idioma**:

- **[`agent.md`](agent.md)** — las instrucciones en CASTELLANO.
- **[`agent.en.md`](agent.en.md)** — su gemelo INGLÉS.

Es lo único que Agentopsy carga de esta carpeta. Vale para cualquier proveedor de IA
(Claude Code, Codex CLI, Gemini CLI, Ollama): por eso se llama `agent.md` y no
`CLAUDE.md`.

**Los dos son el MISMO método escrito dos veces**, no una traducción automática: el
`title` y el `summary` de cada hallazgo viajan tal cual al informe pericial, así que
ese texto se escribe con el cuidado de un texto de producto. Si tocas uno, toca el otro:
`tests/test_agent_registry.py` comprueba que conservan el mismo esqueleto de apartados,
porque si uno gana una sección y el otro no, Agentopsy se comportaría distinto según el
idioma de la interfaz, que es justo lo que una herramienta forense no puede hacer.

**No hay respaldo al otro idioma** (RULE 2). Si falta el fichero del idioma elegido, el
registro de ESE idioma queda vacío y `/api/agent/query` responde 503; nunca se carga el
castellano cuando se pidió el inglés, porque eso dejaría al perito con un agente que
escribe en un idioma que no eligió.

## Cómo lo consume Agentopsy

El `api` lee el fichero del idioma de la petición (de `AGENTOPSY_AGENTS_DIR`) y construye
**un agente por perfil de SO** (`windows`, `unix`) que comparten ese texto como base de
su system prompt. La carga es perezosa y cacheada POR IDIOMA: el perito puede cambiarlo
sin reiniciar nada. En cada corrida, Agentopsy añade el contexto del caso:

- La **evidencia anclada** (verificada por hash, montada solo lectura a nivel de bloque).
- El **triage** (`detected_os`, `detected_kind`) — determinado por el contenido, no por
  el host. `detected_kind` marca el SOPORTE y con él qué herramientas aplican:
  `disk` / `container_disk` (TSK), `memory` (Volatility3) y `document`, que es un
  fichero aportado (un PDF, una foto, un correo, un log, un artefacto suelto, una
  muestra) sobre el que no aplica ninguna de las dos y se lee el fichero en sí.
  Un `document` **nunca** enruta el perfil del caso: no es el sistema investigado.
- La **allowlist de herramientas**, que es el **catálogo filtrado por el `os_profile`**
  del caso (`agentopsy.toolkit.catalog`). El agente elige por id; Agentopsy resuelve el
  argv real desde el allowlist (SECURITY INVARIANT 5) y le inyecta el path de la
  evidencia (nunca lo pone el modelo).

El perfil de SO **no lo elige el cliente**: lo determina el triage por el contenido de
la evidencia y el orquestador enruta al agente de ese perfil. En `unknown` / baja
confianza / señales en conflicto, **el operador ancla** el perfil (RULE 2 — nunca un
default silencioso).

## Dónde escribe el agente

Todo lo que el agente concluye se persiste en las stores del caso, que escribe con sus
tools internas. **Dónde están esas stores depende de cómo se ejecute Agentopsy**, y
conviene no confundirlo: con el `docker compose` por defecto, la raíz de datos del
backend es `/cases` dentro del contenedor, montada desde `./projects` del host
(`AGENTOPSY_CASES_DIR`), así que un caso vive en `./projects/cases/<id>/` en el host y
en `/cases/cases/<id>/` dentro del contenedor. Solo cuando se arranca el backend de
forma nativa, sin compose y sin `AGENTOPSY_HOME`, la raíz es `~/.agentopsy/` y el caso
está en `~/.agentopsy/cases/<id>/`.

| Papel | En Agentopsy |
|---|---|
| `FICHA` / `REGISTRO-DECISIONES` | grafo de conocimiento del caso (`knowledge/<doc_id>.md`, append-only, legible) — `anotar_conocimiento` / `consultar_conocimiento` |
| Hallazgos con evidencia | `findings.jsonl` + audit encadenado — `record_finding`, con su procedencia COMPROBADA contra el registro (ver abajo) |
| `output/NN_tool/__raw` + `_run.md` | artefactos del caso (cada corrida guarda su salida entera + hash + el argv literal en el audit) — se releen con `leer_artefacto` |
| `entregables/` (informe) | subsistema de documentos (`documents/`) |

### La procedencia no se cree, se comprueba

`record_finding` no acepta un identificador por tener buena forma. Antes de persistir
nada, `agentopsy.findings.procedencia` comprueba contra el registro que la ejecución
citada exista, sea de este caso, haya leído esa evidencia y la haya ejecutado esa
herramienta; que el artefacto sea suyo y sus bytes conserven el hash que se registró; y
que el localizador y el extracto correspondan a lo que hay ahí. Los identificadores y los
hashes salen del registro, nunca de lo que el modelo recuerde.

Tres naturalezas, y la diferencia es el punto: `afirmacion` exige una fuente íntegra de una
ejecución que terminó bien; `limitacion` documenta lo que NO se pudo examinar y es la única
que puede citar una ejecución fallida; `descarte` dice que una vía no aportó. Las dos
últimas deben declarar `alcance_examinado`, porque «no se pudo analizar» y «no se encontró»
no son la misma frase.

Corregir un hallazgo no lo sobrescribe: añade una revisión y conserva la anterior, así que
un informe que citó una revisión sigue apuntando a lo que citó.
