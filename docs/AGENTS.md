# FORENSIA — Paquetes de agente entrenado

Este documento describe el **contrato** que FORENSIA exige al equipo que entrena
el agente forense, cómo el sidecar descubre los paquetes y cómo el desktop los
conecta. El catálogo de herramientas y los invariantes forenses están en otros
documentos; aquí sólo se trata el **agente**.

> Carpeta de entrega en repo: [`agentes/`](../agentes/README.md). Los samples
> `sample-unix/` y `sample-windows/` ahí dentro son la referencia ejecutable
> del contrato (se cargan tal cual al arrancar el sidecar en dev).

## 1. Una decisión, no dos agentes

Mantenemos **UN ForensicAgent** parametrizado por `os_profile`
(`unix` / `windows`). El loop de razonamiento es idéntico; lo que cambia por
perfil es el **paquete** cargado:

- los prompts (system / identity / playbook),
- el `model.backend` (local Ollama por defecto, cloud opt-in),
- la allowlist de herramientas (subset del catálogo),
- las políticas de redacción aplicadas antes de cloud.

Por eso la carpeta es declarativa: el entrenador no escribe Python. Sólo deja
ficheros legibles que el loader valida.

## 2. Layout del paquete

```
agentes/<id>/
├── agent.yaml          # manifiesto
├── prompts/
│   ├── system.md
│   ├── identity.md
│   └── playbook.md
├── policy/
│   ├── tools.yaml
│   └── redaction.yaml
└── evals/              # opcional, casos de prueba (formato pendiente)
```

El campo `id` del manifiesto debe coincidir con el nombre de la carpeta en
espíritu pero no es estricto: la identidad la decide el manifiesto. Lo que SÍ
es estricto:

- `id` único en `agentes/`.
- `os_profile` único en `agentes/` (RULE 2: si dos paquetes declaran el mismo
  perfil, la registry falla al arranque).
- Todos los `tool_id` de `policy/tools.yaml` deben existir en
  `backend/forensia/toolkit/catalog.py` **y** declarar el `os_profile` del
  paquete.

## 3. Esquema de `agent.yaml`

| Campo | Tipo | Validación |
|---|---|---|
| `id` | string | kebab-case `^[a-z0-9]+(?:-[a-z0-9]+)*$`, único |
| `name` | string | no vacío |
| `version` | string | semver |
| `os_profile` | enum | `unix` \| `windows` |
| `authors` | list[string] | opcional; el equipo humano, NO atribución a IA (CLAUDE.md RULE 0) |
| `model.backend` | enum | `local` \| `cloud` |
| `model.name` | string | id de Ollama (`llama3.1:8b`) o id cloud (`claude-opus-4-7`) |
| `model.temperature` | number | `[0.0, 2.0]` |
| `model.max_iterations` | int | `[1, 100]`. Tope del loop tool-use |
| `prompts.{system,identity,playbook}` | string | path RELATIVO al directorio del agente; no se permite `..` ni absolutos |
| `policy.tools` | string | path RELATIVO a un YAML con clave `allowed: [tool_id, …]` |
| `policy.redaction` | string | path RELATIVO a un YAML con clave `patterns: [{name, regex, replacement}]` |

Cualquier desviación falla **en seco** con un mensaje que apunta al fichero y
campo concretos (CLAUDE.md RULE 2 — sin fallbacks).

## 4. Cómo lo descubre FORENSIA

1. El proceso principal de Electron lanza el sidecar con
   `FORENSIA_AGENTS_DIR=<resourcesPath>/agentes` (packaged) o `<repo>/agentes`
   (dev).
2. Al importar `forensia.agent.registry`, `AgentRegistry` escanea ese directorio:
   - cada subdirectorio que NO empiece con `.` o `_` pasa por
     `forensia.agent.loader.load_package`,
   - los paquetes válidos se indexan por `id` y por `os_profile`,
   - paquetes inválidos (manifiesto roto, schema malo, allowlist con tools fuera
     del catálogo) se loguean como error y se IGNORAN — un paquete malo no debe
     impedir cargar los buenos —,
   - **dos paquetes válidos con el mismo `os_profile`** → `AgentRegistryError`
     fatal: el sidecar no arranca hasta que la operadora resuelva la ambigüedad.
3. `/api/capabilities` y `/api/agents` exponen el resultado al desktop. La UI
   muestra el agente activo en el header del chat y degrada explícitamente si
   no hay paquete para el perfil del caso.

## 5. Selección del agente en la UI

El chat usa el agente del `os_profile` activo. Por ahora:

- Sin caso seleccionado: usa el perfil que coincide con el host (mac/linux →
  `unix`; win32 → `windows`).
- Con caso seleccionado (cuando la UI lo conecte): usa el `os_profile` del caso.

Si no hay agente cargado para ese perfil, `/api/agent/query` responde 503 y el
chat muestra: *"No hay agente cargado para el perfil `unix`. Suelta su carpeta
dentro de `agentes/` y reinicia FORENSIA"*. **Nunca** se inventa un fallback.

## 6. Cómo lo entrega el equipo de entrenamiento

1. Empaqueta su carpeta `<id>/` con el layout de arriba.
2. La sube al repo bajo `agentes/<id>/`, o se entrega out-of-band y se copia
   antes del `electron-builder` (que ya bundlea `agentes/` vía
   `extraResources`).
3. Reinicia el desktop. El badge "Agente activo" en el chat lo confirma.

## 7. Estado actual del esqueleto

- **Loader + registry**: implementados, con tests en
  `backend/tests/test_agent_registry.py`.
- **`ForensicAgent`**: acepta `AgentPackage` y expone su allowlist; el loop de
  razonamiento sigue siendo `NotImplementedError` (ver CLAUDE.md "Status").
- **`/api/agent/query`**: devuelve un envelope estructurado *skeleton* que
  prueba la carga del paquete y lista las tools permitidas. El contrato
  (request/response) ya es el definitivo; cuando aterrice el loop real sólo
  cambia el cuerpo de la respuesta.
- **`/api/agents`**: lista paquetes cargados + raíz de `agentes/`.
- **Desktop**: ChatPage muestra el agente activo o el aviso de "sin agente".
- **`electron-builder`**: incluye `../agentes` en `extraResources` y
  `asarUnpack`.
