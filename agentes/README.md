# `agentes/` — Drop your trained agent here

Esta carpeta es el punto de entrega de los **paquetes de agente entrenado**. El equipo
que entrena el agente forense (system prompt, persona, playbook, allowlist de tools,
políticas de redacción) deja aquí su carpeta y FORENSIA la descubre al arrancar.

> Convención: una sola carpeta por agente. **Un único agente por `os_profile`**
> (`unix` / `windows`). Si la registry encuentra dos agentes declarando el mismo
> `os_profile`, falla en seco al arranque — coherente con CLAUDE.md RULE 2
> ("no fallbacks, no silent defaults").

---

## Contrato del paquete (declarativo)

```
agentes/<tu-agente>/
├── agent.yaml          # manifiesto: id, version, os_profile, model, paths
├── prompts/
│   ├── system.md       # rol y reglas globales del agente
│   ├── identity.md     # persona / "soul" / cómo se presenta
│   └── playbook.md     # heurísticas forenses (qué tool en qué momento)
├── policy/
│   ├── tools.yaml      # allowlist: subset del catálogo permitido a este agente
│   └── redaction.yaml  # patrones a redactar antes de mandar nada a un modelo cloud
└── evals/              # OPCIONAL — casos de prueba para el harness comparativo
    └── <case>.yaml
```

Nada de código Python del entrenador. Todo el loop de razonamiento lo ejecuta
`forensia.agent.ForensicAgent`, parametrizado con el paquete cargado (ver
[`docs/AGENTS.md`](../docs/AGENTS.md)).

---

## `agent.yaml` — manifiesto

```yaml
id: sample-unix              # kebab-case, único dentro de agentes/
name: "Sample Unix Analyst"  # nombre legible para la UI
version: "0.1.0"             # semver
os_profile: unix             # unix | windows  (UN agente por os_profile)
authors:                     # equipo de entrenamiento — NO atribución a IA
  - "FORENSIA Team"

model:
  backend: local             # local (Ollama, por defecto) | cloud (Anthropic / OpenAI)
  name: "llama3.1:8b"        # id concreto del modelo (Ollama tag o id cloud)
  temperature: 0.2
  max_iterations: 12         # tope de iteraciones del loop tool-use (safety)

prompts:                     # rutas RELATIVAS al directorio del agente
  system: prompts/system.md
  identity: prompts/identity.md
  playbook: prompts/playbook.md

policy:
  tools: policy/tools.yaml
  redaction: policy/redaction.yaml
```

Reglas de validación (las hace `forensia.agent.loader`):

- `id` único en `agentes/`; `os_profile` único en `agentes/`.
- `model.backend` ∈ {`local`, `cloud`}. `cloud` necesita config explícita por caso
  (consentimiento + redacción) — ver `docs/THREAT_MODEL.md` §C.
- `prompts.*` y `policy.*` deben existir como ficheros relativos al directorio del
  agente. Cualquier path absoluto o que se salga de la carpeta del agente es rechazado.
- `policy.tools` referencia sólo `tool_id`s presentes en
  `backend/forensia/toolkit/catalog.py` **y** compatibles con el `os_profile`
  declarado. Una herramienta ajena al catálogo o no aplicable al perfil hace fallar
  la carga.

---

## `policy/tools.yaml` — allowlist de herramientas

```yaml
# Subset del catálogo (forensia.toolkit.catalog) que ESTE agente puede invocar.
# El dispatcher rechaza cualquier tool_id fuera de esta lista, incluso si el modelo
# la emite. La defensa real vive en el dispatcher; este fichero es la intención.
allowed:
  - tsk_mmls
  - tsk_fls
  - tsk_mactime
  - ewf_info
  - bulk_extractor
  - yara
  - volatility3
  - jq
```

---

## `policy/redaction.yaml` — patrones redactados antes de cloud

```yaml
# Aplicados SOLO cuando el case usa un backend cloud. Con backend local los datos
# nunca salen del host y la redacción no se aplica.
patterns:
  - name: email
    regex: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    replacement: "<EMAIL>"
  - name: ipv4
    regex: '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    replacement: "<IPV4>"
```

---

## Cómo lo descubre FORENSIA

1. El sidecar arranca y `forensia.agent.registry.AgentRegistry` escanea esta carpeta.
2. Cada subdirectorio se intenta cargar con `forensia.agent.loader.load_package`.
3. Los paquetes válidos se indexan por `os_profile`. Dos paquetes con el mismo
   `os_profile` → error fatal (RULE 2).
4. `/api/capabilities` expone la lista cargada; `/api/agents` permite consultarla.
5. Al crear un caso con `os_profile=unix`, el chat usa el agente unix cargado.
   Si no hay agente para ese perfil, el endpoint `/api/agent/query` responde 503
   y la UI lo refleja explícitamente — sin "agente fallback".

## Cómo entrega el resultado el entrenador

1. Empaqueta su carpeta `<id>/` con el layout de arriba.
2. La copia a `agentes/<id>/` en el repo (o se le pasa a empaquetado vía
   `electron-builder extraResources`, que ya incluye `agentes/` por defecto).
3. Reinicia el desktop. El agente queda activo.
