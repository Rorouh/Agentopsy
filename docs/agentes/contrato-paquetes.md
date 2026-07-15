# FORENSIA — Paquetes de agente entrenado

Este documento describe el **contrato** que FORENSIA exige al equipo que entrena
el agente forense, cómo el backend (servicio `api`) descubre los paquetes y cómo
la UI web los conecta. El catálogo de herramientas y los invariantes forenses
están en otros documentos; aquí sólo se trata el **agente**.

> Carpeta de entrega en repo: [`agentes/`](../agentes/README.md). Los paquetes
> `forensia-unix/` y `forensia-windows/` ahí dentro son la referencia ejecutable
> del contrato (se cargan tal cual al arrancar el `api` en dev). Junto a ellos
> convive el pack de síntesis `_orchestrator/`, que NO es un agente: la registry
> lo ignora por su prefijo `_` (ver §5).

## 1. Una decisión, no dos agentes

Mantenemos **UN ForensicAgent** parametrizado por `os_profile`
(`unix` / `windows`). El loop de razonamiento es idéntico; lo que cambia por
perfil es el **paquete** cargado:

- los prompts (system / identity / playbook),
- los parámetros de generación (temperatura, tope de iteraciones del loop),
- la allowlist de herramientas (subset del catálogo),
- las políticas de redacción aplicadas antes de que una salida cruce a un
  ejecutor respaldado por cloud o al wire MCP.

El **ejecutor** (Claude Code / Codex CLI / Gemini CLI / Ollama) NO lo declara el
paquete: lo elige el operador en runtime, explícitamente y por caso (RULE 2 —
sin selección, error accionable; ver `arquitectura.md` §5).

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
| `model.backend` | — | **eliminado en v1.2**: el ejecutor lo selecciona el operador en runtime (RULE 2); el paquete no puede fijarlo |
| `model.name` | string | modelo recomendado para el ejecutor `ollama` (`llama3.1:8b`); los ejecutores CLI usan el modelo de la suscripción del usuario |
| `model.temperature` | number | `[0.0, 2.0]` |
| `model.max_iterations` | int | `[1, 100]`. Tope del loop tool-use |
| `prompts.{system,identity,playbook}` | string | path RELATIVO al directorio del agente; no se permite `..` ni absolutos |
| `policy.tools` | string | path RELATIVO a un YAML con clave `allowed: [tool_id, …]` |
| `policy.redaction` | string | path RELATIVO a un YAML con clave `patterns: [{name, regex, replacement}]` |

Cualquier desviación falla **en seco** con un mensaje que apunta al fichero y
campo concretos (CLAUDE.md RULE 2 — sin fallbacks).

## 4. Cómo lo descubre FORENSIA

1. El compose monta `agentes/` del repo en el servicio `api`
   (`FORENSIA_AGENTS_DIR` permite sobreescribir la ruta; en dev con venv,
   `python -m forensia.server` lee `<repo>/agentes`).
2. Al importar `forensia.agent.registry`, `AgentRegistry` escanea ese directorio:
   - cada subdirectorio que NO empiece con `.` o `_` pasa por
     `forensia.agent.loader.load_package`,
   - los paquetes válidos se indexan por `id` y por `os_profile`,
   - paquetes inválidos (manifiesto roto, schema malo, allowlist con tools fuera
     del catálogo) se loguean como error y se IGNORAN — un paquete malo no debe
     impedir cargar los buenos —,
   - **dos paquetes válidos con el mismo `os_profile`** → `AgentRegistryError`
     fatal: el `api` no arranca hasta que la operadora resuelva la ambigüedad.
3. `/api/capabilities` y `/api/agents` exponen el resultado a la UI web. La UI
   muestra el agente activo en el header del chat y degrada explícitamente si
   no hay paquete para el perfil del caso.

## 5. El pack `_orchestrator/` — síntesis (nivel 2)

Junto a los agentes de investigación vive `agentes/_orchestrator/`. **No es un
agente** y la registry lo **ignora a propósito**: su prefijo `_` hace que el
escaneo lo salte (igual que los ficheros ocultos — ver §4, punto 2, y
`backend/forensia/agent/registry.py`). No tiene `agent.yaml` ni declara
`os_profile`, así que nunca colisiona con la regla «un agente por perfil».

Es el paquete declarativo del **orquestador**: prompts y conocimiento con los que
la capa de síntesis (`forensia.reports`, aún sin implementar) convierte los
`Finding[]` ya trazados por los agentes de nivel 1 en los tres entregables de la
propuesta:

1. **Informe pericial** (`reporter.md`) → `ReportDocument`.
2. **Línea temporal** (`timeline.md`) → `TimelineEvent[]`.
3. **Correlación MITRE ATT&CK** (`mitre.md` + `knowledge/`) → `MitreTechniqueMatch[]`.

Es agnóstico del SO: trabaja sobre hallazgos estructurados (con su cadena de
custodia), no sobre la imagen cruda; por eso no encaja en el enum
`os_profile ∈ {unix, windows}`. Detalle en
[`agentes/_orchestrator/README.md`](../agentes/_orchestrator/README.md).

### 5.bis `mitre_hints`: qué mitad del contrato MITRE está cerrada (2026-07-14)

El esquema de hallazgo de los prompts (`agentes/*/prompts/system.md`, «Esquema de
hallazgo») lleva tiempo prescribiendo `mitre_hints`, pero el motor **no lo
implementaba**: `record_finding` cerraba con `additionalProperties: false`, así
que el modelo no podía emitirlo aunque el prompt se lo pidiera, y el campo se
perdía. Eso queda cerrado:

- **`record_finding` acepta `mitre_hints: string[]`** y `Finding` lo persiste.
- **Enum cerrada, validada en el servidor** (`forensia.mitre.catalog`): la lista
  de ids permitidos se **parsea de `_orchestrator/knowledge/mitre_attack_seed.md`**,
  que es la enum que `mitre.md` (regla 1) autoriza. No hay una segunda lista
  transcrita en Python: duplicarla crearía un validador que acepta ids que el
  agente tiene prohibido emitir. Un id fuera de la semilla **rechaza el hallazgo
  entero** (SECURITY INVARIANT 5).
- **Ampliar la cobertura del AGENTE = ampliar la semilla.** La semilla sigue
  siendo la enum cerrada que el agente puede proponer.
- **La matriz pinta el catálogo Enterprise COMPLETO** (2026-07-15,
  `forensia/mitre/enterprise.json`, ~240 técnicas padre, enviado con la imagen).
  Es un eje distinto de la semilla: el **perito** dictamina contra Enterprise
  (`enterprise_is_known`), así que puede anclar un veredicto en cualquier técnica
  real de ATT&CK; el **agente** sigue limitado a la semilla. Los `mitre_hints` de
  la semilla se pintan en su celda Enterprise (la técnica padre si son
  sub-técnicas, vía `enterprise_display_id`), y el «Se sostiene con» de la semilla
  se fusiona en la técnica Enterprise homónima.
- **Correlación bajo demanda (2026-07-15):** además de los hints al registrar, el
  agente puede ANCLAR técnicas a un hallazgo YA registrado con la tool
  `annotate_mitre(finding_id, mitre_hints, note?)`. Así, cuando el perito pide «dame
  la correlación MITRE», el agente **persiste** el mapeo (no solo lo narra) y el
  tablero se puebla; también permite completar hints de hallazgos antiguos. Se
  guarda en `mitre_proposals.jsonl` (append-only, gana la última por hallazgo; lista
  vacía retira) y se audita (`mitre_proposed`). `CoverageStore.proposals` fusiona
  estas anotaciones con los `mitre_hints` del propio hallazgo — **mismo eje** de
  propuesta del agente, nunca dictamen. Los ids siguen validados contra la semilla:
  una técnica que el agente cite pero que no esté en la semilla (p. ej. `T1056.001`,
  `T1133`) se rechaza — para pintarla hay que ampliar la semilla.

Sigue **sin implementarse** la capa de síntesis del orquestador
(`forensia.reports` está vacío): el `MitreTechniqueMatch[]` con `confidence` y
`relatedFindingIds` que describe `mitre.md` **no lo produce nadie todavía**. Lo
que la UI pinta hoy son los `mitre_hints` crudos de los hallazgos (propuesta con
procedencia), no correlaciones sintetizadas. Son cosas distintas y la UI las
distingue: ver §5.ter.

Del esquema de hallazgo siguen huérfanos en el motor `confidence`, `provenance` y
`observed_at` — mismo tipo de deuda, aún abierta.

### 5.ter Propuesta del agente ≠ dictamen del perito

Dos ejes, nunca fundidos (`forensia.mitre.coverage`):

| | Quién | Dónde vive | Qué significa |
|---|---|---|---|
| `proposed_by` | el **agente** | derivado de los `mitre_hints` de hallazgos reales; se recalcula, no se persiste | «este hallazgo sostiene esta técnica». Sugerencia con procedencia. |
| `status` | el **perito** | `mitre_adjudications.jsonl` (append-only) + audit log | `confirmada` / `sospechosa` / `descartada`. **Veredicto**, y exige `rationale`. |

Es el patrón ya sancionado para `os_profile` (la máquina sugiere, el operador
ancla — RULE 2). Fundirlos rompería el sistema en las dos direcciones: o la
sugerencia del agente se disfraza de dictamen pericial, o la siguiente pasada del
agente pisa el dictamen del perito.

Emitir un dictamen es un **acto pericial** que acaba en un informe con firma, así
que entra en el log hash-encadenado (acción `mitre_adjudicated`, FORENSIC
INVARIANT 4) y **no se acepta sin motivo**. En la matriz, una celda sin color
significa **no evaluada**, nunca «ausente».

## 6. Selección del agente en la UI

El chat usa el agente del `os_profile` **del caso**, y ese perfil **se
determina del contenido de la evidencia**, no lo elige el operador al crear el
caso:

- El `os_profile` del caso es **nullable** y arranca `None`. Al registrar una
  evidencia, `forensia.triage` la fingerprint sobre la copia read-only ya
  hash-verificada y, **cuando la determinación es confiable**
  (`family ∈ {unix, windows}` **y** `confidence ∈ {header, markers}`), el
  backend fija el perfil derivado (`os_profile_source = "derived"`) y el
  orquestador enruta al sub-agente que coincide, automáticamente. El perfil
  **nunca se infiere del host** — sólo del contenido de la evidencia (RULE 2).
- El caso registra además `os_profile_source ∈ {derived, operator, conflict}`,
  y la decisión de enrutado (`family`, `confidence`, `signals`) queda en el
  audit log append-only (FORENSIC INVARIANT 4).
- Sin caso seleccionado no hay perfil activo: la UI exige crear o seleccionar
  un caso antes de consultar al agente.

Si no hay agente cargado para ese perfil, `/api/agent/query` responde 503 y el
chat muestra: *"No hay agente cargado para el perfil `unix`. Suelta su carpeta
dentro de `agentes/` y reinicia el servicio `api`"*. **Nunca** se inventa un
fallback.

### 6.1 Determinación del perfil + escalada al operador

El `os_profile` no se adivina: se **determina** por triage o, en su defecto,
lo **ancla el operador**. Las defensas que lo materializan:

1. **Triage backend (`forensia.triage`).** En `EvidenceManager.register()` se
   computa un `DetectedEvidence(family, kind, confidence, signals)` por escaneo
   determinista (Python puro sobre bytes, nunca ejecuta el contenido) sobre la
   copia read-only ya hash-verificada:
   - **family** ∈ {`unix`, `windows`, `unknown`} por marcadores byte-string
     (`Microsoft Windows`, `Linux version`, `/etc/passwd`, `Mach-O`…).
   - **kind** ∈ {`disk`, `memory`, `container_disk`, `unknown`} por cabeceras
     de fixed-offset (LiME, Windows crash dump, EWF, AFF, VMDK, VDI, QCOW,
     VHD/VHDX), MBR/GPT/NTFS/ext, y scoring PE-scatter + RSDS + page-0-zero
     para detectar volcados RAM Volatility-style sin cabecera.
   - **confidence** ∈ {`header`, `markers`, `extension`, `none`} según la
     fuerza de la señal. `triage.routable_profile()` es la única fuente de
     verdad de «¿se puede enrutar solo?»: sólo `family` confiada
     (`header`/`markers`) enruta.
   Los campos se persisten (con `triage_signals` audit-trail). Lazy backfill
   en `get()` para evidencia anterior al módulo.

2. **Auto-set del caso o escalada** (`CaseManager.apply_detected_evidence`,
   llamada tras el triage al registrar). Transiciones monótonas:
   - Caso sin perfil + 1ª evidencia enrutable → **auto-set** derivado
     (`os_profile_source = "derived"`) + audit `os_profile_routed`
     (`decision = auto_set`).
   - 2ª evidencia con `family` confiada **distinta** → **conflicto**: el perfil
     derivado se **limpia** a `None` (`os_profile_source = "conflict"`), audit
     `decision = conflict`. Ya en conflicto, más evidencia **no** re-resuelve
     en silencio.
   - Evidencia **no** enrutable (`unknown` / baja confianza) → **no-op**: el
     perfil queda sin determinar.

3. **Escalada: el operador ancla** (`POST /api/cases/{id}/os-profile` →
   `CaseManager.anchor_os_profile`). En `unknown` / baja confianza / conflicto
   / sin evidencia enrutable, `resolve_os_profile(case)` **falla en seco**
   (`OsProfileUnresolved` → HTTP 409) con mensaje accionable; el chat no
   enruta. El anclaje del operador (`os_profile_source = "operator"`, audit
   `os_profile_anchored`) es **la única** salida del estado ambiguo/conflicto
   y es **final**: evidencia posterior nunca lo tumba. Anclar en la creación
   del caso (`os_profile` explícito) cuenta también como anclaje del operador.

4. **Routing por `kind` en el system prompt.** El `_system_prompt` del
   `ForensicAgent` añade un bloque «Ruta del playbook» según `detected_kind`:
   `memory` → salta a la sección B (Volatility); `disk`/`container_disk` →
   sección A (TSK). Sin esto, el agente arranca siempre por la sección A del
   playbook y desperdicia iteraciones en `tsk_mmls`/`tsk_fls` cuando la
   evidencia es un memdump.

Multi-SO simultáneo (lanzar ambos sub-agentes en un mismo caso, resolviendo el
perfil por-evidencia en el punto de análisis) queda **fuera de alcance del
MVP** — Fase 2b. Hoy, mezcla de SOs = conflicto = escala.

### 6.2 Memoria conversacional del agente

Cada `/api/agent/query` recibe `session_id` (default `"main"`). El backend lee
`ChatStore` y construye prefix de OpenAI messages que se splicea entre system
y el user prompt entrante:

1. **Ledger de tool runs** — del campo `tool_calls` que el frontend persiste
   en cada `assistant` ChatMessage tras una respuesta. Una línea por
   invocación previa con `tool_id + exit_code + run_id[:8]`. Le dice al
   modelo qué YA ejecutó para que no repita el mismo `{tool_id, params}`.
2. **Ledger de findings** — los hallazgos estructurados que el propio agente
   registró con `record_finding` en turnos anteriores. Le dice qué ya
   concluyó para que construya encima en vez de re-deducir.
3. **Transcript user/assistant** — los turnos previos en texto. Le da
   referencia anafórica para mensajes tipo "hazlo".

Caps: 6 turnos / 8K chars de transcript / 30 entradas de ledger / 10
findings. Sin LLM-based summarization en v1. Detalle en
`backend/forensia/agent/history.py`.

Source of truth = `ChatStore` (servidor), no la memoria del renderer — RULE 2:
no confíes en input no verificado. El frontend solo envía `session_id`.

### 6.3 El agente ya no es el único cliente del dispatcher

Desde la rama `mcp`, el `dispatcher` tiene **dos clientes posibles**:

1. **El `ForensicAgent` propio** (vía `/api/agent/query` del servicio `api`) —
   llamado por la UI web. Camino que esta sección describe.
2. **Cualquier cliente MCP externo** (Claude Desktop, Continue, Cline,
   agente custom) vía el servidor `mcp-toolkit` (`python -m forensia.mcp`).

Ambos comparten el mismo dispatcher, el mismo `EvidenceManager`, el mismo
`ArtifactStore` y el mismo `AuditLog`. El servidor MCP **no reimplementa
nada** — delega en `dispatcher.execute(tool_id, params, case_id)`. La
allowlist del paquete activo se enforce en dos puntos (MCP `tools/list`
filtrado + dispatcher contra catálogo).

Esto es el "MCP como núcleo" que pidió el PI (email 2026-06-24): un
agente arbitrario puede operar el maletín FORENSIA hablando el protocolo
estándar, sin código FORENSIA propio. Detalle en
[`mcp-toolkit-s1.md`](../maletin/mcp-toolkit-s1.md) y
[`inventario-mcps.md`](../maletin/inventario-mcps.md). En sprint S2 el propio
`ForensicAgent` también pasará a ser cliente MCP in-process del mismo
servidor, unificando ambos caminos.

## 7. Cómo lo entrega el equipo de entrenamiento

1. Empaqueta su carpeta `<id>/` con el layout de arriba.
2. La sube al repo bajo `agentes/<id>/`, o se entrega out-of-band y se copia en
   `agentes/` — el compose la monta tal cual en el servicio `api`.
3. Reinicia el backend (`docker compose restart api`). El badge "Agente activo"
   en el chat lo confirma.

## 8. Estado actual del esqueleto

- **Loader + registry**: implementados, con tests en
  `backend/tests/test_agent_registry.py`.
- **`ForensicAgent`**: acepta `AgentPackage` y expone su allowlist; el loop de
  razonamiento sigue siendo `NotImplementedError` (ver CLAUDE.md "Status").
- **`/api/agent/query`**: ejecuta el loop real con el ejecutor que el operador
  seleccionó en la petición (`executor: claude-code | codex | gemini | ollama`,
  o `DEFAULT_EXECUTOR` fijado explícitamente en Settings). Sin caso, evidencia
  o ejecutor seleccionados → 4xx accionable; ejecutor inutilizable → 503 con la
  dependencia que falta (RULE 2).
- **`/api/agents`**: lista paquetes cargados + raíz de `agentes/`.
- **UI**: ChatPage muestra el agente activo o el aviso de "sin agente".
- **Compose**: el compose raíz monta `./agentes` read-only en el servicio `api`
  (`/opt/forensia/agentes`, vía `FORENSIA_AGENTS_DIR`) — hecho el 2026-07-02.
