# FORENSIA — Fase 2: Diseño de la capa de agentes

**Orquestador + sub-agentes (Windows / Unix-like)**

> Documento de arquitectura del *slice* de IA (Fase 2 de la propuesta TFM). Es la
> **fuente de verdad** del diseño de los agentes y el contrato que el equipo de
> entrenamiento (este rol) entrega y que el equipo de motor implementa. Se apoya
> en lo ya construido en la rama `tools` y respeta sin excepción los invariantes
> de `CLAUDE.md`, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md` y
> `docs/FORENSIC_SOUNDNESS.md`.

---

## 0. TL;DR

1. La rama `tools` ya trae el **esqueleto** de la capa de agentes: paquete
   declarativo (`agentes/<id>/`), `loader` + `registry` validados con tests,
   `ForensicAgent` (con el loop en `NotImplementedError`), el contrato
   `/api/agent/query`, el catálogo de herramientas con `dispatcher` *shell-free*
   anclado a caso (audit + artifacts), y la capa de modelos `local|cloud`.
2. El repo **colapsó deliberadamente** "orquestador + 2 sub-agentes" en **UN
   `ForensicAgent` parametrizado por `os_profile`**. No hay dos agentes paralelos
   en código; lo que cambia por perfil es una **carpeta declarativa**.
3. Este documento **reconcilia** la propuesta con el repo mediante un **modelo de
   dos niveles**: (a) **sub-agentes de investigación** = dos paquetes declarativos
   `forensia-windows` / `forensia-unix`; (b) **orquestador** = capa de
   coordinación + síntesis (routing por evidencia, agregación de hallazgos,
   informe, timeline, correlación MITRE) que vive en `forensia.reports` y se
   *entrena* con su propio paquete de prompts.
4. Mi entregable como rol de "creación, desarrollo y entrenamiento" es
   **declarativo**: prompts, playbooks, allowlists, políticas de redacción, base
   de conocimiento (RAG) y casos de evaluación. **No** reescribo el loop en
   Python; sí **especifico** su contrato para que motor y entrenamiento encajen.
5. **MCP**: el `dispatcher` nativo ya cumple las garantías de seguridad (enum
   cerrada + params tipados + allowlist + sin shell). Se propone exponerlo como
   un **servidor MCP interno** para que el loop hable un protocolo *agnóstico de
   proveedor*, sin perder ninguna garantía forense.

---

## 1. Qué existe ya (rama `tools`) y qué falta

| Pieza | Estado | Fichero |
|---|---|---|
| Paquete declarativo de agente | **Hecho** (schema + validación + tests) | `agentes/README.md`, `backend/forensia/agent/{package,loader,registry}.py` |
| Paquetes de agente reales (investigación) | **Hechos** (`forensia-unix`, `forensia-windows`) | `agentes/forensia-unix/`, `agentes/forensia-windows/` |
| `ForensicAgent` (constructor + `available_tools`) | **Hecho**; `run()` → `NotImplementedError` | `backend/forensia/agent/agent.py` |
| Contrato HTTP del chat | **Hecho** (envelope *skeleton*; request/response definitivos) | `backend/forensia/routers/agent.py` |
| Catálogo + dispatcher de herramientas | **Hecho** (13 wrappers, *shell-free*, anclado a caso) | `backend/forensia/toolkit/*` |
| Capa de modelos `local|cloud` | **Interfaz hecha**; backends reales pendientes | `backend/forensia/models/*` |
| Almacenamiento caso-como-carpeta (evidence/artifacts/chats/audit) | **Hecho** | `docs/STORAGE.md`, `backend/forensia/{cases,artifacts,chats,audit,evidence}` |
| **Loop de razonamiento** | **Pendiente** | `ForensicAgent.run()` |
| **Orquestador / síntesis** (informe, timeline, MITRE) | **Pendiente** (layout reservado) | `forensia.reports` (no existe aún) |
| **RAG** | **Stub de interfaz**; catálogo en el system prompt | — |
| **Backends de modelo reales** (Ollama / cloud) | **Pendiente** | `models/local.py`, `models/cloud.py` |
| **Pack de síntesis `_orchestrator/`** (prompts) | **Hecho** (v1) ← *mi entregable* | `agentes/_orchestrator/` |
| **Harness de evals cloud-vs-local** | **Pendiente** (formato sin cerrar) | `agentes/*/evals/` |

**Conclusión:** no construyo desde cero. Relleno tres huecos coordinados: los
**paquetes reales** (entrenamiento), la **especificación del loop y del
orquestador** (para el motor), y el **plan de evaluación** (la contribución
científica del TFM: comparativa local vs cloud).

---

## 2. La decisión clave: mapear la propuesta sobre el repo

La propuesta describe **un orquestador y dos sub-agentes**. La arquitectura
bloqueada del repo dice **un agente parametrizado por `os_profile`, sin
orquestador agente**. No es una contradicción si se separan dos
responsabilidades que la propuesta mete en el mismo saco:

- **Investigar** una evidencia con el maletín (depende del SO → sub-agentes).
- **Sintetizar** el caso completo en informe + timeline + MITRE (no depende del
  SO; depende de los *hallazgos* ya recopilados → orquestador).

### 2.1 Modelo de dos niveles (propuesto)

```
                    ┌─────────────────────────────────────────────┐
   Investigador ───▶│  NIVEL 1 — INVESTIGACIÓN (los sub-agentes)   │
   (chat / prompt)  │  ForensicAgent(os_profile) + paquete decl.   │
                    │  · forensia-windows  (os_profile: windows)   │
                    │  · forensia-unix     (os_profile: unix)      │
                    │  Loop tool-use → dispatcher → maletín         │
                    │  Salida: FINDINGS estructurados + artifacts   │
                    └───────────────┬─────────────────────────────┘
                                    │  hallazgos con procedencia
                                    │  (tool_id, params, artifact_id, run_id, hash)
                    ┌───────────────▼─────────────────────────────┐
   [proceed-to-     │  NIVEL 2 — ORQUESTACIÓN / SÍNTESIS           │
    report]    ────▶│  forensia.reports + paquete "orchestrator"   │
                    │  · routing por evidencia (multi-OS)          │
                    │  · agrega y deduplica hallazgos              │
                    │  · redacta el INFORME (narrativa pericial)   │
                    │  · construye la TIMELINE normalizada         │
                    │  · correlaciona con MITRE ATT&CK             │
                    │  Salida: ReportDocument + TimelineEvent[] +  │
                    │          MitreTechniqueMatch[]               │
                    └─────────────────────────────────────────────┘
```

### 2.2 Tabla de equivalencia propuesta ↔ repo

| En la propuesta (Enrique) | En esta arquitectura | Realización en el repo |
|---|---|---|
| "Sub-agente Windows" | Sub-agente de investigación, perfil `windows` | `agentes/forensia-windows/` (paquete declarativo) |
| "Sub-agente Unix-like" | Sub-agente de investigación, perfil `unix` | `agentes/forensia-unix/` |
| "Llamar al sub-agente correspondiente para cada tarea" | Routing por `os_profile` **de la evidencia** | `agent_registry.get_for_profile()` + selector de evidencia |
| "Recopilar y organizar la información que extraigan" | Agregación de `Finding[]` con procedencia | `ArtifactStore` + nuevo `FindingStore` (ver §7) |
| "Redactar el informe" | Síntesis narrativa | `forensia.reports.report` + prompts del orquestador |
| "Crear la timeline" | Normalización de eventos | `forensia.reports.timeline` |
| "Correlacionar con MITRE ATT&CK" | Correlación táctica/técnica + APTs | `forensia.reports.mitre` + KB MITRE (RAG) |

**Por qué esta forma y no un orquestador-LLM que enruta en caliente:** un agente
LLM extra que "decide a qué sub-agente llamar" reintroduciría no-determinismo y
coste de tokens en una decisión que es **determinista** (la evidencia ya declara
su `os_profile`, ver `EvidenceFile.osProfile` en `domain.ts`). El routing debe
ser código, no inferencia (coherente con `CLAUDE.md` RULE 2: sin defaults
silenciosos). El LLM se reserva para lo que sí requiere juicio: investigar y
redactar.

> **Decisión abierta para Enrique (D-1):** si prefieres conservar literalmente un
> *orquestador conversacional* (el investigador habla con el orquestador y este
> delega), se puede — pero recomiendo el modelo de dos niveles por
> trazabilidad y ahorro de tokens. Ver §12.

---

## 3. Nivel 1 — Sub-agentes de investigación

### 3.1 Qué son

Un **único** `ForensicAgent` (clase Python, ya existe) parametrizado por un
`AgentPackage` (carpeta declarativa). Hay **un paquete por `os_profile`**; dos
paquetes con el mismo perfil hacen fallar el arranque del sidecar (RULE 2). Los
dos sub-agentes de la propuesta son, por tanto:

```
agentes/
├── forensia-windows/     # os_profile: windows   (reemplaza sample-windows)
└── forensia-unix/        # os_profile: unix       (reemplaza sample-unix)
```

Cada uno entrega exactamente el contrato ya validado por `loader.py`:

```
agentes/<id>/
├── agent.yaml            # id, name, version, os_profile, model, prompts, policy
├── prompts/
│   ├── system.md         # reglas globales (solo lectura, no-comando, citar fuente…)
│   ├── identity.md       # persona / cómo se presenta
│   └── playbook.md       # heurística forense por tipo de evidencia
├── policy/
│   ├── tools.yaml        # allowlist = subset del catálogo para ese os_profile
│   └── redaction.yaml    # patrones a redactar antes de cloud
└── evals/                # casos de prueba para el harness comparativo
```

### 3.2 Reparto del maletín por perfil

La allowlist de cada sub-agente es un **subset cerrado** del catálogo
(`backend/forensia/toolkit/catalog.py`) cuyos `tool_id` declaran ese `os_profile`.
Reparto propuesto (sobre las 13 herramientas *core* ya implementadas, ampliable):

| Dominio | `unix` | `windows` | Notas |
|---|---|---|---|
| Particiones / imagen | `tsk_mmls`, `ewf_info` | `tsk_mmls`, `ewf_info` | TSK no monta FS (soundness §1) |
| Sistema de ficheros | `tsk_fls`, `tsk_mactime` | `tsk_fls`, `tsk_mactime`, `mftecmd` | `$MFT` solo Windows |
| Registro Windows | — | `regripper` | entrega *container* (Perl) |
| Eventos Windows | — | `evtxecmd`, `hayabusa`, `chainsaw` | EVTX + reglas Sigma |
| Memoria RAM | `volatility3` | `volatility3` | perfil distinto por SO |
| Carving / IOCs | `bulk_extractor`, `yara` | `bulk_extractor`, `yara` | |
| Helpers 2º nivel | `jq` | `jq` | filtra artifacts antes del LLM |

> Unix-like incluye Linux y macOS; en una fase posterior se añaden parsers
> nativos Unix del inventario largo (`ausearch`, `journalctl`, `utmpdump`, `uac`,
> `lynis`, `chkrootkit`) conforme se vendoricen — ver `docs/TOOLS_INVENTORY.md`.

### 3.3 Contrato de SALIDA del sub-agente (lo que la propuesta llama "estructurar la información para que el orquestador tenga visibilidad")

Hoy `ForensicAgent.run()` devuelve un `dict` sin forma fija. Se **fija** que,
además de la respuesta en Markdown para el chat, cada sub-agente emita **findings
estructurados con procedencia completa** (cadena de custodia), que el orquestador
consume. Esquema canónico (ver §7 para el resto de contratos):

```jsonc
// Finding — emitido por el sub-agente, persistido por caso
{
  "id": "fnd-7a3f…",
  "evidence_id": "ev-001",
  "os_profile": "windows",
  "title": "Persistencia vía Run key apuntando a binario no firmado",
  "summary": "HKCU\\…\\Run → %APPDATA%\\svchost.exe (no firmado).",
  "severity": "high",            // low | medium | high | critical
  "confidence": 0.82,            // 0–1, calibrado (ver §9.4)
  "provenance": {                // CADENA DE CUSTODIA — innegociable
    "tool_id": "regripper",
    "params": { "hive": "NTUSER.DAT", "plugin": "run" },
    "run_id": "run-91c2…",       // ArtifactStore
    "artifact_id": "art-55de…",
    "artifact_sha256": "4a44dc1536…",
    "audit_seq": 42              // entrada del audit.jsonl encadenado
  },
  "mitre_hints": ["T1547.001"],  // pista opcional; el orquestador decide
  "observed_at": "2026-06-14T04:15:00Z"  // timestamp del artefacto, no de la ejecución
}
```

Invariante: **ningún finding sin `provenance` resoluble**. Un hallazgo que no
apunta a un `artifact_id` con su `sha256` y su entrada de audit **no es
admisible** (coherente con `FORENSIC_SOUNDNESS.md` §3). El system prompt lo
exige y un validador del motor lo verifica antes de persistir.

---

## 4. Nivel 2 — El orquestador (coordinación + síntesis)

### 4.1 Responsabilidades

El orquestador **no ejecuta herramientas forenses sobre la imagen**: trabaja
sobre los `Finding[]` y los `artifacts` ya producidos. Sus cuatro funciones
(las de la propuesta) son:

1. **Routing y recopilación.** Por cada evidencia del caso, despacha la
   investigación al sub-agente de su `os_profile` y recoge sus findings. Un caso
   con un disco Windows **y** un volcado Linux usa **ambos** sub-agentes — algo
   que el modelo "un agente por caso" no cubría y este sí.
2. **Informe (`[proceed-to-report]`).** Redacta la narrativa pericial a partir de
   los findings, citando procedencia. Produce un `ReportDocument` (draft→final).
3. **Timeline.** Normaliza `observed_at` + fuente + severidad de todos los
   findings/artefactos a `TimelineEvent[]` ordenados.
4. **MITRE ATT&CK.** Correlaciona findings con tácticas/técnicas y sugiere
   grupos/APTs, con confianza y `relatedFindingIds` → `MitreTechniqueMatch[]`.

`[back-to-analysis]` simplemente reabre el nivel 1 sin descartar los findings.

### 4.2 Dónde vive y cómo se "entrena"

- **Código** (motor): nuevo módulo `forensia.reports` con submódulos `report`,
  `timeline`, `mitre` y un `FindingStore`. Layout ya reservado en
  `~/.forensia/cases/<id>/reports/` (`STORAGE.md`).
- **Inteligencia** (entrenamiento, mi rol): el orquestador es *tool-light* pero
  *prompt-heavy* (redacta y correlaciona). Sus prompts y su KB MITRE son
  **assets declarativos** que yo entrego. Para no romper el invariante "un
  paquete por `os_profile`", se entrega como paquete **ignorado por la registry
  de sub-agentes** usando el prefijo que la registry ya salta (`_`):

```
agentes/
├── forensia-windows/
├── forensia-unix/
└── _orchestrator/            # la registry IGNORA dirs que empiezan por "_"/"."
    ├── reporter.md           # estilo y estructura del informe pericial
    ├── timeline.md           # reglas de normalización temporal
    ├── mitre.md              # cómo razonar la correlación (no alucinar técnicas)
    └── knowledge/            # KB para RAG (MITRE ATT&CK, ver §9.3)
```

> **Decisión abierta D-2:** alternativa más explícita = extender el schema del
> paquete con `role: investigation | synthesis` y permitir `os_profile: any`
> para síntesis. Es más limpio conceptualmente pero toca `loader.py`/`registry.py`
> y sus tests. Recomiendo arrancar con `_orchestrator/` (cero cambios de motor) y
> migrar a `role:` si el orquestador crece. Ver §12.

### 4.3 Correlación MITRE — anti-alucinación

El riesgo de que un LLM "invente" técnicas MITRE es alto. Defensa:

- La KB MITRE (técnicas, tácticas, grupos) se entrega como **corpus recuperable**
  (RAG), no se confía a la memoria del modelo.
- El orquestador **solo** puede emitir `technique_id` que existan en la KB; un id
  fuera de catálogo se rechaza (mismo patrón "enum cerrada" que las tools).
- Cada `MitreTechniqueMatch` **debe** citar `relatedFindingIds` no vacío. Sin
  finding que la sostenga, la técnica no se emite — se marca como hipótesis
  descartada (`status: "dismissed"`), nunca como correlación.

---

## 5. Modelo de ejecución del loop (especificación para `ForensicAgent.run`)

Aunque el loop lo implementa el equipo de motor, su contrato condiciona los
prompts, así que se fija aquí. Es un **ReAct acotado**, *provider-agnostic* vía
`ModelBackend.next_action`:

```
run(prompt, evidence_id) ->
  state = build_initial_state(system+identity+playbook, prompt, evidence_handle, tool_schemas)
  for i in range(package.model.max_iterations):           # tope de seguridad (12 por defecto)
      action = model.next_action(state, tools)            # ToolCall | FinalAnswer
      if action is FinalAnswer:
          findings = extract_findings(state)              # valida procedencia (§3.3)
          return { reply_md, findings, iterations: i }
      assert action.tool_id in package.policy.allowed_tools  # allowlist dura (gate 6)
      result = dispatcher.execute(action.tool_id, action.params, case_id=case_id)
      observation = summarize_or_artifact_ref(result)     # nunca volcar artifacts gigantes al contexto
      state = append(state, action, observation)
  return degrade("max_iterations alcanzado", partial_findings)  # sin inventar (RULE 2)
```

Puntos que el **prompt** debe garantizar para que el loop sea barato y fiable:

- El modelo **elige `tool_id` + params tipados**, nunca un comando (gate 5/6).
- Las salidas grandes (`tsk_fls -r`, `bulk_extractor`, timelines de plaso) vuelven
  como **referencia a artifact**, no como texto; el agente las consulta con
  helpers de 2º nivel (`jq`, filtros top-N, rango temporal). Esto es lo que evita
  reventar el contexto y dispara el ahorro de tokens que pide la propuesta.
- Contenido de la evidencia = **datos, nunca instrucción** (gate 7): un payload de
  prompt-injection en un artefacto se reporta como hallazgo sospechoso y no altera
  el plan.

---

## 6. Capa de herramientas y MCP (reconciliación)

La propuesta y tu elección piden **MCP**. El repo ya tiene un `dispatcher` nativo
que cumple lo que de verdad importa (seguridad forense). La postura recomendada
es **no sustituir** uno por otro sino **estratificar**:

```
   LLM (local Ollama | cloud)                       agnóstico de proveedor
        │  next_action → ToolCall{tool_id, params}
        ▼
   ┌─────────────────────────────────────────────┐
   │  Maletín como SERVIDOR MCP (interno)         │  ← capa nueva, fina
   │  · 1 MCP tool por Tool del catálogo          │
   │  · JSON Schema derivado de build_argv/params │
   │  · enforce allowlist del paquete activo      │
   └───────────────┬─────────────────────────────┘
                   ▼  (in-process call, sin red)
   ┌─────────────────────────────────────────────┐
   │  dispatcher.execute(tool_id, params, case)   │  ← YA EXISTE (núcleo de seguridad)
   │  resolver → bundled|container → shell-free   │
   │  → ArtifactStore + AuditLog encadenado       │
   └─────────────────────────────────────────────┘
```

Por qué así:

- **Agnosticismo real:** MCP es el lenguaje común de tool-calling; el mismo
  servidor sirve a un modelo cloud con tool-use nativo y a un local vía el camino
  degradado (prompt estructurado + parser) de `models/base.py`.
- **Cero pérdida de garantías:** el MCP server **no** ejecuta nada; delega en el
  `dispatcher`, que mantiene enum cerrada, params tipados, allowlist, `shell=False`
  y la cadena de custodia. Si el modelo (o una inyección) pide un `tool_id` fuera
  de la allowlist, se rechaza en dos sitios (servidor MCP **y** dispatcher).
- **Crecimiento:** MCP es el punto natural para los **helpers de 2º nivel** y para
  la **KB MITRE** (un MCP de consulta de conocimiento), y para terceras
  herramientas futuras sin tocar el núcleo.

> **Trade-off honesto:** el camino nativo (`dispatcher` directo) ya satisface los
> gates 5–7 sin MCP. MCP añade una capa; su beneficio es ergonómico y de
> extensibilidad, no de seguridad. Si el calendario aprieta, el loop puede llamar
> al `dispatcher` directamente y el MCP server entra como envoltura después, sin
> reescribir prompts (el contrato `{tool_id, params}` es idéntico).
>
> **Decisión abierta D-3:** ¿MCP desde el día 1 o como capa 2? Recomiendo
> diseñar los schemas MCP ya (los necesito para documentar las tools a los
> agentes) e implementarlos en cuanto el loop nativo esté verde.

---

## 7. Contratos de datos (alineados con la UI y el almacenamiento)

La UI ya define los tipos que debe rendir (`desktop/renderer/src/types/domain.ts`).
La capa de agentes **produce** estos contratos; no se inventan formatos nuevos
de cara al front. Mapeo:

| Salida de la capa de agentes | Tipo UI (`domain.ts`) | Sección de la app |
|---|---|---|
| `Finding` (interno, §3.3) | `InvestigationFinding` (proyección) | Investigación → "Hallazgos del caso" |
| `TimelineEvent` | `TimelineEvent` | Timeline |
| `MitreTechniqueMatch` | `MitreTechniqueMatch` | MITRE ATT&CK |
| `ReportDocument` | `ReportDocument` | Documentos |

Notas de proyección (sub-agente/orquestador → UI):

- `InvestigationFinding` es la vista *delgada* del `Finding` (sin `provenance`
  completa); la procedencia vive en el audit log y en el manifest del artifact,
  consultable por el perito (no se expone por HTTP — `STORAGE.md`).
- `TimelineEvent.severity` y `Finding.severity` comparten enum
  (`low|medium|high|critical`) — coherencia directa con los filtros de la UI.
- `MitreTechniqueMatch.confidence` es 0–100 en la UI; internamente 0–1. La
  proyección multiplica ×100. `relatedFindingIds` no vacío (anti-alucinación §4.3).
- `ReportDocument.sha256` + `pageCount` los rellena el render PDF del informe; el
  hash entra en el manifest del caso (reproducibilidad, `FORENSIC_SOUNDNESS.md` §6).
- Persistencia: se añade `FindingStore` (JSONL append-only por caso, mismo patrón
  que `chats`/`audit`) en `~/.forensia/cases/<id>/findings.jsonl`. Encaja en el
  layout sin base de datos de `STORAGE.md`.

---

## 8. Modelos y agnosticismo de proveedor

La capa `ModelBackend` (`backend/forensia/models/base.py`) ya declara
**capacidades** (`supports_native_tools`, `json_mode`, `max_context`, `is_local`)
además de `next_action`. El paquete de cada agente fija su `model.backend`
(`local|cloud`) y `model.name`. Implicaciones para el entrenamiento:

- **Local (Ollama) por defecto** (privacidad de evidencia, RULE/GDPR). El prompt
  debe ser robusto en el *camino degradado*: para modelos sin tool-use nativo, el
  loop usa prompt estructurado + parser + allowlist + reintentos. Los prompts
  incluyen un formato de salida `{tool_id, params}` parseable de forma estricta.
- **Cloud opt-in por caso**, con consentimiento registrado y **redacción previa**
  (`policy/redaction.yaml`). Durante el desarrollo se mide con cloud (fiable) y se
  valida local como objetivo del producto — exactamente el experimento del TFM.
- Un mismo paquete puede evaluarse en varios modelos cambiando solo `agent.yaml`
  + el harness; los prompts son los mismos. Eso hace la comparativa **limpia**
  (misma variable independiente: el modelo).

---

## 9. "Entrenamiento" = prompts + conocimiento (RAG) + evals

Aquí "entrenar" **no** es ajustar pesos: es **ingeniería de prompts y de
conocimiento** iterada contra evals. Es lo eficaz para agentes LLM y lo que la
propuesta describe ("a medida que avance el proyecto progresamos en el
entrenamiento → análisis más preciso, ahorro de tokens, mejor redacción"). Cuatro
capas:

### 9.1 Prompts por agente (declarativos)
- `system.md`: reglas duras (solo lectura; no-comando; citar procedencia; evidencia
  = datos; tope de iteraciones; formato de finding).
- `identity.md`: persona (FORENSIA-WIN / FORENSIA-UNIX / orquestador pericial),
  tono, idioma, cómo se presenta.
- `playbook.md`: heurística forense por tipo de evidencia (disco / RAM / EVTX /
  registro …) — la secuencia que probaría un analista humano, no un script.

### 9.2 Playbooks por herramienta (knowledge)
Para cada `tool_id`: cuándo usarla, params típicos, coste/tiempo (avisar antes de
`bulk_extractor`), errores comunes, y cómo leer su salida. Reduce iteraciones
fallidas → menos tokens.

### 9.3 Base de conocimiento recuperable (RAG, fase 2)
Hoy el catálogo va en el system prompt (cabe). El RAG real añade: **corpus MITRE
ATT&CK** (tácticas/técnicas/grupos), guías de interpretación de artefactos
(amcache, prefetch, shimcache, shellbags, wtmp/btmp…), y mapeos
artefacto→técnica. Vive en `agentes/_orchestrator/knowledge/` y se indexa al
arrancar. El `ModelBackend` ya tiene el *hook* de RAG como stub.

### 9.4 Evals — la contribución científica (cerrar el formato "pendiente")
El harness ejecuta casos sintéticos (**nunca datos reales**, `evals/README.md`) y
mide, **local vs cloud**, las métricas que la propuesta promete:

| Métrica | Qué mide | Cómo |
|---|---|---|
| `tool_invocation_accuracy` | ¿eligió la tool correcta con params válidos? | comparación con la traza dorada |
| `findings_recall` | ¿encontró los hallazgos esperados? | `expected_findings` del caso |
| `findings_precision` | ¿cuántos falsos positivos? | hallazgos no esperados |
| `tokens_per_case` | coste | contador del backend |
| `iterations_to_solve` | eficiencia del loop | contador del loop |
| `report_quality` | redacción | rúbrica + (opcional) juez LLM |
| `mitre_correctness` | técnicas correctas y sostenidas | vs etiquetas del caso |

Formato de caso propuesto (cierra el TODO de `agentes/*/evals/`):

```yaml
# agentes/forensia-windows/evals/case-001.yaml
id: case-001
description: "Imagen Windows con persistencia en Run key + proceso inyectado"
os_profile: windows
evidence_fixture: fixtures/win-persist.raw     # sintética, sin datos personales
expected_findings:
  - title_glob: "*Run key*"
    severity: high
    provenance_tool: regripper
  - title_glob: "*proceso inyectado*"
    severity: critical
    provenance_tool: volatility3
expected_mitre:
  - technique_id: T1547.001     # Registry Run Keys
  - technique_id: T1055         # Process Injection
budget:
  max_iterations: 12
  max_tokens: 200000
```

La tabla comparativa resultante (local vs cloud por métrica) es el resultado
publicable del TFM.

---

## 10. Seguridad y soundness que la capa de agentes DEBE preservar

La capa de agentes hereda y **no puede erosionar** los gates de
`THREAT_MODEL.md`/`FORENSIC_SOUNDNESS.md`. Los que dependen directamente del
entrenamiento o del loop:

- **Gate 5/6 (sin shell / enum cerrada):** el prompt nunca induce a "escribir un
  comando"; la salida es `{tool_id, params}`. Reforzado por allowlist en MCP y
  dispatcher.
- **Gate 7 (evidencia = datos):** regla explícita en `system.md` + caso de eval
  dedicado a prompt-injection desde un artefacto.
- **Gate 9 (cloud opt-in + redacción):** `redaction.yaml` por agente; sin
  consentimiento, 0 bytes salen.
- **Custodia (audit encadenado):** cada finding cita `audit_seq`; el loop registra
  el `argv` literal, no la intención del modelo.
- **Contenedores:** un sub-agente Windows que necesite `regripper`/`evtxecmd`
  (entrega *container*) trabaja sobre **artefactos pre-extraídos** con TSK a través
  del handle read-only — nunca monta la imagen cruda (`FORENSIC_SOUNDNESS.md` §7).
  El playbook lo refleja paso a paso.

---

## 11. Roadmap de implementación (incremental) y mis entregables

Slices pequeños, cada uno *testeable* end-to-end (coherente con Fase 4: testear
antes de la versión final).

| # | Slice | Entregable (rol entrenamiento) | Depende de (motor) |
|---|---|---|---|
| S0 | **Este documento** | diseño cerrado + decisiones | — |
| S1 | **Paquetes reales v1** | `agentes/forensia-unix` y `forensia-windows` (prompts+playbook+allowlist+redaction) que reemplazan los sample | loader/registry (ya están) |
| S2 | **Contrato de finding + loop** | esquema `Finding`, prompts alineados al loop | `ForensicAgent.run()` mínimo + `FindingStore` |
| S3 | **Maletín MCP** | JSON Schemas de tools para los agentes | MCP server sobre dispatcher |
| S4 | **Orquestador v1** | `_orchestrator/{reporter,timeline,mitre}.md` | `forensia.reports.{report,timeline}` |
| S5 | **MITRE + KB/RAG** | corpus MITRE + reglas anti-alucinación | `forensia.reports.mitre` + hook RAG |
| S6 | **Harness de evals** | casos `evals/*.yaml` + rúbricas | runner local-vs-cloud |
| S7 | **Comparativa local vs cloud** | tabla de métricas (resultado TFM) | backends `local`/`cloud` reales |

Mi siguiente paso natural tras este doc es **S1**: escribir los dos paquetes
reales (sustituyendo los sample) y un primer `_orchestrator/`. Son ficheros
declarativos que el sidecar carga sin más, así que dan demo inmediata aunque el
loop siga en esqueleto (el envelope ya lista la allowlist).

---

## 12. Decisiones abiertas (te las dejo para confirmar)

- **D-1 — Forma del orquestador.** Recomendado: dos niveles (routing
  determinista + síntesis). Alternativa: orquestador conversacional que delega en
  caliente. *Impacto:* trazabilidad y tokens.
- **D-2 — Hogar de los prompts del orquestador.** Recomendado: `agentes/_orchestrator/`
  (cero cambios de motor). Alternativa: extender el schema con `role:`.
- **D-3 — MCP ahora o como capa 2.** Recomendado: diseñar schemas ya, implementar
  tras el loop nativo. El contrato `{tool_id, params}` no cambia.
- **D-4 — Modelo local por defecto.** ¿Qué modelo Ollama fijamos como base de la
  comparativa (p. ej. `llama3.1:8b` vs `qwen2.5:14b`)? Afecta al *camino degradado*
  de los prompts.
- **D-5 — Alcance Unix-like.** ¿`unix` = solo Linux en v1, o Linux+macOS desde el
  principio? Afecta al playbook y a qué parsers vendorizamos primero.

---

## Apéndice A — Glosario propuesta ↔ repo

| Propuesta | Repo / este doc |
|---|---|
| Agente orquestador | `forensia.reports` + paquete `_orchestrator/` (nivel 2) |
| Sub-agente Windows / Unix | `agentes/forensia-windows` / `forensia-unix` (nivel 1) |
| Maletín | `backend/forensia/toolkit/catalog.py` + `vendor/` + imágenes OCI |
| "Información estructurada" | `Finding[]` con `provenance` + `ArtifactStore` |
| Informe / Timeline / MITRE | `ReportDocument` / `TimelineEvent[]` / `MitreTechniqueMatch[]` |
| `[proceed-to-report]` / `[back-to-analysis]` | disparadores del nivel 2 / retorno al nivel 1 |

---

*Fin del diseño de Fase 2. Los invariantes de `CLAUDE.md` (RULES 0–4),
`THREAT_MODEL.md` (gates 1–12) y `FORENSIC_SOUNDNESS.md` (cadena de custodia) son
condiciones de aceptación de cualquier slice descrito arriba.*
