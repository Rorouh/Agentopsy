# FORENSIA — Inventario de MCPs (núcleo del TFM)

Catálogo de **servidores MCP** que FORENSIA expone para que el agente — y, opcionalmente, un
cliente externo — opere el maletín forense, consulte conocimiento y emita el informe a través
de un protocolo único. Mirroreado en estructura con
[`docs/maletin/inventario-tools.md`](inventario-tools.md): este documento es la lista larga; la
selección final implementada vive en `backend/forensia/mcp/` (el `mcp-toolkit` de S1 ya
está ahí — ver [`mcp-toolkit-s1.md`](mcp-toolkit-s1.md)).

> **Por qué este documento existe ahora**: en el email del 2026-06-24, el PI movió MCP de
> "Fase 2 opcional si sobra tiempo" a **núcleo del TFM** ("la integración avanzada de los
> agentes con las herramientas CLI mediante protocolos de contexto debe ser el núcleo del
> TFM, no un añadido"). Es la nueva línea base del proyecto, y la rama `mcp` se cortó de
> `main` el 2026-06-29 para sostenerla.

> Inventario construido el 2026-06-29 a partir de un panel de 4 perspectivas en paralelo
> (arquitecto MCP, perito DFIR, ingeniería de FORENSIA, knowledge / threat-intel). Los
> desacuerdos del panel y cómo se resolvieron están en §8.

---

## 1. Arquitectura de despliegue (cómo viven los MCPs en FORENSIA)

```
        ┌──── UI web (React) ──── HTTP + token de sesión ────► api (FastAPI) ───┐
        │                                                                       │
        │                          (puerto publicado solo en 127.0.0.1)         │
        │                                                                       ▼
        │                                            ┌────────────────────────────────┐
        │                                            │ ForensicAgent loop             │
        │                                            │  ↓ next_action                 │
        │                                            │  cliente MCP in-process        │
        │                                            └────────────┬───────────────────┘
        │                                                         │ stdio (in-proc)
        │                                                         ▼
        │                       ┌────────────── MCP servers (todos in-process) ──────────────┐
        │                       │                                                            │
        │                       │  mcp-toolkit     mcp-evidence    mcp-knowledge-{mitre,…}   │
        │                       │  mcp-cases       mcp-audit       mcp-report                │
        │                       │                                                            │
        │                       │     ▲ todos delegan en el dispatcher / EvidenceManager /   │
        │                       │       AuditLog / FindingStore existentes — cero            │
        │                       │       reimplementación, una sola cadena de custodia.       │
        │                       └────────────────────────────────────────────────────────────┘
        │
        └─ stdio externo OPCIONAL (deshabilitado por defecto, activable con --mcp-stdio):
           expone los MISMOS servidores a un cliente externo (Claude Desktop, Continue,
           otro agente). Es la demostración "MCP como protocolo público" del TFM.
```

**Decisiones cerradas** (detalle en §8):

- Todos los servidores MCP **viven dentro del proceso Python del backend (servicio
  `api`)**, no como procesos separados — un solo proceso, una sola cadena de audit,
  nada que instalar fuera de `docker compose up --build`. RULE 1 intacta.
- Transporte por defecto: stdio in-process. Transporte externo opcional (también stdio,
  para máxima portabilidad spec-compliant) — deshabilitado por defecto (RULE 2).
- El servidor MCP **nunca ejecuta argv directamente**. Delega siempre en
  `forensia.toolkit.dispatcher.execute(tool_id, params, case_id)`. La allowlist se
  enforce en dos puntos (MCP `tools/list` filtrado por paquete activo del caso, y el
  dispatcher por catálogo). Defensa en profundidad.
- Schemas JSON de los `tools` MCP **se derivan automáticamente** del catálogo
  (`Tool.allowed_flags` + firma de `build_argv`). Si no se puede derivar, el tool no se
  publica vía MCP hasta que su wrapper exponga el contrato — RULE 2.

---

## 2. Toolkit forense (envoltura del dispatcher)

| MCP id | Primitivas | Envuelve | Prio | Net new code | Por qué |
|---|---|---|---|---|---|
| `mcp-toolkit` | tools | `dispatcher.execute` + `catalog.BY_ID` (16 tools) | **P0** | S (~200 LOC) | El servidor del TFM. Convierte "tenemos un `dispatcher` seguro" en "tenemos un protocolo público". Cada `Tool` del catálogo → un MCP tool con `inputSchema` autogenerado. La allowlist del paquete activo (`policy/tools.yaml`) recorta `tools/list`. |

**Por qué un solo servidor (y no `mcp-tsk` + `mcp-volatility` + `mcp-zimmerman` + …)**:

- Multiplicar servidores multiplica procesos que arrancar, supervisar y auditar, y rompe
  la continuidad del `AuditLog` (hash-chained por caso — con N procesos pasaría a N
  cadenas inconexas).
- El `dispatcher` ya es el punto único de seguridad (shell-free, allowlist, audit, hash
  baseline). Replicarlo en N servidores duplica la superficie de drift.
- El agente se beneficia de **un solo `tools/list`** filtrado por su allowlist — no de
  descubrir N servidores y reconciliar capabilities.

**Cómo se modelan tools complejas** (compromiso entre "1:1 con catálogo" y "agrupado por
verbos forenses"):

- Por defecto, **un MCP tool por `Tool` del catálogo** (16 tools → 16 MCP tools), idéntico
  uno a uno. No inventamos verbos agregados (`investigate_persistence`) — sería lógica
  disfrazada en un router que CLAUDE.md RULE 3 prohíbe.
- Cuando una tool tiene parámetros muy variables (`volatility3` con docenas de plugins),
  el `inputSchema` la modela con `plugin` como **enum cerrado** del subset soportado por
  el wrapper, no como `string` libre. Eso da al agente la flexibilidad real sin perder el
  control de argv.

---

## 3. Evidencia, casos y auditoría (resources)

| MCP id | Primitivas | Envuelve | Prio | Por qué |
|---|---|---|---|---|
| `mcp-evidence` | resources | `EvidenceManager.get/list/verify` + `triage.fingerprint_evidence` | **P0** | URIs `evidence://<case>/<id>` resolubles. Cada llamada de `mcp-toolkit` que toma `evidence_id` debe poder leer este resource para confirmar `detected_os`/`detected_kind`/`sha256`. Sin esto, cualquier futuro MCP re-implementa custodia. |
| `mcp-cases` | resources | `CaseManager` + `ArtifactStore.list/get_run` + `FindingStore.list` | **P1** | Recursos `case://<id>`, `artifact://<case>/<run>`, `finding://<case>/<id>`. Hace que el orquestador vea el contexto entre turnos sin reinventar contratos. |
| `mcp-audit` | resources (read-only) | `AuditLog` encadenado por caso | **P1** | URI `audit://<case>/<seq>` para citar la cadena de custodia desde el informe. Refuerza el "toda afirmación, su prueba" de `_orchestrator/reporter.md`. |

**Por qué `mcp-evidence` está en P0** (resources antes que tools sería tentador; aquí ambos
en P0 conjuntamente):

- `mcp-toolkit` necesita `evidence_id` como parámetro de casi todos sus tools. Sin
  `mcp-evidence` exponiendo el handle, el cliente MCP no puede validar que el id es real
  antes de la llamada.
- Hace MCP visible al evaluador del TFM como **protocolo de datos**, no solo de acciones.
  La sección "MCP" de la memoria contiene tools **y** resources — eso es la spec completa,
  no medio protocolo.

---

## 4. Conocimiento (knowledge bases — RAG real)

El `_orchestrator/` (Fase 2) declaró un seed de ATT&CK + plantillas de informe pero hoy
todo vive como markdown estático en el system prompt. Estos MCPs convierten esa estática
en consulta dirigida a tiempo de razonamiento.

| MCP id | Tipo | Fuente | Offline | Prio | Por qué al razonar |
|---|---|---|---|---|---|
| `mcp-mitre-attack` | knowledge (RAG) | ATT&CK Enterprise STIX bundle v15+ (técnicas, sub-técnicas, grupos, data sources) | **Sí (obligatorio)** | **P0** | Sin esto el agente alucina técnicas. La seed actual de 15 entradas no cubre 14 tácticas × ~600 técnicas/sub-técnicas reales. ~30 MB JSON bundleable. **Crítico para el `_orchestrator/mitre.md`**. |
| `mcp-artifact-playbooks` | knowledge | Markdown curado: cómo leer Amcache / Prefetch / Shellbags / SRUM / UsnJrnl / $MFT / wtmp | **Sí (obligatorio)** | **P1** | "Cómo interpretar la salida de tool X" — reduce iteraciones fallidas, crítico para el camino degradado Ollama. ~5 MB. |
| `mcp-yara-rules` | knowledge | Subset curado de `signature-base` (Florian Roth): webshells, ransomware notes, persistencia común | **Sí (obligatorio)** | **P1** | El playbook Windows pide `yara` para T1505.003 y T1486. Sin catálogo legible no sabe qué buscar. ~50 MB. |
| `mcp-sigma-rules` | knowledge | SigmaHQ subset Win/Linux | **Sí** | **P1** | Hayabusa/Chainsaw consumen Sigma; el agente debe poder razonar sobre qué regla disparó y mapearla a MITRE. ~40 MB. |

Presupuesto total de knowledge bundle P0+P1 ≈ **~125 MB comprimidos**. Aceptable contra el
tamaño de las imágenes de los maletines. `agentes/_orchestrator/knowledge/MANIFEST.json` con
sha256 + fecha por dataset para reproducibilidad.

---

## 5. Síntesis (timeline + reporte)

| MCP id | Primitivas | Envuelve | Prio | Por qué |
|---|---|---|---|---|
| `mcp-timeline` | tools + resources | Módulo `forensia.timeline` (no existe aún) que ingiere bodyfile + CSV de EVTX/MFT/Registry + JSON de Volatility + `plaso.storage` | **P0** | El núcleo forense del TFM. Sin un store consultable por ventana ± delta y por `artifact_id`, el LLM reconstruye timelines en prompt e inventa correlaciones. La diferencia entre "tool inventory" y "case closure". |
| `mcp-report` | tools (1: `render_report_pdf`) | `forensia.reports` (no existe aún) — markdown → docx → PDF con manifest hash | **P2** | Cierre del caso; consume `mcp-timeline` + `mcp-mitre-attack`. Posterior porque el módulo de reportes todavía no existe; construirlo y exponerlo a la vez es doble riesgo. |

**Nota sobre `mcp-timeline`**: el módulo backend `forensia.timeline` está pendiente
(`../operacion/proximos-pasos.md §2`). El MCP server se diseña ahora pero su implementación va detrás del
módulo nativo (P0 conceptual / P1 de tiempo real). Hasta entonces, el agente correlaciona
en prompt con limitaciones conocidas — material de la sección "limitaciones" de la
memoria.

---

## 6. Lookup local + online opt-in (enriquecimiento)

| MCP id | Tipo | Fuente | Offline | Prio | Por qué |
|---|---|---|---|---|---|
| `mcp-cve-cpe-local` | lookup | NVD JSON snapshot (KEV + CVSS≥7, últimos 5 años; ~150 MB comprimido) | **Sí** | **P2** | Enriquece findings con CVE/CPE sin egress. Snapshot versionado, no live. |
| `mcp-hash-reputation-local` | lookup | NSRL RDS minimal + MalwareBazaar export semanal | **Sí** | **P2** | Discrimina binarios benignos (NSRL) vs malware conocido sin enviar el hash a terceros. |
| `mcp-ioc-local` | lookup | Bundle MISP-format de URLhaus + Feodo + abuse.ch | **Sí** | **P2** | Valida IPs/dominios extraídos de RAM contra IOCs conocidos sin tocar Internet. |
| `mcp-vt-cloud` | lookup | VirusTotal API | **No (online)** | **P3 opt-in** | Solo con consentimiento firmado del perito por caso. Sujeto a `policy/redaction.yaml`. Riesgo GDPR claro. |
| `mcp-otx-cloud` | lookup | AlienVault OTX / AbuseIPDB | **No (online)** | **P3 opt-in** | Idem VT. Solo enriquecimiento de IOCs ya extraídos. |

**Régimen de egress** (consolidado de las 4 voces del panel):

| Bucket | Política |
|---|---|
| Conocimiento público estático (MITRE, YARA, Sigma, playbooks) | Bundled obligatorio. Sin versión online aunque exista. |
| Lookups sensibles a la evidencia (CVE-CPE, hash, IOC) | Bundled snapshot versionado. Sin online aunque exista API. |
| Inteligencia online (VT, OTX) | Opt-in por caso, consentimiento firmado, redaction activa, registro en `audit.jsonl` de cada query saliente. Never-upload-samples. |
| Resources de evidencia (`mcp-evidence`, `mcp-cases`, `mcp-audit`) | Local puro. Token de sesión del backend `api`. |

---

## 7. El MCP número 1 — `mcp-toolkit`

Si FORENSIA solo pudiese tener **un** servidor MCP, sería `mcp-toolkit`. Tres argumentos
que el panel coincidió (excepto el de knowledge, que vota por `mcp-mitre-attack` — ver §8):

1. **Coste mínimo, señal máxima.** El `dispatcher` ya es shell-free, allowlisted,
   audit-encadenado, anclado a caso. Envolverlo como servidor MCP único in-process son
   ~200 LOC de adaptador que itera `CATALOG` y publica `tools/list` + `tools/call`. El
   agente cambia `dispatch_tool(...)` por `mcp_client.call(...)` y nada más.

2. **Es el reframing que pide el supervisor.** "MCP es el núcleo" no se sostiene con
   knowledge MCPs por sí solos — al evaluador hay que poder mostrarle que **el agente
   habla con el maletín forense vía MCP**, y que un cliente MCP externo arbitrario
   (Claude Desktop, Continue.dev) puede operar el maletín FORENSIA sin saber nada
   internamente del proyecto. Eso es `mcp-toolkit` con su stdio externo opcional.

3. **Habilita a los demás MCPs.** `mcp-evidence`, `mcp-cases`, `mcp-audit`,
   `mcp-mitre-attack` solo aportan valor si el agente está ejecutando tools — y el agente
   solo ejecuta tools si hay un servidor que las publica. `mcp-toolkit` es el cimiento.

**Segundo lugar honoris causa: `mcp-mitre-attack`** (P0 también). El argumento del
panelista de knowledge es válido y se acepta: sin un MCP MITRE bundleado el orquestador
no es defendible. Pero se construye DESPUÉS de `mcp-toolkit` porque el TFM debe demostrar
primero "el agente opera por protocolo", luego "el agente razona con KB por protocolo".

---

## 8. Decisiones del panel (cómo se resolvieron los desacuerdos)

| # | Desacuerdo | Voces | Decisión |
|---|---|---|---|
| 1 | ¿`mcp-toolkit` 1:1 con catálogo o agrupado por familias forenses? | Protocolo: 1:1 estricto. DFIR: agrupar (`mcp-tsk` con methods `walk_tree`, `list_partitions`…). | **1:1 con `catalog.py`** + parámetros tipados con enums cerrados (volatility plugins, flags TSK). Reconcilia ambas voces: no inventamos verbos, pero el `inputSchema` no es string libre. |
| 2 | ¿Servidores MCP separados por familia o un solo `mcp-toolkit`? | DFIR: 15+ (`mcp-tsk`, `mcp-libewf`, `mcp-evtx`…). Ingeniería: 1 in-process. | **Un solo `mcp-toolkit`** in-process. Multiplicar procesos rompe RULE 1 (bundling), multiplica firmas, fragmenta el `AuditLog`. La granularidad la lleva el catálogo, no el número de servidores. |
| 3 | ¿Tools primero o resources primero? | Protocolo: resources (`mcp-evidence`) primero. Ingeniería: tools (`mcp-toolkit`) primero. DFIR: ambos en P0. | **Ambos en P0 conjuntamente**, se construyen el mismo sprint. Cada tool del toolkit toma `evidence_id` → necesita `mcp-evidence` para validarlo. |
| 4 | ¿stdio externo expuesto o solo in-process? | Protocolo: stdio publicable. Ingeniería: solo in-process por seguridad. | **In-process por defecto + stdio externo opcional (`--mcp-stdio`, deshabilitado por defecto)**. El externo es la prueba "MCP como protocolo público" para el TFM. RULE 2: no se activa silenciosamente. |
| 5 | ¿MITRE como tool, como knowledge MCP, o como prompt estático? | Protocolo: knowledge MCP (`resources/list` + `prompts/get`). DFIR: MCP con sub-techniques + data-sources. Knowledge: P0 obligatorio. Ingeniería: P2. | **`mcp-mitre-attack` como knowledge MCP, P0**. La voz de Ingeniería se rebaja en prioridad (era P2 por coste de KB real) porque el panel coincide en que sin MITRE serio el orquestador no aterriza. La de Knowledge gana: ATT&CK STIX bundle versionado, ~30 MB, `resources/list` + `resources/read`. |
| 6 | ¿`forensia.reports` + `mcp-report` simultáneo o secuencial? | Knowledge: P0. Ingeniería: P3, módulo no existe. | **`mcp-report` queda P2**. Primero `forensia.reports` nativo (NEXT_STEPS §2 ya lo agendaba), después su superficie MCP. Construir ambos a la vez duplica riesgo. |

---

## 9. Líneas rojas innegociables (consolidadas)

- **RULE 1 — entrega única**: cero servidores MCP que se instalen aparte. Todos viven
  dentro del proceso Python del backend (servicio `api`). Si un MCP necesita dataset
  externo (knowledge bundles), va en `agentes/_orchestrator/knowledge/` con
  `MANIFEST.json` (sha256 + fecha) y llega montado por el compose junto con `agentes/`.

- **RULE 2 — sin defaults silenciosos**: `tools/call` sin `case_id` o sin paquete cargado
  para el `os_profile` devuelve `INVALID_PARAMS` MCP estándar con mensaje accionable.
  Nunca elige caso por defecto, nunca cae a un agente fallback. El stdio externo está
  deshabilitado salvo flag explícito.

- **Frontera de custodia inviolable**: todo MCP recibe `evidence_id` y obtiene el handle
  read-only vía `mcp-evidence`. Cero paths absolutos crudos en argv del cliente MCP.
  Cero `mount` dentro de contenedores proxy (HyperKit/WSL2 dispara journal replay —
  ver `docs/soundness-forense.md`).

- **Argv literal en el audit, no JSON-RPC**: cada llamada MCP → resolución a argv array
  → `subprocess.run([...], shell=False)` → entrada en `audit.jsonl` con argv, versión de
  tool, `evidence_id` + hash, stdout/stderr/exit y SHA-256 de cada artefacto. El registro
  que vale es el **argv ejecutado**, no la intención del modelo ni el wire del MCP.

- **Schemas derivados, no escritos a mano**: `inputSchema` JSON de cada MCP tool se
  genera desde `Tool.allowed_flags` + firma de `build_argv`. Schema manual = deriva
  silenciosa = RULE 2 rota. Si la derivación falla, el tool no se publica vía MCP hasta
  que su wrapper exponga el contrato.

- **Egress online opt-in, registrado**: `mcp-vt-cloud` / `mcp-otx-cloud` solo se invocan
  con consentimiento del perito por caso, `policy/redaction.yaml` aplicada, y cada query
  saliente registrada en `audit.jsonl`. Never-upload-samples: solo hashes / IOCs ya
  derivados, jamás bytes de evidencia.

---

## 10. Plan de implementación por sprint (cronograma real del TFM)

| Sprint | MCPs cerrados | Personas (de 6) | Estado / Resultado defendible |
|---|---|---|---|
| S1 | **`mcp-toolkit` (P0)** standalone stdio con patrón Jira + 16 tools + ResourceLinks + redaction modes | 2 | ✅ **CERRADO 2026-06-29**. Verificado E2E con Claude Desktop sobre memdump real 5 GiB Windows 7 SP1. 2 rounds de panel; líneas rojas L1–L6 verificadas. 335 tests passing. Detalle: [`mcp-toolkit-s1.md`](mcp-toolkit-s1.md). |
| S2 | `mcp-evidence` (P0) + integración `ForensicAgent` propio como cliente MCP in-process del `mcp-toolkit` | 2 | Pendiente. Unifica los dos caminos al dispatcher (API HTTP del backend + servidor MCP) bajo el mismo protocolo. Demo: el agente nativo ejecuta su cadena vía cliente MCP, output idéntico al dispatcher directo (test diferencial — ya escrito). |
| S3 | `mcp-mitre-attack` (P0) — bundle ATT&CK Enterprise + cliente MCP en el orquestador | 1 | Pendiente. El informe cita técnicas + sub-técnicas + data sources del bundle, no del prompt. ~30 MB bundleados. |
| S4 | `mcp-cases` (P1) + `mcp-audit` (P1) + `mcp-artifact-playbooks` (P1) + `mcp-yara-rules` (P1) + `mcp-sigma-rules` (P1) | 3 (paralelo) | Pendiente. Conocimiento + custodia accesibles vía protocolo en toda la app. |
| S5 | `mcp-timeline` (P0 conceptual / P1 real — después de `forensia.timeline` nativo) | 2 | Pendiente. Timeline correlacionada por protocolo; consultable por ventana ± delta. |
| S6 (cierre) | `mcp-report` (P2) + cliente demo finalizado (Claude Desktop / Continue) | 2 | Pendiente. Cliente MCP externo opera el maletín sin código FORENSIA propio — demo estrella del TFM. |
| Posterior | `mcp-cve-cpe-local`, `mcp-hash-reputation-local`, `mcp-ioc-local` (P2) + `mcp-vt-cloud`/`mcp-otx-cloud` (P3 opt-in) | — | Enriquecimiento offline + opcionales online con consent. |

Reparto entre 6 personas (alineado con el email del 2026-06-24):

- **2 personas: equipo MCP** — diseño + `mcp-toolkit` + `mcp-evidence` + schemas
  derivados + stdio externo + cliente demo.
- **2 personas: equipo de agentes + knowledge MCPs** — completar Ollama backend,
  curaduría de los bundles (MITRE/YARA/Sigma/playbooks), evals, y los MCPs P0/P1 de
  conocimiento.
- **1 persona: reportes + timeline** — `forensia.reports` + `forensia.timeline` + sus
  superficies MCP.
- **1 persona: UI + compose** — páginas mock pendientes (la SPA ya migró al servicio
  `web` el 2026-07-02: `web/` compilada y servida por nginx con proxy al api) y CI que
  verifique el build de las imágenes del compose.

---

## Resumen del estado

| Bloque | MCPs | Estado |
|---|---:|---|
| Toolkit + custodia (P0) | 2 | `mcp-toolkit` **✅ cerrado en S1** (rama `mcp`). `mcp-evidence` pendiente para S2. |
| Conocimiento bundleado (P0+P1) | 4 | Diseñados; bundles a curar. ATT&CK Enterprise es P0 obligatorio (S3). |
| Síntesis (P0/P1/P2) | 2 | Dependen de módulos backend (`forensia.timeline`, `forensia.reports`) que no existen aún. |
| Lookup local snapshot (P2) | 3 | Datasets offline a empaquetar en `knowledge/`; post-MVP del TFM. |
| Lookup online opt-in (P3) | 2 | Solo con consent firmado. Bandera explícita por caso. |
| **Total inventariado** | **13** | — |

Los 4 panelistas coincidieron en que **`mcp-toolkit` es el MCP número 1 que debe estar sí
o sí** (el de knowledge proponía `mcp-mitre-attack`, aceptado como P0 número 2). Sin
`mcp-toolkit` ningún otro MCP aporta valor real al agente; con él, MCP **es** el núcleo
del TFM tal como el supervisor lo pidió.
