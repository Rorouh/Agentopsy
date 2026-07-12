# FORENSIA — Mapa de arquitectura (contexto rápido)

> **Para qué es este fichero.** Un mapa curado de la estructura del código, para
> orientarte al empezar sin recorrer los ~160 ficheros. Léelo en vez de grepear:
> ahorra tokens. Es un **resumen derivado** del grafo de código que genera
> `tools/graph/` (graphify, modo `--code-only`: AST local con tree-sitter,
> determinista, **sin LLM ni API key**). No sustituye a `CLAUDE.md` (invariantes)
> ni a los docs de `docs/`; los complementa.
>
> **Anclado a:** commit `410fd11` · **Grafo:** 1741 nodos · 3029 aristas · 143
> comunidades (backend) + 249 · 556 · 10 (web). Regenera el grafo interactivo con
> `tools/graph/graph-build.ps1` (o `.sh`) y **actualiza este fichero** cuando la
> arquitectura cambie de forma relevante.

---

## Abstracciones núcleo (god-nodes: por donde pasa todo)

Ordenadas por conectividad en el grafo — son los puntos de entrada para entender el
sistema:

1. **`CaseManager`** — dueño de `CONFIG_DIR/cases/`: crea / lista / carga / cierra
   casos, con guarda anti path-traversal. El **caso** es la unidad de la que cuelga
   todo (evidencia, artefactos, chats, auditoría). Máxima intermediación del grafo.
2. **`AuditLog`** — log **append-only y hash-encadenado** (tamper-evident). Cada
   acción registra el **argv literal ejecutado**, versión de tool, id+hash de
   evidencia, stdout/stderr/exit y el SHA-256 de cada artefacto. (FORENSIC INVARIANT 4)
3. **`EvidenceManager`** — **único dueño de la evidencia**: `ingest → hash baseline →
   handle read-only a nivel de bloque`. Nada llega a una tool sin baseline.
   (FORENSIC INVARIANTS 1-2)
4. **`ForensicAgent`** — el **bucle del agente**, parametrizado por un `AgentPackage`;
   decide qué tool pedir y consolida resultados vía el ejecutor. Nunca ve el
   ground-truth.
5. **`Tool`** — contrato de tool de **enum cerrada**; declara además cada parámetro
   filesystem con `PathParameter` (rol, fichero/directorio y allowlist exacta cuando
   aplica). Es la ÚNICA vía sancionada de ejecución (`run_argv`, shell-free).
   (SECURITY INVARIANTS 4-6)
6. **`ArtifactStore` / `ArtifactRun`** — manifiesto por corrida con argv literal
   fijado antes del runner, estados `running | finished | error` y ficheros de salida
   hasheados.
7. **`load_package()` / `AgentPackageError` / `AgentRegistry`** — carga, valida e
   indexa los paquetes declarativos `agentes/<id>/` por `os_profile`.

---

## Mapa por capas (backend `forensia/*`)

**Evidencia y custodia** — `EvidenceManager`, `EvidenceHandle` (ingesta, puerta de
hash, handle RO); **triage** `fingerprint_evidence()` / `fingerprint_os()` →
`DetectedEvidence` / `routable_profile()`; **resolución de perfil**
`resolve_os_profile()` / `OsProfileUnresolved` (el único punto que decide el
`os_profile`, o falla fuerte — RULE 2).

**Auditoría** — `AuditLog` hash-encadenado + gates de integridad (hash-chain,
tamper).

**Casos** — `Case` / `CaseManager` (ciclo de vida, `case.json` por dir, confinamiento
de directorio).

**Almacenes por caso** — `ArtifactStore`/`ArtifactRun` (argv fijado y estados
`running | finished | error`); `FindingStore` (findings estructurados, JSONL
append-only); `ChatStore` (JSONL por sesión de chat).

**Paquetes de agente** — tipos (`AgentPackageModel` / `Policy` / `Prompts`), parsers
(`AgentPackageError`), loader (`load_package`), registro (`AgentRegistry`: descubre +
indexa por `os_profile`, sin fallback — RULE 2).

**Bucle del agente** — `run()` (`AgentLoopResult`); presupuesto de contexto
`window_messages()` / `keep_last_tool_results` (Bug 008); `bounded_json`; guarda
anti-bucle (Bug 001); selección de sección de playbook `select_playbook_section()`;
replay de chat `build_replay_messages()`.

**Ejecutores** (pivot 2026-07-02) — `PromptExecutor` (ABC) + `CliPromptExecutor`;
`ClaudeCodeExecutor`, `CodexExecutor`, `GeminiExecutor`, `OllamaExecutor` (la opción
100% local); adaptador `ExecutorBackend` (`PromptExecutor → ModelBackend`) y puente
`ModelBackend`; superficies de config `list_executors` / `list_models` /
`executor_models`. **Selección explícita del operador, sin default** (RULE 2); sin
API keys en el repo (RULE 7).

**Toolkit** — `catalog` (`by_tier` / `for_profile`, `Tool` de enum cerrada y contrato
central `PathParameter`); `forensia.path_policy` (roles `EVIDENCE_INPUT`, `CASE_INPUT`,
`DERIVED_INPUT`, `RUN_OUTPUT`, `BUNDLED_RULESET`, `RUNTIME_DEVICE`, canonicalización y
confinamiento same-case); `forensia.artifact_ref` (contrato único
`{run_id, relpath, sha256?, size?}`, sin extras; el store re-hashea y valida metadatos);
`dispatcher.execute()` (`tool + params → gate de rutas antes
del run → ArtifactRun → argv fijado → tool_run_start
durable → runner → intento único de finish o error accionable`); `maletin`
(allowlist ∩ catalog, `select_maletin` por `os_profile` sin fallback, sonda de
disponibilidad para `capabilities`); `resolver` (binario / runtime OCI);
`run_in_container`; `Tool.run_argv()` shell-free.

**Wrappers de tool** (todos con la misma forma `build_argv()` + `parse()` — el
catálogo es uniforme):

- **Cross / disco-memoria:** TSK `fls` / `icat` / `mmls` / `mactime`, `volatility3`,
  plaso `log2timeline` / `psort`, `bulk_extractor`, `foremost`, `hashdeep`,
  `ewfinfo`, `file_info`, `xxd`, `strings`, `yara`, `jq`, `qemu_nbd`.
  `bulk_extractor` crea `out/bulk_extractor` desde inexistente; `qemu_nbd` siempre
  incorpora `-r` y solo acepta el device-id cerrado `nbd0`.
- **Windows (registro / eventos / EZ Tools):** `RegRipper`, `AmcacheParser`,
  `AppCompatCacheParser`, `MFTECmd`, `EvtxECmd`, `Hayabusa`, `Chainsaw`, `LECmd`,
  `JLECmd`, `SBECmd`, `RBCmd`, `RECmd`, `WxTCmd`.

**Servidor MCP** (`mcp-toolkit`, S1) — servidor core (`_dispatch_forensic`); las **4
tools patrón Jira** (`list_cases` / `select_case` / `list_evidence` /
`select_evidence`; exige `select_case` antes de cualquier tool — RULE 2); `McpSession`
/ `build_server`; entrypoint stdio `__main__`; resource links de artefactos.

**Routers HTTP** (adaptadores finos, `forensia/routers/*`) — casos, bandeja/registro
de evidencia, token de sesión, chats, findings, uso de tools, artefactos,
`capabilities` / config. **Endurecimiento de transporte:** `create_app`,
`allowed_hosts`, `HostHeaderMiddleware` (anti DNS-rebinding), `require_token`; gates
de seguridad. (SECURITY INVARIANTS 1-3)

**Redacción / GDPR** — policy de redacción del paquete (`apply_redaction`,
`RedactionPattern`); redacción de egress antes de cruzar a un modelo cloud; modo de
redacción.

**Config y arranque** — `Config` (`~/.forensia/config.json` con override por env);
seeding del volumen `forensia-cli-auth` (`docker/api` entrypoint); api FastAPI
(`_free_port`, `_ReadyAnnouncingServer`, standalone en `127.0.0.1`).

---

## Frontend (`web/`)

SPA React/TypeScript (33 `.tsx` + 8 `.ts`) servida por nginx, que habla con la api
por `web/src/api/client.ts` (token desde `GET /api/session`, en memoria). Grafo
propio: 249 nodos / 556 aristas / 10 comunidades. Lleva el selector de ejecutor, el
flujo auditado de consentimiento cloud y el registro de evidencia desde la bandeja.

---

## Cómo usar este grafo como contexto

```powershell
$g = "<ruta a graphify.exe>"          # ver tools/graph/README.md
$G = "tools\graph\out\forensia-graph.json"
& $g explain "EvidenceManager" --graph $G      # nodo + vecindario
& $g path "dispatcher" "catalog"   --graph $G   # camino más corto
& $g query "que conecta capabilities con los maletines" --graph $G
& $g affected "AuditLog" --graph $G             # qué se ve afectado si lo tocas
```

---

## Caveats de fidelidad (no sobre-interpretar)

- **Los "nodos" incluyen fragmentos de docstring**, no solo símbolos: los 1741 nodos
  y 143 comunidades están inflados por texto de docstrings (graphify extrae
  "conceptos"). Sirve para navegar; para métricas, tenlo en cuenta (41 comunidades
  "thin" <3 nodos se omiten del report).
- **~19% de aristas son `INFERRED`** (call-graph, confianza media 0.68). Algunas son
  ruido: `ValueError` o `typing.Any` aparecen como hubs por usarse en todas partes,
  **no** son abstracciones reales.
- **Backend y web son dos islas disjuntas** en modo code-only: el puente real (el
  contrato HTTP `web ↔ /api`) no es una llamada de código que tree-sitter vea; solo
  emergería con la pasada semántica LLM (que no usamos).

---

## Mantenimiento

Es un **auxiliar de desarrollo**, no parte del producto (no viaja en el compose —
RULE 1; sin keys — RULE 7; sin atribución IA — RULE 0). Para refrescarlo:
`tools/graph/graph-build.ps1` (Windows) o `tools/graph/graph-build.sh`
(Linux/macOS), y actualiza las cifras/god-nodes de arriba si la arquitectura se
mueve. Detalle completo y guardarraíles en `tools/graph/README.md`.
