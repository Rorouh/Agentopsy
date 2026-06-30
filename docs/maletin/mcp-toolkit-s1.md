# `mcp-toolkit` — plan de implementación para la demo del equipo

> **Estado: ✅ S1 CERRADO 2026-06-29.** Servidor MCP standalone funcional contra Claude
> Desktop, sobre el memdump real Windows 7 SP1 de 5 GiB del caso `f3abd274...`. 2 rounds
> de panel de expertos verificados; las 6 líneas rojas L1–L6 funcionales por test.
> 335/335 tests passing. Commit `92083f2` en `origin/mcp`. Lo que sigue (sprint S2):
> `mcp-evidence` standalone + integración del `ForensicAgent` propio como cliente MCP
> in-process — ver [`inventario-mcps.md §10`](inventario-mcps.md#10-plan-de-implementación-por-sprint-cronograma-real-del-tfm).
>
> **Post-S1 update (2026-06-30, propuesta v1.1).** L5 / Tarea 2 se implementó originalmente
> con `fcntl.flock`. Tras pasar la propuesta a *app universal Windows / macOS / Linux con
> instalable one-liner*, `fcntl` (POSIX-only) dejó de servir y el lock se migró a la lib
> `filelock` (POSIX `fcntl` / Windows `msvcrt`) sobre un sidecar `audit.jsonl.lock`. El
> contrato (cadena hash coherente bajo concurrencia sidecar↔MCP) y el test
> `test_audit_lock.py` siguen igual; lo único que cambia es el mecanismo de adquisición
> del lock. Las menciones de `fcntl.flock` en el cuerpo histórico de este documento
> reflejan el cierre original de S1.

Plan operativo para construir el primer servidor MCP de FORENSIA y dejarlo demoable a los
compañeros y al PI. Es el desglose accionable del MCP número 1 declarado en
[`docs/maletin/inventario-mcps.md`](inventario-mcps.md): un servidor que publica los 16 `Tool` del
catálogo (`backend/forensia/toolkit/catalog.py`) por protocolo MCP, delegando en el
`dispatcher` existente sin reimplementar nada, con **patrón Jira para selección de caso y
evidencia**.

> **Objetivo de la demo**: arrancar Claude Desktop (cliente MCP de terceros, sin saber
> nada de FORENSIA) y reproducir un flujo natural — "¿qué casos tengo?" → "usa el caso
> Windows" → "analiza la evidencia con `volatility3 windows.pslist`" — sobre una evidencia
> ya registrada (el memdump real Windows 7 SP1 de 5 GiB del caso `f3abd274...`). En
> paralelo, en otro panel, el `ForensicAgent` propio de FORENSIA ejecuta la misma cadena
> conectándose como cliente MCP in-process. El cierre: `tail -f audit.jsonl` mostrando
> los runs con argv idénticos por par y `output_files[].sha256` coincidentes — la
> traducción literal de "integración avanzada de los agentes con las herramientas CLI
> mediante protocolos de contexto" del email del PI.

Este plan integra los hallazgos de un panel de 4 expertos (arquitecto MCP, ingeniería
FORENSIA, forensic-soundness/threat model, DFIR practitioner) que revisó la primera
versión del plan el 2026-06-29. Sus desacuerdos están resueltos en §2 y §8.

---

## 1. Dependencias

| Pieza | Detalle | Coste |
|---|---|---|
| SDK Python oficial `mcp>=1.0,<2.0` | Añadir a `backend/pyproject.toml` como extra `[mcp]`. `pip install -e .[mcp]` en el venv del backend. | Trivial. |
| `mcp` CLI para validar | Para tests automatizables e iteración rápida. Viene con el SDK. | Cero extra. |
| Claude Desktop | Cliente cloud externo para la demo en vivo. Descarga oficial + 1 archivo JSON de config. | 5 min. |
| Evidencia real | Reutilizar `~/.forensia/cases/f3abd274.../evidence/cc212366.../original.raw` (memdump Windows 7 SP1, 5 GiB). | Cero. |
| Flag de consentimiento cloud | `FORENSIA_CLOUD_CONSENT=claude_desktop` al arrancar el servidor. Sin esto el servidor se niega a arrancar si está hablando con cliente externo. | Cero — se documenta. |

---

## 2. Decisiones de diseño cerradas tras el panel

| # | Decisión | Estado |
|---|---|---|
| **D1'** | **Patrón Jira para selección de caso**: tools `list_cases()` + `select_case(case_id)` con estado mutable de sesión del servidor. El flujo natural en Claude Desktop es "¿qué casos tengo?" → "usa el caso X". El env var `FORENSIA_CASE_ID` queda como **fallback solo para tests automatizables del CI** — si está presente, se usa como caso preseleccionado; si no, hay que llamar `select_case` antes de cualquier tool forense (RULE 2: fallar loud con `INVALID_PARAMS` + "llama `select_case` primero"). | **Cerrada** |
| **D2'** | **Patrón Jira simétrico para evidencia**: tools `list_evidence()` + `select_evidence(evidence_id)` operando sobre el caso seleccionado. Si el caso solo tiene una evidencia y `select_evidence` no se llamó, las tools forenses fallan loud con `INVALID_PARAMS` — NO auto-seleccionar "la única". RULE 2 no admite excepciones cómodas. | **Cerrada** |
| **D3** | **Filtrado por allowlist autoritativo**: `tools/list` = `Tool.os_profiles ∩ AgentPackage.policy.allowed_tools` del paquete del `os_profile` del caso seleccionado. Si no hay paquete cargado para ese perfil, el servidor falla loud al `select_case` (503 equivalente — `INVALID_PARAMS` con mensaje "no agent package for profile X"). Tras `select_case` emite `notifications/tools/list_changed`. | **Cerrada** |
| **D4** | **Pydantic `params_schema` por tool**: cada `Tool` del catálogo declara un `BaseModel` con validators tipados. El servidor MCP serializa con `model_json_schema(mode="serialization")` y aplana `$ref` antes de publicar (algunos clientes MCP no resuelven `$ref` internos). El `params_schema` es la **frontera tipada** — rechaza paths crudos a evidencia, solo acepta `evidence_id` UUID4. | **Cerrada** |
| **D5'** | **Outputs como `resource_link` MCP**: `output_files` se devuelven como bloques `resource_link` con URI `artifact://<case_id>/<run_id>/<relpath>`. El servidor registra un handler `resources/read` que sirve los artefactos con límite de tamaño (~1 MB por read, recortado y marcado `truncated: true` si es más). Sin esto, Claude Desktop recibe strings opacos y la demo es fake. | **Cerrada** |
| **D6** | **Transporte stdio puro**. El servidor NO abre sockets de red, verificable por test (`lsof` post-arranque). Streamable HTTP / SSE solo entran tras revisión explícita de threat model — no es decisión de implementación. | **Cerrada** |
| **D7** | **Standalone para la demo, in-process para la integración**: la demo arranca `python -m forensia.mcp` como subproceso de Claude Desktop. En paralelo, el `ForensicAgent` propio se conectará como cliente MCP **in-process** dentro del sidecar (modificación al loop del agente). Ambos comparten el mismo `dispatcher`, `EvidenceManager`, `AuditLog` (con flock — ver L5). El standalone es modo dev/demo; no se distribuye al usuario final como binario PyInstaller separado. | **Cerrada** |

---

## 3. Layout en disco

```
backend/forensia/mcp/
├── __init__.py
├── __main__.py            # `python -m forensia.mcp` → arranca el servidor stdio
├── toolkit.py             # servidor MCP: list_tools/call_tool sobre catalog.BY_ID
├── session.py             # estado mutable: SelectedCase, SelectedEvidence
├── jira_tools.py          # list_cases, select_case, list_evidence, select_evidence
├── schemas.py             # serialización Pydantic → JSON Schema MCP (aplana $ref)
├── resources.py           # handler resources/read sirviendo artifact://
└── redaction.py           # aplica policy/redaction.yaml a samples antes de responder

backend/forensia/toolkit/
├── catalog.py             # extender cada Tool con `params_schema: type[BaseModel]`
└── tools/
    ├── volatility3.py     # añadir VolatilityParams(BaseModel) con plugin enum
    ├── tsk_mmls.py        # MmlsParams
    └── ...                # 14 más

backend/forensia/audit/
└── log.py                 # añadir fcntl.flock para concurrencia (L5)

backend/tests/
├── test_mcp_toolkit.py    # round-trip + select flow + listChanged + differential
└── test_audit_lock.py     # concurrencia AuditLog con flock

docs/
└── mcp-toolkit-s1.md    # este documento
```

---

## 4. Pasos en orden (panel-inverted)

| # | Paso | Output | Coste real |
|---|---|---|---|
| 1 | Añadir `mcp>=1.0,<2.0` a `pyproject.toml [project.optional-dependencies] mcp`, `pip install -e .[mcp]` | venv funcional, `python -c "import mcp"` ok | 15 min |
| 2 | **Añadir `fcntl.flock` a `AuditLog.append`** + test de concurrencia (L5 — antes del MCP, no después) | AuditLog thread/process-safe | ½ día |
| 3 | **Server skeleton + UN tool hardcoded** (`tsk_mmls` con schema inline mínimo). Round-trip in-process verde. Esto valida el SDK antes de invertir tiempo en schemas. | `python -m forensia.mcp` arranca, cliente in-process lista 1 tool, call_tool funciona | 1 día |
| 4 | **Estado de sesión** (`session.py`) + Jira tools (`list_cases`, `select_case`, `list_evidence`, `select_evidence`) + `tools/listChanged` emitido al cambiar de caso | Flujo Jira funcionando, sin tools forenses todavía | 1.5 días |
| 5 | **Pydantic schemas para los 12 tools simples** (`file_info`, `xxd_head`, `strings_head`, `tsk_mmls`, `tsk_fls`, `tsk_mactime`, `ewf_info`, `evtxecmd`, `mftecmd`, `regripper`, `yara`, `jq`). Inyectar en MCP `inputSchema` con aplanamiento de `$ref`. | 12 tools publicadas, validadas | 1 día |
| 6 | **Pydantic schemas para los 4 tools complejos** (`volatility3` con plugin enum curado, `bulk_extractor` con scanner enum, `tsk_icat`, `hayabusa`/`chainsaw`). | 16 tools publicadas | 1.5 días |
| 7 | **Wiring final del MCP server**: itera `BY_ID` filtrado por `package.policy.allowed_tools`, en `call_tool` valida con `BaseModel` y delega en `dispatcher.execute(tool_id, params, case_id=session.case_id)` | Tools forenses ejecutables vía MCP | 1 día |
| 8 | **Cloud consent + redaction** (L3 + L6): `FORENSIA_CLOUD_CONSENT` requerido si servidor publica a cliente externo; entradas `mcp_session_open`/`mcp_session_select_case`/`mcp_session_close` en `audit.jsonl` con `consent_ref`. Pasada de `policy/redaction.yaml` del paquete activo sobre `stdout_sample`/`stderr_sample` antes de responder. | Cloud opt-in atado, redaction aplicada | 1 día |
| 9 | **Resource links + `resources/read`** (D5'): outputs como `resource_link` con URI `artifact://`; handler que sirve los archivos con límite de tamaño. Test que Claude Desktop puede leer. | output_files navegables desde el cliente MCP | ½ día |
| 10 | **Tests**: round-trip, happy path Jira flow, `listChanged` on case switch, `INVALID_PARAMS` sin select, differential `dispatcher.execute` directo vs `mcp_client.call_tool` → `dispatcher.execute` (comparar `argv`, `exit_code`, `output_files[].sha256`). 322/322 legados siguen verdes. | Suite verde | 1 día |
| 11 | **E2E real**: spawn server, conectar cliente, hacer `list_cases → select_case Windows → list_evidence → select_evidence → volatility3 windows.pslist` contra el memdump real. Verificar respuesta + `audit.jsonl` + `output_files` persistidos en disco. | Demo reproducible | ½ día |
| 12 | **Claude Desktop config + capturas**: `claude_desktop_config.json` con `command: python -m forensia.mcp`, `env: { FORENSIA_CLOUD_CONSENT: claude_desktop }`. Reproducir el flujo natural y capturar pantalla. | Materiales para presentación | ½ día |
| 13 | **`inventario-mcps.md §10`** marcar S1 hecho + commit + push | Inventario al día (RULE 4) | ½ h |

**Total estimado**: ~10 días-persona. Con 2 personas en paralelo (uno schemas, otro server + Jira tools), 5-6 días reales.

---

## 5. Definition of done para la demo

### Funcional

- [ ] `python -m forensia.mcp` arranca el servidor stdio sin errores con `FORENSIA_CLOUD_CONSENT=claude_desktop` exportado.
- [ ] `mcp` CLI conecta, hace `initialize`, recibe `serverInfo`, hace `tools/list` (4 Jira tools + ningún tool forense hasta select_case), llama `list_cases` → ve la lista real, llama `select_case(uuid)` → recibe `notifications/tools/list_changed`, hace `tools/list` de nuevo → ve N tools forenses filtradas por `os_profile + policy.allowed_tools`.
- [ ] Claude Desktop con FORENSIA configurado puede listar casos, seleccionar uno, listar evidencias, seleccionar una, y ejecutar `volatility3 plugin=windows.pslist.PsList` con resultado real.
- [ ] El run queda registrado en `~/.forensia/cases/<id>/audit.jsonl` con argv literal — exactamente como si lo hubiera lanzado el agente nativo.
- [ ] `audit.jsonl` también contiene `mcp_session_open` con `consent_ref` + `mcp_session_select_case` + `mcp_session_close`.
- [ ] `output_files` se sirven vía `artifact://` y Claude Desktop puede leerlos (handler `resources/read` funcional).
- [ ] `stdout_sample`/`stderr_sample` pasan por `policy/redaction.yaml` del paquete activo.

### Tests

- [ ] Round-trip in-process: cliente arma, `initialize`, llama todos los flujos felices, sale limpio.
- [ ] Happy path Jira: `list_cases` → `select_case` válido → `tools/list_changed` recibido → `list_evidence` → `select_evidence` → tool forense.
- [ ] Error paths: `select_case(uuid-inexistente)` → `INVALID_PARAMS` con mensaje accionable. Llamar tool forense sin `select_case` → `INVALID_PARAMS` con "call `select_case` first". Llamar `select_case` para perfil sin paquete cargado → `INVALID_PARAMS` con "no agent package for profile X".
- [ ] `listChanged` correcto: al cambiar de caso `unix → windows`, la lista de tools cambia (allowlists distintas).
- [ ] Differential: ejecutar `volatility3 windows.info` con los mismos params (a) via `dispatcher.execute()` directo, (b) via `mcp_client.call_tool` → `dispatcher`. Comparar `argv` (idéntico), `exit_code` (idéntico), `output_files[].sha256` (idéntico). **NO comparar stdout** (volatility emite timestamps en metadata).
- [ ] Concurrencia AuditLog: dos appends paralelos con flock → cadena hash intacta, verificable con `AuditLog.verify()`.
- [ ] `lsof` post-arranque del servidor MCP: cero sockets de red abiertos.
- [ ] 322 tests legados siguen verdes.

### Forense / seguridad

- [ ] Sin `FORENSIA_CLOUD_CONSENT` y con cliente externo, el servidor falla loud al arrancar con mensaje accionable.
- [ ] Schemas Pydantic rechazan campos `path`/`file`/`image_path`/`dump_path` que no sean `evidence_id` UUID4 derivado del estado de sesión.
- [ ] El servidor MCP no escribe en `audit.jsonl` directamente — solo `dispatcher.execute()` lo hace (verificable por inspección del log: una entrada por run, no dos).
- [ ] Redaction se aplica a `stdout_sample`/`stderr_sample` antes de la respuesta MCP, no después.

---

## 6. Fuera de alcance de este sprint (S1)

- ❌ Distribuir `python -m forensia.mcp` standalone como binario PyInstaller separado. Sigue siendo modo dev/demo.
- ❌ Los demás MCPs del inventario (`mcp-mitre-attack`, `mcp-cases`, `mcp-audit`, `mcp-yara-rules`, etc.) — sprints posteriores.
- ❌ Docker-compose como envoltorio de arranque — el servidor corre en el venv del backend.
- ❌ Reanudar sesión MCP tras reinicio del servidor — el estado mutable es in-memory por proceso.
- ❌ Múltiples clientes concurrentes — un servidor por cliente (Claude Desktop spawnea uno, el `ForensicAgent` in-process consume otro).

---

## 7. Líneas rojas innegociables (consolidadas del panel)

| ID | Línea roja | Cómo se verifica |
|---|---|---|
| **L1** | El servidor MCP **no escribe en `audit.jsonl`** directamente. Una sola entrada por run, escrita por `dispatcher`, con argv literal. El adaptador MCP es transparente al log. | Test que valida exactamente 1× `tool_run_start` + 1× `tool_run_finish` por `call_tool`. |
| **L2** | **Ningún parámetro MCP acepta paths crudos a evidencia**. Solo `evidence_id` UUID4 resuelto vía `EvidenceManager`. | Pydantic `params_schema` valida formato; tools forenses NO tienen `image_path`/`dump_path` en sus schemas — esos los inyecta el `dispatcher` desde la sesión. |
| **L3** | **Cloud opt-in obligatorio con cliente cloud**. Sin `FORENSIA_CLOUD_CONSENT` el servidor se niega a arrancar. `mcp_session_open` con `consent_ref` registrada en audit. | Test: lanzar `python -m forensia.mcp` sin la env var → exit≠0 con mensaje accionable. |
| **L4** | **Stdio puro, sin sockets de red**. SSE/HTTP solo tras revisión explícita de threat model. | Test post-arranque verifica `lsof -i -P -n` sobre el PID del servidor: cero entradas. |
| **L5** | **`AuditLog.append` con `fcntl.flock`** antes de codear el MCP. Sin esto la cadena hash se rompe silenciosamente en concurrencia. | Test que arma dos appends paralelos y verifica con `AuditLog.verify()`. |
| **L6** | **Redaction de outputs aplicada antes de responder**. `policy/redaction.yaml` del paquete del agente del caso activo se aplica a `stdout_sample` y `stderr_sample`. | Test con un patrón fácil de redactar (e.g. una IP) y verificar que la respuesta MCP la trae redactada. |

---

## 8. Riesgos identificados con mitigaciones del panel

| Riesgo | Mitigación |
|---|---|
| SDK Python `mcp` no acepta Pydantic `$ref` y rompe en algunos clientes | Aplanar `$ref` con `jsonref.replace_refs` antes de publicar `inputSchema`. Validar contra Claude Desktop en paso 3 (round-trip con un tool) antes de invertir tiempo en los 16. |
| Claude Desktop no resuelve `FORENSIA_CLOUD_CONSENT` del entorno del subproceso | El config de Claude Desktop soporta `env:`; documentar el snippet exacto en §11 del plan ejecutado. |
| Volatility3 emite timestamps no deterministas en stdout — el differential test fallaría sobre bytes | Comparar `output_files[].sha256` (estable) + `exit_code` + estructura `parsed`, NO bytes de stdout. |
| Conexión Claude Desktop cierra stdin abruptamente, deja `subprocess.run()` de `dispatcher` huérfano | Manejar `asyncio.CancelledError` en `call_tool` y propagar `subprocess.terminate()`. Test con SIGTERM al servidor durante un run. |
| Estado de sesión inconsistente si el modelo llama tools forenses antes de `select_case` | `INVALID_PARAMS` con mensaje accionable en cada tool forense; documentado en `description` del schema MCP para que el modelo lo sepa de antemano. |
| Payload size — `volatility3 timeliner` puede generar MBs de stdout | `stdout_sample` acotado a 64 KB; el resto vive como `resource_link` artifact. |

---

## 9. Decisiones para confirmar al arrancar

1. **Versión target del SDK MCP**: `mcp>=1.0,<2.0` (pinneado). ✅ confirmado.
2. **`FORENSIA_CLOUD_CONSENT`** como flag obligatoria con cliente externo. ✅ confirmado.
3. **Formato de la demo al equipo**: vivo en la reunión + capturas estáticas + grabación de respaldo (3 min). ✅ confirmado por DFIR review.
4. **Quién lleva el código**: el operador actual + el supervisor lo revisa antes de mergear a `main`. ✅ implícito.

---

## 10. Materiales para la reunión del equipo

- Este `mcp-toolkit-s1.md` + `inventario-mcps.md` en el repo.
- `claude_desktop_config.json` de ejemplo con FORENSIA registrado y el consent flag.
- Grabación de 90 s del flujo natural "list_cases → select_case → list_evidence → volatility3 windows.pslist" en Claude Desktop.
- Captura del `audit.jsonl` post-run con argv literal idéntico al del agente nativo.
- Una slide con la tabla de §2 (las 7 decisiones cerradas) — para los compañeros que prefieran texto a demo.

La pregunta para los compañeros tras la demo: **"¿Aprobamos `mcp-toolkit` + `mcp-evidence` como sprint S1-S2 del cronograma del TFM, con `mcp-mitre-attack` como S3?"**.
