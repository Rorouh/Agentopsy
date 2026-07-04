# FORENSIA — Próximos pasos

Inventario único de deuda técnica y trabajo pendiente. Cualquier conversación,
diseño futuro o nueva tarjeta de Kanban debería **enlazar a un ítem de aquí**
en vez de inventar otra lista paralela.

> **Por qué existe este doc**: la deuda vivía dispersa entre cuerpos de commit,
> la sección `## Status` de `CLAUDE.md` y conversaciones en chat. Esto la
> centraliza. La capa de **agentes / orquestador / RAG / MCP / evals** tiene su
> propio diseño detallado en [`diseno-fase2.md`](../agentes/diseno-fase2.md);
> aquí solo se referencia.

---

## Pivote 2026-07-02 — Docker Compose total + ejecutores CLI sin API keys (propuesta v1.2)

Decisión definitiva del equipo (revierte el desvío a "instalable nativo / Electron",
que fue un error de comunicación):

- **Entrega**: todo el proyecto se despliega con `git clone` + `docker compose up
  --build` y se usa desde el navegador en `http://127.0.0.1:5173`. Cinco servicios:
  `web` (React), `api` (FastAPI), `ollama`, `toolkit-windows`, `toolkit-unix`. Sin
  instalador nativo, sin Electron, sin PyInstaller, sin firma de código, sin
  auto-update. Puertos publicados solo en `127.0.0.1`.
- **Sin API keys**: los prompts de Investigación corren por el ejecutor que elige el
  operador — Claude Code (`claude -p`), Codex CLI (`codex exec`), Gemini CLI
  (`gemini -p`) u Ollama (HTTP al servicio del compose). Los CLIs van instalados en la
  imagen del servicio `api` y se autentican con la sesión del volumen `forensia-cli-auth`
  (el entrypoint la *seedea* una vez desde las credenciales del host montadas read-only
  como staging, o el operador inicia sesión dentro del contenedor). `ANTHROPIC_API_KEY` /
  `OPENAI_API_KEY` desaparecen del proyecto. RULE 2: sin ejecutor seleccionado → error
  accionable, jamás un default silencioso.

**Estado**: documentación realineada (raíz + `docs/`) el 2026-07-02. Trabajo de código
pendiente, en la rama `feature/compose-y-cli-executors`:

- [x] Servicios `web` / `api` / `ollama` en el compose raíz — hecho el 2026-07-02:
      `docker-compose.yml` vive ahora en la raíz del repo y levanta los cinco
      servicios. La imagen `api` (`docker/api/Dockerfile`) instala el backend y
      los tres CLIs con versiones fijadas; su entrypoint seedea al volumen
      `forensia-cli-auth` las credenciales del host montadas read-only como staging
      (o el operador inicia sesión en el contenedor); `web` (`docker/web/`) compila la SPA de `web/` y la sirve con
      nginx (proxy `/api`+`/ws` hacia el api) desde el 2026-07-02.
- [x] Capa de ejecución `PromptExecutor` con los cuatro ejecutores — hecho el
      2026-07-02: `backend/forensia/executors/` (Claude Code / Codex CLI / Gemini
      CLI como subprocesos `shell=False` con flags verificados en la doc oficial
      de cada CLI; Ollama por HTTP stdlib a `OLLAMA_HOST`). `models/cloud.py` y
      `models/local.py` eliminados; `models/base.py` queda como adapter
      (`ExecutorBackend`, camino degradado prompt estructurado + parser estricto)
      hacia `ForensicAgent`. Cada ejecución se registra en el audit log con el
      argv literal. `/api/agent/query` exige `executor` en la petición (o
      `DEFAULT_EXECUTOR` fijado explícitamente por el usuario) — sin selección →
      422 accionable; seleccionado pero inutilizable → 503 con la razón;
      ejecutor cloud sin consentimiento registrado para el caso → **403**
      (`forensia.consent`, gate no solo-UI; ollama nunca lo requiere). El demo
      loop por keywords y la respuesta skeleton se eliminaron (eran degradaciones
      silenciosas contrarias a RULE 2).
- [ ] Volumen `forensia-cli-auth` + staging ro de credenciales CLI + exclusión del
      volumen y del staging de `evidenceRoot` + gate 19 del modelo de amenazas (con
      test). Seeding idempotente y `is_available()` real por CLI ya implementados y
      testeados (2026-07-03: `test_cli_auth_seeding.py`, `test_executors.py`); pendiente
      el test del confinamiento de paths (gate 19).
- [x] Retirar `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` del allowlist de
      `routers/config.py`, del código y de los tests — hecho el 2026-07-02
      (resuelve D-3 de §7). Claves editables ahora: `DEFAULT_EXECUTOR` (opcional,
      lo fija el usuario en Settings), `OLLAMA_HOST` y `OLLAMA_MODEL`; dependencia
      `openai` y extra `[models]` fuera de `pyproject.toml`; test de regresión
      (`tests/test_executors.py`) que barre `backend/` y falla si las cadenas
      reaparecen. `capabilities` reporta los cuatro ejecutores con su razón
      accionable cuando no están disponibles.
- [x] Migrar la SPA React al servicio `web` — hecho el 2026-07-02:
      `desktop/renderer/` se movió a `web/` (raíz) como app Vite independiente sin
      Electron; la cadena `window.forensia`/IPC se sustituyó por el cliente HTTP
      tipado (`web/src/api/client.ts`) con token de sesión obtenido de
      `GET /api/session` (solo memoria, mismo-origen; nuevo
      `forensia/routers/session.py` + `FORENSIA_UI_ORIGINS` en el Host-check).
      La UI añade el selector de ejecutor con razones accionables, el aviso +
      consentimiento cloud auditado (`POST /api/agent/cloud-consent`) y la bandeja
      de evidencias (`GET /api/evidence/sources`, `./evidence` del host) en lugar
      del diálogo nativo. `docker/web/` pasa de placeholder a build real
      (node → nginx con proxy). Tests en `backend/tests/test_web_surface.py`.
- [x] Desmontar el modelo antiguo — hecho el 2026-07-02: eliminados `desktop/`
      (Electron main/preload, electron-builder), `docker/agent/` (`forensia_agent`
      con providers de API keys; su orquestador/prompts/informe estaban superados
      por `backend/forensia/agent/` + `agentes/`), `vendor/` +
      `scripts/bundle-tool.mjs`, `backend/build/forensia.spec` (PyInstaller),
      `scripts/build-images.sh` y `.github/workflows/release.yml` (pipeline de
      instaladores). El resolver del toolkit ya no busca en `vendor/` ni dentro
      del bundle PyInstaller (`bundled` = env override → PATH del host). Queda
      `images/` (imágenes por-herramienta que el catálogo aún referencia) hasta
      absorberlas en los maletines — ver sección A.

Los ítems de las secciones siguientes que asumían el modelo anterior quedan marcados
como **[SUPERSEDIDO]** con puntero aquí, en vez de borrarse en silencio.

---

## 0. Lo que YA está hecho (estado a 2026-06-28)

Resumen para que un nuevo contribuidor no repita trabajo. Detalle por slice
en los cuerpos de commit (`git log --oneline main`).

> **Nota**: snapshot previo al pivote del 2026-07-02. Las filas que citan Electron /
> sidecar / `electron-builder` / `main.cjs` describen el modelo de entrega anterior:
> el trabajo hecho sigue siendo real, pero esas piezas de entrega se desmontan (ver la
> sección del pivote, arriba).

| Capa | Estado |
|---|---|
| Esqueleto Electron + sidecar Python | ✅ Operativo. Race de `FORENSIA_SIDECAR_READY` arreglado. |
| Seguridad de transporte (gates 1-3, 5) | ✅ Token + Host-header + CORS exacto + tests `test_security_gates.py`. |
| RULE 1 (delivery: bundled \| container) | ✅ Política aceptada en `CLAUDE.md`, reflejada en catálogo, executor y resolver. |
| Storage caso-como-carpeta | ✅ Cases / Evidence / Artifacts / Chats / Audit (hash-chained) / Findings. storage.md documentado. |
| EvidenceManager real | ✅ Hash gate completo (stream SHA-256 → copy → re-hash → chmod 0o444 → baseline.json → apend `evidence_register` al audit). `verify()` persiste a `verification.json` + apenda `evidence_verify` (expuesto en `POST /api/cases/{id}/evidence/{eid}/verify`). Ambos eventos en la cadena hash-chained (forensic invariant 4). |
| Catálogo de tools | ✅ 16 core (incl. `file_info`, `xxd_head`, `strings_head`) + 6 extended (stubs). Wrappers reales para los 16 core. |
| Dispatcher | ✅ Bundled + container path, con `case_id` opcional para anclar ArtifactRun + audit. |
| Pipeline OCI | ✅ Dockerfiles `regripper`, `evtxecmd`, `mftecmd` + `scripts/build-images.sh` + bundling en `electron-builder` + loader en `main.cjs`. **Falta correr el script** (ver §1.A). |
| Agente real (cloud LLM) | ✅ `CloudBackend` OpenAI con tool-calling nativo + `ForensicAgent.run()` con allowlist + inyección de paths + tool interna `record_finding`. |
| Paquetes de agente declarativos | ✅ `forensia-unix`, `forensia-windows`, `_orchestrator` (ignorado por registry por convención `_`). Loader + tests. |
| Triage de evidencia (`forensia.triage`) | ✅ Fingerprint determinista de `(family, kind)` (sin LLM, sin tools externas) en `register()`, persistido a `baseline.json`, lazy-backfill en `get()`. `family ∈ {unix, windows, unknown}` por marcadores OS; `kind ∈ {disk, memory, container_disk, unknown}` por cabeceras (LiME / PAGEDU64 / E01 / VMDK / VDI / QCOW / VHD / VHDX), MBR/GPT/NTFS/ext, y scoring PE-scatter + RSDS + página 0 vacía para detectar volcados RAM Volatility-style. Las dos axes van al system prompt del agente. |
| Guard rail de perfil en los prompts | ✅ Regla nueva en `system.md` de `forensia-unix` y `forensia-windows`: ante mismatch detectado, el agente se niega a invocar tools y pide a la operadora reabrir el caso con el perfil correcto. RULE 2 intacta: nunca auto-switch. |
| Banner de desajuste en UI | ✅ `InvestigationPage` muestra un banner amarillo cuando `evidence.detected_os` discrepa de `case.os_profile`, con copy explicando que el cambio lo hace el operador (no FORENSIA). El header del caso también muestra `detectado <os> / <kind>` cuando hay señal. |
| Memoria conversacional del agente | ✅ `QueryRequest.session_id` + nuevo `forensia.agent.history.build_replay_messages(case_id, session_id)` que lee `ChatStore` y construye prefix de OpenAI messages: ledger de tool runs (de `tool_calls` persistidos en assistant ChatMessages) + ledger de findings + tail-capped user/assistant transcript. Splicea entre system y user. Cap: 6 turnos / 8K chars / 30 entradas de ledger. El frontend ya envía `session_id` y persiste `tool_calls` con cada respuesta de la API. |
| Routing por `detected_kind` + max_iter 18 | ✅ `_system_prompt` añade «Ruta del playbook — MEMORY DUMP/DISK IMAGE/CONTAINER» según `detected_kind`, ahorrando al agente la ronda de fail-and-pivot. `max_iterations` subido de 12 a 18 en ambos `agent.yaml` para que los turnos "hazlo" puedan encadenar 4-6 tool calls. |
| **MCP `mcp-toolkit` S1 (rama `mcp`)** | ✅ Servidor MCP standalone (`python -m forensia.mcp`) que expone los 16 tools del catálogo como herramientas MCP estándar. Patrón Jira (`list_cases`/`select_case`/`list_evidence`/`select_evidence`). Verificado E2E con Claude Desktop sobre el memdump real Windows 7 SP1 de 5 GiB. Líneas rojas L1-L6 verificadas por panel de 4 expertos en 2 rounds. Concurrencia con el sidecar HTTP vía `filelock` cross-platform sobre el sidecar `audit.jsonl.lock`. Detalle en [`mcp-toolkit-s1.md`](../maletin/mcp-toolkit-s1.md). |
| `AuditLog` concurrencia | ✅ `filelock` exclusivo cross-platform sobre el sidecar `.lock`; cadena hash sobrevive a appends concurrentes desde el sidecar HTTP y el servidor MCP. Test `test_audit_lock.py` con `multiprocessing` (4 workers × 50 entradas). |
| `apply_in` por patrón de redaction | ✅ `RedactionPattern.apply_in: ("strict",)` por defecto; los patrones que opten a `("strict","relaxed")` se aplican incluso en modo relajado. Loader valida el campo. Permite preservar IoCs forenses (IPs, MACs, SIDs) en sesiones locales sin perder scrubbing de credenciales. |
| Regla "No fallbacks" en CLAUDE.md | ✅ RULE 2 reforzada con cinco corolarios explícitos: no "try the other tool", no "use the only/latest one", no "guess from context", no "default to cloud", no "downgrade silently". |
| UI desmoqueada | ✅ Casos y evidencias, Investigación (con findings panel reactivo), Settings (form de modelos + dropdown). |
| Tests backend | ✅ **335** (322 legacy + 10 MCP toolkit + 3 audit lock concurrency). 0 fallos. |

---

## 1. Críticos para una demo defendible del TFM

Ratio impacto / esfuerzo más alto. Si solo se atacan estos 4, hay demo:

### A. ~~Construir las 3 imágenes OCI~~ **[SUPERSEDIDO por el pivote 2026-07-02]**

El mecanismo de imágenes OCI sueltas (`scripts/build-images.sh` →
`desktop/resources/images/{regripper,evtxecmd,mftecmd}.tar` cargadas por `main.cjs`)
era parte del modelo instalable. En el modelo compose, RegRipper / EvtxECmd / MFTECmd
viven en la imagen del maletín `toolkit-windows`, que se construye con el resto del
stack en `docker compose up --build` (RULE 1). Trabajo restante: absorber esos
Dockerfiles en la imagen del maletín y retirar `scripts/build-images.sh` cuando la rama
del pivote aterrice.

**Realineación del modelo + reporte — hecho el 2026-07-03** (rama
`feature/compose-y-cli-executors`): cada entrada de `catalog.py` declara ahora en qué
maletín vive (`toolkits=`: `toolkit-unix` / `toolkit-windows`; los tools del stage `base`
en ambos). El nuevo `forensia.toolkit.maletin` sondea cada maletín (¿contenedor en
ejecución? ¿binario presente?) y `capabilities` reporta por tool `{available, toolkits,
reason}` + una sección `toolkits` con el estado de cada maletín — antes el mapa salía
todo `false` porque el resolver miraba el `PATH` del contenedor `api` (que no lleva
ninguna tool). RULE 2 intacta: un tool solo se resuelve contra los maletines que declara;
sin sustituciones. La SPA (`SystemStatusPage`, `SettingsPage`) consume la nueva forma.

**Restante concreto de §A** (el sondeo lo delata ahora con razón accionable):
- ~~**RegRipper**~~ ✅ **reconciliado (2026-07-04):** el catálogo apunta a `rip.pl` (el binario
  real del maletín) y se retiró su `delivery`/`container_image`/`host_mounts` legacy; ahora se
  ejecuta por el exec-agent como el resto (verificado: 7 plugins sobre las 5 hives → findings).
- **EvtxECmd / MFTECmd** (.NET) **aún no están** en el Dockerfile del maletín — el catálogo
  todavía referencia las imágenes OCI muertas (`forensia/evtxecmd:latest`, `forensia/
  mftecmd:latest`) por el `delivery`/`container_image` legacy. Absorber .NET Core + esas
  tools en el stage `windows`.
- Retirar `scripts/build-images.sh` (ya eliminado en el desmontaje) y el `delivery`/
  `container_image` legacy del catálogo cuando la ejecución se unifique (ver más abajo).

### B. ~~Instalar el maletín bundled en el Mac de dev~~ **[SUPERSEDIDO por el pivote 2026-07-02]**

El mecanismo "bundled" (binarios en el host del desarrollador / `vendor/`) desaparece:
la única vía de entrega de tools son las imágenes de los maletines (`toolkit-windows` /
`toolkit-unix`) construidas por el compose, idénticas en los tres SOs del host. Trabajo
restante: asegurar que `bulk_extractor`, `yara`, `hayabusa` y `chainsaw` están en los
Dockerfiles de `docker/` con versión pineada, y que `capabilities` los reporta desde
los contenedores.

**Estado tras la realineación (2026-07-03):** `capabilities` ya los reporta desde los
maletines (ver §A). El sondeo confirma `bulk_extractor` en el stage `base` y `hayabusa` /
`chainsaw` en el stage `windows` con versión pineada. **Gap pendiente:** `yara` **no
está** en ningún Dockerfile (ni en `base` ni en `windows`) — el catálogo lo declara core
`("unix","windows")` pero falta instalarlo. Verificar también `xxd`/`strings` (no se
instalan explícitamente en el stage `base`; puede que falten). Todos estos huecos los
delata ahora el sondeo con `reason` = «binario ausente en <maletín>» en vez del antiguo
`false` silencioso.

### B.bis — Canal api→maletín (exec-agent) **[HECHO — canal + sondeo + dispatcher]**

Se eligió la **opción §B (exec-agent)** frente al socket docker en `api` (§A). Montar
`/var/run/docker.sock` en el `api` —componente que procesa evidencia hostil— equivale a
root en el host y `:ro` sobre el socket no es una frontera real; §B evita esa escalada y
respeta SECURITY INVARIANT 1.

**Hecho:**

- **Exec-agent en cada maletín** (`docker/docker/forensic-toolkit/exec_agent.py`): HTTP
  stdlib en la red interna del compose, **sin puerto publicado** (mismo modelo de
  confianza que `ollama`). Endpoints `GET /health`, `POST /which` (presencia de binarios)
  y `POST /exec` (argv shell-free, `subprocess.run(..., shell=False)`); token opcional
  `FORENSIA_EXEC_AGENT_TOKEN`. Los maletines lo arrancan con `command:` en el compose y
  publican `FORENSIA_TOOLKIT_UNIX_URL` / `FORENSIA_TOOLKIT_WINDOWS_URL` al `api`.
- **Sondeo migrado** (`forensia.toolkit.maletin`): `probe_service`/`probe_binaries` hablan
  HTTP con el exec-agent en vez de `docker inspect`/`docker exec`. `capabilities` reporta
  la disponibilidad real de cada tool con el compose por defecto — **sin socket, sin
  cliente docker en el `api`**. Tests: `backend/tests/test_maletin.py`. Diseño y modelo de
  amenazas: [`exec-agent.md`](exec-agent.md).

- **Dispatcher unificado (Parte 2)** — `toolkit/dispatcher.py` ejecuta las tools por el
  exec-agent: si el binario no está en el PATH del `api` (RULE 1), `execute()` selecciona
  el maletín por `os_profile` (`_select_maletin`, sin fallback entre maletines — RULE 2) y
  manda `[binary, *argv]` al `POST /exec` vía `maletin.run_argv_in_maletin`. Rutas sin
  traducción: `/evidence` (ro) y `/cases` están montados en las MISMAS rutas en api y
  maletín. Se retiró el path muerto `docker run <container_image>` (el `delivery`/
  `container_image` legacy del `Tool` queda sin usar). `os_profile` se cablea desde los
  dos llamadores (`agent.py`, `mcp/toolkit.py`). Verificado end-to-end sobre una imagen
  real (`tsk_fls` → 22 entradas, ArtifactRun + audit hash-chained). Tests:
  `backend/tests/test_dispatcher.py`. **Con esto el agente ejecuta herramientas end-to-end
  desde el chat.**

**Pendiente menor:** retirar formalmente los campos `delivery`/`container_image` del
`Tool` y `toolkit/container.py` (hoy sin consumidores en el dispatcher; los conserva
`test_container.py`).

### B.ter — Maletines fijados a `linux/amd64` **[hecho 2026-07-03]**

El PPA GIFT no publica paquetes arm64, así que `toolkit-windows` / `toolkit-unix` llevan
`platform: linux/amd64` en el compose: en Apple Silicon corren bajo emulación
(Rosetta/QEMU) — funcionales pero más lentos en build/análisis; en x86_64, plataforma
nativa, sin coste. Documentado en `README.md` y `docker/README.md`.

### C. Reemplazar TSK por `dissect.target` para mounting

| | |
|---|---|
| **Qué** | Wrapper nuevo `wrappers/dissect_open.py` que use `Target.open(image_path)` de la librería `dissect.target` y devuelva la lista de filesystems detectados + particiones + metadatos. |
| **Por qué** | `tsk_mmls` falla con "Cannot determine partition type" en evidencias sin tabla de particiones convencional (memdumps, sparse, formatos privativos). `dissect.target` auto-detecta E01 / VMDK / DD / raw + ext4 / btrfs / xfs / NTFS / APFS con overlay CoW. Mantener TSK como fallback explícito. |
| **Dónde toca** | `backend/pyproject.toml` `[mounting]` extra nuevo (`dissect.target>=3.4.0`), `backend/forensia/toolkit/wrappers/dissect_open.py` (nuevo), `catalog.py` (nueva entry core), `agent/tool_schemas.py` (schema OpenAI), `agent/agent.py` `_EVIDENCE_INJECTION`, `agentes/forensia-unix/policy/tools.yaml` + `forensia-windows`, playbooks de ambos. |
| **Estimación** | 2-3 h (wrapper + tests + cableo). |
| **Referencia** | PeritIA usa este patrón (`/Users/danielramos/workspace/PeritIA/peritia/acquisition/disk.py`). |

### D. Datasets de prueba reales

| | |
|---|---|
| **Qué** | Descargar al menos uno: NIST CFReDS "Hacking Case" (~1.5 GB E01 + memdump) o NIST "Lone Wolf" (~30 GB Windows 10 + memdump). |
| **Por qué** | Sin datos reales no hay defensa de TFM. El `.raw` que el equipo está usando como prueba sale como "application/octet-stream" en `file` y todas las tools especializadas fallan. |
| **Dónde toca** | Fuera del repo (carpeta de evidencias del operador). |
| **Estimación** | 5-30 min de descarga según conexión. |
| **Referencia** | Listado en `FORENSIA_Alcance_y_Planificacion.md` §5. |

---

## 2. Pendientes por módulo

### `forensia.reports` — generador de informes (no existe)

| | |
|---|---|
| **Qué** | Módulo Python que toma `Finding[]` + `audit.jsonl` + `case.json` y compone Markdown → DOCX (Jinja2 + python-docx). PDF opcional via WeasyPrint. |
| **Por qué** | La carpeta `~/.forensia/cases/<id>/reports/` está reservada en el layout pero nadie escribe ahí. La propuesta TFM exige "Generación de informe forense estructurado". |
| **Dónde toca** | `backend/forensia/reports/__init__.py` + `templates/` + `generator.py` + router `routers/reports.py`. |
| **Estimación** | 1-2 días (incluido template UCM). |
| **Diseño** | `diseno-fase2.md` §4 + `_orchestrator/reporter.md` ya tienen prompt + contrato. |

### `forensia.timeline` — consolidación cronológica (no existe)

| | |
|---|---|
| **Qué** | Módulo que lee todos los `artifacts/<run-id>/manifest.json` + `findings.jsonl` + `audit.jsonl` y produce `TimelineEvent[]` cronológico filtrable por severidad / fuente. |
| **Por qué** | `TimelinePage.tsx` (frontend) sigue con mock data. Sin esto la pantalla "Timeline" no es real. |
| **Dónde toca** | `backend/forensia/timeline/` + `routers/timeline.py` + cableo en `InvestigationPage` "Ver Timeline →" y en `TimelinePage`. |
| **Estimación** | 4-6 h. |
| **Diseño** | `diseno-fase2.md` §4 (orquestador) + `_orchestrator/timeline.md`. |

### Calidad del playbook windows — siete mejoras observadas en sesión real

Tras arreglar memoria conversacional + triage tipado + routing por `kind`, una
sesión real sobre el memdump Windows 7 SP1 + hMailServer dejó al desnudo siete
problemas que YA NO son de infraestructura sino de **prompt-engineering del
playbook**. Todos viven en `agentes/forensia-windows/prompts/playbook.md` y
`system.md`; cero código.

| # | Síntoma | Cambio propuesto en el playbook |
|---|---|---|
| 1 | Severity High para "regiones RWX" en `explorer.exe` y `svchost.exe` sin payload analizado. Falso positivo notorio: CLR/JIT/ASLR pintan RWX legítimo. | Sección B paso 3: «`malfind` por sí solo NO concluye maliciousness — clasifícalo `medium` hasta que `windows.dumpfiles` + hash + comparación devuelva un payload sospechoso». |
| 2 | El finding cita "regiones RWX en `explorer.exe`" sin PID, sin offset, sin primeras instrucciones. | Sección de "Esquema de hallazgo": para `malfind`, exigir `{pid, vaddr, size_bytes, first_bytes_hex[:32]}` como provenance — el output del plugin ya los devuelve. |
| 3 | Missed la storyline: hMailServer + sshd + W7 SP1 EOL + puertos 25/110/143/587 abiertos = casi seguro "compromised mail server" (escenario CTF/CFReDS conocido). El agente reportó inventario, no narrativa. | Nueva sección "Patrones de caso conocidos" en playbook: lista de combinaciones (servicio EOL + puertos atípicos + cuentas locales sospechosas) → hipótesis a verificar, con cita al artefacto correspondiente. |
| 4 | `pslist` y `netscan` se reportan como findings separados. Pierden la correlación PID↔puerto que ya está en sus outputs. | Sección B paso 4: «cuando tengas `pslist` y `netscan` del mismo dump, **emite un único finding** por PID con la tupla `{pid, image, owner, listening_ports, established_remote_eps}` — no dos findings disjuntos». |
| 5 | "Monitoreo de red" como próximo paso — la máquina ya está volcada, no hay red viva. Confunde post-mortem con live response. | Reforzar regla 1 del system prompt: «sugerencias de "monitorizar" / "capturar tráfico en vivo" están PROHIBIDAS — el caso es post-mortem por definición. Si sospechas que falta un PCAP, sugiere "buscar PCAP del incidente en la carpeta del caso", no instalar Wireshark ahora». |
| 6 | "Herramientas adicionales" sigue genérico ("herramientas de análisis de tráfico"). El operador pidió explícitamente sugerencias concretas. | Sección "Cuando tu allowlist no llega": pedir nombres concretos por categoría (forensia de red: Wireshark/tshark, Zeek, Suricata + ET Open; reputación de hashes: hashlookup.circl.lu, MISP, VirusTotal CLI; correlación TTPs: framework MITRE local). No vendor-speak. |
| 7 | El agente reporta RWX en `svchost.exe` (High) pero NO autoencadena `windows.dumpfiles --pid X`, `windows.cmdline --pid X`, `windows.handles --pid X` — todos en su allowlist. | Sección B paso 3, después de `malfind`: «por cada PID flagged, encadena `dumpfiles` + `cmdline` + `handles` en el MISMO turno antes de cerrar. No reportes "regiones sospechosas" sin haber extraído el binario en memoria y hasheado». |

| | |
|---|---|
| **Por qué** | El motor (memoria + triage + routing + max_iter) ya está bien; lo que limita la calidad del análisis ahora es la prosa del playbook. La diferencia entre "inventario forense" y "narrativa pericial" se juega en estas reglas. |
| **Dónde toca** | `agentes/forensia-windows/prompts/playbook.md` (entradas 1, 2, 4, 7 — secciones B paso 3-4 y "Esquema de hallazgo"); `agentes/forensia-windows/prompts/system.md` (entradas 5, 6 — reforzar regla 1 + nueva sección "Cuando tu allowlist no llega"); nueva sección 3 "Patrones de caso conocidos" en playbook (entrada 3, opcional). Aplicar simétrico en `forensia-unix/` cuando aplique (4, 6, 7 sí; 1, 2, 3, 5 con matices). |
| **Estimación** | 2-4 h de pulido + una iteración de prueba contra el mismo memdump para confirmar que el agente ahora autoencadena dumpfiles/cmdline/handles en lugar de cerrar con un finding incompleto. |
| **Observación** | Estas son las siete entradas levantadas en la sesión del 2026-06-29 sobre el caso `f3abd274…` (hMailServer + W7 SP1). Cualquiera con acceso al chat persistido (`~/.forensia/cases/f3abd274.../chats/main.jsonl`) puede reproducir el material de juicio. |

### Acción "Reabrir caso con perfil correcto" (UI)

| | |
|---|---|
| **Qué** | Botón en el banner amarillo de `InvestigationPage` que cierre el caso actual y lance el formulario de creación con `os_profile` pre-rellenado al `detected_os`. Hoy el banner es solo texto: la operadora tiene que ir a "Casos y evidencias" a mano. |
| **Por qué** | El backend ya conoce el desajuste (`forensia.triage`) y el agente ya rechaza ejecutar tools (guard rail). Lo único que falta es bajar la fricción del flujo correcto. **RULE 2 sigue intacta**: el botón abre el formulario, no crea el caso automáticamente. |
| **Dónde toca** | `web/src/pages/InvestigationPage.tsx` (botón) + `RepositoryPage.tsx` (aceptar `?prefilledProfile=…` o equivalente) + posible nuevo endpoint para "re-registrar evidencia a otro caso" si no se quiere obligar a re-hashing. |
| **Estimación** | 2-3 h. |

### [HECHO 2026-07-02] Capa de ejecución (`PromptExecutor`) — sustituye a `models.local` / `models.anthropic`

> **Hecho el 2026-07-02** — ver los dos ítems marcados `[x]` en el checklist del
> pivote (arriba). Implementación en `backend/forensia/executors/`; queda como
> registro del diseño original.

| | |
|---|---|
| **Qué** | Implementar la capa de ejecución del pivote 2026-07-02: interfaz `PromptExecutor` + cuatro ejecutores — Claude Code (`claude -p`), Codex CLI (`codex exec`) y Gemini CLI (`gemini -p`) como subprocesos `shell=False` dentro del servicio `api`, y Ollama por HTTP al servicio del compose con el camino degradado (prompt estructurado + parser + allowlist + reintentos, porque el tool-calling nativo en modelos open es frágil). |
| **Por qué** | Sin API keys en el proyecto: el operador usa su propia suscripción (CLIs con la sesión del volumen `forensia-cli-auth`, seeded del host o login en el contenedor) u Ollama como vía 100 % local. La comparativa entre los cuatro ejecutores es la contribución experimental del TFM. RULE 2: sin ejecutor seleccionado → 503 accionable, jamás un default. |
| **Dónde toca** | `backend/forensia/` (nueva capa que reemplaza `models/local.py` y `models/cloud.py`), routers, capabilities, y limpieza de `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` en `routers/config.py` + tests. Diseño en `arquitectura.md` §5 y `diseno-fase2.md` §8. |
| **Estimación** | 2-4 días + tests (incluye la advertencia + consentimiento auditado para ejecutores respaldados por cloud — gate 9). |

Los antiguos ítems `models.local` (Ollama `NotImplementedError`) y `models.anthropic`
(clave aceptada sin uso) quedan absorbidos aquí: el primero se convierte en el ejecutor
Ollama; el segundo desaparece — no habrá backend por SDK con API key (resuelve D-3 de §7).

### Páginas frontend aún mock

| Página | Mock que falta cablear |
|---|---|
| `TimelinePage.tsx` | Necesita `forensia.timeline` (ver arriba). |
| `DocumentViewerPage.tsx` | Necesita `forensia.reports` (ver arriba). |
| `MitreAttackPage.tsx` | Necesita `_orchestrator/mitre.md` ejecutado por la capa de síntesis. |
| `SettingsPage` tabs "Operador" / "Reportes" / "Seguridad" / "Acerca de" | Inputs aún `disabled`. Operador + Reportes podrían persistirse vía el mismo `/api/config` extendiendo el allowlist. Seguridad es UI conceptual. |
| `GuidePage.tsx` | Estática, OK como tal por ahora — el contenido refleja el flujo real. |

---

## 3. MCP y RAG (estado y siguiente sprint)

Cubierto en detalle en [`inventario-mcps.md`](../maletin/inventario-mcps.md) (13 servidores
inventariados, priorizados P0–P3) y [`mcp-toolkit-s1.md`](../maletin/mcp-toolkit-s1.md)
(plan operativo + decisiones D1–D7 cerradas + líneas rojas L1–L6).
**No duplicar aquí.** Estado real:

- **`mcp-toolkit` (P0, sprint S1)** — ✅ **CERRADO** en la rama `mcp`. Servidor
  MCP standalone con patrón Jira + 16 tools forenses + ResourceLinks +
  redaction modes + consent flag. Verificado E2E con Claude Desktop sobre el
  memdump real. 2 rounds de panel de expertos.
- **`mcp-evidence` (P0, sprint S2)** — pendiente. Resource server independiente
  con URIs `evidence://<case>/<id>`. Cuando se integre el `ForensicAgent`
  propio como cliente MCP in-process, este será la frontera de custodia
  visible para los demás MCPs.
- **`mcp-mitre-attack` (P0, sprint S3)** — pendiente. Bundle ATT&CK Enterprise
  STIX (~30 MB) + `resources/list` por técnica. Sin él, el `_orchestrator/
  mitre.md` no aterriza más allá del seed de 15 entradas.
- **Resto de la lista** (`mcp-cases`, `mcp-audit`, `mcp-yara-rules`,
  `mcp-sigma-rules`, `mcp-artifact-playbooks`, `mcp-timeline`, `mcp-report`,
  los 3 lookup locales y los 2 cloud opt-in) — sprints S4–S6, ver §10 de
  `inventario-mcps.md`.
- **RAG real**: hoy el "conocimiento" del agente vive en los prompts del
  package (`agentes/<id>/prompts/*.md`) + en el bundle estático que servirá
  `mcp-mitre-attack`. RAG con embeddings + vector store (Chroma / FAISS) es
  Fase 2, seguir §9.3 del diseño.

---

## 4. Tests pendientes

Cobertura actual es **335 backend tests** (322 legacy + 10 MCP + 3 audit lock).
Gaps todavía abiertos:

| Falta | Prioridad | Notas |
|---|---|---|
| `test_findings.py` (store + router) | Alta | Se introdujo en `b6ea63c` sin tests dedicados. Mismo patrón que `test_chats.py`. |
| Tests de la capa de ejecución (`PromptExecutor` con los cuatro ejecutores stubbed) | Alta | Sustituye al antiguo `test_cloud_backend.py` con mock OpenAI. Cubre además RULE 2: sin ejecutor → 503; CLI sin credenciales / `ollama` caído → capability no disponible con error accionable. |
| `test_agent_loop.py` end-to-end con `PromptExecutor` falso | Alta | Cubrir: allowlist refusal, `record_finding` intercept, evidence path injection, max_iterations cap, tool error handling. |
| `test_config_router.py` | Media | Validación de claves no editables, valores inválidos, masking de secrets. |
| Frontend tests (Vitest + RTL) | Media | Cero hoy. Prioritizar `RepositoryPage` y `InvestigationPage` por ser las más interactivas. |
| Integration test E2E (servicio `api` real + curl) | Baja | Útil para CI pre-release; no bloquea desarrollo. |

---

## 5. Entrega (compose)

El pivote 2026-07-02 elimina esta categoría tal como estaba: **ya no hay** bundle
PyInstaller, vendoring de binarios por OS/arch (`scripts/bundle-tool.mjs` + `vendor/`),
pipeline de release de instaladores ni firma de código macOS/Windows. La entrega es el
repo mismo: `git clone` + `docker compose up --build`.

| | |
|---|---|
| **Compose raíz completo** | Servicios `web` / `api` / `ollama` junto a los dos maletines (`platform: linux/amd64` — ver §1.B.ter), con puertos publicados en `127.0.0.1`, evidencia montada `:ro`, `./projects/` como raíz de casos y credenciales CLI montadas ro. En curso en `feature/compose-y-cli-executors`. |
| **CI workflow** | Adaptado al modelo compose el 2026-07-03: `backend` corre ruff + pytest solo en `ubuntu-latest` (el runtime son contenedores Linux — la matriz de 3 SOs pertenecía al instalable por plataforma), `web` hace `npm ci` + `npm run typecheck` + `npm run build` sobre `web/`, y el job `compose` valida `docker compose config -q` y construye las imágenes `api` + `web`. Pendiente: un job aparte (programado, no por push) que construya los maletines — su build (PPA GIFT + plaso/sleuthkit/bulk-extractor/libguestfs) es demasiado lento y frágil para cada push. |
| **Prueba de despliegue desde cero** | En una máquina limpia por cada SO del host: `git clone` + `docker compose up --build` + flujo evidencia → informe desde el navegador. Es la prueba de release del modelo compose (sustituye a "correr `release.yml` y validar artefactos"). |
| **Desmontaje del modelo anterior** | **Hecho el 2026-07-02**: `desktop/` (Electron), `vendor/`, `scripts/bundle-tool.mjs`, `build/forensia.spec`, `release.yml` y `docker/agent/` eliminados (detalle en la sección de desmontaje más arriba). |

---

## 6. Docs por refrescar

| Doc | Qué actualizar |
|---|---|
| `CLAUDE.md` § Status | Sigue diciendo "esqueleto" / "stubs" pese a que el agente, los 16 wrappers, el dispatcher anclado a caso y los findings persistidos son reales. La realineación v1.2 (2026-07-02) actualizó entrega y ejecutores pero mantuvo ese framing: reescribir a estado de implementación real. |
| `docs/arquitectura.md` § 8 ("Lo que el esqueleto NO implementa todavía") | Misma desactualización. Mover ítems hechos a una sección "Lo que SÍ está implementado" y dejar solo los reales pendientes. |
| `docs/operacion/frontend-journal.md` | Añadir entradas para el desmoqueo de Casos y evidencias, Investigación + findings panel, Settings con LLM config form. (La entrada del pivote 2026-07-02 ya está.) |
| `docs/ai-context/frontend.md` | Refrescar el árbol de `src/pages/` (las pages que antes eran "mock-only" ya no lo son) y la sección "Current Technical Debt". (Realineado al modelo compose el 2026-07-02; este refresco sigue pendiente.) |
| `scripts/dev.md` | Sección "Setup dev" apuntando al compose: los maletines se levantan con `docker compose up --build`; sin `brew install` de tools forenses en el host. |

---

## 7. Decisiones abiertas

Cosas que **no son TODO sino preguntas pendientes** para el equipo:

| ID | Decisión | Estado |
|---|---|---|
| **D-1** | ¿Conservar TSK como fallback explícito cuando se cablee `dissect.target`, o deprecar? | Abierta. |
| **D-2** | Si el orquestador necesita `role: investigation \| synthesis` en `agent.yaml`, o seguir con el truco de prefijo `_` para que la registry lo ignore. | Cubierta en `diseno-fase2.md`. |
| **D-3** | Anthropic backend: ¿se implementa pre-defensa o se quita del allowlist de config para que RULE 2 sea estricta? | **Resuelta por el pivote 2026-07-02**: sin API keys en el proyecto — se retira del allowlist. El acceso a modelos Anthropic es vía el ejecutor Claude Code con la suscripción del operador. |
| **D-4** | El campo `os_profile` del `Case` es **frozen** hoy. ¿Permitir cambio post-creación con entrada en audit log? Caso de uso: el examinador eligió mal al crear el caso. | Abierta. |
| **D-5** | ¿Auto-detección del `os_profile` al registrar la primera evidencia (warning, no override)? | Abierta. |

---

## 8. Resumen de prioridades sugeridas

Orden ejecutable para llegar a una **demo end-to-end real** sobre Caso CFReDS:

1. Pivote — servicios `web`/`api`/`ollama` del compose raíz + capa de ejecución
   `PromptExecutor` (ver la sección del pivote y §2). Es el bloqueador de todo lo demás.
2. §1.D — descargar NIST Hacking Case (5-30 min).
3. §1.A/§1.B — completar los maletines: RegRipper / EvtxECmd / MFTECmd + bulk_extractor,
   yara, hayabusa y chainsaw en los Dockerfiles de `docker/`, y verificar que
   `capabilities` los reporta desde los contenedores.
4. §6 — refrescar `CLAUDE.md § Status` y `arquitectura.md § 8` (30 min).
5. §1.C — `dissect.target` wrapper (medio día).
6. §2 — `forensia.reports` para cerrar el flujo análisis → informe (1-2 días).
7. §2 — `forensia.timeline` para desmoquear TimelinePage (medio día).
8. §3 — MCP S2 (`mcp-evidence` + agente como cliente MCP) si queda tiempo (1-2 días).

Si solo hay tiempo para los puntos 1-3, hay demo de "el analista despliega con un
comando, el agente investiga un caso real por el ejecutor elegido, ejecuta tools de
verdad en los maletines, persiste findings, todo trazable" — que es el corazón de la
propuesta TFM.
