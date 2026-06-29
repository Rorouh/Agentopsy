# FORENSIA — Próximos pasos

Inventario único de deuda técnica y trabajo pendiente. Cualquier conversación,
diseño futuro o nueva tarjeta de Kanban debería **enlazar a un ítem de aquí**
en vez de inventar otra lista paralela.

> **Por qué existe este doc**: la deuda vivía dispersa entre cuerpos de commit,
> la sección `## Status` de `CLAUDE.md` y conversaciones en chat. Esto la
> centraliza. La capa de **agentes / orquestador / RAG / MCP / evals** tiene su
> propio diseño detallado en [`FASE2_AGENTES_DISENO.md`](FASE2_AGENTES_DISENO.md);
> aquí solo se referencia.

---

## 0. Lo que YA está hecho (estado a 2026-06-28)

Resumen para que un nuevo contribuidor no repita trabajo. Detalle por slice
en los cuerpos de commit (`git log --oneline main`).

| Capa | Estado |
|---|---|
| Esqueleto Electron + sidecar Python | ✅ Operativo. Race de `FORENSIA_SIDECAR_READY` arreglado. |
| Seguridad de transporte (gates 1-3, 5) | ✅ Token + Host-header + CORS exacto + tests `test_security_gates.py`. |
| RULE 1 (delivery: bundled \| container) | ✅ Política aceptada en `CLAUDE.md`, reflejada en catálogo, executor y resolver. |
| Storage caso-como-carpeta | ✅ Cases / Evidence / Artifacts / Chats / Audit (hash-chained) / Findings. STORAGE.md documentado. |
| EvidenceManager real | ✅ Hash gate completo (stream SHA-256 → copy → re-hash → chmod 0o444 → baseline.json). `verify()` persiste a `verification.json` + apenda a `audit.jsonl`. |
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
| UI desmoqueada | ✅ Casos y evidencias, Investigación (con findings panel reactivo), Settings (form de modelos + dropdown). |
| Tests backend | ✅ 322 (cases 24, evidence_real 18, artifacts 22, chats 34, dispatcher_anchored 9, routers_storage 22, agent_registry 17, smoke 3, security_gates 4, wrappers 109, container 34, dispatcher 11, catalog_integrity 11, others 4). |

---

## 1. Críticos para una demo defendible del TFM

Ratio impacto / esfuerzo más alto. Si solo se atacan estos 4, hay demo:

### A. Construir las 3 imágenes OCI

| | |
|---|---|
| **Qué** | Correr `bash scripts/build-images.sh` contra el daemon Docker / Podman del Mac de build. Produce `desktop/resources/images/{regripper,evtxecmd,mftecmd}.tar`. |
| **Por qué** | Desbloquea `EvtxECmd` / `MFTECmd` / `RegRipper` sobre evidencia Windows real. Sin esto el agente intentará invocarlos y el wrapper container fallará con "image not found". |
| **Dónde toca** | Solo ejecución; el código ya está. |
| **Estimación** | 10-20 min de ejecución + ~600 MB de bandwidth (bases `mcr.microsoft.com/dotnet/runtime:8.0-alpine` + `perl:5.38-slim` + zips de EZ tools + clone de RegRipper3.0). |
| **Dependencias** | Docker / Podman / nerdctl en PATH del build host. Conectividad a Docker Hub + GitHub + descargas de Eric Zimmerman. |

### B. Instalar el maletín bundled en el Mac de dev

| | |
|---|---|
| **Qué** | `brew install bulk_extractor yara chainsaw` + descargar hayabusa del release de GitHub a `~/bin/` (no está en homebrew). |
| **Por qué** | Sin ellos `/api/capabilities` reporta `bulk_extractor: false`, `yara: false`, `hayabusa: false`, `chainsaw: false`. El agente los pide en su playbook y el dispatcher lanza `ToolExecutionError` por binario no resoluble. |
| **Dónde toca** | Solo el Mac de dev. NO entra al repo. |
| **Estimación** | 5 min. |
| **Documentación** | Falta una sección "Setup dev local" en `scripts/dev.md` con estos comandos. Crear (estimación 5 min). |

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
| **Diseño** | `FASE2_AGENTES_DISENO.md` §4 + `_orchestrator/reporter.md` ya tienen prompt + contrato. |

### `forensia.timeline` — consolidación cronológica (no existe)

| | |
|---|---|
| **Qué** | Módulo que lee todos los `artifacts/<run-id>/manifest.json` + `findings.jsonl` + `audit.jsonl` y produce `TimelineEvent[]` cronológico filtrable por severidad / fuente. |
| **Por qué** | `TimelinePage.tsx` (frontend) sigue con mock data. Sin esto la pantalla "Timeline" no es real. |
| **Dónde toca** | `backend/forensia/timeline/` + `routers/timeline.py` + cableo en `InvestigationPage` "Ver Timeline →" y en `TimelinePage`. |
| **Estimación** | 4-6 h. |
| **Diseño** | `FASE2_AGENTES_DISENO.md` §4 (orquestador) + `_orchestrator/timeline.md`. |

### Acción "Reabrir caso con perfil correcto" (UI)

| | |
|---|---|
| **Qué** | Botón en el banner amarillo de `InvestigationPage` que cierre el caso actual y lance el formulario de creación con `os_profile` pre-rellenado al `detected_os`. Hoy el banner es solo texto: la operadora tiene que ir a "Casos y evidencias" a mano. |
| **Por qué** | El backend ya conoce el desajuste (`forensia.triage`) y el agente ya rechaza ejecutar tools (guard rail). Lo único que falta es bajar la fricción del flujo correcto. **RULE 2 sigue intacta**: el botón abre el formulario, no crea el caso automáticamente. |
| **Dónde toca** | `desktop/renderer/src/pages/InvestigationPage.tsx` (botón) + `RepositoryPage.tsx` (aceptar `?prefilledProfile=…` o equivalente) + posible nuevo endpoint para "re-registrar evidencia a otro caso" si no se quiere obligar a re-hashing. |
| **Estimación** | 2-3 h. |

### `models.local` — Ollama (NotImplementedError hoy)

| | |
|---|---|
| **Qué** | Implementar `LocalOllamaBackend.next_action(state, tools)` usando el camino degradado: prompt estructurado + parser + allowlist + reintentos (porque tool-calling nativo en modelos open suele ser frágil). |
| **Por qué** | RULE de privacidad: local-first por defecto, cloud opt-in. Sin Ollama wired, "local" es ilusión. La tabla comparativa local-vs-cloud es la contribución científica del TFM. |
| **Dónde toca** | `backend/forensia/models/local.py`. |
| **Estimación** | 1-2 días + tests. |

### `models.anthropic` (clave aceptada pero sin uso)

| | |
|---|---|
| **Qué** | Subclase `AnthropicBackend(ModelBackend)` análoga a `CloudBackend` pero usando el SDK `anthropic`. |
| **Por qué** | El formulario de Settings acepta `ANTHROPIC_API_KEY` (allowlist en `routers/config.py`) pero nada la consume. RULE 2 ("no fallbacks silentes") obliga: o se implementa o se quita del allowlist. |
| **Dónde toca** | `backend/forensia/models/anthropic.py` (nuevo) + `models/base.py:get_backend()` (extender) + dependencia en `pyproject` `[models]`. |
| **Estimación** | 3-5 h. |

### Páginas frontend aún mock

| Página | Mock que falta cablear |
|---|---|
| `TimelinePage.tsx` | Necesita `forensia.timeline` (ver arriba). |
| `DocumentViewerPage.tsx` | Necesita `forensia.reports` (ver arriba). |
| `MitreAttackPage.tsx` | Necesita `_orchestrator/mitre.md` ejecutado por la capa de síntesis. |
| `SettingsPage` tabs "Operador" / "Reportes" / "Seguridad" / "Acerca de" | Inputs aún `disabled`. Operador + Reportes podrían persistirse vía el mismo `/api/config` extendiendo el allowlist. Seguridad es UI conceptual. |
| `GuidePage.tsx` | Estática, OK como tal por ahora — el contenido refleja el flujo real. |

---

## 3. MCP y RAG (Fase 2)

Cubierto en detalle en [`FASE2_AGENTES_DISENO.md`](FASE2_AGENTES_DISENO.md) §6 y §9.3.
**No duplicar aquí.** Resumen de status:

- **MCP server interno** envolviendo el dispatcher: diseñado, no implementado.
  Beneficio: protocol-agnostic, futuro inter-op con otros agentes. Estimación
  1-2 días.
- **RAG real**: hoy el "conocimiento" del agente vive en los prompts del package
  (`agentes/<id>/prompts/*.md`). Para RAG con embeddings + vector store
  (Chroma / FAISS), seguir §9.3 del diseño Fase 2.

---

## 4. Tests pendientes

Cobertura actual es 322 backend tests pero hay gaps cubiertos:

| Falta | Prioridad | Notas |
|---|---|---|
| `test_findings.py` (store + router) | Alta | Se introdujo en `b6ea63c` sin tests dedicados. Mismo patrón que `test_chats.py`. |
| `test_cloud_backend.py` con mock OpenAI | Alta | El loop nunca se ha verificado con la API stubbed. Usar `unittest.mock` sobre `OpenAI`. |
| `test_agent_loop.py` end-to-end con `ModelBackend` falso | Alta | Cubrir: allowlist refusal, `record_finding` intercept, evidence path injection, max_iterations cap, tool error handling. |
| `test_config_router.py` | Media | Validación de claves no editables, valores inválidos, masking de secrets. |
| Frontend tests (Vitest + RTL) | Media | Cero hoy. Prioritizar `RepositoryPage` y `InvestigationPage` por ser las más interactivas. |
| Integration test E2E (sidecar real + curl) | Baja | Útil para CI pre-release; no bloquea desarrollo. |

---

## 5. Empaquetado y distribución

| | |
|---|---|
| **PyInstaller bundle real** | El `forensia.spec` existe pero nunca se ha construido con los `[forensics]` (volatility3, plaso) pinned. Pendiente: pin de versiones en `pyproject.toml` + `pyinstaller build/forensia.spec --noconfirm` por OS/arch. Estimación: medio día. |
| **Vendoring real de binarios** | `scripts/bundle-tool.mjs` está cableado pero `vendor/` está vacío. Pendiente: correr el script por cada tool bundled (TSK family, libewf, libvmdk, bulk_extractor, yara, hayabusa, chainsaw, jq, file, xxd, strings, …) en cada OS/arch (mac-arm64, mac-x64, win-x64, linux-x64). Estimación: 1 día por OS/arch. |
| **CI workflow** | `.github/workflows/ci.yml` corre ruff + pytest en matriz de OS. Pendiente: añadir `openai` a `pip install`, exigir `npm run typecheck` en el job `renderer`, opcionalmente `npm run build`. Estimación: 30 min. |
| **Release pipeline** | `.github/workflows/release.yml` es `workflow_dispatch` manual. Funciona pero nadie lo ha ejecutado todavía. Estimación: 0 — solo correrlo y validar artefactos. |
| **Code signing macOS / Windows** | Diferido en `ARCHITECTURE.md` §6. Solo bloqueador si hay distribución externa. |

---

## 6. Docs por refrescar

| Doc | Qué actualizar |
|---|---|
| `CLAUDE.md` § Status | Dice "esqueleto" y "agente, RAG, model backends, real tool wrappers ... intentionally not implemented yet". Falso ahora: el agente cloud está real, los 16 wrappers están reales, el dispatcher anclado a caso está real, los findings están persistidos. Reescribir a estado actual. |
| `docs/ARCHITECTURE.md` § 7 ("Lo que el esqueleto NO implementa todavía") | Misma desactualización. Mover ítems hechos a una sección "Lo que SÍ está implementado al 2026-06-28" y dejar solo los reales pendientes. |
| `docs/FRONTEND_JOURNAL.md` | Añadir entradas para el desmoqueo de Casos y evidencias, Investigación + findings panel, Settings con LLM config form. |
| `docs/ai/FRONTEND_CONTEXT.md` | Refrescar el árbol de `src/pages/` (las pages que antes eran "mock-only" ya no lo son) y la sección "Current Technical Debt". |
| `vendor/CATALOG.md` | Añadir `file`, `xxd`, `strings` como tools del kit core. |
| `scripts/dev.md` | Añadir sección "Setup del maletín en dev" con los `brew install` listados en §1.B. |

---

## 7. Decisiones abiertas

Cosas que **no son TODO sino preguntas pendientes** para el equipo:

| ID | Decisión | Estado |
|---|---|---|
| **D-1** | ¿Conservar TSK como fallback explícito cuando se cablee `dissect.target`, o deprecar? | Abierta. |
| **D-2** | Si el orquestador necesita `role: investigation \| synthesis` en `agent.yaml`, o seguir con el truco de prefijo `_` para que la registry lo ignore. | Cubierta en `FASE2_AGENTES_DISENO.md`. |
| **D-3** | Anthropic backend: ¿se implementa pre-defensa o se quita del allowlist de config para que RULE 2 sea estricta? | Abierta. |
| **D-4** | El campo `os_profile` del `Case` es **frozen** hoy. ¿Permitir cambio post-creación con entrada en audit log? Caso de uso: el examinador eligió mal al crear el caso. | Abierta. |
| **D-5** | ¿Auto-detección del `os_profile` al registrar la primera evidencia (warning, no override)? | Abierta. |

---

## 8. Resumen de prioridades sugeridas

Orden ejecutable para llegar a una **demo end-to-end real** sobre Caso CFReDS:

1. §1.B — `brew install bulk_extractor yara chainsaw` + hayabusa (5 min).
2. §1.D — descargar NIST Hacking Case (5-30 min).
3. §1.A — `bash scripts/build-images.sh` (10-20 min).
4. §6 — refrescar `CLAUDE.md § Status` y `ARCHITECTURE.md § 7` (30 min).
5. §1.C — `dissect.target` wrapper (medio día).
6. §2 — `forensia.reports` para cerrar el flujo análisis → informe (1-2 días).
7. §2 — `forensia.timeline` para desmoquear TimelinePage (medio día).
8. §3 — empezar MCP wrapper si queda tiempo (1-2 días).

Si solo hay tiempo para los puntos 1-3 + 4, hay demo de "agente investiga un
caso real, ejecuta tools de verdad, persiste findings, todo trazable" — que es
el corazón de la propuesta TFM.
