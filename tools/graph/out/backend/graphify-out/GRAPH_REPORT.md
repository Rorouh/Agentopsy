# Graph Report - C:\Users\super\Desktop\TFM - Forensia\Forensia-AI\tools\graph\out\backend  (2026-07-30)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 3582 nodes · 6527 edges · 250 communities (166 shown, 84 thin omitted)
- Extraction: 83% EXTRACTED · 17% INFERRED · 0% AMBIGUOUS · INFERRED: 1141 edges (avg confidence: 0.71)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `94a4ebaf`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- test_report_writer.py
- test_executors.py
- DocumentStore
- run_in_container
- _msg
- test_agent_registry.py
- test_knowledge_store.py
- test_token_cache_accounting.py
- login.py
- build_material
- CaseManager
- test_redaction_no_ciega_al_agente.py
- FindingStore
- TestCasesRoutes
- .run
- test_timeline.py
- estimate_analysis
- test_evidence_context.py
- test_catalog_integrity.py
- EvidenceManager
- HTTPException
- builder.py
- test_web_surface.py
- Tool
- catalog.py
- ClaudeCodeExecutor
- TestRegister
- CodexExecutor
- ForensicAgent
- test_session_windowing.py
- JobRegistry
- OsProfileUnresolved
- ExecutorAvailability
- test_evidence_ewf_segments.py
- Usage
- execute
- register_evidence
- test_derived_handoff.py
- test_triage_deep.py
- create_app
- ScriptedBackend
- test_executor_login.py
- test_maletin.py
- OllamaExecutor
- documents.py
- test_ewf_routing.py
- TestCreate
- test_finalize_investigation.py
- _gate_path_parameters
- ArtifactStore
- PromptExecutor
- tool_runs
- classify
- probe_image
- test_dispatcher_case_anchored.py
- test_tool_batch.py
- agent.py
- test_vmdk_routing.py
- make_package
- TestUpdate
- test_tool_path_policy.py
- TestStartRun
- evidence.py
- test_leer_artefacto.py
- window_messages
- test_tool_version.py
- ExecutorBackend
- ToolCall
- fingerprint_evidence
- store.py
- test_knowledge_agent_tools.py
- test_mcp_toolkit.py
- .adjudicate
- coverage_to_navigator_layer
- internal_tool_specs
- AuditLog
- _ReadyAnnouncingServer
- human_readable_size
- evidence_jobs.py
- findings.py
- mitre.py
- timeline.py
- test_e2e_chain.py
- test_pivote_declarado.py
- TestUploadSegmentSet
- build_custody_act
- FastAPI
- DetectedEvidence
- wire_dispatcher_custody
- test_cli_auth_seeding.py
- test_evidence_context_e2e.py
- test_findings_contract.py
- McpSession
- resources.py
- config.py
- TestFinalizeRun
- test_binary_stdout_channel.py
- test_wrappers.py
- Finding
- coverage_to_csv
- timeline_to_csv
- _PreparedExecution
- TestAsyncRoute
- TestVolatility3
- validate_artifact_ref
- evidence.py
- TestDelete
- test_evidence_register_async.py
- _write_ewf_set
- _load_module
- TestFtkImager
- TestRegripper
- TestTskFls
- is_uploadable_evidence_ext
- GeminiExecutor
- _StrictModel
- Lifecycle
- _dispatch_forensic
- TestChainsaw
- __main__.py
- schemas.py
- chats.py
- test_history_ledger.py
- TestTskIcat
- .append
- RegisterJobRegistry
- knowledge.py
- TestAff4Imager
- TestBulkExtractor
- TestEvtxECmd
- TestJq
- TestLECmd
- TestRECmd
- TestTskMactime
- TestTskMmls
- apply_redaction
- build_argv
- _hammer
- test_dispatcher_hashes_final_bytes_after_process_death
- test_security_gates.py
- TestAmcacheParser
- TestForemost
- TestHashdeep
- TestHayabusa
- TestJLECmd
- TestMftECmd
- TestPlasoLog2timeline
- TestQemuNbd
- TestRBCmd
- TestYara
- .from_handle
- build_argv
- parse
- parse
- build_argv
- build_argv
- build_argv
- build_argv
- build_argv
- build_argv
- build_argv
- build_argv
- build_argv
- parse
- build_argv
- parse
- build_argv
- build_argv
- build_argv
- build_argv
- parse
- parse
- parse
- build_argv
- build_argv
- build_argv
- build_argv
- build_argv
- parse
- build_argv
- build_argv
- test_smoke.py
- TestAppCompatCacheParser
- TestSBECmd
- TestWxTCmd
- bodyfile_to_fs_events
- build_argv
- _ScriptedModel
- TestProgress
- build_investigation_timeline
- parse_summary
- _symlink_support.py
- test_catalog_carries_the_forensic_artifact_that_supports_each_technique
- RegRipperParams
- .delivery_for
- __init__.py
- __init__.py
- __init__.py
- __init__.py
- __init__.py
- __init__.py
- __init__.py
- __init__.py
- __init__.py
- Aff4ImagerParams
- AppCompatCacheParserParams
- ChainsawParams
- EvtxECmdParams
- EwfInfoParams
- ForemostParams
- FtkImagerParams
- HashdeepParams
- HayabusaParams
- JLECmdParams
- LECmdParams
- MFTECmdParams
- PlasoPsortParams
- TskFlsParams
- TskIcatParams
- RECmdParams
- WxTCmdParams
- RBCmdParams
- YaraParams
- Volatility3Params
- XxdHeadParams
- StringsHeadParams
- __init__.py
- __init__.py
- __init__.py
- __init__.py
- __init__.py
- __init__.py
- __init__.py
- wired
- test_finding_rejects_a_hallucinated_technique_id
- test_catalog_is_derived_from_the_orchestrator_seed
- _mmls_parsed
- Any
- Any
- RuntimeError
- Any
- Any
- Exception
- Response
- SimpleNamespace
- Path
- Path
- TestClient
- forensia

## God Nodes (most connected - your core abstractions)
1. `CaseManager` - 157 edges
2. `AuditLog` - 106 edges
3. `EvidenceManager` - 80 edges
4. `ForensicAgent` - 62 edges
5. `ArtifactStore` - 53 edges
6. `FindingStore` - 36 edges
7. `Tool` - 36 edges
8. `ClaudeCodeExecutor` - 34 edges
9. `_StrictModel` - 34 edges
10. `CoverageStore` - 32 edges

## Surprising Connections (you probably didn't know these)
- `client()` --calls--> `create_app()`  [INFERRED]
  tests/test_routers_storage.py → forensia/server.py
- `test_divergent_versions_across_maletines_report_no_single_identity()` --calls--> `Tool`  [INFERRED]
  tests/test_tool_version.py → forensia/toolkit/tool.py
- `test_negative_or_bool_token_values_are_rejected()` --calls--> `ClaudeCodeExecutor`  [INFERRED]
  tests/test_executor_cost.py → forensia/executors/claude_code.py
- `test_allowlist_comes_from_catalog_by_profile()` --calls--> `default_allowed_tools()`  [INFERRED]
  tests/test_agent_registry.py → forensia/agent/loader.py
- `test_reads_the_single_agent_md()` --calls--> `read_instructions()`  [INFERRED]
  tests/test_agent_registry.py → forensia/agent/loader.py

## Import Cycles
- None detected.

## Communities (250 total, 84 thin omitted)

### Community 0 - "test_report_writer.py"
Cohesion: 0.06
Nodes (69): ExecutorResult, contrato_del_indice(), El ÍNDICE del informe pericial — lo único que dos informes tienen en común.  A, El índice como texto para el prompt del redactor: número, título y qué     debe, Un apartado del índice canónico.      ``num`` y ``title`` son el contrato ESTR, SeccionIndice, build_prompt(), _contrato_de_respuesta() (+61 more)

### Community 1 - "test_executors.py"
Cohesion: 0.06
Nodes (58): Timeout in seconds for one executor run.      Resolution order — every step op, resolve_timeout(), clean_config(), client(), _fake_status(), _gemini_with_home(), _ListAudit, list (+50 more)

### Community 2 - "DocumentStore"
Cohesion: 0.08
Nodes (45): _block(), _cover(), _finding(), _h2(), _kv(), _meta_table(), Any, Render de un ``Document`` a PDF real con fpdf2, siguiendo la lógica del **infor (+37 more)

### Community 3 - "run_in_container"
Cohesion: 0.06
Nodes (58): CompletedProcess, Path, Execute a Tool inside its declared OCI image.  Security (THREAT_MODEL gates 5-, Run `tool.container_image` with `argv_inside` against the host's OCI runtime., run_in_container(), _validate_mount_paths(), container_name(), _is_forbidden_version() (+50 more)

### Community 4 - "_msg"
Cohesion: 0.05
Nodes (34): build_replay_messages(), _cap_transcript(), _drop_trailing_user(), _findings_ledger(), Any, Server-side replay of a chat session for the next agent turn.  Without this mo, The renderer appends the user message BEFORE calling /api/agent/query.     Stri, Keep the last ``max_turns`` user/assistant turns, then enforce a     cumulative (+26 more)

### Community 5 - "test_agent_registry.py"
Cohesion: 0.07
Nodes (44): AgentPackageError, build_package(), default_allowed_tools(), load_packages(), Path, ValueError, Carga del agente desde el **único** archivo de comportamiento ``agentes/agent.md, Lee el texto de ``agent.md`` bajo ``agents_dir``. Falla en seco si no existe o (+36 more)

### Community 6 - "test_knowledge_store.py"
Cohesion: 0.06
Nodes (21): KnowledgeBlock, KnowledgeNode, KnowledgeStore, NodeSummary, Path, Append-only store con vista consolidada para el grafo de conocimiento del caso., (vista .md, registro .jsonl) — ambos verificados dentro del caso., El registro íntegro del nodo, en orden de escritura. No viaja al modelo. (+13 more)

### Community 7 - "test_token_cache_accounting.py"
Cohesion: 0.07
Nodes (47): CacheHealthMonitor, Any, Permanent regression guard on prompt-cache reuse.  The whole saving of ``docs/, Flat, JSON-serialisable state for the run's audit event., Tracks ``cache_read`` growth across the turns of ONE analysis run.      Statef, _block_types(), find_transcript(), inspect_transcript() (+39 more)

### Community 8 - "login.py"
Cohesion: 0.08
Nodes (39): _availability(), cancel_login(), _child_env(), _drop(), login_capabilities(), login_info(), login_status(), LoginError (+31 more)

### Community 9 - "build_material"
Cohesion: 0.08
Nodes (44): _basename(), build_material(), _caso_material(), _evidencias_material(), _hallazgos_material(), _integridad_material(), _mitre_material(), naturaleza() (+36 more)

### Community 10 - "CaseManager"
Cohesion: 0.11
Nodes (24): Case, CaseManager, _clear_readonly_and_retry(), BaseException, Path, Case lifecycle: create / list / load / close, persisted as ``case.json`` per dir, ``shutil.rmtree`` error handler for the immutable evidence copies.      Eviden, Owns ``CONFIG_DIR/cases/``. Creates, lists, loads, and closes cases.      Not (+16 more)

### Community 11 - "test_redaction_no_ciega_al_agente.py"
Cohesion: 0.08
Nodes (29): RedactionPattern, _applies(), apply_redaction(), Any, Egress redaction — minimize personal data before it crosses to a cloud model., Return a COPY of an OpenAI-shape message list with every string ``content``, Run every applicable pattern's ``regex`` → ``replacement`` over ``text``., redact_messages() (+21 more)

### Community 12 - "FindingStore"
Cohesion: 0.09
Nodes (30): FindingStore, CoverageStore, MITRE ATT&CK — catálogo (enum cerrada) y cobertura (propuesta vs dictamen).  L, Regresión: sin default, `Finding(**data)` reventaría y los hallazgos     antigu, La correlación bajo demanda: annotate ancla técnicas a un hallazgo ya     regis, FORENSIC INVARIANT 4: la propuesta anclada entra en el log hash-encadenado., El eje del agente y el del operador no se funden nunca., Un «confirmada» sin motivo no vale nada en un informe pericial. (+22 more)

### Community 13 - "TestCasesRoutes"
Cohesion: 0.07
Nodes (6): client(), HTTP surface for cases / evidence / artifacts / chats — token gate + roundtrips., TestArtifactsRoutes, TestCasesRoutes, TestChatsRoutes, TestEvidenceRoutes

### Community 14 - ".run"
Cohesion: 0.08
Nodes (25): AgentLoopResult, _bounded_json(), _consulta_summary(), _max_tool_attempts(), _preview_params(), Any, The forensic agent loop.  ONE agent configured by the single ``agentes/agent.m, Append one event to the case audit chain, if an AuditLog was wired.          T (+17 more)

### Community 15 - "test_timeline.py"
Cohesion: 0.11
Nodes (34): _Ctx, _fake_cases(), _Handle, _persist_query_timeline(), Path, Timeline builders: the deterministic investigation layer and the MACB expansion, La super-timeline generada se materializa bajo el caso y se puede recuperar, A partitioned disk: mmls lists two filesystems; fls runs per partition offset an (+26 more)

### Community 16 - "estimate_analysis"
Cohesion: 0.10
Nodes (34): _avg_duration_ms(), _basis_summary(), estimate_analysis(), _estimate_cost(), _estimate_time(), _estimate_tokens(), _history_for(), Any (+26 more)

### Community 17 - "test_evidence_context.py"
Cohesion: 0.09
Nodes (31): EvidenceContext, Verified evidence context threaded from ``EvidenceManager`` to every tool run., Immutable ``(evidence_id, baseline_sha256)`` a tool run is anchored to., The uniform fields recorded in ``tool_run_start`` / ``tool_run_finish``., _assert_pair_carries(), cases(), _make_derived_ref(), P0.5-3 — verified evidence context on EVERY anchored tool run (INVARIANT 4). (+23 more)

### Community 18 - "test_catalog_integrity.py"
Cohesion: 0.07
Nodes (28): by_tier(), for_profile(), _output(), _path(), Tool, The curated maletín. Each entry is a closed-enum Tool the agent may select.  T, Lightweight invariants over the catalog wiring.  These tests are a tripwire: a, A tool applicable to an OS profile must live in that profile's maletín — so a (+20 more)

### Community 19 - "EvidenceManager"
Cohesion: 0.13
Nodes (20): _copy_file(), EvidenceHandle, EvidenceManager, EvidenceSegment, Path, Last on-demand verification result, persisted to ``verification.json``.      F, One file of a multi-segment evidence set (an EWF ``.E01`` split), with its, Stream-hash ``path`` in chunks. Returns ``(hex_digest, size_bytes)``.      Nev (+12 more)

### Community 20 - "HTTPException"
Cohesion: 0.14
Nodes (34): anchor_os_profile(), AnchorOsProfileRequest, _case_dict(), close_case(), create_case(), CreateCaseRequest, delete_case(), DeleteCaseRequest (+26 more)

### Community 21 - "builder.py"
Cohesion: 0.11
Nodes (34): assemble_investigation_timeline(), _bodyfile_to_all_events(), _dt_to_z(), _epoch_to_z(), _filesystem_partitions(), _finding_event(), _fs_timeline_path(), load_filesystem_timeline() (+26 more)

### Community 22 - "test_web_surface.py"
Cohesion: 0.14
Nodes (33): client(), _create_case(), MonkeyPatch, TestClient, _query(), Superficie HTTP para la SPA (migración del frontend al servicio `web`).  Cover, El endpoint fino agrega el usage de los eventos executor_run_finish., test_anchor_os_profile_endpoint_sets_and_persists() (+25 more)

### Community 23 - "Tool"
Cohesion: 0.12
Nodes (31): _build_result(), RuntimeError, Raised when a tool cannot be executed (not when it runs and fails — that     ca, Fix the single execution venue for this run (RULE 1 order, RULE 2 no fallback)., Authoritative version of the tool that is about to execute (anchored runs)., Which maletín runs `tool`, honouring RULE 2 (no fallback between maletines)., _resolve_tool_version(), _resolve_venue() (+23 more)

### Community 24 - "catalog.py"
Cohesion: 0.12
Nodes (29): _agents_dir(), as_dict(), Catalog, enterprise_as_dict(), enterprise_display_id(), _enterprise_index(), enterprise_is_known(), enterprise_technique() (+21 more)

### Community 25 - "ClaudeCodeExecutor"
Cohesion: 0.08
Nodes (25): ExecutorError, Return ``model`` unchanged if it is a safe id, else raise ``ExecutorError``., The executor could not produce a response (missing binary, non-zero exit,     u, validate_model_id(), ClaudeCodeExecutor, Claude Code executor — ``claude -p <prompt> --output-format json``.  Flags ver, The CLI's own conversation id from the JSON envelope, or ``None``.          Ve, ``num_turns`` from the envelope — how many turns the CLI actually put         i (+17 more)

### Community 26 - "TestRegister"
Cohesion: 0.06
Nodes (10): cases(), known_file(), manager(), EvidenceManager hash-gate contract + read-only invariant + cleanup on failure., If shutil.copy2 produces a file whose hash does not match the source,         r, A file with known content + known sha256., TestGetAndList, TestHashGateCleanup (+2 more)

### Community 27 - "CodexExecutor"
Cohesion: 0.09
Nodes (21): CodexExecutor, Any, Codex CLI executor — ``codex exec <prompt>`` in non-interactive mode.  Flags v, executor_cost(), _float(), _int(), Any, Per-case executor cost/token stats, aggregated from the append-only audit log. (+13 more)

### Community 28 - "ForensicAgent"
Cohesion: 0.14
Nodes (22): ForensicAgent, Tool, Índice del grafo del caso: una línea por nodo, sin contenido.          Lleva l, Tools the agent is ACTUALLY allowed to invoke (allowlist ∩ catalog)., _AlwaysSameTool, _FakeEvidence, Any, MonkeyPatch (+14 more)

### Community 29 - "test_session_windowing.py"
Cohesion: 0.13
Nodes (22): Safety ceiling (chars) for sending the transcript UNCUT under session     trans, session_context_budget_chars(), _CaptureBackend, _contents(), _ListAudit, ok_dispatcher(), Any, list (+14 more)

### Community 30 - "JobRegistry"
Cohesion: 0.12
Nodes (20): Job, JobRegistry, Any, Ejecución ASÍNCRONA del análisis del agente — desacoplada de la petición HTTP., Pide parar un job en curso. Devuelve True si se señalizó (estaba         corrie, Vista pública del job (estado + eventos desde `since`), bajo lock., Fichas de los jobs de un caso (sin eventos), más recientes primero., Encola `fn(emit)` en un hilo de fondo y devuelve el Job (status=running). (+12 more)

### Community 31 - "OsProfileUnresolved"
Cohesion: 0.15
Nodes (17): OsProfileUnresolved, RuntimeError, Resolve the ``os_profile`` a case routes on, or fail loud.      The SINGLE res, The case has no ``os_profile`` that can be routed on.      Raised by ``resolve, resolve_os_profile(), Honour FORENSIA_CASE_ID as a *test-only* preselection.          The env var ex, _audit(), cases() (+9 more)

### Community 32 - "ExecutorAvailability"
Cohesion: 0.10
Nodes (17): CliPromptExecutor, ExecutorAvailability, _ms(), neutral_cwd(), ABC, Execution layer contract: ``PromptExecutor``.  The 2026-07-02 pivot replaces t, Working directory for CLI executor subprocesses: a dedicated EMPTY dir.      `, Shared plumbing for the three CLI executors.      Subclasses declare the binar (+9 more)

### Community 33 - "test_evidence_ewf_segments.py"
Cohesion: 0.11
Nodes (13): cases(), _evidence_dirs(), _ewf_ext(), manager(), Multi-segment EWF (``.E01``) ingestion: the whole co-located segment set is reg, The extension for segment ``index`` of the same scheme as ``first_ext``     (``, Create ``stem.E01`` … ``stem.E0<count>`` with DISTINCT content. Returns the, TestIncompleteSetRejected (+5 more)

### Community 34 - "Usage"
Cohesion: 0.10
Nodes (19): _as_float(), _as_int(), _find_key(), Any, Token/cost accounting for ONE executor run, parsed from the envelope the     ex, The REAL prompt size: uncached remainder + cache writes + cache reads., The subset actually present — flat keys for the audit event.          Purely A, Best-effort token/cost accounting from the executor's own envelope.          R (+11 more)

### Community 35 - "execute"
Cohesion: 0.14
Nodes (27): _append_finish_or_raise(), _binary_artifact_ref(), _build_argv_tail(), _exception_message(), execute(), _inject_run_outputs(), _parse_wants_stderr(), _partial_streams() (+19 more)

### Community 36 - "register_evidence"
Cohesion: 0.12
Nodes (27): context_for(), Path, Shared helpers for the P0.5-3 anchored-run custody contract.  Every ANCHORED d, Register real evidence through EvidenceManager's hash gate; returns the handle., register_evidence(), anchored(), anchored(), anchored() (+19 more)

### Community 37 - "test_derived_handoff.py"
Cohesion: 0.12
Nodes (25): cases(), _fake_maletin(), _finished_run_with_output(), _producer_in_state(), Derived handoff: a binary tool's output refers to its artifact, and a downstream, A derivative produced from evidence B must never run under evidence A's     ver, A producer run with ctx-matching provenance whose artifact bytes are INTACT —, The rejection is actionable: it names the producer's error and the remedy. (+17 more)

### Community 38 - "test_triage_deep.py"
Cohesion: 0.14
Nodes (26): _audit(), cases(), evidence(), _ewf_blob(), FakeMaletin, Triage PROFUNDO: el SO de una imagen CONTENEDOR se determina abriéndola.  El f, Cabecera EWF real + relleno. El pase superficial la clasifica     `container_di, Cabecera VMDK sparse (`KDMV`) → `container_disk` / `unknown`. (+18 more)

### Community 39 - "create_app"
Cohesion: 0.08
Nodes (14): BaseHTTPMiddleware, allowed_hosts(), HostHeaderMiddleware, new_session_token(), Request, Transport hardening for the local api service (THREAT_MODEL gates 1-3, 12).  -, Reject any request whose Host header is not our exact loopback host:port., Constant-time check of the per-session token on protected routes. (+6 more)

### Community 40 - "ScriptedBackend"
Cohesion: 0.13
Nodes (18): AgentPackageModel, AgentPackagePolicy, AgentPackagePrompts, CaseKnowledgeNode, KnowledgeDoc, Objetivo, Tipos del agente en memoria.  Un ``AgentPackage`` es la configuración VALIDADA, Un documento de referencia que el agente consulta BAJO DEMANDA (mapa de     mem (+10 more)

### Community 41 - "test_executor_login.py"
Cohesion: 0.13
Nodes (18): client(), fake(), MonkeyPatch, Path, TestClient, Web-driven CLI login (2026-07-15).  Exercises ``forensia.executors.login`` end, Return a helper that rewires one executor's spec to the fake CLI and its     av, test_claude_start_waits_then_submit_code_logs_in() (+10 more)

### Community 42 - "test_maletin.py"
Cohesion: 0.15
Nodes (22): _cross_tool(), MonkeyPatch, Unit tests for the maletín availability probe (forensia.toolkit.maletin).  The, A windows-only tool must NOT be reported available just because toolkit-unix is, test_binary_absent_in_running_maletin_reports_reason(), test_container_name_env_override(), test_cross_tool_available_if_present_in_any_declared_maletin(), test_env_override_wins_over_maletin() (+14 more)

### Community 43 - "OllamaExecutor"
Cohesion: 0.12
Nodes (15): Any, Capability contract: the UI never assumes a platform — it asks here and degrades, snapshot(), executor_models(), executors_status(), get_executor(), Execution layer: the four operator-selected executors (2026-07-02 pivot).  ``g, Availability of the four executors, with the actionable reason when one     is (+7 more)

### Community 44 - "documents.py"
Cohesion: 0.14
Nodes (24): create_document(), CreateDocumentRequest, delete_document(), document_pdf(), finalize_investigation(), FinalizeInvestigationRequest, get_document(), get_report_job() (+16 more)

### Community 45 - "test_ewf_routing.py"
Cohesion: 0.14
Nodes (23): _is_ewf_path(), _exec_fake(), _load_exec_agent(), _post_exec(), EWF (`.E01`) routing through `ewfmount` (bloqueante del audit — gap libewf)., Wire run_argv_in_maletin's transport to a fake /exec responder., An exec-agent that does not report what it executed cannot be verified — the, A maletín that ran a DIFFERENT command than the audited one is a custody break. (+15 more)

### Community 46 - "TestCreate"
Cohesion: 0.08
Nodes (6): manager(), CaseManager contract: create / list / load / close + path-traversal guard., TestCaseDirConfinement, TestCreate, TestList, TestLoad

### Community 47 - "test_finalize_investigation.py"
Cohesion: 0.17
Nodes (19): _con_hallazgo(), entorno(), _Executor, CaseManager, «Finalizar investigación»: la ÚNICA superficie que emite un informe pericial., ``tool_usage`` sobre los casos de ESTE test (el módulo usa el singleton)., Una respuesta VÁLIDA del redactor: cubre el índice canónico exacto., _reply() (+11 more)

### Community 48 - "_gate_path_parameters"
Cohesion: 0.15
Nodes (21): is_artifact_ref(), BundledPath, generated_run_output(), inject_evidence_path(), map_exact_identifier(), PathKind, PathParameter, PathPolicyError (+13 more)

### Community 49 - "ArtifactStore"
Cohesion: 0.16
Nodes (12): ArtifactRun, ArtifactStore, Any, Filesystem-backed store for tool-invocation artifacts., Return ``(run_dir, manifest)`` for a still-running invocation., Persist streams/hashes and atomically close a running manifest., Persist the resolved literal argv while the run is still open.          The di, Close a run: persist stdout/stderr, hash every output, write the         final (+4 more)

### Community 50 - "PromptExecutor"
Cohesion: 0.11
Nodes (11): AgentPackage, AuditLog, EvidenceManager, PromptExecutor, One prompt in, one structured result out. Selected explicitly by the     operat, FinalAnswer, ModelBackend, ModelCapabilities (+3 more)

### Community 51 - "tool_runs"
Cohesion: 0.14
Nodes (21): audited_argvs(), Any, CaseManager, FindingStore, «Trabajos realizados» — las ejecuciones reales, reensambladas del audit log., El conjunto de comandos literales auditados, normalizados por espacios.      E, Las corridas de herramienta del caso, en orden de inicio.      Una entrada por, tool_runs() (+13 more)

### Community 52 - "classify"
Cohesion: 0.14
Nodes (20): classify(), Any, Deterministic relevance classifier for filesystem (MACB) events.  Forensic tri, Return ``{category, reason, weight}`` for a relevant event, or ``None``., Pick the forensically relevant events out of a full MACB event list.      Each, One relevance rule: a path pattern → (category, human reason, weight).      ``, _Rule, select_relevant_events() (+12 more)

### Community 53 - "probe_image"
Cohesion: 0.13
Nodes (20): _container_mode(), _decide_family(), DeepTriageResult, DeepTriageRun, DeepTriageUnavailable, _partition_offsets(), probe_image(), RuntimeError (+12 more)

### Community 54 - "test_dispatcher_case_anchored.py"
Cohesion: 0.11
Nodes (13): cases(), _fake_jq_exec(), Dispatcher behaviour when anchored to a case: audit log + artifact manifest., Tmp-rooted storage + evidence, maletín venue, faked version transport., jq does not declare output_dir in its params; the dispatcher does inject it, RUN_OUTPUT belongs to ArtifactStore even when the caller picks an in-case path., store(), TestCaseAnchored (+5 more)

### Community 55 - "test_tool_batch.py"
Cohesion: 0.16
Nodes (18): Varias herramientas pedidas en UN turno del modelo.      El coste de una corri, ToolBatch, _call(), _FakeEvidence, _OneBatchThenFinal, _parse(), Any, SimpleNamespace (+10 more)

### Community 56 - "agent.py"
Cohesion: 0.12
Nodes (20): analyze(), analyze_estimate(), cancel_job(), get_job(), list_case_jobs(), _prepare_run(), BaseModel, query() (+12 more)

### Community 57 - "test_vmdk_routing.py"
Cohesion: 0.17
Nodes (20): _qemu_format_for_path(), The qemu block-driver name for a container-disk path, or None if it is not one., _exec_fake(), _load_exec_agent(), _post_exec(), Container-disk routing through `qemu-storage-daemon`'s FUSE export (Bug 4).  T, No `qemu-storage-daemon` on the dev host / CI runner → 424 naming the dependency, test_exec_agent_ewf_and_qemu_mutually_exclusive() (+12 more)

### Community 58 - "make_package"
Cohesion: 0.15
Nodes (15): make_package(), Helper de tests: construye un ``AgentPackage`` desde el único ``agentes/agent.md, Agente del perfil pedido, con el texto real de ``agent.md``.      ``overrides`, test_agent_threads_context_built_from_handle(), _handle(), _MultiEvidence, Any, SimpleNamespace (+7 more)

### Community 59 - "TestUpdate"
Cohesion: 0.10
Nodes (4): _audit(), TestClose, TestReopen, TestUpdate

### Community 60 - "test_tool_path_policy.py"
Cohesion: 0.12
Nodes (15): cases(), P0.5-2/3: mandatory path-role gate before every forensic runner boundary.  Anc, Same-case is NOT same-evidence: a path to evidence B cannot run with A's     ve, The same-evidence rule also binds AUXILIARY inputs: a CASE_INPUT (yara     rule, Maletín-venue wiring: captured argv list + faked version transport., store(), test_derived_input_rejects_free_artifact_path_and_accepts_verified_ref(), test_mcp_path_flows_to_shared_dispatcher_gate() (+7 more)

### Community 61 - "TestStartRun"
Cohesion: 0.11
Nodes (7): OutputFile, cases(), ArtifactStore contract: start_run / finalize_run + hashing + atomic manifest., store(), TestFailRun, TestListAndGet, TestStartRun

### Community 62 - "evidence.py"
Cohesion: 0.14
Nodes (15): _clear_readonly_and_retry(), _discard_staging(), _discover_ewf_segment_set(), _ewf_segment_index(), _is_ewf_first_segment(), _is_ewf_middle_segment(), BaseException, Evidence ingestion: hash gate + immutable copy under the owning case directory. (+7 more)

### Community 63 - "test_leer_artefacto.py"
Cohesion: 0.10
Nodes (9): CP1 — El agente puede LEER sus propias salidas.  El agujero que cierra: hasta, Una regex del modelo seria un vector (ReDoS) y una fuente de sorpresas: los, Al paginar una BÚSQUEDA, `desde` numera las coincidencias, no el fichero., Un run cerrado con una salida realista de regripper., store_run(), test_buscar_es_subcadena_literal_no_regex(), test_desde_cuenta_sobre_las_lineas_relevantes(), test_lee_un_fichero_de_out_declarado_en_el_manifiesto() (+1 more)

### Community 64 - "window_messages"
Cohesion: 0.17
Nodes (14): _embedded_json(), keep_last_tool_results_default(), Any, Provider-agnostic context-window management for the agent loop (Bug 008).  The, One-line replacement for an elided tool-result body. Best-effort extracts     `, Return a COPY of ``messages`` with all but the most recent     ``keep_last_tool, Total content chars of a message list — the datum the session budget and     it, How many of the most recent tool-result messages stay verbatim on the wire. (+6 more)

### Community 65 - "test_tool_version.py"
Cohesion: 0.12
Nodes (8): cases(), tool_version — the AUTHORITATIVE version identity of every anchored tool run., _start_finish(), store(), test_divergent_versions_across_maletines_report_no_single_identity(), test_nonzero_exit_finish_keeps_version(), test_success_start_and_finish_carry_same_resolved_version(), _wired_success()

### Community 66 - "ExecutorBackend"
Cohesion: 0.22
Nodes (9): Action, ExecutorBackend, Any, Adapter: ``PromptExecutor`` → ``ModelBackend`` for ``ForensicAgent``.      ``r, Choose between a delta into the live session and full context.          Return, Fold one executor result into the session state and cache watchdog., Full context: everything the model needs, ordered for prefix caching., Only what the session does not have yet, plus the response contract. (+1 more)

### Community 67 - "ToolCall"
Cohesion: 0.16
Nodes (10): ToolCall, Anti-inyección (SECURITY INVARIANTS): un resultado de tool con bytes de     evi, El stub de un resultado envuelto sigue nombrando tool/exit/run (context.py, TestUntrustedToolResultSpotlighting, _FakeEvidence, Any, SimpleNamespace, _Scripted (+2 more)

### Community 68 - "fingerprint_evidence"
Cohesion: 0.16
Nodes (18): _accumulate_family(), _classify_header(), _count_markers(), _decide_family(), fingerprint_evidence(), fingerprint_os(), _mbr_partitions_sane(), Path (+10 more)

### Community 69 - "store.py"
Cohesion: 0.16
Nodes (14): ArtifactIntegrityError, _atomic_write_json(), _atomic_write_text(), _hash_file(), _now_iso(), Path, RuntimeError, Artifact storage: one directory per tool invocation under ``<case_dir>/artifacts (+6 more)

### Community 70 - "test_knowledge_agent_tools.py"
Cohesion: 0.22
Nodes (16): _call(), _FakeEvidence, SimpleNamespace, CP3 — Las dos tools del grafo, cableadas en el loop.  Gates: - `anotar_conoci, Ámbito del caso primero: si el agente creó un nodo con el id de un doc del, El paquete ya no trae docs estáticos: `anotar_conocimiento` se ofrece     siemp, test_anotar_persiste_y_devuelve_ok(), test_anotar_queda_en_el_audit_sin_el_contenido() (+8 more)

### Community 71 - "test_mcp_toolkit.py"
Cohesion: 0.22
Nodes (16): _build_session_cm(), _extract_payload(), Any, Tests for ``forensia.mcp.toolkit`` — the MCP server S1.  Uses in-process memor, Run windows.info both directly via dispatcher and via the MCP client.     Compa, Pull the JSON dict out of a CallToolResult's first text content block., test_differential_dispatcher_vs_mcp(), test_forensic_tool_without_select_case_fails_loud() (+8 more)

### Community 72 - ".adjudicate"
Cohesion: 0.13
Nodes (10): Adjudication, Any, Cobertura ATT&CK de un caso — dos ejes que NUNCA se funden.  1. **Propuesta de, Ancla técnicas ATT&CK a un hallazgo YA registrado (propuesta del agente,, Registra el veredicto del perito. Falla fuerte, nunca normaliza en silencio., El dictamen vigente de cada técnica (la última línea gana)., Una entrada por técnica tocada — propuesta, dictaminada, o ambas., `technique_id -> [finding_id, …]` a partir de los `mitre_hints` reales. (+2 more)

### Community 73 - "coverage_to_navigator_layer"
Cohesion: 0.14
Nodes (16): coverage_to_navigator_layer(), _findings_for(), _navigator_comment(), Any, Exportaciones de la cobertura ATT&CK de un caso — CSV y ATT&CK Navigator layer., Comentario de la celda del Navigator: dictamen del perito (con su motivo) y/o la, Construye un *layer* del ATT&CK Navigator (formato 4.5, dominio     ``enterpris, ``tactic_id -> nombre`` desde el catálogo Enterprise. Vacío si no está montado. (+8 more)

### Community 74 - "internal_tool_specs"
Cohesion: 0.17
Nodes (15): internal_tool_specs(), Any, JSON Schemas que describen los params de cada Tool del catálogo en el formato d, Return the function-calling spec for ``tool_id``, or None if unsupported., Inyecta un ``evidence_id`` OPCIONAL en el schema cuando el caso tiene MÁS DE, tool_spec(), tool_specs(), _with_evidence_selector() (+7 more)

### Community 75 - "AuditLog"
Cohesion: 0.25
Nodes (6): AuditLog, Path, A ``subprocess.TimeoutExpired`` crossing the runner boundary (defensive, Only the tool_run_* audit entries (evidence registration also appends)., TestAuditableRunnerBoundary, _tool_entries()

### Community 76 - "_ReadyAnnouncingServer"
Cohesion: 0.17
Nodes (8): Config, Any, Configuration: ~/.forensia/config.json with environment-variable override.  RU, _free_port(), main(), The Agentopsy api (FastAPI). Standalone mode binds 127.0.0.1 on an ephemeral por, Print the READY line only after `self.started` flips (sockets listening)., _ReadyAnnouncingServer

### Community 77 - "human_readable_size"
Cohesion: 0.14
Nodes (7): human_readable_size(), Bytes → short human string (``1.5 GB``). Base-1024, one decimal above KB., cases(), manager(), Acquisition metadata + acta de adquisición (custody act).  Gates that matter:, TestHumanReadableSize, TestMetadata

### Community 78 - "evidence_jobs.py"
Cohesion: 0.15
Nodes (11): _error_text(), Any, BaseException, Registro ASÍNCRONO de evidencia — desacoplado de la petición HTTP.  Espejo de, Lanza ``register(case_id, source_path)`` en un hilo daemon y devuelve el, Vista pública del job, bajo lock. ``None`` si no existe., Jobs de registro de un caso, más recientes primero. La usa la web al         mo, Mensaje ACCIONABLE del fallo (RULE 2): el texto que ``register`` lanzó,     pre (+3 more)

### Community 79 - "findings.py"
Cohesion: 0.16
Nodes (14): append_finding(), AppendFindingRequest, list_executor_cost(), list_findings(), list_tool_usage(), Any, BaseModel, Per-case findings HTTP surface. Thin adapter over forensia.findings.store. (+6 more)

### Community 80 - "mitre.py"
Cohesion: 0.16
Nodes (15): adjudicate(), AdjudicateRequest, export_coverage_csv(), export_navigator_layer(), get_catalog(), get_coverage(), Any, BaseModel (+7 more)

### Community 81 - "timeline.py"
Cohesion: 0.16
Nodes (15): export_investigation_timeline_csv(), FilesystemTimelineRequest, get_filesystem_timeline_job(), get_persisted_filesystem_timeline(), investigation_timeline(), Any, BaseModel, Response (+7 more)

### Community 82 - "test_e2e_chain.py"
Cohesion: 0.20
Nodes (15): bindir(), cases(), chain(), _entries(), _load_exec_agent(), _one(), Path, E2E: the full forensic chain over the PRODUCT PATH, with a real loopback exec-ag (+7 more)

### Community 83 - "test_pivote_declarado.py"
Cohesion: 0.23
Nodes (13): _audit_events(), _FakeEvidence, _pivote(), Any, SimpleNamespace, CP4 — El agente puede cambiar de vía, pero declarándolo.  La jugada que resolv, Declarar no es actuar: el pivote solo deja constancia. Si además ejecutase, test_el_perito_puede_ver_el_pivote_en_la_actividad() (+5 more)

### Community 84 - "TestUploadSegmentSet"
Cohesion: 0.18
Nodes (8): BinaryIO, _inbox_root(), list_source_files(), Resuelve la bandeja de entrada (``FORENSIA_EVIDENCE_DIR``) o lanza un     ``Run, Deposita una evidencia SUBIDA por el perito en la raíz de la bandeja     (``FOR, Enumera las evidencias disponibles en la bandeja de entrada     (``FORENSIA_EVI, save_uploaded_source(), TestUploadSegmentSet

### Community 85 - "build_custody_act"
Cohesion: 0.21
Nodes (8): build_custody_act(), _find_register_entry(), Any, Acta de adquisición — structured chain-of-custody record for one evidence.  Pu, The ``evidence_register`` audit event for ``evidence_id`` (first match)., Build the structured acquisition act for ``(case_id, evidence_id)``.      ``ca, _utc_now_iso(), TestCustodyAct

### Community 86 - "FastAPI"
Cohesion: 0.17
Nodes (9): get_artifact(), list_artifacts(), Any, Artifact-run HTTP surface.  Thin adapter over ``forensia.artifacts.store.artif, _run_dict(), Request, Entrega del token de sesión a la SPA (mismo-origen).  Con el compose, la UI ll, session() (+1 more)

### Community 87 - "DetectedEvidence"
Cohesion: 0.22
Nodes (11): deepen(), Path, Enrich ``shallow`` with a deep determination when — and only when — it is     n, DetectedEvidence, Triage record persisted to ``baseline.json`` and surfaced on the handle., Return the ``os_profile`` this evidence can be auto-routed to, or ``None``, routable_profile(), TestRoutablePredicate (+3 more)

### Community 88 - "wire_dispatcher_custody"
Cohesion: 0.16
Nodes (15): Point the dispatcher's singletons at tmp-rooted storage/evidence.      ``fake_, wire_dispatcher_custody(), wired_dispatcher(), wired_dispatcher(), wired(), dispatch_case(), Path, Transport failure looking up the version → NO ArtifactRun, NO tool_run_start, (+7 more)

### Community 89 - "test_cli_auth_seeding.py"
Cohesion: 0.32
Nodes (14): dirs(), populate_staging(), _posix_perms_enforced(), CompletedProcess, Path, Seeding de credenciales al volumen ``forensia-cli-auth`` (docker/api/entrypoint., True iff ``chmod`` group/other bits actually stick. On Windows ``st_mode``, run_entrypoint() (+6 more)

### Community 90 - "test_evidence_context_e2e.py"
Cohesion: 0.21
Nodes (14): _entries(), _load_exec_agent(), _one(), Path, P0.5-3 E2E — the verified evidence context survives the whole PRODUCT path.  D, Parse every rendered tool-result block out of the executor prompt — the scripted, tsk_icat → regripper(icat's exact ArtifactRef) → final. Deterministic: the step, _scripted_reply() (+6 more)

### Community 91 - "test_findings_contract.py"
Cohesion: 0.13
Nodes (8): Contrato de hallazgo: procedencia obligatoria + confidence / observed_at.  Cie, El asdict del hallazgo con los nuevos campos serializa a JSON válido., Las EZ Tools encadenan tsk_icat.output → tool.input vía ArtifactRef., Un descarte legítimo (una vía que NO aportó) queda exento de procedencia., store_case(), test_descarte_finding_without_run_id_is_allowed(), test_ez_tools_accept_a_derived_artifact_input(), test_finding_serialization_is_stable_json()

### Community 92 - "McpSession"
Cohesion: 0.29
Nodes (11): _err(), list_cases(), list_evidence(), Any, The four Jira-pattern tools: list_cases, select_case, list_evidence, select_evi, select_case(), select_evidence(), McpSession (+3 more)

### Community 93 - "resources.py"
Cohesion: 0.20
Nodes (13): ArtifactRef, build_resource_links_for_run(), parse_artifact_uri(), Path, ``resources/read`` handler for MCP `mcp-toolkit` (D5').  URI scheme: ``artifac, Build one ``ResourceLink`` per artifact file in a finished run.      Includes:, Parse ``artifact://<case>/<run>/<relpath>`` or raise ``ValueError``., Return the absolute, canonical filesystem path of the referenced artifact. (+5 more)

### Community 94 - "config.py"
Cohesion: 0.21
Nodes (13): get_config(), list_executors(), list_models(), Any, BaseModel, Operator config read/write surface.  Reads and writes ``config.json`` under ``, Remove ``key`` from ``config.json`` and the live singleton (used when the     o, Closed enum of executor ids for the Settings dropdown. Availability (with     t (+5 more)

### Community 96 - "test_binary_stdout_channel.py"
Cohesion: 0.16
Nodes (11): cases(), _load_exec_agent(), Binary-safe stdout channel for tools like TSK ``icat`` (bloqueante #2 del audit), `tsk_fls` with body_format=True streams its bodyfile to a hashed out/stdout.bin, Without body_format, fls lists files inline (parsed entries) and does NOT divert, P0.5-5: the binary channel is fd-direct (the child's stdout IS the file) and the, store(), test_exec_agent_stdout_path_writes_exact_bytes() (+3 more)

### Community 97 - "test_wrappers.py"
Cohesion: 0.14
Nodes (3): Per-wrapper contract tests.  For each catalog wrapper (the 13 core-tier ones p, TestEwfInfo, TestPlasoPsort

### Community 98 - "Finding"
Cohesion: 0.23
Nodes (10): Finding, Any, Append-only JSONL store of structured findings, one file per case.  Layout: ``, Valida los `mitre_hints` de un hallazgo contra la semilla ATT&CK.      Enum ce, _utc_now_iso(), _validate_mitre_hints(), _finding(), _id() (+2 more)

### Community 99 - "coverage_to_csv"
Cohesion: 0.27
Nodes (12): coverage_to_csv(), Serializa la cobertura del caso a CSV (una fila por técnica evaluada).      ``, Exportaciones de la cobertura ATT&CK — CSV y ATT&CK Navigator layer (hallazgo D), El perito puede dictaminar una técnica que el agente no propuso., Cero técnicas evaluadas → cabecera y 0 filas, no un error., _rows(), test_csv_carries_the_examiner_verdict_and_rationale(), test_csv_empty_case_is_header_only() (+4 more)

### Community 100 - "timeline_to_csv"
Cohesion: 0.26
Nodes (11): Any, Exportación CSV del timeline de investigación (CLAUDE.md RULE 3: lógica aquí)., Serializa el timeline de investigación a CSV (una fila por evento).      ``eve, timeline_to_csv(), _finding(), Exportación CSV del timeline de investigación (hallazgo D).  Reusa el builder, _rows(), test_csv_has_one_row_per_event_across_both_kinds() (+3 more)

### Community 101 - "_PreparedExecution"
Cohesion: 0.15
Nodes (11): _invoke_prepared(), _prepare_execution(), _PreparedExecution, Path, Literal argv plus its single, already-resolved execution venue., Construct the exact argv for the already-fixed venue, without invoking a runner., Cross the runner boundary for an already-fixed literal argv and venue., The Tool contract and the ONLY sanctioned way to execute one.  Security (THREA (+3 more)

### Community 102 - "TestAsyncRoute"
Cohesion: 0.18
Nodes (5): client(), _poll_http(), TestClient, El registro síncrono no se retira (MCP / tests / scripts lo usan)., TestAsyncRoute

### Community 104 - "validate_artifact_ref"
Cohesion: 0.20
Nodes (10): artifact_ref_json_schema(), ArtifactRef, Any, BaseModel, Shared contract for references to files produced by an ArtifactRun., A same-case derived input that ArtifactStore must resolve and re-hash., Validate and normalize an ArtifactRef without trusting its custody hints., Return an independent JSON Schema copy for non-Pydantic tool surfaces. (+2 more)

### Community 105 - "evidence.py"
Cohesion: 0.18
Nodes (11): custody_act(), evidence_metadata(), Any, Evidence inbox listing. Registration is per-case (``/api/cases/{case_id}/evidenc, Bandeja de entrada de evidencias (``FORENSIA_EVIDENCE_DIR`` — en el     compose, Sube una evidencia a la bandeja (``save_uploaded_source``). Camino de     ESCRI, Metadata de custodia de una evidencia: sha256 baseline, tamaño (bytes +     leg, Acta de adquisición estructurada (``forensia.custody.build_custody_act``): (+3 more)

### Community 106 - "TestDelete"
Cohesion: 0.17
Nodes (4): Borrado PERMANENTE del caso: destruye TODA la cadena de custodia, así que     l, El rmtree JAMÁS corre sobre una ruta que se resolvió fuera de la raíz         d, Las copias de evidencia son inmutables (chmod 0444). Borrar el caso         deb, TestDelete

### Community 107 - "test_evidence_register_async.py"
Cohesion: 0.20
Nodes (8): _audit_events(), _baseline(), cases(), _evidence_root(), isolated_cases(), manager(), Registro de evidencia ASÍNCRONO y ATÓMICO (2026-07-27).  Dos problemas reales, Mismo origen, con y sin callback → baseline, segmentos y audit idénticos

### Community 108 - "_write_ewf_set"
Cohesion: 0.21
Nodes (7): _evidence_entries(), Corte a mitad de copia del 3er segmento (los dos primeros ya están         cong, El fallo tras la copia (aquí: escribir baseline.json) también revierte:, Si el proceso muere entre la copia y la limpieza, el temporal que quede, ``stem.E01`` … ``stem.E0<count>`` con contenido DISTINTO por segmento., TestAtomicity, _write_ewf_set()

### Community 109 - "_load_module"
Cohesion: 0.23
Nodes (12): gen(), _get(), _load_module(), No caller-controlled inputs: a query string is not the closed route → 404, and, One designated source per binary — the ARG env for the pinned releases, the, One GET against an in-process loopback exec-agent., test_gen_versions_designated_sources(), test_versions_endpoint_corrupt_manifest_is_500() (+4 more)

### Community 113 - "is_uploadable_evidence_ext"
Cohesion: 0.29
Nodes (7): _is_ewf_numeric_segment(), is_registrable_evidence_ext(), is_uploadable_evidence_ext(), ¿Se puede DEPOSITAR en la bandeja un fichero con esta extensión?, ¿Es esta extensión un punto de entrada REGISTRABLE (lo que el operador     pued, A segment in the NUMERIC part of the naming scheme (``.E01`` … ``.E99`` /     `, TestIntakePredicates

### Community 114 - "GeminiExecutor"
Cohesion: 0.18
Nodes (7): GeminiExecutor, Gemini CLI executor — ``gemini -p <prompt> --output-format json``.  Flags veri, RULE 2: forma inesperada → 'no reportado', jamás un número fabricado., test_gemini_finds_canonical_token_keys_nested_in_stats(), test_unparseable_or_reshaped_envelope_degrades_to_none(), Codex/Gemini report a prompt TOTAL in `input_tokens` (cached tokens are a     s, test_executors_without_cache_accounting_report_none()

### Community 115 - "_StrictModel"
Cohesion: 0.18
Nodes (11): BulkExtractorParams, FileInfoParams, JqParams, BaseModel, ``mactime`` — turn a body file (from `tsk_fls -m`) into a timeline., Common base: reject unknown fields (RULE L2).      Without ``extra='forbid'``, ``jq`` — query a JSON artifact already on disk (typically a prior run's output)., ``file`` — identify the file format / MIME type of the evidence.      The evid (+3 more)

### Community 116 - "Lifecycle"
Cohesion: 0.24
Nodes (6): build_server(), Lifecycle, Called from select_case once we know which case absorbs the early         sessi, Construct the MCP server and its lifecycle hooks. Returned together so     ``__, Callbacks invoked from __main__.py to bracket the MCP session in the     audit, Server

### Community 117 - "_dispatch_forensic"
Cohesion: 0.29
Nodes (10): _dispatch_forensic(), _error(), Any, _pydantic_to_json_schema(), MCP `mcp-toolkit` — the core server (S1).  Lo que hace: - Publica las 4 Jira, Serialise a Python dict/list/str into a single MCP TextContent block., Tool execution that fails business-logic-wise returns an isError content     bl, Return a flat (no-$ref) JSON Schema for an MCP ``inputSchema``.      Some MCP (+2 more)

### Community 119 - "__main__.py"
Cohesion: 0.27
Nodes (9): _consent_or_die(), _force_exit(), main(), Entry point — ``python -m forensia.mcp`` arranca el servidor MCP por stdio.  L, Last-resort exit when the cooperative shutdown can't unwind within     ``_FORCE, Return the consent ref or exit non-zero with an actionable message.      The v, Run the MCP server, racing ``server.run`` against an external shutdown     even, _serve() (+1 more)

### Community 120 - "schemas.py"
Cohesion: 0.20
Nodes (9): AmcacheParserParams, PlasoLog2TimelineParams, Pydantic input schemas for every forensic tool published via MCP.  D4 of mcp-t, ``mmls`` — list partitions of a disk image. Evidence path is injected., ``log2timeline.py`` — build a super-timeline (.plaso) from the evidence., ``amcacheparser`` — parse `Amcache.hve` into CSVs (evidence injected)., ``sbecmd`` — parse ShellBags from the user hives under a directory into     CSV, SBECmdParams (+1 more)

### Community 121 - "chats.py"
Cohesion: 0.33
Nodes (9): append_chat_message(), AppendMessageRequest, list_chat_sessions(), _msg_dict(), Any, BaseModel, Chat-session HTTP surface.  Thin adapter over ``forensia.chats.store.chat_stor, read_chat_session() (+1 more)

### Community 122 - "test_history_ledger.py"
Cohesion: 0.33
Nodes (9): _finding(), MonkeyPatch, El ledger de hallazgos del replay DEBE exponer el finding_id real.  Regresión, Anti-inyección: los títulos (texto derivado de evidencia hostil) van     entrec, El ledger de hallazgos NO entra como `system` (rol de instrucciones): sus     t, test_findings_ledger_empty_when_no_findings(), test_findings_ledger_exposes_the_real_finding_id(), test_findings_ledger_quotes_titles_and_flags_them_untrusted() (+1 more)

### Community 124 - ".append"
Cohesion: 0.28
Nodes (4): _canonical(), Any, Tamper-evident audit log: one JSON object per line, each chained to the previous, Parsed entries in append order.          Read-only view for policy lookups and

### Community 125 - "RegisterJobRegistry"
Cohesion: 0.47
Nodes (3): RegisterJobRegistry, TestJobs, _wait()

### Community 126 - "knowledge.py"
Cohesion: 0.28
Nodes (8): list_nodes(), Any, Grafo de conocimiento por caso — superficie HTTP.  Adaptador fino sobre ``fore, Índice del grafo: un nodo por entrada, con sus secciones. Sin contenido., La vista consolidada de un nodo: última versión de cada sección., El registro append-only íntegro del nodo, en orden de escritura.      Es lo qu, read_history(), read_node()

### Community 135 - "apply_redaction"
Cohesion: 0.32
Nodes (7): apply_redaction(), get_redaction_mode(), Any, Apply the active agent package's redaction policy to tool outputs (L6).  The a, Read FORENSIA_REDACTION_MODE from the env. Default ``strict``.      Unknown va, Mutate ``result`` in place applying the package's redaction patterns to     ``s, RedactionMode

### Community 136 - "build_argv"
Cohesion: 0.32
Nodes (7): build_argv(), _is_valid_plugin_name(), parse(), Any, RegRipper wrapper — run a plugin against a pre-extracted Windows registry hive., Compose argv for rip.pl as it runs INSIDE the container.      params:, RegRipper writes plain text; structure varies by plugin.      The wrapper retu

### Community 137 - "_hammer"
Cohesion: 0.36
Nodes (7): _hammer(), Path, Concurrency test for AuditLog.append + cross-platform file lock.  Without the, Child process: append `n` entries with `label` as discriminator., If something inside append() raises, we must not leak the file descriptor., test_concurrent_appends_keep_chain_intact(), test_no_fd_leak_on_exception()

### Community 138 - "test_dispatcher_hashes_final_bytes_after_process_death"
Cohesion: 0.39
Nodes (7): _load_exec_agent(), Custody of the timeout boundary: a `timeout=null` run is ALWAYS bounded, and the, A `null` timeout applies the ceiling; an explicit non-positive one is a loud 400, test_dispatcher_hashes_final_bytes_after_process_death(), test_http_timeout_exceeds_exec_agent_ceiling(), test_non_positive_timeout_is_rejected(), test_null_timeout_is_bounded_and_kills_process()

### Community 139 - "test_security_gates.py"
Cohesion: 0.32
Nodes (5): client(), TestClient, Behavioural + static security gates (THREAT_MODEL). Cheap now, expensive to retr, test_gate2_foreign_host_header_rejected(), test_gate3_capabilities_requires_token()

### Community 150 - ".from_handle"
Cohesion: 0.29
Nodes (5): Any, Build from a hash-verified ``EvidenceHandle`` (``EvidenceManager.get``)., True when this context corresponds to ``handle`` (same id + baseline hash)., test_context_inconsistent_with_handle_is_detectable(), test_from_handle_copies_id_and_hash()

### Community 151 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, aff4imager wrapper — list/extract streams from an AFF4 volume.  Runs `aff4imag, Compose argv for aff4imager.      params:         image_path (str, required):, Listing prints one `aff4://…` URN per line; other runs print sparse     `Key: v

### Community 152 - "parse"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, AmcacheParser wrapper — parse a pre-extracted `Amcache.hve`.  Runs `amcachepar, Compose argv for AmcacheParser.      params:         hive_path (str, required, AmcacheParser closes with `Key: value` totals (shared EZ shape).

### Community 153 - "parse"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, AppCompatCacheParser wrapper — parse the ShimCache from a `SYSTEM` hive.  Runs, Compose argv for AppCompatCacheParser.      params:         hive_path (str, r, ACCP prints `Found N cache entries …` + `Key: value` lines (EZ shape).

### Community 154 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, bulk_extractor wrapper — parallel scanner for emails, URLs, IPs, credit cards…, Compose argv for bulk_extractor.      params:         image_path (str, requir, Extract per-scanner feature counts from the BE summary printed on stdout.

### Community 155 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, Chainsaw wrapper — hunt Sigma / Chainsaw rules over EVTX or JSON event files., Compose argv for Chainsaw.      params:         target_dir (str, required): h, Summarise a Chainsaw hunt.      Bug 007: Chainsaw prints its banner, progress

### Community 156 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, EvtxECmd wrapper — parse a pre-extracted `.evtx` file (or a directory of them)., Compose argv for EvtxECmd.      params:         evtx_path (str, required): pa, EvtxECmd prints a `Processed X events from Y file(s)` summary line.      We su

### Community 157 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, libewf `ewfinfo` wrapper — read case metadata from an E01 image., params: {image_path: str}, Flatten ewfinfo's key/value sections into a single dict.

### Community 158 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, file_info wrapper — characterize the evidence via libmagic (`file`).  POSIX st, Compose argv for file.      params:         image_path (str, required): host, Split the descriptive line into head + traits + raw.

### Community 159 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, foremost wrapper — file carving by header/footer from unallocated (and raw) spac, Compose argv for foremost.      params:         image_path (str, required): r, Summarise foremost stdout. The authoritative per-type breakdown lives in the

### Community 160 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, FTK Imager CLI wrapper — convert the disk-image evidence between formats.  Run, Compose argv for ftkimager (`source dest_base [options]`).      params:, ftkimager closes with per-algorithm blocks (`[MD5]`/`[SHA1]`) of     `Key: valu

### Community 161 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, hashdeep wrapper — recursive, multi-algorithm hashing.  Computes several hashe, Compose argv for hashdeep.      params:         image_path (str, required): f, Parse hashdeep CSV output into per-file hash maps.      Format: header lines s

### Community 162 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, Hayabusa wrapper — run Sigma-based detections over a directory of EVTX files., Compose argv for Hayabusa.      params:         evtx_dir (str, required): hos, Pull the `Key: value` summary lines Hayabusa prints after the run.

### Community 163 - "parse"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, JLECmd wrapper — parse pre-extracted Windows Jump Lists.  Runs `jlecmd` (Eric, Compose argv for JLECmd.      params:         target_path (str, required): pa, JLECmd closes with `Processed …` + `Key: value` lines (shared EZ shape).

### Community 164 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, jq wrapper — run a filter over a JSON file.  Bundled cross-platform helper use, Compose argv for jq.      params:         filter (str, required): jq filter e, Try to parse stdout as JSON; fall back to raw text with a line count.

### Community 165 - "parse"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, LECmd wrapper — parse pre-extracted Windows shortcut (`.lnk`) files.  Runs `le, Compose argv for LECmd.      params:         target_path (str, required): pat, LECmd closes with `Processed …` + `Key: value` lines (shared EZ shape).

### Community 166 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, MFTECmd wrapper — parse a pre-extracted NTFS `$MFT` file.  Runs `MFTECmd` (Eri, Compose argv for MFTECmd.      params:         mft_path (str, required): path, MFTECmd prints a `Processed X MFT records` summary line plus K/V tails.

### Community 167 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, plaso `log2timeline.py` wrapper — build a super-timeline (.plaso storage) from a, Compose argv for log2timeline.py.      params:         image_path (str, requi, log2timeline con `--status_view none` imprime poco; el resultado es el `.plaso`

### Community 168 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, plaso `psort.py` wrapper — post-process a .plaso storage into a timeline.  Rea, Compose argv for psort.py.      params:         plaso_path (str, required): t, psort imprime un resumen (eventos escritos/filtrados). Lo captura; el CSV comple

### Community 169 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, qemu_nbd wrapper — attach a disk image as a READ-ONLY NBD block device (mount he, Compose argv for qemu-nbd (read-only connect).      params:         image_pat, qemu-nbd `-c` no imprime nada en éxito; el efecto es el device conectado.

### Community 170 - "parse"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, RBCmd wrapper — parse Recycle Bin `$I` metadata files.  Runs `rbcmd` (Eric Zim, Compose argv for RBCmd.      params:         target_path (str, required): `$R, RBCmd prints `Processed N out of M files …` + `Key: value` (EZ shape).

### Community 171 - "parse"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, RECmd wrapper — run a RECmd batch against pre-extracted registry hives.  Runs, Compose argv for RECmd (batch mode).      params:         hive_path (str, req, RECmd closes with `Processed …` + `Key: value` lines (shared EZ shape).

### Community 172 - "parse"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, SBECmd wrapper — parse ShellBags from user registry hives.  Runs `sbecmd` (Eri, Compose argv for SBECmd.      params:         target_path (str, required): di, SBECmd prints `Total ShellBags found: N` + `Processed …` (EZ shape).

### Community 173 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, TSK `fls` wrapper — list files and directories from a raw image / partition., Compose argv for fls.      params:         image_path (str, required): host p, Parse fls regular-format output. Body-format (`-m`) is handed off as raw.

### Community 174 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, TSK `icat` wrapper — extract a file's content by inode, without mounting.  Giv, Compose argv for icat.      params:         image_path (str, required): raw i, Summarise the extracted content: length, a text/binary heuristic and a preview.

### Community 175 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, TSK `mactime` wrapper — build a timeline from a body file produced by `fls -m`., Compose argv for mactime.      params:         bodyfile_path (str, required):, Summarise mactime CSV: row count, day histogram, first / last events.

### Community 176 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, TSK `mmls` wrapper — list partitions of a raw disk image.  Example TSK output, Compose argv for mmls.      params:         image_path (str, required): host, Extract partitions into a structured dict the agent can reason over.

### Community 177 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, Volatility 3 wrapper — run a plugin against a memory dump.  Bundled cross-plat, Compose argv for Volatility 3.      params:         dump_path (str, required), Volatility 3 with `-r json` emits a JSON array of row dicts.      Returns a BO

### Community 178 - "parse"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, WxTCmd wrapper — parse a pre-extracted Windows Timeline database.  Runs `wxtcm, Compose argv for WxTCmd.      params:         target_path (str, required): pa, WxTCmd closes with `Processed …` + `Key: value` lines (EZ shape).

### Community 179 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, xxd wrapper — hex dump of the first bytes of the evidence.  POSIX (`xxd` ships, Compose argv for xxd.      params:         image_path (str, required)., xxd output is already structured; we just summarise.

### Community 180 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, YARA wrapper — match a rules file against a path on disk.  Bundled cross-platf, Compose argv for yara.      params:         rules_path (str, required): host, Each YARA hit is a line `rule_name target_path`; -s appends string lines     th

### Community 181 - "test_smoke.py"
Cohesion: 0.38
Nodes (6): client(), Path, TestClient, test_audit_log_is_hash_chained(), test_capabilities_reports_container_runtime(), test_health_is_public()

### Community 185 - "bodyfile_to_fs_events"
Cohesion: 0.33
Nodes (6): bodyfile_to_fs_events(), Expand a TSK bodyfile (``fls -m`` output) into MACB filesystem events.      Th, test_bodyfile_all_times_equal_yields_full_macb(), test_bodyfile_events_sorted_chronologically_and_capped(), test_bodyfile_macb_grouping_and_letters(), test_bodyfile_skips_zero_times_and_malformed_lines()

### Community 186 - "build_argv"
Cohesion: 0.40
Nodes (5): build_argv(), parse(), Any, strings wrapper — extract printable strings ≥ N chars from the evidence.  POSI, Compose argv for strings.      params:         image_path (str, required).

### Community 187 - "_ScriptedModel"
Cohesion: 0.40
Nodes (3): Any, Emite una lista fija de acciones y GUARDA los mensajes que ve en cada turno., _ScriptedModel

### Community 189 - "build_investigation_timeline"
Cohesion: 0.50
Nodes (4): build_investigation_timeline(), Load the case's audit log + findings and assemble the investigation timeline., test_build_investigation_timeline_empty_case(), test_build_investigation_timeline_reads_audit_and_findings()

### Community 190 - "parse_summary"
Cohesion: 0.50
Nodes (3): parse_summary(), Any, Shared stdout summariser for the Eric Zimmerman .NET tool wrappers.  Every EZ

### Community 191 - "_symlink_support.py"
Cohesion: 0.50
Nodes (3): Shared guard for tests that need to CREATE a symlink.  On Windows, ``os.symlin, True iff this process can create a symlink (probes a throwaway one)., _symlinks_supported()

### Community 192 - "test_catalog_carries_the_forensic_artifact_that_supports_each_technique"
Cohesion: 0.33
Nodes (4): La columna «Se sostiene con» de la semilla llega hasta la UI., El artefacto forense de la semilla viaja a la técnica Enterprise homónima., test_catalog_carries_the_forensic_artifact_that_supports_each_technique(), test_enterprise_merges_seed_supported_by()

### Community 193 - "RegRipperParams"
Cohesion: 0.67
Nodes (3): ``rip`` (RegRipper) — run a registry-analysis plugin against a hive file., RegRipperParams, test_artifact_ref_shared_contract_accepts_minimal_and_producer_shape()

## Knowledge Gaps
- **1 isolated node(s):** `forensia`
  These have ≤1 connection - possible missing edges or undocumented components.
- **84 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `CaseManager` connect `CaseManager` to `DocumentStore`, `_msg`, `test_knowledge_store.py`, `test_dispatcher_hashes_final_bytes_after_process_death`, `FindingStore`, `TestCasesRoutes`, `test_timeline.py`, `estimate_analysis`, `test_evidence_context.py`, `EvidenceManager`, `test_web_surface.py`, `TestRegister`, `CodexExecutor`, `OsProfileUnresolved`, `test_evidence_ewf_segments.py`, `register_evidence`, `test_derived_handoff.py`, `test_triage_deep.py`, `create_app`, `ScriptedBackend`, `TestCreate`, `ArtifactStore`, `test_dispatcher_case_anchored.py`, `TestUpdate`, `TestProgress`, `TestStartRun`, `evidence.py`, `test_leer_artefacto.py`, `build_investigation_timeline`, `test_tool_path_policy.py`, `test_tool_version.py`, `ToolCall`, `store.py`, `AuditLog`, `human_readable_size`, `test_e2e_chain.py`, `test_pivote_declarado.py`, `TestUploadSegmentSet`, `build_custody_act`, `DetectedEvidence`, `wire_dispatcher_custody`, `test_evidence_context_e2e.py`, `test_findings_contract.py`, `TestFinalizeRun`, `test_binary_stdout_channel.py`, `coverage_to_csv`, `TestAsyncRoute`, `wired`, `TestDelete`, `test_evidence_register_async.py`, `_write_ewf_set`, `is_uploadable_evidence_ext`, `RegisterJobRegistry`?**
  _High betweenness centrality (0.244) - this node is a cross-community bridge._
- **Why does `AuditLog` connect `AuditLog` to `DocumentStore`, `_hammer`, `CaseManager`, `FindingStore`, `estimate_analysis`, `test_evidence_context.py`, `EvidenceManager`, `test_web_surface.py`, `Tool`, `CodexExecutor`, `OsProfileUnresolved`, `test_evidence_ewf_segments.py`, `execute`, `register_evidence`, `test_derived_handoff.py`, `ScriptedBackend`, `test_smoke.py`, `test_dispatcher_case_anchored.py`, `test_tool_path_policy.py`, `build_investigation_timeline`, `evidence.py`, `test_tool_version.py`, `.adjudicate`, `human_readable_size`, `test_e2e_chain.py`, `TestUploadSegmentSet`, `build_custody_act`, `wire_dispatcher_custody`, `test_evidence_context_e2e.py`, `McpSession`, `_PreparedExecution`, `is_uploadable_evidence_ext`, `Lifecycle`, `.append`?**
  _High betweenness centrality (0.181) - this node is a cross-community bridge._
- **Why does `ForensicAgent` connect `ForensicAgent` to `window_messages`, `ToolCall`, `test_knowledge_agent_tools.py`, `ScriptedBackend`, `test_redaction_no_ciega_al_agente.py`, `.run`, `PromptExecutor`, `test_pivote_declarado.py`, `test_tool_batch.py`, `agent.py`, `make_package`, `_ScriptedModel`, `test_session_windowing.py`?**
  _High betweenness centrality (0.116) - this node is a cross-community bridge._
- **Are the 83 inferred relationships involving `CaseManager` (e.g. with `ArtifactIntegrityError` and `ArtifactRun`) actually correct?**
  _`CaseManager` has 83 INFERRED edges - model-reasoned connections that need verification._
- **Are the 96 inferred relationships involving `AuditLog` (e.g. with `Case` and `CaseManager`) actually correct?**
  _`AuditLog` has 96 INFERRED edges - model-reasoned connections that need verification._
- **Are the 51 inferred relationships involving `EvidenceManager` (e.g. with `AuditLog` and `DetectedEvidence`) actually correct?**
  _`EvidenceManager` has 51 INFERRED edges - model-reasoned connections that need verification._
- **Are the 50 inferred relationships involving `ForensicAgent` (e.g. with `QueryRequest` and `TestBoundedJson`) actually correct?**
  _`ForensicAgent` has 50 INFERRED edges - model-reasoned connections that need verification._