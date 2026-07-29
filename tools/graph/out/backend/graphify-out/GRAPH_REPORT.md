# Graph Report - C:\Users\super\Desktop\TFM - Forensia\Forensia-AI\tools\graph\out\backend  (2026-07-29)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 3355 nodes · 6176 edges · 216 communities (160 shown, 56 thin omitted)
- Extraction: 81% EXTRACTED · 19% INFERRED · 0% AMBIGUOUS · INFERRED: 1144 edges (avg confidence: 0.7)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `a323b718`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- test_token_cache_accounting.py
- ArtifactRef
- DocumentStore
- run_in_container
- _msg
- AgentPackage
- test_executors.py
- Usage
- login.py
- FindingStore
- EvidenceContext
- ArtifactStore
- CaseManager
- test_timeline.py
- test_tool_version.py
- test_web_surface.py
- ClaudeCodeExecutor
- cases.py
- catalog.py
- make_package
- register_evidence
- CodexExecutor
- coverage_to_csv
- JobRegistry
- test_derived_handoff.py
- OsProfileUnresolved
- builder.py
- test_evidence_ewf_segments.py
- evidence.py
- EvidenceManager
- test_triage_deep.py
- ScriptedBackend
- dispatcher.py
- test_executor_login.py
- test_leer_artefacto.py
- test_maletin.py
- ._new_case
- AuditLog
- path_policy.py
- ToolExecutionError
- test_ewf_routing.py
- TestCreate
- build_pericial_report
- .run
- agent.py
- classify
- probe_image
- test_tool_batch.py
- test_catalog_integrity.py
- test_vmdk_routing.py
- TestUpdate
- test_tool_path_policy.py
- ToolCall
- ForensicAgent
- Tool
- _AlwaysSameTool
- TestStartRun
- documents.py
- test_knowledge_store.py
- create_app
- estimate_analysis
- executor_models
- fingerprint_evidence
- ModelBackend
- test_evidence_real.py
- test_knowledge_agent_tools.py
- test_mcp_toolkit.py
- window_messages
- estimate.py
- .adjudicate
- _ReadyAnnouncingServer
- human_readable_size
- evidence_jobs.py
- OllamaExecutor
- mitre.py
- test_e2e_chain.py
- test_pivote_declarado.py
- TestUploadSegmentSet
- build_custody_act
- McpSession
- DetectedEvidence
- test_cli_auth_seeding.py
- test_dispatcher_case_anchored.py
- test_evidence_context_e2e.py
- test_findings_contract.py
- internal_tool_specs
- resources.py
- HTTPException
- config.py
- wire_dispatcher_custody
- TestFinalizeRun
- test_binary_stdout_channel.py
- test_wrappers.py
- KnowledgeStore
- timeline.py
- timeline_to_csv
- TestRegister
- TestAsyncRoute
- TestCasesRoutes
- TestVolatility3
- RedactionPattern
- .append
- evidence.py
- TestDelete
- test_evidence_register_async.py
- _write_ewf_set
- TestFtkImager
- TestRegripper
- TestTskFls
- is_uploadable_evidence_ext
- _dispatch_forensic
- test_knowledge_api.py
- TestChainsaw
- __main__.py
- Lifecycle
- chats.py
- test_auto_draft_report.py
- test_history_ledger.py
- test_report_generator.py
- TestTskIcat
- RegisterJobRegistry
- Finding
- apply_redaction
- knowledge.py
- TestBulkExtractor
- TestEvtxECmd
- TestJq
- TestLECmd
- TestRECmd
- TestTskMactime
- TestTskMmls
- assemble_investigation_timeline
- _invoke_prepared
- build_argv
- _hammer
- TestCaseAnchored
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
- .history
- build_investigation_timeline
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
- artifacts.py
- bodyfile_to_fs_events
- build_argv
- _ScriptedModel
- tool_usage
- TestProgress
- session.py
- parse_summary
- _symlink_support.py
- __init__.py
- __init__.py
- __init__.py
- __init__.py
- __init__.py
- __init__.py
- __init__.py
- __init__.py
- __init__.py
- __init__.py
- __init__.py
- __init__.py
- __init__.py
- __init__.py
- __init__.py
- __init__.py
- wired
- test_catalog_is_derived_from_the_orchestrator_seed
- Any
- Any
- Path
- forensia
- SimpleNamespace
- ValueError

## God Nodes (most connected - your core abstractions)
1. `CaseManager` - 162 edges
2. `AuditLog` - 109 edges
3. `EvidenceManager` - 88 edges
4. `ForensicAgent` - 59 edges
5. `ArtifactStore` - 53 edges
6. `Tool` - 41 edges
7. `FindingStore` - 40 edges
8. `CoverageStore` - 36 edges
9. `ClaudeCodeExecutor` - 31 edges
10. `ArtifactRef` - 30 edges

## Surprising Connections (you probably didn't know these)
- `test_proteger_no_desactiva_los_demas_patrones()` --calls--> `RedactionPattern`  [INFERRED]
  tests/test_redaction_no_ciega_al_agente.py → forensia/agent/package.py
- `test_un_patron_que_no_aplica_al_modo_no_se_ejecuta()` --calls--> `RedactionPattern`  [INFERRED]
  tests/test_redaction_no_ciega_al_agente.py → forensia/agent/package.py
- `test_negative_or_bool_token_values_are_rejected()` --calls--> `ClaudeCodeExecutor`  [INFERRED]
  tests/test_executor_cost.py → forensia/executors/claude_code.py
- `test_ollama_parses_eval_counts_and_has_no_cost()` --calls--> `OllamaExecutor`  [INFERRED]
  tests/test_executor_cost.py → forensia/executors/ollama.py
- `client()` --calls--> `create_app()`  [INFERRED]
  tests/test_routers_storage.py → forensia/server.py

## Import Cycles
- None detected.

## Communities (216 total, 56 thin omitted)

### Community 0 - "test_token_cache_accounting.py"
Cohesion: 0.05
Nodes (58): Action, CacheHealthMonitor, Any, Permanent regression guard on prompt-cache reuse.  The whole saving of ``docs/, Flat, JSON-serialisable state for the run's audit event., Tracks ``cache_read`` growth across the turns of ONE analysis run.      Statef, Record one turn; return an actionable warning the first time the         cache, _block_types() (+50 more)

### Community 1 - "ArtifactRef"
Cohesion: 0.05
Nodes (66): artifact_ref_json_schema(), ArtifactRef, is_artifact_ref(), Any, BaseModel, Shared contract for references to files produced by an ArtifactRun., A same-case derived input that ArtifactStore must resolve and re-hash., Validate and normalize an ArtifactRef without trusting its custody hints. (+58 more)

### Community 2 - "DocumentStore"
Cohesion: 0.08
Nodes (45): _block(), _cover(), _finding(), _h2(), _kv(), _meta_table(), Any, Render de un ``Document`` a PDF real con fpdf2, siguiendo la lógica del **infor (+37 more)

### Community 3 - "run_in_container"
Cohesion: 0.06
Nodes (58): CompletedProcess, Path, Execute a Tool inside its declared OCI image.  Security (THREAT_MODEL gates 5-, Run `tool.container_image` with `argv_inside` against the host's OCI runtime., run_in_container(), _validate_mount_paths(), container_name(), _is_forbidden_version() (+50 more)

### Community 4 - "_msg"
Cohesion: 0.05
Nodes (33): build_replay_messages(), _cap_transcript(), _drop_trailing_user(), _findings_ledger(), Any, Server-side replay of a chat session for the next agent turn.  Without this mo, The renderer appends the user message BEFORE calling /api/agent/query.     Stri, Keep the last ``max_turns`` user/assistant turns, then enforce a     cumulative (+25 more)

### Community 5 - "AgentPackage"
Cohesion: 0.07
Nodes (44): AgentPackageError, build_package(), default_allowed_tools(), load_packages(), Path, ValueError, Carga del agente desde el **único** archivo de comportamiento ``agentes/agent.md, Lee el texto de ``agent.md`` bajo ``agents_dir``. Falla en seco si no existe o (+36 more)

### Community 6 - "test_executors.py"
Cohesion: 0.08
Nodes (50): ExecutorError, RuntimeError, Timeout in seconds for one executor run.      Resolution order — every step op, Return ``model`` unchanged if it is a safe id, else raise ``ExecutorError``., The executor could not produce a response (missing binary, non-zero exit,     u, resolve_timeout(), validate_model_id(), clean_config() (+42 more)

### Community 7 - "Usage"
Cohesion: 0.06
Nodes (30): _as_float(), _as_int(), CliPromptExecutor, _find_key(), _ms(), PromptExecutor, ABC, Any (+22 more)

### Community 8 - "login.py"
Cohesion: 0.08
Nodes (39): _availability(), cancel_login(), _child_env(), _drop(), login_capabilities(), login_info(), login_status(), LoginError (+31 more)

### Community 9 - "FindingStore"
Cohesion: 0.08
Nodes (37): FindingStore, CoverageStore, wiring(), MITRE ATT&CK — catálogo (enum cerrada) y cobertura (propuesta vs dictamen).  L, SECURITY INVARIANT 5: el LLM no inventa ids; el servidor lo hace cumplir., Regresión: sin default, `Finding(**data)` reventaría y los hallazgos     antigu, La correlación bajo demanda: annotate ancla técnicas a un hallazgo ya     regis, FORENSIC INVARIANT 4: la propuesta anclada entra en el log hash-encadenado. (+29 more)

### Community 10 - "EvidenceContext"
Cohesion: 0.08
Nodes (35): EvidenceContext, Any, Verified evidence context threaded from ``EvidenceManager`` to every tool run., Immutable ``(evidence_id, baseline_sha256)`` a tool run is anchored to., Build from a hash-verified ``EvidenceHandle`` (``EvidenceManager.get``)., True when this context corresponds to ``handle`` (same id + baseline hash)., The uniform fields recorded in ``tool_run_start`` / ``tool_run_finish``., _assert_pair_carries() (+27 more)

### Community 11 - "ArtifactStore"
Cohesion: 0.10
Nodes (26): ArtifactRun, ArtifactStore, _atomic_write_json(), _atomic_write_text(), _hash_file(), _now_iso(), Any, Path (+18 more)

### Community 12 - "CaseManager"
Cohesion: 0.11
Nodes (23): Case, CaseManager, _clear_readonly_and_retry(), BaseException, Path, Case lifecycle: create / list / load / close, persisted as ``case.json`` per dir, ``shutil.rmtree`` error handler for the immutable evidence copies.      Eviden, Owns ``CONFIG_DIR/cases/``. Creates, lists, loads, and closes cases.      Not (+15 more)

### Community 13 - "test_timeline.py"
Cohesion: 0.09
Nodes (38): load_filesystem_timeline(), Carga la última super-timeline persistida de una evidencia, o ``None`` si     n, _Ctx, _fake_cases(), _Handle, _mmls_parsed(), _persist_query_timeline(), Path (+30 more)

### Community 14 - "test_tool_version.py"
Cohesion: 0.08
Nodes (28): cases(), gen(), _get(), _load_module(), Path, tool_version — the AUTHORITATIVE version identity of every anchored tool run., No caller-controlled inputs: a query string is not the closed route → 404, and, Transport failure looking up the version → NO ArtifactRun, NO tool_run_start, (+20 more)

### Community 15 - "test_web_surface.py"
Cohesion: 0.12
Nodes (37): _audit_actions(), client(), _create_case(), isolated_cases(), MonkeyPatch, TestClient, _query(), Superficie HTTP para la SPA (migración del frontend al servicio `web`).  Cover (+29 more)

### Community 16 - "ClaudeCodeExecutor"
Cohesion: 0.06
Nodes (26): ExecutorAvailability, ClaudeCodeExecutor, Claude Code executor — ``claude -p <prompt> --output-format json``.  Flags ver, The CLI's own conversation id from the JSON envelope, or ``None``.          Ve, ``num_turns`` from the envelope — how many turns the CLI actually put         i, GeminiExecutor, Gemini CLI executor — ``gemini -p <prompt> --output-format json``.  Flags veri, RULE 2: forma inesperada → 'no reportado', jamás un número fabricado. (+18 more)

### Community 17 - "cases.py"
Cohesion: 0.13
Nodes (33): anchor_os_profile(), AnchorOsProfileRequest, _case_dict(), close_case(), create_case(), CreateCaseRequest, delete_case(), DeleteCaseRequest (+25 more)

### Community 18 - "catalog.py"
Cohesion: 0.12
Nodes (29): _agents_dir(), as_dict(), Catalog, enterprise_as_dict(), enterprise_display_id(), _enterprise_index(), enterprise_is_known(), enterprise_technique() (+21 more)

### Community 19 - "make_package"
Cohesion: 0.09
Nodes (23): make_package(), Helper de tests: construye un ``AgentPackage`` desde el único ``agentes/agent.md, Agente del perfil pedido, con el texto real de ``agent.md``.      ``overrides`, test_agent_threads_context_built_from_handle(), _Capturador, _FakeEvidence, Any, SimpleNamespace (+15 more)

### Community 20 - "register_evidence"
Cohesion: 0.10
Nodes (31): context_for(), Path, Shared helpers for the P0.5-3 anchored-run custody contract.  Every ANCHORED d, Register real evidence through EvidenceManager's hash gate; returns the handle., register_evidence(), anchored(), anchored(), A derivative produced from evidence B must never run under evidence A's     ver (+23 more)

### Community 21 - "CodexExecutor"
Cohesion: 0.09
Nodes (24): CodexExecutor, Codex CLI executor — ``codex exec <prompt>`` in non-interactive mode.  Flags v, executor_cost(), _float(), _int(), Any, Per-case executor cost/token stats, aggregated from the append-only audit log., Return ``[{executor, runs, runs_with_tokens, input_tokens, output_tokens,     t (+16 more)

### Community 22 - "coverage_to_csv"
Cohesion: 0.11
Nodes (28): coverage_to_csv(), coverage_to_navigator_layer(), _findings_for(), _navigator_comment(), Any, Exportaciones de la cobertura ATT&CK de un caso — CSV y ATT&CK Navigator layer., Comentario de la celda del Navigator: dictamen del perito (con su motivo) y/o la, Construye un *layer* del ATT&CK Navigator (formato 4.5, dominio     ``enterpris (+20 more)

### Community 23 - "JobRegistry"
Cohesion: 0.12
Nodes (20): Job, JobRegistry, Any, Ejecución ASÍNCRONA del análisis del agente — desacoplada de la petición HTTP., Pide parar un job en curso. Devuelve True si se señalizó (estaba         corrie, Vista pública del job (estado + eventos desde `since`), bajo lock., Fichas de los jobs de un caso (sin eventos), más recientes primero., Encola `fn(emit)` en un hilo de fondo y devuelve el Job (status=running). (+12 more)

### Community 24 - "test_derived_handoff.py"
Cohesion: 0.11
Nodes (26): ArtifactIntegrityError, RuntimeError, A derived artifact's on-disk bytes no longer match the SHA-256 its producing run, _fake_maletin(), _finished_run_with_output(), _producer_in_state(), Derived handoff: a binary tool's output refers to its artifact, and a downstream, A producer run with ctx-matching provenance whose artifact bytes are INTACT — (+18 more)

### Community 25 - "OsProfileUnresolved"
Cohesion: 0.15
Nodes (17): OsProfileUnresolved, RuntimeError, Resolve the ``os_profile`` a case routes on, or fail loud.      The SINGLE res, The case has no ``os_profile`` that can be routed on.      Raised by ``resolve, resolve_os_profile(), Honour FORENSIA_CASE_ID as a *test-only* preselection.          The env var ex, _audit(), cases() (+9 more)

### Community 26 - "builder.py"
Cohesion: 0.14
Nodes (28): _bodyfile_to_all_events(), _dt_to_z(), _epoch_to_z(), _filesystem_partitions(), _finding_event(), _fs_timeline_path(), _normalize_iso_utc(), _parse_iso_utc() (+20 more)

### Community 27 - "test_evidence_ewf_segments.py"
Cohesion: 0.11
Nodes (13): cases(), _evidence_dirs(), _ewf_ext(), manager(), Multi-segment EWF (``.E01``) ingestion: the whole co-located segment set is reg, The extension for segment ``index`` of the same scheme as ``first_ext``     (``, Create ``stem.E01`` … ``stem.E0<count>`` with DISTINCT content. Returns the, TestIncompleteSetRejected (+5 more)

### Community 28 - "evidence.py"
Cohesion: 0.10
Nodes (24): _clear_readonly_and_retry(), _copy_file(), _discard_staging(), _discover_ewf_segment_set(), EvidenceSegment, _ewf_segment_index(), _is_ewf_first_segment(), _is_ewf_middle_segment() (+16 more)

### Community 29 - "EvidenceManager"
Cohesion: 0.20
Nodes (11): EvidenceHandle, EvidenceManager, Path, Last on-demand verification result, persisted to ``verification.json``.      F, Registers evidence into a case and exposes hash-verified, read-only handles., Re-run the OS determination on an ALREADY-registered evidence.          The de, Chain-of-custody metadata for ONE registered evidence, JSON-friendly., Run the deep OS determination and persist whatever it establishes.          Re (+3 more)

### Community 30 - "test_triage_deep.py"
Cohesion: 0.14
Nodes (26): _audit(), cases(), evidence(), _ewf_blob(), FakeMaletin, Triage PROFUNDO: el SO de una imagen CONTENEDOR se determina abriéndola.  El f, Cabecera EWF real + relleno. El pase superficial la clasifica     `container_di, Cabecera VMDK sparse (`KDMV`) → `container_disk` / `unknown`. (+18 more)

### Community 31 - "ScriptedBackend"
Cohesion: 0.13
Nodes (18): AgentPackageModel, AgentPackagePolicy, AgentPackagePrompts, CaseKnowledgeNode, KnowledgeDoc, Objetivo, Tipos del agente en memoria.  Un ``AgentPackage`` es la configuración VALIDADA, Un documento de referencia que el agente consulta BAJO DEMANDA (mapa de     mem (+10 more)

### Community 32 - "dispatcher.py"
Cohesion: 0.12
Nodes (26): _append_finish_or_raise(), _binary_artifact_ref(), _build_argv_tail(), _exception_message(), _gate_path_parameters(), _parse_wants_stderr(), _partial_streams(), Any (+18 more)

### Community 33 - "test_executor_login.py"
Cohesion: 0.13
Nodes (18): client(), fake(), MonkeyPatch, Path, TestClient, Web-driven CLI login (2026-07-15).  Exercises ``forensia.executors.login`` end, Return a helper that rewires one executor's spec to the fake CLI and its     av, test_claude_start_waits_then_submit_code_logs_in() (+10 more)

### Community 34 - "test_leer_artefacto.py"
Cohesion: 0.09
Nodes (11): _FakeEvidence, Any, SimpleNamespace, CP1 — El agente puede LEER sus propias salidas.  El agujero que cierra: hasta, Una regex del modelo seria un vector (ReDoS) y una fuente de sorpresas: los, Al paginar una BÚSQUEDA, `desde` numera las coincidencias, no el fichero., _Scripted, test_buscar_es_subcadena_literal_no_regex() (+3 more)

### Community 35 - "test_maletin.py"
Cohesion: 0.15
Nodes (22): _cross_tool(), MonkeyPatch, Unit tests for the maletín availability probe (forensia.toolkit.maletin).  The, A windows-only tool must NOT be reported available just because toolkit-unix is, test_binary_absent_in_running_maletin_reports_reason(), test_container_name_env_override(), test_cross_tool_available_if_present_in_any_declared_maletin(), test_env_override_wins_over_maletin() (+14 more)

### Community 36 - "._new_case"
Cohesion: 0.11
Nodes (5): client(), HTTP surface for cases / evidence / artifacts / chats — token gate + roundtrips., TestArtifactsRoutes, TestChatsRoutes, TestEvidenceRoutes

### Community 37 - "AuditLog"
Cohesion: 0.15
Nodes (10): AuditLog, _canonical(), Any, Path, Tamper-evident audit log: one JSON object per line, each chained to the previous, Parsed entries in append order.          Read-only view for policy lookups and, A ``subprocess.TimeoutExpired`` crossing the runner boundary (defensive, Only the tool_run_* audit entries (evidence registration also appends). (+2 more)

### Community 38 - "path_policy.py"
Cohesion: 0.14
Nodes (21): BundledPath, generated_run_output(), inject_evidence_path(), map_exact_identifier(), PathKind, PathParameter, PathPolicyError, PathRole (+13 more)

### Community 39 - "ToolExecutionError"
Cohesion: 0.14
Nodes (24): _build_result(), execute(), RuntimeError, Resolve, run, and parse a tool by id. Returns a result dict.      The result i, Raised when a tool cannot be executed (not when it runs and fails — that     ca, Authoritative version of the tool that is about to execute (anchored runs)., _resolve_tool_version(), ToolExecutionError (+16 more)

### Community 40 - "test_ewf_routing.py"
Cohesion: 0.14
Nodes (23): _is_ewf_path(), _exec_fake(), _load_exec_agent(), _post_exec(), EWF (`.E01`) routing through `ewfmount` (bloqueante del audit — gap libewf)., Wire run_argv_in_maletin's transport to a fake /exec responder., An exec-agent that does not report what it executed cannot be verified — the, A maletín that ran a DIFFERENT command than the audited one is a custody break. (+15 more)

### Community 41 - "TestCreate"
Cohesion: 0.08
Nodes (6): manager(), CaseManager contract: create / list / load / close + path-traversal guard., TestCaseDirConfinement, TestCreate, TestList, TestLoad

### Community 42 - "build_pericial_report"
Cohesion: 0.18
Nodes (23): build_pericial_report(), _cadena_custodia(), _conclusiones(), _correlacion_mitre(), _datos_informe(), _finding_provenance(), generate_draft_report(), _hallazgos() (+15 more)

### Community 43 - ".run"
Cohesion: 0.13
Nodes (16): AgentLoopResult, _consulta_summary(), _preview_params(), Any, The forensic agent loop.  ONE agent configured by the single ``agentes/agent.m, Append one event to the case audit chain, if an AuditLog was wired.          T, Display-safe subset of tool params for a progress event (strings truncated)., One-line human summary of a tool result for the live activity log. (+8 more)

### Community 44 - "agent.py"
Cohesion: 0.12
Nodes (21): analyze(), cancel_job(), get_job(), list_case_jobs(), _maybe_auto_draft(), _prepare_run(), Any, BaseModel (+13 more)

### Community 45 - "classify"
Cohesion: 0.14
Nodes (20): classify(), Any, Deterministic relevance classifier for filesystem (MACB) events.  Forensic tri, Return ``{category, reason, weight}`` for a relevant event, or ``None``., Pick the forensically relevant events out of a full MACB event list.      Each, One relevance rule: a path pattern → (category, human reason, weight).      ``, _Rule, select_relevant_events() (+12 more)

### Community 46 - "probe_image"
Cohesion: 0.13
Nodes (20): _container_mode(), _decide_family(), DeepTriageResult, DeepTriageRun, DeepTriageUnavailable, _partition_offsets(), probe_image(), RuntimeError (+12 more)

### Community 47 - "test_tool_batch.py"
Cohesion: 0.16
Nodes (18): Varias herramientas pedidas en UN turno del modelo.      El coste de una corri, ToolBatch, _call(), _FakeEvidence, _OneBatchThenFinal, _parse(), Any, SimpleNamespace (+10 more)

### Community 48 - "test_catalog_integrity.py"
Cohesion: 0.11
Nodes (15): by_tier(), for_profile(), Lightweight invariants over the catalog wiring.  These tests are a tripwire: a, A tool applicable to an OS profile must live in that profile's maletín — so a, Tripwire for every wrapper parameter that represents a filesystem path., Every core tool must override the stub `_not_built` for both callables., Extended tools still in `_EXTENDED_STILL_STUB` keep the `_not_built` stub;, test_core_tier_matches_expected_kit() (+7 more)

### Community 49 - "test_vmdk_routing.py"
Cohesion: 0.17
Nodes (20): _qemu_format_for_path(), The qemu block-driver name for a container-disk path, or None if it is not one., _exec_fake(), _load_exec_agent(), _post_exec(), Container-disk routing through `qemu-storage-daemon`'s FUSE export (Bug 4).  T, No `qemu-storage-daemon` on the dev host / CI runner → 424 naming the dependency, test_exec_agent_ewf_and_qemu_mutually_exclusive() (+12 more)

### Community 50 - "TestUpdate"
Cohesion: 0.10
Nodes (4): _audit(), TestClose, TestReopen, TestUpdate

### Community 51 - "test_tool_path_policy.py"
Cohesion: 0.12
Nodes (15): cases(), P0.5-2/3: mandatory path-role gate before every forensic runner boundary.  Anc, Same-case is NOT same-evidence: a path to evidence B cannot run with A's     ve, The same-evidence rule also binds AUXILIARY inputs: a CASE_INPUT (yara     rule, Maletín-venue wiring: captured argv list + faked version transport., store(), test_derived_input_rejects_free_artifact_path_and_accepts_verified_ref(), test_mcp_path_flows_to_shared_dispatcher_gate() (+7 more)

### Community 52 - "ToolCall"
Cohesion: 0.14
Nodes (10): _bounded_json(), Serialize ``body`` to JSON, kept under ``limit`` chars WITHOUT ever emitting, ToolCall, Context-budget / token-consumption guards (Bug 008).  The executor is stateles, Anti-inyección (SECURITY INVARIANTS): un resultado de tool con bytes de     evi, El stub de un resultado envuelto sigue nombrando tool/exit/run (context.py, TestBoundedJson, TestToolResultPayloadOrder (+2 more)

### Community 53 - "ForensicAgent"
Cohesion: 0.17
Nodes (13): ForensicAgent, Índice del grafo del caso: una línea por nodo, sin contenido.          Lleva l, _handle(), _MultiEvidence, Any, SimpleNamespace, El agente ve y usa TODAS las evidencias del caso (RAM + disco), no solo una., Doble con DOS evidencias: memoria y disco. (+5 more)

### Community 54 - "Tool"
Cohesion: 0.13
Nodes (18): Tools the agent is ACTUALLY allowed to invoke (allowlist ∩ catalog)., _inject_run_outputs(), _prepare_execution(), _PreparedExecution, Path, Literal argv plus its single, already-resolved execution venue., Fix the single execution venue for this run (RULE 1 order, RULE 2 no fallback)., Construct the exact argv for the already-fixed venue, without invoking a runner. (+10 more)

### Community 55 - "_AlwaysSameTool"
Cohesion: 0.18
Nodes (17): _max_tool_attempts(), Anti-loop guardrail (Bug 001): how many times a tool may FAIL (exit≠0 or an, _AlwaysSameTool, _FakeEvidence, Any, MonkeyPatch, SimpleNamespace, Guardrail anti-bucle del loop del agente (Bug 001).  Una tool que falla no deb (+9 more)

### Community 56 - "TestStartRun"
Cohesion: 0.11
Nodes (7): OutputFile, cases(), ArtifactStore contract: start_run / finalize_run + hashing + atomic manifest., store(), TestFailRun, TestListAndGet, TestStartRun

### Community 57 - "documents.py"
Cohesion: 0.18
Nodes (20): create_document(), CreateDocumentRequest, delete_document(), document_pdf(), generate_report(), GenerateReportRequest, get_document(), list_documents() (+12 more)

### Community 59 - "create_app"
Cohesion: 0.12
Nodes (13): BaseHTTPMiddleware, allowed_hosts(), HostHeaderMiddleware, new_session_token(), Request, Transport hardening for the local api service (THREAT_MODEL gates 1-3, 12).  -, Reject any request whose Host header is not our exact loopback host:port., Constant-time check of the per-session token on protected routes. (+5 more)

### Community 60 - "estimate_analysis"
Cohesion: 0.21
Nodes (18): estimate_analysis(), Return an honest pre-flight estimate for one analysis run.      Ranges for ite, _finish(), _patch_cases(), Estimación pre-vuelo del análisis (hallazgo E).  Los gates que importan: - Co, El bug que este test fija.      En un ejecutor con caché de prompt, `input_tok, El log es append-only: los eventos escritos antes del 2026-07-29 no traen     c, La heurística anterior (5.000) era un supuesto sin medir, un orden de     magni (+10 more)

### Community 61 - "executor_models"
Cohesion: 0.12
Nodes (17): Any, Capability contract: the UI never assumes a platform — it asks here and degrades, snapshot(), executor_models(), executors_status(), get_executor(), Execution layer: the four operator-selected executors (2026-07-02 pivot).  ``g, Availability of the four executors, with the actionable reason when one     is (+9 more)

### Community 62 - "fingerprint_evidence"
Cohesion: 0.16
Nodes (18): _accumulate_family(), _classify_header(), _count_markers(), _decide_family(), fingerprint_evidence(), fingerprint_os(), _mbr_partitions_sane(), Path (+10 more)

### Community 63 - "ModelBackend"
Cohesion: 0.14
Nodes (6): FinalAnswer, ModelBackend, ModelCapabilities, ABC, Bridge between the agent loop and the execution layer.  ``ForensicAgent.run``, _Scripted

### Community 64 - "test_evidence_real.py"
Cohesion: 0.11
Nodes (9): cases(), known_file(), manager(), EvidenceManager hash-gate contract + read-only invariant + cleanup on failure., If shutil.copy2 produces a file whose hash does not match the source,         r, A file with known content + known sha256., TestGetAndList, TestHashGateCleanup (+1 more)

### Community 65 - "test_knowledge_agent_tools.py"
Cohesion: 0.22
Nodes (16): _call(), _FakeEvidence, SimpleNamespace, CP3 — Las dos tools del grafo, cableadas en el loop.  Gates: - `anotar_conoci, Ámbito del caso primero: si el agente creó un nodo con el id de un doc del, El paquete ya no trae docs estáticos: `anotar_conocimiento` se ofrece     siemp, test_anotar_persiste_y_devuelve_ok(), test_anotar_queda_en_el_audit_sin_el_contenido() (+8 more)

### Community 66 - "test_mcp_toolkit.py"
Cohesion: 0.22
Nodes (16): _build_session_cm(), _extract_payload(), Any, Tests for ``forensia.mcp.toolkit`` — the MCP server S1.  Uses in-process memor, Run windows.info both directly via dispatcher and via the MCP client.     Compa, Pull the JSON dict out of a CallToolResult's first text content block., test_differential_dispatcher_vs_mcp(), test_forensic_tool_without_select_case_fails_loud() (+8 more)

### Community 67 - "window_messages"
Cohesion: 0.21
Nodes (11): _embedded_json(), keep_last_tool_results_default(), Any, Provider-agnostic context-window management for the agent loop (Bug 008).  The, Return a COPY of ``messages`` with all but the most recent     ``keep_last_tool, How many of the most recent tool-result messages stay verbatim on the wire., Best-effort: parse the outermost ``{...}`` object embedded in ``text`` (a tool, One-line replacement for an elided tool-result body. Best-effort extracts     ` (+3 more)

### Community 68 - "estimate.py"
Cohesion: 0.15
Nodes (16): _avg_duration_ms(), _basis_summary(), _estimate_cost(), _estimate_time(), _estimate_tokens(), _history_for(), Any, Pre-flight estimate of an analysis run: iterations, tokens, cost and time.  To (+8 more)

### Community 69 - ".adjudicate"
Cohesion: 0.13
Nodes (10): Adjudication, Any, Cobertura ATT&CK de un caso — dos ejes que NUNCA se funden.  1. **Propuesta de, Ancla técnicas ATT&CK a un hallazgo YA registrado (propuesta del agente,, Registra el veredicto del perito. Falla fuerte, nunca normaliza en silencio., El dictamen vigente de cada técnica (la última línea gana)., Una entrada por técnica tocada — propuesta, dictaminada, o ambas., `technique_id -> [finding_id, …]` a partir de los `mitre_hints` reales. (+2 more)

### Community 70 - "_ReadyAnnouncingServer"
Cohesion: 0.17
Nodes (8): Config, Any, Configuration: ~/.forensia/config.json with environment-variable override.  RU, _free_port(), main(), The Agentopsy api (FastAPI). Standalone mode binds 127.0.0.1 on an ephemeral por, Print the READY line only after `self.started` flips (sockets listening)., _ReadyAnnouncingServer

### Community 71 - "human_readable_size"
Cohesion: 0.14
Nodes (7): human_readable_size(), Bytes → short human string (``1.5 GB``). Base-1024, one decimal above KB., cases(), manager(), Acquisition metadata + acta de adquisición (custody act).  Gates that matter:, TestHumanReadableSize, TestMetadata

### Community 72 - "evidence_jobs.py"
Cohesion: 0.15
Nodes (11): _error_text(), Any, BaseException, Registro ASÍNCRONO de evidencia — desacoplado de la petición HTTP.  Espejo de, Lanza ``register(case_id, source_path)`` en un hilo daemon y devuelve el, Vista pública del job, bajo lock. ``None`` si no existe., Jobs de registro de un caso, más recientes primero. La usa la web al         mo, Mensaje ACCIONABLE del fallo (RULE 2): el texto que ``register`` lanzó,     pre (+3 more)

### Community 73 - "OllamaExecutor"
Cohesion: 0.20
Nodes (7): ExecutorResult, Any, OllamaExecutor, Any, Ollama executor — HTTP to the compose ``ollama`` service. The 100% local option., Installed model names from ``{host}/api/tags`` (sorted, de-duped).          Ra, test_ollama_unavailable_without_host()

### Community 74 - "mitre.py"
Cohesion: 0.16
Nodes (15): adjudicate(), AdjudicateRequest, export_coverage_csv(), export_navigator_layer(), get_catalog(), get_coverage(), Any, BaseModel (+7 more)

### Community 75 - "test_e2e_chain.py"
Cohesion: 0.20
Nodes (15): bindir(), cases(), chain(), _entries(), _load_exec_agent(), _one(), Path, E2E: the full forensic chain over the PRODUCT PATH, with a real loopback exec-ag (+7 more)

### Community 76 - "test_pivote_declarado.py"
Cohesion: 0.23
Nodes (13): _audit_events(), _FakeEvidence, _pivote(), Any, SimpleNamespace, CP4 — El agente puede cambiar de vía, pero declarándolo.  La jugada que resolv, Declarar no es actuar: el pivote solo deja constancia. Si además ejecutase, test_el_perito_puede_ver_el_pivote_en_la_actividad() (+5 more)

### Community 77 - "TestUploadSegmentSet"
Cohesion: 0.18
Nodes (8): BinaryIO, _inbox_root(), list_source_files(), Resuelve la bandeja de entrada (``FORENSIA_EVIDENCE_DIR``) o lanza un     ``Run, Deposita una evidencia SUBIDA por el perito en la raíz de la bandeja     (``FOR, Enumera las evidencias disponibles en la bandeja de entrada     (``FORENSIA_EVI, save_uploaded_source(), TestUploadSegmentSet

### Community 78 - "build_custody_act"
Cohesion: 0.21
Nodes (8): build_custody_act(), _find_register_entry(), Any, Acta de adquisición — structured chain-of-custody record for one evidence.  Pu, The ``evidence_register`` audit event for ``evidence_id`` (first match)., Build the structured acquisition act for ``(case_id, evidence_id)``.      ``ca, _utc_now_iso(), TestCustodyAct

### Community 79 - "McpSession"
Cohesion: 0.26
Nodes (11): _err(), list_cases(), list_evidence(), Any, The four Jira-pattern tools: list_cases, select_case, list_evidence, select_evi, select_case(), select_evidence(), McpSession (+3 more)

### Community 80 - "DetectedEvidence"
Cohesion: 0.22
Nodes (11): deepen(), Path, Enrich ``shallow`` with a deep determination when — and only when — it is     n, DetectedEvidence, Triage record persisted to ``baseline.json`` and surfaced on the handle., Return the ``os_profile`` this evidence can be auto-routed to, or ``None``, routable_profile(), TestRoutablePredicate (+3 more)

### Community 81 - "test_cli_auth_seeding.py"
Cohesion: 0.32
Nodes (14): dirs(), populate_staging(), _posix_perms_enforced(), CompletedProcess, Path, Seeding de credenciales al volumen ``forensia-cli-auth`` (docker/api/entrypoint., True iff ``chmod`` group/other bits actually stick. On Windows ``st_mode``, run_entrypoint() (+6 more)

### Community 82 - "test_dispatcher_case_anchored.py"
Cohesion: 0.13
Nodes (10): cases(), Dispatcher behaviour when anchored to a case: audit log + artifact manifest., Tmp-rooted storage + evidence, maletín venue, faked version transport., RUN_OUTPUT belongs to ArtifactStore even when the caller picks an in-case path., store(), TestInvalidCaseId, TestOutputDirInjection, TestUnanchoredRejection (+2 more)

### Community 83 - "test_evidence_context_e2e.py"
Cohesion: 0.21
Nodes (14): _entries(), _load_exec_agent(), _one(), Path, P0.5-3 E2E — the verified evidence context survives the whole PRODUCT path.  D, Parse every rendered tool-result block out of the executor prompt — the scripted, tsk_icat → regripper(icat's exact ArtifactRef) → final. Deterministic: the step, _scripted_reply() (+6 more)

### Community 84 - "test_findings_contract.py"
Cohesion: 0.13
Nodes (8): Contrato de hallazgo: procedencia obligatoria + confidence / observed_at.  Cie, El asdict del hallazgo con los nuevos campos serializa a JSON válido., Las EZ Tools encadenan tsk_icat.output → tool.input vía ArtifactRef., Un descarte legítimo (una vía que NO aportó) queda exento de procedencia., store_case(), test_descarte_finding_without_run_id_is_allowed(), test_ez_tools_accept_a_derived_artifact_input(), test_finding_serialization_is_stable_json()

### Community 85 - "internal_tool_specs"
Cohesion: 0.20
Nodes (13): internal_tool_specs(), Any, JSON Schemas que describen los params de cada Tool del catálogo en el formato d, Inyecta un ``evidence_id`` OPCIONAL en el schema cuando el caso tiene MÁS DE, Return the function-calling spec for ``tool_id``, or None if unsupported., tool_spec(), tool_specs(), _with_evidence_selector() (+5 more)

### Community 86 - "resources.py"
Cohesion: 0.20
Nodes (13): ArtifactRef, build_resource_links_for_run(), parse_artifact_uri(), Path, ``resources/read`` handler for MCP `mcp-toolkit` (D5').  URI scheme: ``artifac, Build one ``ResourceLink`` per artifact file in a finished run.      Includes:, Parse ``artifact://<case>/<run>/<relpath>`` or raise ``ValueError``., Return the absolute, canonical filesystem path of the referenced artifact. (+5 more)

### Community 87 - "HTTPException"
Cohesion: 0.22
Nodes (13): analyze_estimate(), Estimación HONESTA (rangos + supuestos) del coste de lanzar un análisis:     it, append_finding(), AppendFindingRequest, list_executor_cost(), list_findings(), list_tool_usage(), Any (+5 more)

### Community 88 - "config.py"
Cohesion: 0.21
Nodes (13): get_config(), list_executors(), list_models(), Any, BaseModel, Operator config read/write surface.  Reads and writes ``config.json`` under ``, Remove ``key`` from ``config.json`` and the live singleton (used when the     o, Closed enum of executor ids for the Settings dropdown. Availability (with     t (+5 more)

### Community 89 - "wire_dispatcher_custody"
Cohesion: 0.19
Nodes (13): Point the dispatcher's singletons at tmp-rooted storage/evidence.      ``fake_, wire_dispatcher_custody(), wired_dispatcher(), wired_dispatcher(), dispatch_case(), _load_exec_agent(), Custody of the timeout boundary: a `timeout=null` run is ALWAYS bounded, and the, A `null` timeout applies the ceiling; an explicit non-positive one is a loud 400 (+5 more)

### Community 91 - "test_binary_stdout_channel.py"
Cohesion: 0.16
Nodes (11): cases(), _load_exec_agent(), Binary-safe stdout channel for tools like TSK ``icat`` (bloqueante #2 del audit), `tsk_fls` with body_format=True streams its bodyfile to a hashed out/stdout.bin, Without body_format, fls lists files inline (parsed entries) and does NOT divert, P0.5-5: the binary channel is fd-direct (the child's stdout IS the file) and the, store(), test_exec_agent_stdout_path_writes_exact_bytes() (+3 more)

### Community 92 - "test_wrappers.py"
Cohesion: 0.14
Nodes (3): Per-wrapper contract tests.  For each catalog wrapper (the 13 core-tier ones p, TestEwfInfo, TestPlasoPsort

### Community 93 - "KnowledgeStore"
Cohesion: 0.23
Nodes (7): KnowledgeStore, Path, (vista .md, registro .jsonl) — ambos verificados dentro del caso., Índice del grafo del caso. Es lo ÚNICO que viaja siempre en el prompt., Última versión de cada sección, en orden de PRIMERA aparición.          Que el, wired(), store_case()

### Community 94 - "timeline.py"
Cohesion: 0.21
Nodes (12): FilesystemTimelineRequest, get_filesystem_timeline_job(), get_persisted_filesystem_timeline(), investigation_timeline(), Any, BaseModel, Timeline HTTP surface. Thin adapter over ``forensia.timeline`` (CLAUDE.md RULE 3, Última super-timeline PERSISTIDA de una evidencia (``{result: … | null}``). (+4 more)

### Community 95 - "timeline_to_csv"
Cohesion: 0.26
Nodes (11): Any, Exportación CSV del timeline de investigación (CLAUDE.md RULE 3: lógica aquí)., Serializa el timeline de investigación a CSV (una fila por evento).      ``eve, timeline_to_csv(), _finding(), Exportación CSV del timeline de investigación (hallazgo D).  Reusa el builder, _rows(), test_csv_has_one_row_per_event_across_both_kinds() (+3 more)

### Community 97 - "TestAsyncRoute"
Cohesion: 0.18
Nodes (5): client(), _poll_http(), TestClient, El registro síncrono no se retira (MCP / tests / scripts lo usan)., TestAsyncRoute

### Community 100 - "RedactionPattern"
Cohesion: 0.26
Nodes (10): RedactionPattern, _applies(), apply_redaction(), Any, Egress redaction — minimize personal data before it crosses to a cloud model., Return a COPY of an OpenAI-shape message list with every string ``content``, Run every applicable pattern's ``regex`` → ``replacement`` over ``text``., redact_messages() (+2 more)

### Community 101 - ".append"
Cohesion: 0.23
Nodes (9): KnowledgeBlock, NodeSummary, Append-only store con vista consolidada para el grafo de conocimiento del caso., Añade un bloque y re-renderiza la vista. NUNCA modifica lo ya escrito., Una escritura. Inmutable: una vez en el ``.jsonl`` no se toca jamás., Una línea del índice que viaja SIEMPRE en el system prompt.      Deliberadamen, _utc_now_iso(), _validate_content() (+1 more)

### Community 102 - "evidence.py"
Cohesion: 0.18
Nodes (11): custody_act(), evidence_metadata(), Any, Evidence inbox listing. Registration is per-case (``/api/cases/{case_id}/evidenc, Bandeja de entrada de evidencias (``FORENSIA_EVIDENCE_DIR`` — en el     compose, Sube una evidencia a la bandeja (``save_uploaded_source``). Camino de     ESCRI, Metadata de custodia de una evidencia: sha256 baseline, tamaño (bytes +     leg, Acta de adquisición estructurada (``forensia.custody.build_custody_act``): (+3 more)

### Community 103 - "TestDelete"
Cohesion: 0.17
Nodes (4): Borrado PERMANENTE del caso: destruye TODA la cadena de custodia, así que     l, El rmtree JAMÁS corre sobre una ruta que se resolvió fuera de la raíz         d, Las copias de evidencia son inmutables (chmod 0444). Borrar el caso         deb, TestDelete

### Community 104 - "test_evidence_register_async.py"
Cohesion: 0.20
Nodes (8): _audit_events(), _baseline(), cases(), _evidence_root(), isolated_cases(), manager(), Registro de evidencia ASÍNCRONO y ATÓMICO (2026-07-27).  Dos problemas reales, Mismo origen, con y sin callback → baseline, segmentos y audit idénticos

### Community 105 - "_write_ewf_set"
Cohesion: 0.21
Nodes (7): _evidence_entries(), Corte a mitad de copia del 3er segmento (los dos primeros ya están         cong, El fallo tras la copia (aquí: escribir baseline.json) también revierte:, Si el proceso muere entre la copia y la limpieza, el temporal que quede, ``stem.E01`` … ``stem.E0<count>`` con contenido DISTINTO por segmento., TestAtomicity, _write_ewf_set()

### Community 109 - "is_uploadable_evidence_ext"
Cohesion: 0.29
Nodes (7): _is_ewf_numeric_segment(), is_registrable_evidence_ext(), is_uploadable_evidence_ext(), ¿Se puede DEPOSITAR en la bandeja un fichero con esta extensión?, ¿Es esta extensión un punto de entrada REGISTRABLE (lo que el operador     pued, A segment in the NUMERIC part of the naming scheme (``.E01`` … ``.E99`` /     `, TestIntakePredicates

### Community 110 - "_dispatch_forensic"
Cohesion: 0.29
Nodes (10): _dispatch_forensic(), _error(), Any, _pydantic_to_json_schema(), MCP `mcp-toolkit` — the core server (S1).  Lo que hace: - Publica las 4 Jira, Serialise a Python dict/list/str into a single MCP TextContent block., Tool execution that fails business-logic-wise returns an isError content     bl, Return a flat (no-$ref) JSON Schema for an MCP ``inputSchema``.      Some MCP (+2 more)

### Community 113 - "__main__.py"
Cohesion: 0.27
Nodes (9): _consent_or_die(), _force_exit(), main(), Entry point — ``python -m forensia.mcp`` arranca el servidor MCP por stdio.  L, Last-resort exit when the cooperative shutdown can't unwind within     ``_FORCE, Return the consent ref or exit non-zero with an actionable message.      The v, Run the MCP server, racing ``server.run`` against an external shutdown     even, _serve() (+1 more)

### Community 114 - "Lifecycle"
Cohesion: 0.24
Nodes (6): build_server(), Lifecycle, Called from select_case once we know which case absorbs the early         sessi, Construct the MCP server and its lifecycle hooks. Returned together so     ``__, Callbacks invoked from __main__.py to bracket the MCP session in the     audit, Server

### Community 115 - "chats.py"
Cohesion: 0.33
Nodes (9): append_chat_message(), AppendMessageRequest, list_chat_sessions(), _msg_dict(), Any, BaseModel, Chat-session HTTP surface.  Thin adapter over ``forensia.chats.store.chat_stor, read_chat_session() (+1 more)

### Community 116 - "test_auto_draft_report.py"
Cohesion: 0.49
Nodes (9): _add_finding(), _draft(), Borrador AUTOMÁTICO del informe pericial al cerrar un análisis.  Los gates que, _register_evidence(), test_no_findings_creates_nothing(), test_refresh_leaves_operator_documents_alone(), test_refresh_replaces_without_stacking(), test_signed_final_is_never_deleted_by_refresh() (+1 more)

### Community 117 - "test_history_ledger.py"
Cohesion: 0.33
Nodes (9): _finding(), MonkeyPatch, El ledger de hallazgos del replay DEBE exponer el finding_id real.  Regresión, Anti-inyección: los títulos (texto derivado de evidencia hostil) van     entrec, El ledger de hallazgos NO entra como `system` (rol de instrucciones): sus     t, test_findings_ledger_empty_when_no_findings(), test_findings_ledger_exposes_the_real_finding_id(), test_findings_ledger_quotes_titles_and_flags_them_untrusted() (+1 more)

### Community 118 - "test_report_generator.py"
Cohesion: 0.29
Nodes (9): _generate(), Síntesis del informe pericial desde los datos reales del caso.  Los gates que, Un stack de almacenes sobre un ``CaseManager`` temporal (aislado del real)., _register_evidence(), test_empty_case_report_is_honest_not_fake(), test_full_report_is_well_formed_and_persists(), test_perito_defaults_to_case_examiner(), test_unknown_case_fails_loud() (+1 more)

### Community 120 - "RegisterJobRegistry"
Cohesion: 0.47
Nodes (3): RegisterJobRegistry, TestJobs, _wait()

### Community 121 - "Finding"
Cohesion: 0.36
Nodes (6): Finding, Any, Append-only JSONL store of structured findings, one file per case.  Layout: ``, Valida los `mitre_hints` de un hallazgo contra la semilla ATT&CK.      Enum ce, _utc_now_iso(), _validate_mitre_hints()

### Community 122 - "apply_redaction"
Cohesion: 0.28
Nodes (7): apply_redaction(), get_redaction_mode(), Any, Apply the active agent package's redaction policy to tool outputs (L6).  The a, Read FORENSIA_REDACTION_MODE from the env. Default ``strict``.      Unknown va, Mutate ``result`` in place applying the package's redaction patterns to     ``s, RedactionMode

### Community 123 - "knowledge.py"
Cohesion: 0.28
Nodes (8): list_nodes(), Any, Grafo de conocimiento por caso — superficie HTTP.  Adaptador fino sobre ``fore, Índice del grafo: un nodo por entrada, con sus secciones. Sin contenido., La vista consolidada de un nodo: última versión de cada sección., El registro append-only íntegro del nodo, en orden de escritura.      Es lo qu, read_history(), read_node()

### Community 131 - "assemble_investigation_timeline"
Cohesion: 0.32
Nodes (8): assemble_investigation_timeline(), Merge audit tool runs and findings into one chronologically ordered event list., _finding(), _id(), test_assemble_orders_tool_runs_and_findings_chronologically(), test_tool_run_event_pairs_start_with_finish(), test_tool_run_without_finish_is_running_and_kept(), test_unparseable_timestamp_sorts_last_never_dropped()

### Community 132 - "_invoke_prepared"
Cohesion: 0.25
Nodes (6): _invoke_prepared(), Cross the runner boundary for an already-fixed literal argv and venue., The Tool contract and the ONLY sanctioned way to execute one.  Security (THREA, Execute a fully-resolved argv array. shell-free by construction.      Default:, run_argv(), test_run_argv_binary_stdout_exact_roundtrip()

### Community 133 - "build_argv"
Cohesion: 0.32
Nodes (7): build_argv(), _is_valid_plugin_name(), parse(), Any, RegRipper wrapper — run a plugin against a pre-extracted Windows registry hive., Compose argv for rip.pl as it runs INSIDE the container.      params:, RegRipper writes plain text; structure varies by plugin.      The wrapper retu

### Community 134 - "_hammer"
Cohesion: 0.36
Nodes (7): _hammer(), Path, Concurrency test for AuditLog.append + cross-platform file lock.  Without the, Child process: append `n` entries with `label` as discriminator., If something inside append() raises, we must not leak the file descriptor., test_concurrent_appends_keep_chain_intact(), test_no_fd_leak_on_exception()

### Community 135 - "TestCaseAnchored"
Cohesion: 0.36
Nodes (3): _fake_jq_exec(), jq does not declare output_dir in its params; the dispatcher does inject it, TestCaseAnchored

### Community 136 - "test_security_gates.py"
Cohesion: 0.32
Nodes (5): client(), TestClient, Behavioural + static security gates (THREAT_MODEL). Cheap now, expensive to retr, test_gate2_foreign_host_header_rejected(), test_gate3_capabilities_requires_token()

### Community 147 - ".history"
Cohesion: 0.33
Nodes (5): KnowledgeNode, El registro íntegro del nodo, en orden de escritura. No viaja al modelo., La vista consolidada. ``None`` si el nodo no existe., La VISTA consolidada de un nodo: última versión de cada sección., _validate_doc_id()

### Community 148 - "build_investigation_timeline"
Cohesion: 0.29
Nodes (7): export_investigation_timeline_csv(), Response, CSV del timeline de investigación (ejecuciones de herramienta + hallazgos, en, build_investigation_timeline(), Load the case's audit log + findings and assemble the investigation timeline., test_build_investigation_timeline_empty_case(), test_build_investigation_timeline_reads_audit_and_findings()

### Community 149 - "parse"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, AmcacheParser wrapper — parse a pre-extracted `Amcache.hve`.  Runs `amcachepar, Compose argv for AmcacheParser.      params:         hive_path (str, required, AmcacheParser closes with `Key: value` totals (shared EZ shape).

### Community 150 - "parse"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, AppCompatCacheParser wrapper — parse the ShimCache from a `SYSTEM` hive.  Runs, Compose argv for AppCompatCacheParser.      params:         hive_path (str, r, ACCP prints `Found N cache entries …` + `Key: value` lines (EZ shape).

### Community 151 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, bulk_extractor wrapper — parallel scanner for emails, URLs, IPs, credit cards…, Compose argv for bulk_extractor.      params:         image_path (str, requir, Extract per-scanner feature counts from the BE summary printed on stdout.

### Community 152 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, Chainsaw wrapper — hunt Sigma / Chainsaw rules over EVTX or JSON event files., Compose argv for Chainsaw.      params:         target_dir (str, required): h, Summarise a Chainsaw hunt.      Bug 007: Chainsaw prints its banner, progress

### Community 153 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, EvtxECmd wrapper — parse a pre-extracted `.evtx` file (or a directory of them)., Compose argv for EvtxECmd.      params:         evtx_path (str, required): pa, EvtxECmd prints a `Processed X events from Y file(s)` summary line.      We su

### Community 154 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, libewf `ewfinfo` wrapper — read case metadata from an E01 image., params: {image_path: str}, Flatten ewfinfo's key/value sections into a single dict.

### Community 155 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, file_info wrapper — characterize the evidence via libmagic (`file`).  POSIX st, Compose argv for file.      params:         image_path (str, required): host, Split the descriptive line into head + traits + raw.

### Community 156 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, foremost wrapper — file carving by header/footer from unallocated (and raw) spac, Compose argv for foremost.      params:         image_path (str, required): r, Summarise foremost stdout. The authoritative per-type breakdown lives in the

### Community 157 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, FTK Imager CLI wrapper — convert the disk-image evidence between formats.  Run, Compose argv for ftkimager (`source dest_base [options]`).      params:, ftkimager closes with per-algorithm blocks (`[MD5]`/`[SHA1]`) of     `Key: valu

### Community 158 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, hashdeep wrapper — recursive, multi-algorithm hashing.  Computes several hashe, Compose argv for hashdeep.      params:         image_path (str, required): f, Parse hashdeep CSV output into per-file hash maps.      Format: header lines s

### Community 159 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, Hayabusa wrapper — run Sigma-based detections over a directory of EVTX files., Compose argv for Hayabusa.      params:         evtx_dir (str, required): hos, Pull the `Key: value` summary lines Hayabusa prints after the run.

### Community 160 - "parse"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, JLECmd wrapper — parse pre-extracted Windows Jump Lists.  Runs `jlecmd` (Eric, Compose argv for JLECmd.      params:         target_path (str, required): pa, JLECmd closes with `Processed …` + `Key: value` lines (shared EZ shape).

### Community 161 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, jq wrapper — run a filter over a JSON file.  Bundled cross-platform helper use, Compose argv for jq.      params:         filter (str, required): jq filter e, Try to parse stdout as JSON; fall back to raw text with a line count.

### Community 162 - "parse"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, LECmd wrapper — parse pre-extracted Windows shortcut (`.lnk`) files.  Runs `le, Compose argv for LECmd.      params:         target_path (str, required): pat, LECmd closes with `Processed …` + `Key: value` lines (shared EZ shape).

### Community 163 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, MFTECmd wrapper — parse a pre-extracted NTFS `$MFT` file.  Runs `MFTECmd` (Eri, Compose argv for MFTECmd.      params:         mft_path (str, required): path, MFTECmd prints a `Processed X MFT records` summary line plus K/V tails.

### Community 164 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, plaso `log2timeline.py` wrapper — build a super-timeline (.plaso storage) from a, Compose argv for log2timeline.py.      params:         image_path (str, requi, log2timeline con `--status_view none` imprime poco; el resultado es el `.plaso`

### Community 165 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, plaso `psort.py` wrapper — post-process a .plaso storage into a timeline.  Rea, Compose argv for psort.py.      params:         plaso_path (str, required): t, psort imprime un resumen (eventos escritos/filtrados). Lo captura; el CSV comple

### Community 166 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, qemu_nbd wrapper — attach a disk image as a READ-ONLY NBD block device (mount he, Compose argv for qemu-nbd (read-only connect).      params:         image_pat, qemu-nbd `-c` no imprime nada en éxito; el efecto es el device conectado.

### Community 167 - "parse"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, RBCmd wrapper — parse Recycle Bin `$I` metadata files.  Runs `rbcmd` (Eric Zim, Compose argv for RBCmd.      params:         target_path (str, required): `$R, RBCmd prints `Processed N out of M files …` + `Key: value` (EZ shape).

### Community 168 - "parse"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, RECmd wrapper — run a RECmd batch against pre-extracted registry hives.  Runs, Compose argv for RECmd (batch mode).      params:         hive_path (str, req, RECmd closes with `Processed …` + `Key: value` lines (shared EZ shape).

### Community 169 - "parse"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, SBECmd wrapper — parse ShellBags from user registry hives.  Runs `sbecmd` (Eri, Compose argv for SBECmd.      params:         target_path (str, required): di, SBECmd prints `Total ShellBags found: N` + `Processed …` (EZ shape).

### Community 170 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, TSK `fls` wrapper — list files and directories from a raw image / partition., Compose argv for fls.      params:         image_path (str, required): host p, Parse fls regular-format output. Body-format (`-m`) is handed off as raw.

### Community 171 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, TSK `icat` wrapper — extract a file's content by inode, without mounting.  Giv, Compose argv for icat.      params:         image_path (str, required): raw i, Summarise the extracted content: length, a text/binary heuristic and a preview.

### Community 172 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, TSK `mactime` wrapper — build a timeline from a body file produced by `fls -m`., Compose argv for mactime.      params:         bodyfile_path (str, required):, Summarise mactime CSV: row count, day histogram, first / last events.

### Community 173 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, TSK `mmls` wrapper — list partitions of a raw disk image.  Example TSK output, Compose argv for mmls.      params:         image_path (str, required): host, Extract partitions into a structured dict the agent can reason over.

### Community 174 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, Volatility 3 wrapper — run a plugin against a memory dump.  Bundled cross-plat, Compose argv for Volatility 3.      params:         dump_path (str, required), Volatility 3 with `-r json` emits a JSON array of row dicts.      Returns a BO

### Community 175 - "parse"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, WxTCmd wrapper — parse a pre-extracted Windows Timeline database.  Runs `wxtcm, Compose argv for WxTCmd.      params:         target_path (str, required): pa, WxTCmd closes with `Processed …` + `Key: value` lines (EZ shape).

### Community 176 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, xxd wrapper — hex dump of the first bytes of the evidence.  POSIX (`xxd` ships, Compose argv for xxd.      params:         image_path (str, required)., xxd output is already structured; we just summarise.

### Community 177 - "build_argv"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, YARA wrapper — match a rules file against a path on disk.  Bundled cross-platf, Compose argv for yara.      params:         rules_path (str, required): host, Each YARA hit is a line `rule_name target_path`; -s appends string lines     th

### Community 178 - "test_smoke.py"
Cohesion: 0.38
Nodes (6): client(), Path, TestClient, test_audit_log_is_hash_chained(), test_capabilities_reports_container_runtime(), test_health_is_public()

### Community 182 - "artifacts.py"
Cohesion: 0.60
Nodes (5): get_artifact(), list_artifacts(), Any, Artifact-run HTTP surface.  Thin adapter over ``forensia.artifacts.store.artif, _run_dict()

### Community 183 - "bodyfile_to_fs_events"
Cohesion: 0.33
Nodes (6): bodyfile_to_fs_events(), Expand a TSK bodyfile (``fls -m`` output) into MACB filesystem events.      Th, test_bodyfile_all_times_equal_yields_full_macb(), test_bodyfile_events_sorted_chronologically_and_capped(), test_bodyfile_macb_grouping_and_letters(), test_bodyfile_skips_zero_times_and_malformed_lines()

### Community 184 - "build_argv"
Cohesion: 0.40
Nodes (5): build_argv(), parse(), Any, strings wrapper — extract printable strings ≥ N chars from the evidence.  POSI, Compose argv for strings.      params:         image_path (str, required).

### Community 185 - "_ScriptedModel"
Cohesion: 0.40
Nodes (3): Any, Emite una lista fija de acciones y GUARDA los mensajes que ve en cada turno., _ScriptedModel

### Community 186 - "tool_usage"
Cohesion: 0.40
Nodes (4): Any, Per-case tool-usage stats, aggregated from the append-only audit log.  Read-on, Return ``[{tool_id, total, ok, failed}]`` sorted by most-used first.      Rais, tool_usage()

### Community 188 - "session.py"
Cohesion: 0.50
Nodes (3): Request, Entrega del token de sesión a la SPA (mismo-origen).  Con el compose, la UI ll, session()

### Community 189 - "parse_summary"
Cohesion: 0.50
Nodes (3): parse_summary(), Any, Shared stdout summariser for the Eric Zimmerman .NET tool wrappers.  Every EZ

### Community 190 - "_symlink_support.py"
Cohesion: 0.50
Nodes (3): Shared guard for tests that need to CREATE a symlink.  On Windows, ``os.symlin, True iff this process can create a symlink (probes a throwaway one)., _symlinks_supported()

## Knowledge Gaps
- **1 isolated node(s):** `forensia`
  These have ≤1 connection - possible missing edges or undocumented components.
- **56 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `CaseManager` connect `CaseManager` to `DocumentStore`, `_msg`, `TestCaseAnchored`, `FindingStore`, `EvidenceContext`, `ArtifactStore`, `test_timeline.py`, `test_tool_version.py`, `test_web_surface.py`, `register_evidence`, `CodexExecutor`, `coverage_to_csv`, `build_investigation_timeline`, `test_derived_handoff.py`, `OsProfileUnresolved`, `test_evidence_ewf_segments.py`, `evidence.py`, `EvidenceManager`, `test_triage_deep.py`, `ScriptedBackend`, `test_leer_artefacto.py`, `._new_case`, `AuditLog`, `TestCreate`, `build_pericial_report`, `TestUpdate`, `test_tool_path_policy.py`, `TestStartRun`, `TestProgress`, `estimate_analysis`, `test_evidence_real.py`, `human_readable_size`, `test_e2e_chain.py`, `test_pivote_declarado.py`, `TestUploadSegmentSet`, `build_custody_act`, `wired`, `DetectedEvidence`, `test_dispatcher_case_anchored.py`, `test_evidence_context_e2e.py`, `test_findings_contract.py`, `wire_dispatcher_custody`, `TestFinalizeRun`, `test_binary_stdout_channel.py`, `KnowledgeStore`, `TestRegister`, `TestAsyncRoute`, `TestCasesRoutes`, `TestDelete`, `test_evidence_register_async.py`, `_write_ewf_set`, `is_uploadable_evidence_ext`, `test_report_generator.py`, `RegisterJobRegistry`?**
  _High betweenness centrality (0.208) - this node is a cross-community bridge._
- **Why does `AuditLog` connect `AuditLog` to `DocumentStore`, `_hammer`, `TestCaseAnchored`, `FindingStore`, `EvidenceContext`, `CaseManager`, `test_tool_version.py`, `test_web_surface.py`, `build_investigation_timeline`, `register_evidence`, `CodexExecutor`, `test_derived_handoff.py`, `OsProfileUnresolved`, `test_evidence_ewf_segments.py`, `evidence.py`, `EvidenceManager`, `ScriptedBackend`, `dispatcher.py`, `ToolExecutionError`, `agent.py`, `test_smoke.py`, `test_tool_path_policy.py`, `Tool`, `estimate_analysis`, `ModelBackend`, `.adjudicate`, `human_readable_size`, `test_e2e_chain.py`, `TestUploadSegmentSet`, `build_custody_act`, `McpSession`, `test_dispatcher_case_anchored.py`, `test_evidence_context_e2e.py`, `is_uploadable_evidence_ext`, `Lifecycle`?**
  _High betweenness centrality (0.161) - this node is a cross-community bridge._
- **Why does `ForensicAgent` connect `ForensicAgent` to `test_knowledge_agent_tools.py`, `test_leer_artefacto.py`, `window_messages`, `AgentPackage`, `ToolExecutionError`, `EvidenceContext`, `.run`, `agent.py`, `test_pivote_declarado.py`, `test_tool_batch.py`, `make_package`, `ToolCall`, `Tool`, `_AlwaysSameTool`, `_ScriptedModel`, `ScriptedBackend`, `EvidenceManager`, `ModelBackend`?**
  _High betweenness centrality (0.106) - this node is a cross-community bridge._
- **Are the 85 inferred relationships involving `CaseManager` (e.g. with `ArtifactIntegrityError` and `ArtifactRun`) actually correct?**
  _`CaseManager` has 85 INFERRED edges - model-reasoned connections that need verification._
- **Are the 98 inferred relationships involving `AuditLog` (e.g. with `Case` and `CaseManager`) actually correct?**
  _`AuditLog` has 98 INFERRED edges - model-reasoned connections that need verification._
- **Are the 55 inferred relationships involving `EvidenceManager` (e.g. with `AgentLoopResult` and `ForensicAgent`) actually correct?**
  _`EvidenceManager` has 55 INFERRED edges - model-reasoned connections that need verification._
- **Are the 47 inferred relationships involving `ForensicAgent` (e.g. with `AgentPackage` and `EvidenceContext`) actually correct?**
  _`ForensicAgent` has 47 INFERRED edges - model-reasoned connections that need verification._