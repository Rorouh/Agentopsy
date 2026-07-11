# Graph Report - C:\Users\super\Desktop\TFM - Forensia\Forensia-AI\tools\graph\out\backend  (2026-07-11)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 1741 nodes · 3029 edges · 143 communities (102 shown, 41 thin omitted)
- Extraction: 81% EXTRACTED · 19% INFERRED · 0% AMBIGUOUS · INFERRED: 574 edges (avg confidence: 0.68)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `410fd11f`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- Community 0
- Community 1
- Community 2
- Community 3
- Community 4
- CaseManager
- ForensicAgent
- test_executors.py
- OsProfileUnresolved
- cases.py
- test_maletin.py
- ExecutorError
- TestCreate
- Community 13
- Community 14
- Community 15
- Community 16
- Community 17
- Community 18
- Community 19
- Community 20
- TestUpdate
- test_redaction_windows.py
- AgentPackage
- AuditLog
- ChatStore
- ClaudeCodeExecutor
- ToolExecutionError
- fingerprint_evidence
- test_mcp_toolkit.py
- CodexExecutor
- window_messages
- AgentPackageError
- _msg
- test_cli_auth_seeding.py
- Tool
- resources.py
- findings.py
- test_dispatcher.py
- _AlwaysSameTool
- ValueError
- select_playbook_section
- build_replay_messages
- _dispatch_forensic
- TestVolatility3
- Community 45
- Community 46
- Community 47
- Community 48
- Community 49
- TestChainsaw
- TestRECmd
- __main__.py
- McpSession
- chats.py
- test_chats.py
- TestTskIcat
- HostHeaderMiddleware
- .append
- _dispatch_jira
- DetectedEvidence
- TestBulkExtractor
- TestEvtxECmd
- TestJq
- TestLECmd
- TestTskMactime
- TestTskMmls
- redact_messages
- Config
- executor_models
- apply_redaction
- _ReadyAnnouncingServer
- build_argv
- test_security_gates.py
- test_wrappers.py
- TestAmcacheParser
- TestForemost
- TestHashdeep
- TestHayabusa
- TestJLECmd
- TestMftECmd
- TestPlasoLog2timeline
- TestRBCmd
- TestYara
- _bounded_json
- Community 85
- Community 86
- Community 87
- Community 88
- Community 89
- Community 90
- Community 91
- Community 92
- Community 93
- Community 94
- Community 95
- Community 96
- Community 97
- Community 98
- Community 99
- Community 100
- Community 101
- Community 102
- Community 103
- Community 104
- Community 105
- Community 106
- Community 107
- Community 108
- Community 109
- Community 110
- Community 111
- Community 112
- Community 113
- Community 114
- Community 115
- Community 116
- Community 117
- Community 118
- Community 119
- Community 120
- Community 121
- Community 122
- Community 123
- Community 124
- evidence.py
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
- forensia

## God Nodes (most connected - your core abstractions)
1. `CaseManager` - 85 edges
2. `AuditLog` - 55 edges
3. `EvidenceManager` - 42 edges
4. `ForensicAgent` - 35 edges
5. `Tool` - 29 edges
6. `AgentPackageError` - 27 edges
7. `_StrictModel` - 27 edges
8. `ArtifactStore` - 26 edges
9. `load_package()` - 23 edges
10. `Case` - 23 edges

## Surprising Connections (you probably didn't know these)
- `client()` --calls--> `create_app()`  [INFERRED]
  tests/test_routers_storage.py → forensia/server.py
- `test_execute_bundled_runs_and_returns_result()` --calls--> `execute()`  [INFERRED]
  tests/test_dispatcher.py → forensia/toolkit/dispatcher.py
- `test_execute_routes_to_maletin_when_binary_not_on_api()` --calls--> `execute()`  [INFERRED]
  tests/test_dispatcher.py → forensia/toolkit/dispatcher.py
- `TestBoundedJson` --uses--> `ForensicAgent`  [INFERRED]
  tests/test_agent_context_budget.py → forensia/agent/agent.py
- `TestSelectPlaybookSection` --uses--> `ForensicAgent`  [INFERRED]
  tests/test_agent_context_budget.py → forensia/agent/agent.py

## Import Cycles
- None detected.

## Communities (143 total, 41 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.06
Nodes (26): EvidenceHandle, EvidenceManager, list_source_files(), Path, Evidence ingestion: hash gate + immutable copy under the owning case directory., Stream-hash ``path`` in chunks. Returns ``(hex_digest, size_bytes)``.      Never, Registers evidence into a case and exposes hash-verified, read-only handles., Enumera las evidencias disponibles en la bandeja de entrada     (``FORENSIA_EVID (+18 more)

### Community 1 - "Community 1"
Cohesion: 0.06
Nodes (23): ArtifactRun, ArtifactStore, _atomic_write_json(), _atomic_write_text(), _hash_file(), _now_iso(), OutputFile, Path (+15 more)

### Community 2 - "Community 2"
Cohesion: 0.06
Nodes (52): AmcacheParserParams, AppCompatCacheParserParams, BulkExtractorParams, ChainsawParams, EvtxECmdParams, EwfInfoParams, FileInfoParams, HayabusaParams (+44 more)

### Community 3 - "Community 3"
Cohesion: 0.08
Nodes (38): Any, Capability contract: the UI never assumes a platform — it asks here and degrades, snapshot(), get_cloud_consent(), has_cloud_consent(), Any, Cloud-executor consent — recorded AND enforced on the HTTP agent-query path.  SE, Append the operator's consent for ``executor_id`` on ``case_id`` to the     case (+30 more)

### Community 4 - "Community 4"
Cohesion: 0.07
Nodes (6): client(), HTTP surface for cases / evidence / artifacts / chats — token gate + roundtrips., TestArtifactsRoutes, TestCasesRoutes, TestChatsRoutes, TestEvidenceRoutes

### Community 5 - "CaseManager"
Cohesion: 0.15
Nodes (16): Case, CaseManager, Path, Case lifecycle: create / list / load / close, persisted as ``case.json`` per dir, Owns ``CONFIG_DIR/cases/``. Creates, lists, loads, and closes cases.      Not th, Flip a closed case back to ``active`` — the only way to register         more ev, Edit case metadata. Only the provided fields change — ``None`` means         "le, Derive/adjust the case ``os_profile`` from a newly registered         evidence's (+8 more)

### Community 6 - "ForensicAgent"
Cohesion: 0.17
Nodes (21): ForensicAgent, AgentPackageModel, AgentPackagePolicy, AgentPackagePrompts, Tipos del paquete de agente entrenado (los que vienen de ``agentes/<id>/``).  Un, RedactionPattern, CloudConsent, Per-case record that the operator opted in to cloud egress.      Cloud is OFF by (+13 more)

### Community 7 - "test_executors.py"
Cohesion: 0.13
Nodes (29): clean_config(), client(), _fake_status(), _gemini_with_home(), MonkeyPatch, Path, TestClient, _query() (+21 more)

### Community 8 - "OsProfileUnresolved"
Cohesion: 0.15
Nodes (17): OsProfileUnresolved, RuntimeError, Resolve the ``os_profile`` a case routes on, or fail loud.      The SINGLE resol, The case has no ``os_profile`` that can be routed on.      Raised by ``resolve_o, resolve_os_profile(), Honour FORENSIA_CASE_ID as a *test-only* preselection.          The env var exis, _audit(), cases() (+9 more)

### Community 9 - "cases.py"
Cohesion: 0.18
Nodes (25): anchor_os_profile(), AnchorOsProfileRequest, _case_dict(), close_case(), create_case(), CreateCaseRequest, _evidence_dict(), get_case() (+17 more)

### Community 10 - "test_maletin.py"
Cohesion: 0.15
Nodes (22): _cross_tool(), MonkeyPatch, Unit tests for the maletín availability probe (forensia.toolkit.maletin).  The p, A windows-only tool must NOT be reported available just because toolkit-unix is, test_binary_absent_in_running_maletin_reports_reason(), test_container_name_env_override(), test_cross_tool_available_if_present_in_any_declared_maletin(), test_env_override_wins_over_maletin() (+14 more)

### Community 11 - "ExecutorError"
Cohesion: 0.12
Nodes (18): ExecutorError, RuntimeError, Timeout in seconds for one executor run.      Resolution order — every step oper, The executor could not produce a response (missing binary, non-zero exit,     un, resolve_timeout(), OllamaExecutor, Any, Ollama executor — HTTP to the compose ``ollama`` service. The 100% local option. (+10 more)

### Community 13 - "Community 13"
Cohesion: 0.23
Nodes (23): load_package(), Carga + valida un único ``agentes/<id>/`` y devuelve el ``AgentPackage``.      L, client(), Path, TestClient, Tests for the agent package loader + registry.  Covers: - Valid manifest loads e, test_absolute_prompt_path_rejected(), test_empty_allowlist_rejected() (+15 more)

### Community 14 - "Community 14"
Cohesion: 0.13
Nodes (14): CliPromptExecutor, _ms(), PromptExecutor, ABC, Any, Execution layer contract: ``PromptExecutor``.  The 2026-07-02 pivot replaces the, Shared plumbing for the three CLI executors.      Subclasses declare the binary,, Run the CLI's NON-INTERACTIVE auth-status command.          Returns ``(logged_in (+6 more)

### Community 15 - "Community 15"
Cohesion: 0.18
Nodes (22): _audit_actions(), client(), _create_case(), MonkeyPatch, TestClient, Superficie HTTP para la SPA (migración del frontend al servicio `web`).  Covers:, test_anchor_os_profile_endpoint_sets_and_persists(), test_anchor_os_profile_rejects_invalid() (+14 more)

### Community 16 - "Community 16"
Cohesion: 0.17
Nodes (21): CompletedProcess, Path, Execute a Tool inside its declared OCI image.  Security (THREAT_MODEL gates 5-7), Run `tool.container_image` with `argv_inside` against the host's OCI runtime., run_in_container(), _validate_mount_paths(), _make_container_tool(), Tests for forensia.toolkit.container — runtime execution + mount guard.  Critica (+13 more)

### Community 17 - "Community 17"
Cohesion: 0.12
Nodes (12): cases(), Dispatcher behaviour when anchored to a case: audit log + artifact manifest., jq does not declare output_dir in its params; the dispatcher does inject it, If the caller supplied output_dir explicitly the dispatcher must not overwrite i, Swap the module-level singletons used by the dispatcher so storage lives in tmp_, _require_jq(), store(), TestCaseAnchored (+4 more)

### Community 18 - "Community 18"
Cohesion: 0.14
Nodes (15): AgentLoopResult, _max_tool_attempts(), _preview_params(), Any, The forensic agent loop.  ONE agent parametrized by an ``AgentPackage`` loaded f, One-line human summary of a tool result for the live activity log., Convenience dict subclass for typing the run() return., Append one event to the case audit chain, if an AuditLog was wired.          The (+7 more)

### Community 19 - "Community 19"
Cohesion: 0.11
Nodes (14): by_tier(), for_profile(), The curated maletín. Each entry is a closed-enum Tool the agent may select.  Tie, Lightweight invariants over the catalog wiring.  These tests are a tripwire: any, A tool applicable to an OS profile must live in that profile's maletín — so a, Every core tool must override the stub `_not_built` for both callables., Extended tools still in `_EXTENDED_STILL_STUB` keep the `_not_built` stub;     a, test_core_tier_matches_expected_kit() (+6 more)

### Community 20 - "Community 20"
Cohesion: 0.15
Nodes (21): container_name(), MaletinExecError, _no_url_reason(), probe_binaries(), probe_service(), Any, RuntimeError, The maletín model + the availability probe `capabilities` reports (RULE 1).  Eve (+13 more)

### Community 21 - "TestUpdate"
Cohesion: 0.07
Nodes (9): _audit(), manager(), CaseManager contract: create / list / load / close + path-traversal guard., TestCaseDirConfinement, TestClose, TestList, TestLoad, TestReopen (+1 more)

### Community 22 - "test_redaction_windows.py"
Cohesion: 0.17
Nodes (19): _apply(), _pattern(), Gate de la policy de redacción del paquete `forensia-windows`.  Verifica, sin im, Aplica los patrones del modo dado, en orden, como el motor., Ejecuta fn() en un hilo; devuelve el tiempo o None si excede el presupuesto, _run_with_budget(), test_credenciales_tambien_en_relaxed(), test_credential_dump_line_redacted() (+11 more)

### Community 23 - "AgentPackage"
Cohesion: 0.15
Nodes (12): AgentPackage, Vista JSON-friendly para ``/api/agents`` y ``/api/capabilities``. No         inc, AgentRegistry, AgentRegistryError, _default_agents_dir(), Path, RuntimeError, Discovery + indexing of agent packages dropped in ``agentes/`` at repo root.  Re (+4 more)

### Community 24 - "AuditLog"
Cohesion: 0.16
Nodes (13): AuditLog, _canonical(), Any, Path, Tamper-evident audit log: one JSON object per line, each chained to the previous, Parsed entries in append order.          Read-only view for policy lookups (e.g., _hammer(), Path (+5 more)

### Community 25 - "ChatStore"
Cohesion: 0.16
Nodes (12): ChatMessage, ChatStore, _now_iso(), Path, Chat session storage: append-only JSONL per session under ``<case_dir>/chats/``., Return session ids found in ``chats/`` (filenames stripped of ``.jsonl``)., Filesystem-backed JSONL store for chat sessions., Append one JSON object (one message) to ``chats/<session_id>.jsonl``.          A (+4 more)

### Community 26 - "ClaudeCodeExecutor"
Cohesion: 0.15
Nodes (14): ExecutorAvailability, ClaudeCodeExecutor, Claude Code executor — ``claude -p <prompt> --output-format json``.  Flags verif, Regresión del fallo E2E 2026-07-06 (chat con claude-code): el router         val, Si la sesión cae ENTRE el probe de auth y el run (probe OK, `claude -p`     exit, Capa executor↔parser: un stdout que no es el envelope de     `--output-format js, Envelope de éxito de `--output-format json` (campos documentados:     `result` +, test_claude_extract_text_happy_envelope_returns_result() (+6 more)

### Community 27 - "ToolExecutionError"
Cohesion: 0.17
Nodes (18): execute(), _parse_wants_stderr(), Any, RuntimeError, End-to-end dispatcher: from `(tool_id, params)` to a parsed result.  Glue betwee, True when a wrapper's ``parse`` accepts a second positional arg (stderr).      W, Coerce non-JSON-native values (Path, bytes) to strings so the audit log's     ca, Raised when a tool cannot be executed (not when it runs and fails — that     cas (+10 more)

### Community 28 - "fingerprint_evidence"
Cohesion: 0.16
Nodes (18): _accumulate_family(), _classify_header(), _count_markers(), _decide_family(), fingerprint_evidence(), fingerprint_os(), _mbr_partitions_sane(), Path (+10 more)

### Community 29 - "test_mcp_toolkit.py"
Cohesion: 0.22
Nodes (16): _build_session_cm(), _extract_payload(), Any, Tests for ``forensia.mcp.toolkit`` — the MCP server S1.  Uses in-process memory, Run windows.info both directly via dispatcher and via the MCP client.     Compar, Pull the JSON dict out of a CallToolResult's first text content block., test_differential_dispatcher_vs_mcp(), test_forensic_tool_without_select_case_fails_loud() (+8 more)

### Community 30 - "CodexExecutor"
Cohesion: 0.12
Nodes (6): CodexExecutor, Any, Codex CLI executor — ``codex exec <prompt>`` in non-interactive mode.  Flags ver, GeminiExecutor, Gemini CLI executor — ``gemini -p <prompt> --output-format json``.  Flags verifi, Execution layer: the four operator-selected executors (2026-07-02 pivot).  ``get

### Community 31 - "window_messages"
Cohesion: 0.23
Nodes (9): keep_last_tool_results_default(), Any, Provider-agnostic context-window management for the agent loop (Bug 008).  The e, How many of the most recent tool-result messages stay verbatim on the wire., One-line replacement for an elided tool-result body. Best-effort extracts     ``, Return a COPY of ``messages`` with all but the most recent     ``keep_last_tool_, _stub_for(), window_messages() (+1 more)

### Community 32 - "AgentPackageError"
Cohesion: 0.42
Nodes (14): AgentPackageError, _coerce_authors(), _parse_model(), _parse_policy(), _parse_prompts(), _parse_redaction_pattern(), Any, Path (+6 more)

### Community 33 - "_msg"
Cohesion: 0.22
Nodes (3): _msg(), TestAppend, TestRead

### Community 34 - "test_cli_auth_seeding.py"
Cohesion: 0.32
Nodes (14): dirs(), populate_staging(), _posix_perms_enforced(), CompletedProcess, Path, Seeding de credenciales al volumen ``forensia-cli-auth`` (docker/api/entrypoint., True iff ``chmod`` group/other bits actually stick. On Windows ``st_mode``     i, run_entrypoint() (+6 more)

### Community 35 - "Tool"
Cohesion: 0.20
Nodes (12): Tools the agent is ACTUALLY allowed to invoke (allowlist ∩ catalog)., Which maletín runs `tool`, honouring RULE 2 (no fallback between maletines)., Run the tool inside its maletín via the exec-agent (§B). The recorded argv is, _run_maletin(), _select_maletin(), HostOs, Tool, test_select_maletin_ambiguous_without_profile_raises() (+4 more)

### Community 36 - "resources.py"
Cohesion: 0.20
Nodes (13): ArtifactRef, build_resource_links_for_run(), parse_artifact_uri(), Path, ``resources/read`` handler for MCP `mcp-toolkit` (D5').  URI scheme: ``artifact:, Build one ``ResourceLink`` per artifact file in a finished run.      Includes:, Parse ``artifact://<case>/<run>/<relpath>`` or raise ``ValueError``., Return the absolute, canonical filesystem path of the referenced artifact. (+5 more)

### Community 37 - "findings.py"
Cohesion: 0.18
Nodes (12): append_finding(), AppendFindingRequest, list_findings(), list_tool_usage(), Any, BaseModel, Per-case findings HTTP surface. Thin adapter over forensia.findings.store., Per-tool run counts for the case (Tools panel). Aggregated from audit.jsonl. (+4 more)

### Community 38 - "test_dispatcher.py"
Cohesion: 0.20
Nodes (13): _build_result(), Tests for forensia.toolkit.dispatcher.execute and _build_result.  `execute()` is, Bug 007: wrappers whose useful summary lands on stderr declare     parse(stdout,, A classic parse(stdout) must keep receiving stdout alone — no arity break., If a wrapper's parse() raises, the dispatcher must NOT crash — the     structure, test_build_result_nonzero_exit_skips_parse(), test_build_result_parser_exception_becomes_structured_error(), test_build_result_passes_stderr_to_two_arg_parser() (+5 more)

### Community 39 - "_AlwaysSameTool"
Cohesion: 0.22
Nodes (10): _AlwaysSameTool, _FakeEvidence, Any, MonkeyPatch, Guardrail anti-bucle del loop del agente (Bug 001).  Una tool que falla no debe, Modelo que SIEMPRE pide la misma tool — simula el bucle del Bug 001., Una tool que va bien puede llamarse muchas veces (p. ej. tsk_icat por inodo): el, test_failing_tool_blocked_after_max_attempts() (+2 more)

### Community 40 - "ValueError"
Cohesion: 0.26
Nodes (7): Action, SEC-1 — reject any auxiliary path that escapes the FORENSIA case tree.      Acce, _validate_confined_path(), ExecutorBackend, Any, Adapter: ``PromptExecutor`` → ``ModelBackend`` for ``ForensicAgent``.      ``run, ValueError

### Community 41 - "select_playbook_section"
Cohesion: 0.24
Nodes (5): Classify a level-2 playbook section by its heading: ``disk`` | ``memory`` |, Return the playbook with the primary branch that does NOT match     ``detected_k, _section_branch(), select_playbook_section(), TestSelectPlaybookSection

### Community 42 - "build_replay_messages"
Cohesion: 0.21
Nodes (12): build_replay_messages(), _cap_transcript(), _drop_trailing_user(), _findings_ledger(), Any, Server-side replay of a chat session for the next agent turn.  Without this modu, Keep the last ``max_turns`` user/assistant turns, then enforce a     cumulative, Build a markdown summary of tool runs persisted on prior assistant     turns. En (+4 more)

### Community 43 - "_dispatch_forensic"
Cohesion: 0.26
Nodes (12): _dispatch_forensic(), _error(), _inject_evidence_path(), Any, _pydantic_to_json_schema(), MCP `mcp-toolkit` — the core server (S1).  Lo que hace: - Publica las 4 Jira too, Mirror of ``ForensicAgent._EVIDENCE_INJECTION`` — the dispatcher expects     the, Serialise a Python dict/list/str into a single MCP TextContent block. (+4 more)

### Community 45 - "Community 45"
Cohesion: 0.20
Nodes (5): FinalAnswer, ModelBackend, ModelCapabilities, ABC, Bridge between the agent loop and the execution layer.  ``ForensicAgent.run`` dr

### Community 46 - "Community 46"
Cohesion: 0.23
Nodes (11): get_config(), list_executors(), list_models(), Any, BaseModel, Operator config read/write surface.  Reads and writes ``config.json`` under ``FO, Closed enum of executor ids for the Settings dropdown. Availability (with     th, Models the composer's model picker offers for ``executor_id``. Ollama returns (+3 more)

### Community 49 - "Community 49"
Cohesion: 0.22
Nodes (6): allowed_hosts(), new_session_token(), Transport hardening for the local api service (THREAT_MODEL gates 1-3, 12).  - P, create_app(), ``ui_origins`` — orígenes exactos de la UI web (p. ej.     ``http://127.0.0.1:51, FastAPI

### Community 52 - "__main__.py"
Cohesion: 0.27
Nodes (9): _consent_or_die(), _force_exit(), main(), Entry point — ``python -m forensia.mcp`` arranca el servidor MCP por stdio.  Lif, Last-resort exit when the cooperative shutdown can't unwind within     ``_FORCE_, Return the consent ref or exit non-zero with an actionable message.      The var, Run the MCP server, racing ``server.run`` against an external shutdown     event, _serve() (+1 more)

### Community 53 - "McpSession"
Cohesion: 0.22
Nodes (6): McpSession, In-memory session state for the MCP server.  A single ``McpSession`` instance li, Mutable session state. Public attributes accessed by toolkit.py., build_server(), Construct the MCP server and its lifecycle hooks. Returned together so     ``__m, Server

### Community 54 - "chats.py"
Cohesion: 0.33
Nodes (8): append_chat_message(), AppendMessageRequest, _msg_dict(), Any, BaseModel, Chat-session HTTP surface.  Thin adapter over ``forensia.chats.store.chat_store`, read_chat_session(), _utc_now_iso()

### Community 55 - "test_chats.py"
Cohesion: 0.20
Nodes (4): cases(), ChatStore contract: append/read JSONL with role + session_id validation., TestListSessions, TestSequentialAppendsAreOrdered

### Community 57 - "HostHeaderMiddleware"
Cohesion: 0.22
Nodes (7): BaseHTTPMiddleware, HostHeaderMiddleware, Request, Reject any request whose Host header is not our exact loopback host:port., Constant-time check of the per-session token on protected routes., require_token(), token()

### Community 58 - ".append"
Cohesion: 0.33
Nodes (5): Finding, FindingStore, Any, Append-only JSONL store of structured findings, one file per case.  Layout: ``~/, _utc_now_iso()

### Community 59 - "_dispatch_jira"
Cohesion: 0.50
Nodes (8): _err(), list_cases(), list_evidence(), Any, The four Jira-pattern tools: list_cases, select_case, list_evidence, select_evid, select_case(), select_evidence(), _dispatch_jira()

### Community 60 - "DetectedEvidence"
Cohesion: 0.39
Nodes (5): DetectedEvidence, Triage record persisted to ``baseline.json`` and surfaced on the handle.      ``, Return the ``os_profile`` this evidence can be auto-routed to, or ``None``     w, routable_profile(), TestRoutablePredicate

### Community 67 - "redact_messages"
Cohesion: 0.29
Nodes (6): apply_redaction(), Any, Egress redaction — minimize personal data before it crosses to a cloud model.  P, Run every pattern's ``regex`` → ``replacement`` over ``text``, in order.      Pa, Return a COPY of an OpenAI-shape message list with every string ``content``, redact_messages()

### Community 68 - "Config"
Cohesion: 0.32
Nodes (3): Config, Any, Configuration: ~/.forensia/config.json with environment-variable override.  RULE

### Community 69 - "executor_models"
Cohesion: 0.25
Nodes (8): executor_models(), Models selectable for ``executor_id``, for the composer's model picker.      Onl, Los CLIs cloud gestionan su modelo; FORENSIA no lo sobrescribe (RULE 2)., Host caído → lista vacía + la razón accionable en note (no un fallo mudo)., test_executor_models_cloud_is_not_editable_and_notes_cli(), test_executor_models_ollama_degrades_on_host_error(), test_executor_models_ollama_lists_installed(), test_executor_models_unknown_id_fails_loud()

### Community 70 - "apply_redaction"
Cohesion: 0.32
Nodes (7): apply_redaction(), get_redaction_mode(), Any, Apply the active agent package's redaction policy to tool outputs (L6).  The age, Read FORENSIA_REDACTION_MODE from the env. Default ``strict``.      Unknown valu, Mutate ``result`` in place applying the package's redaction patterns to     ``st, RedactionMode

### Community 71 - "_ReadyAnnouncingServer"
Cohesion: 0.36
Nodes (5): _free_port(), main(), The FORENSIA api (FastAPI). Standalone mode binds 127.0.0.1 on an ephemeral port, Print the READY line only after `self.started` flips (sockets listening)., _ReadyAnnouncingServer

### Community 72 - "build_argv"
Cohesion: 0.32
Nodes (7): build_argv(), _is_valid_plugin_name(), parse(), Any, RegRipper wrapper — run a plugin against a pre-extracted Windows registry hive., Compose argv for rip.pl as it runs INSIDE the container.      params:         hi, RegRipper writes plain text; structure varies by plugin.      The wrapper return

### Community 73 - "test_security_gates.py"
Cohesion: 0.32
Nodes (5): client(), TestClient, Behavioural + static security gates (THREAT_MODEL). Cheap now, expensive to retr, test_gate2_foreign_host_header_rejected(), test_gate3_capabilities_requires_token()

### Community 84 - "_bounded_json"
Cohesion: 0.20
Nodes (6): _bounded_json(), Serialize ``body`` to JSON, kept under ``limit`` chars WITHOUT ever emitting, Context-budget / token-consumption guards (Bug 008).  The executor is stateless, TestBoundedJson, TestToolResultPayloadOrder, _tool_msg()

### Community 85 - "Community 85"
Cohesion: 0.43
Nodes (6): internal_tool_specs(), Any, JSON Schemas que describen los params de cada Tool del catálogo en el formato de, Return the function-calling spec for ``tool_id``, or None if unsupported., tool_spec(), tool_specs()

### Community 86 - "Community 86"
Cohesion: 0.38
Nodes (3): Lifecycle, Called from select_case once we know which case absorbs the early         sessio, Callbacks invoked from __main__.py to bracket the MCP session in the     audit l

### Community 87 - "Community 87"
Cohesion: 0.29
Nodes (6): container_runtime(), current_host_os(), HostOs, Path, Low-level resolution helpers per CLAUDE.md RULE 1.  - `resolve(binary)`: env ove, Return the path to a usable OCI runtime, or None.      Tries docker, podman, ner

### Community 88 - "Community 88"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, AmcacheParser wrapper — parse a pre-extracted `Amcache.hve`.  Runs `amcacheparse, Compose argv for AmcacheParser.      params:         hive_path (str, required):, AmcacheParser closes with `Key: value` totals (shared EZ shape).

### Community 89 - "Community 89"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, AppCompatCacheParser wrapper — parse the ShimCache from a `SYSTEM` hive.  Runs `, Compose argv for AppCompatCacheParser.      params:         hive_path (str, requ, ACCP prints `Found N cache entries …` + `Key: value` lines (EZ shape).

### Community 90 - "Community 90"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, bulk_extractor wrapper — parallel scanner for emails, URLs, IPs, credit cards…, Compose argv for bulk_extractor.      params:         image_path (str, required), Extract per-scanner feature counts from the BE summary printed on stdout.

### Community 91 - "Community 91"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, Chainsaw wrapper — hunt Sigma / Chainsaw rules over EVTX or JSON event files.  B, Compose argv for Chainsaw.      params:         target_dir (str, required): host, Summarise a Chainsaw hunt.      Bug 007: Chainsaw prints its banner, progress an

### Community 92 - "Community 92"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, EvtxECmd wrapper — parse a pre-extracted `.evtx` file (or a directory of them)., Compose argv for EvtxECmd.      params:         evtx_path (str, required): path, EvtxECmd prints a `Processed X events from Y file(s)` summary line.      We surf

### Community 93 - "Community 93"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, libewf `ewfinfo` wrapper — read case metadata from an E01 image., params: {image_path: str}, Flatten ewfinfo's key/value sections into a single dict.

### Community 94 - "Community 94"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, file_info wrapper — characterize the evidence via libmagic (`file`).  POSIX stan, Compose argv for file.      params:         image_path (str, required): host pat, Split the descriptive line into head + traits + raw.

### Community 95 - "Community 95"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, foremost wrapper — file carving by header/footer from unallocated (and raw) spac, Compose argv for foremost.      params:         image_path (str, required): raw, Summarise foremost stdout. The authoritative per-type breakdown lives in the

### Community 96 - "Community 96"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, hashdeep wrapper — recursive, multi-algorithm hashing.  Computes several hashes, Compose argv for hashdeep.      params:         image_path (str, required): file, Parse hashdeep CSV output into per-file hash maps.      Format: header lines sta

### Community 97 - "Community 97"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, Hayabusa wrapper — run Sigma-based detections over a directory of EVTX files.  B, Compose argv for Hayabusa.      params:         evtx_dir (str, required): host d, Pull the `Key: value` summary lines Hayabusa prints after the run.

### Community 98 - "Community 98"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, JLECmd wrapper — parse pre-extracted Windows Jump Lists.  Runs `jlecmd` (Eric Zi, Compose argv for JLECmd.      params:         target_path (str, required): path, JLECmd closes with `Processed …` + `Key: value` lines (shared EZ shape).

### Community 99 - "Community 99"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, jq wrapper — run a filter over a JSON file.  Bundled cross-platform helper used, Compose argv for jq.      params:         filter (str, required): jq filter expr, Try to parse stdout as JSON; fall back to raw text with a line count.

### Community 100 - "Community 100"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, LECmd wrapper — parse pre-extracted Windows shortcut (`.lnk`) files.  Runs `lecm, Compose argv for LECmd.      params:         target_path (str, required): path t, LECmd closes with `Processed …` + `Key: value` lines (shared EZ shape).

### Community 101 - "Community 101"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, MFTECmd wrapper — parse a pre-extracted NTFS `$MFT` file.  Runs `MFTECmd` (Eric, Compose argv for MFTECmd.      params:         mft_path (str, required): path to, MFTECmd prints a `Processed X MFT records` summary line plus K/V tails.

### Community 102 - "Community 102"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, plaso `log2timeline.py` wrapper — build a super-timeline (.plaso storage) from a, Compose argv for log2timeline.py.      params:         image_path (str, required, log2timeline con `--status_view none` imprime poco; el resultado es el `.plaso`

### Community 103 - "Community 103"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, plaso `psort.py` wrapper — post-process a .plaso storage into a timeline.  Reads, Compose argv for psort.py.      params:         plaso_path (str, required): the, psort imprime un resumen (eventos escritos/filtrados). Lo captura; el CSV comple

### Community 104 - "Community 104"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, qemu_nbd wrapper — attach a disk image as a READ-ONLY NBD block device (mount he, Compose argv for qemu-nbd (read-only connect).      params:         image_path (, qemu-nbd `-c` no imprime nada en éxito; el efecto es el device conectado.

### Community 105 - "Community 105"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, RBCmd wrapper — parse Recycle Bin `$I` metadata files.  Runs `rbcmd` (Eric Zimme, Compose argv for RBCmd.      params:         target_path (str, required): `$Recy, RBCmd prints `Processed N out of M files …` + `Key: value` (EZ shape).

### Community 106 - "Community 106"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, RECmd wrapper — run a RECmd batch against pre-extracted registry hives.  Runs `r, Compose argv for RECmd (batch mode).      params:         hive_path (str, requir, RECmd closes with `Processed …` + `Key: value` lines (shared EZ shape).

### Community 107 - "Community 107"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, SBECmd wrapper — parse ShellBags from user registry hives.  Runs `sbecmd` (Eric, Compose argv for SBECmd.      params:         target_path (str, required): direc, SBECmd prints `Total ShellBags found: N` + `Processed …` (EZ shape).

### Community 108 - "Community 108"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, TSK `fls` wrapper — list files and directories from a raw image / partition.  Bu, Compose argv for fls.      params:         image_path (str, required): host path, Parse fls regular-format output. Body-format (`-m`) is handed off as raw.

### Community 109 - "Community 109"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, TSK `icat` wrapper — extract a file's content by inode, without mounting.  Given, Compose argv for icat.      params:         image_path (str, required): raw imag, Summarise the extracted content: length, a text/binary heuristic and a preview.

### Community 110 - "Community 110"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, TSK `mactime` wrapper — build a timeline from a body file produced by `fls -m`., Compose argv for mactime.      params:         bodyfile_path (str, required): bo, Summarise mactime CSV: row count, day histogram, first / last events.

### Community 111 - "Community 111"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, TSK `mmls` wrapper — list partitions of a raw disk image.  Example TSK output (D, Compose argv for mmls.      params:         image_path (str, required): host pat, Extract partitions into a structured dict the agent can reason over.

### Community 112 - "Community 112"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, Volatility 3 wrapper — run a plugin against a memory dump.  Bundled cross-platfo, Compose argv for Volatility 3.      params:         dump_path (str, required): h, Volatility 3 with `-r json` emits a JSON array of row dicts.      Returns a BOUN

### Community 113 - "Community 113"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, WxTCmd wrapper — parse a pre-extracted Windows Timeline database.  Runs `wxtcmd`, Compose argv for WxTCmd.      params:         target_path (str, required): path, WxTCmd closes with `Processed …` + `Key: value` lines (EZ shape).

### Community 114 - "Community 114"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, xxd wrapper — hex dump of the first bytes of the evidence.  POSIX (`xxd` ships w, Compose argv for xxd.      params:         image_path (str, required).         b, xxd output is already structured; we just summarise.

### Community 115 - "Community 115"
Cohesion: 0.33
Nodes (6): build_argv(), parse(), Any, YARA wrapper — match a rules file against a path on disk.  Bundled cross-platfor, Compose argv for yara.      params:         rules_path (str, required): host pat, Each YARA hit is a line `rule_name target_path`; -s appends string lines     tha

### Community 116 - "Community 116"
Cohesion: 0.38
Nodes (6): client(), Path, TestClient, test_audit_log_is_hash_chained(), test_capabilities_reports_container_runtime(), test_health_is_public()

### Community 121 - "Community 121"
Cohesion: 0.60
Nodes (5): get_artifact(), list_artifacts(), Any, Artifact-run HTTP surface.  Thin adapter over ``forensia.artifacts.store.artifac, _run_dict()

### Community 122 - "Community 122"
Cohesion: 0.40
Nodes (5): build_argv(), parse(), Any, strings wrapper — extract printable strings ≥ N chars from the evidence.  POSIX, Compose argv for strings.      params:         image_path (str, required).

### Community 124 - "Community 124"
Cohesion: 0.40
Nodes (3): The Tool contract and the ONLY sanctioned way to execute one.  Security (THREAT_, Execute a fully-resolved argv array. shell-free by construction., run_argv()

### Community 126 - "evidence.py"
Cohesion: 0.50
Nodes (3): Evidence inbox listing. Registration is per-case (``/api/cases/{case_id}/evidenc, Bandeja de entrada de evidencias (``FORENSIA_EVIDENCE_DIR`` — en el     compose,, sources()

### Community 127 - "session.py"
Cohesion: 0.50
Nodes (3): Request, Entrega del token de sesión a la SPA (mismo-origen).  Con el compose, la UI lleg, session()

### Community 128 - "parse_summary"
Cohesion: 0.50
Nodes (3): parse_summary(), Any, Shared stdout summariser for the Eric Zimmerman .NET tool wrappers.  Every EZ to

### Community 129 - "_symlink_support.py"
Cohesion: 0.50
Nodes (3): Shared guard for tests that need to CREATE a symlink.  On Windows, ``os.symlink`, True iff this process can create a symlink (probes a throwaway one)., _symlinks_supported()

## Knowledge Gaps
- **1 isolated node(s):** `forensia`
  These have ≤1 connection - possible missing edges or undocumented components.
- **41 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `CaseManager` connect `CaseManager` to `Community 0`, `Community 1`, `_msg`, `ClaudeCodeExecutor`, `Community 4`, `ForensicAgent`, `ValueError`, `OsProfileUnresolved`, `TestCreate`, `Community 15`, `Community 17`, `TestUpdate`, `test_chats.py`, `AuditLog`, `ChatStore`, `.append`, `DetectedEvidence`?**
  _High betweenness centrality (0.179) - this node is a cross-community bridge._
- **Why does `AuditLog` connect `AuditLog` to `Community 0`, `Community 3`, `CaseManager`, `ForensicAgent`, `OsProfileUnresolved`, `ToolExecutionError`, `Community 45`, `Community 15`, `Community 17`, `Community 116`, `Community 86`, `ClaudeCodeExecutor`, `_dispatch_jira`?**
  _High betweenness centrality (0.114) - this node is a cross-community bridge._
- **Why does `get_executor()` connect `Community 3` to `ValueError`, `executor_models`, `Community 14`, `CodexExecutor`?**
  _High betweenness centrality (0.077) - this node is a cross-community bridge._
- **Are the 48 inferred relationships involving `CaseManager` (e.g. with `ArtifactRun` and `ArtifactStore`) actually correct?**
  _`CaseManager` has 48 INFERRED edges - model-reasoned connections that need verification._
- **Are the 61 inferred relationships involving `ValueError` (e.g. with `.run()` and `.finalize_run()`) actually correct?**
  _`ValueError` has 61 INFERRED edges - model-reasoned connections that need verification._
- **Are the 43 inferred relationships involving `AuditLog` (e.g. with `Case` and `CaseManager`) actually correct?**
  _`AuditLog` has 43 INFERRED edges - model-reasoned connections that need verification._
- **Are the 24 inferred relationships involving `EvidenceManager` (e.g. with `AgentLoopResult` and `ForensicAgent`) actually correct?**
  _`EvidenceManager` has 24 INFERRED edges - model-reasoned connections that need verification._