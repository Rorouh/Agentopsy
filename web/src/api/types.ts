// Tipos espejo de los contratos JSON del servicio api (backend/forensia/routers/*).
// Convención: snake_case 1:1 con el backend — sin transformaciones en el cliente.

export type ExecutorId = "claude-code" | "codex" | "gemini" | "ollama";

// Análisis del agente lanzado en SEGUNDO PLANO (POST /api/agent/analyze). Corre
// desacoplado de la conexión: una desconexión no lo aborta. Se consulta por id.
export interface AgentJob {
  job_id: string;
  case_id: string;
  kind: string;
  status: "running" | "done" | "error" | "cancelled";
  created_at: string;
  finished_at: string | null;
  result: { reply: string; iterations: number; tool_calls: unknown[] } | null;
  error: string | null;
  // Eventos de progreso acumulados (tool_call con argv, tool_result, finding…);
  // `event_count` es el total (para sondear con `since`).
  events?: StreamEvent[];
  event_count?: number;
}

// Estado de un ejecutor tal y como lo reporta /api/capabilities (RULE 2: si no
// está disponible, `reason` trae la razón accionable — binario ausente,
// credenciales sin montar, Ollama inaccesible — y la UI degrada explícitamente).
export interface ExecutorStatus {
  name: string;
  local: boolean;
  available: boolean;
  reason: string | null;
}

// Modelos que el selector del composer ofrece para un ejecutor
// (/api/executors/{id}/models). Todos son `editable`: el operador elige el modelo
// y Agentopsy lo respeta (Ollama por HTTP; los CLIs cloud como flag --model). La
// lista difiere: Ollama devuelve los modelos REALES instalados; los CLIs cloud,
// solo atajos como sugerencia (`allow_custom` siempre true — se puede escribir
// cualquier id que acepte el CLI). Agentopsy no puede enumerar el catálogo de un
// CLI cloud sin API key (SECURITY INVARIANT 7); vacío = el modelo por defecto del
// CLI (RULE 2). El modelo elegido se persiste por proveedor (MODEL_CONFIG_KEY).
export interface ExecutorModels {
  executor: ExecutorId;
  editable: boolean;
  allow_custom: boolean;
  models: string[];
  note: string | null;
}

// ── Login web de un ejecutor CLI cloud (2026-07-15) ────────────────────────
// El operador conecta Codex/Claude DESDE LA WEB sin abrir una terminal: el
// backend relaya el flujo device/OAuth del propio CLI. La sesión sigue viviendo
// en el volumen forensia-cli-auth (SECURITY INVARIANT 7 — sin API keys).

// Capacidad de relay de cada ejecutor cloud (/api/executors/login-capabilities).
// `relay_supported:false` (Gemini) → la UI degrada al comando manual + «Comprobar»
// en vez de un spinner infinito (RULE 2).
export interface ExecutorLoginCapability {
  executor: ExecutorId;
  relay_supported: boolean;
  needs_code_input: boolean;
  manual_command: string;
  reason: string | null;
}

// Respuesta de POST /api/executors/{id}/login: URL a abrir y, para el flujo
// device (Codex), el código de un solo uso a introducir EN EL NAVEGADOR.
export interface ExecutorLoginStart {
  executor: ExecutorId;
  state: "waiting";
  url: string;
  code: string | null;
  needs_code_input: boolean;
}

export type ExecutorLoginState = "waiting" | "logged_in" | "error" | "expired";

// GET /api/executors/{id}/login/status — sondeado cada ~2-3 s por el modal.
export interface ExecutorLoginStatus {
  executor: ExecutorId;
  state: ExecutorLoginState;
  available: boolean;
  reason: string | null;
  needs_code_input?: boolean;
  code_submitted?: boolean;
}

// Eventos del stream de progreso del agente (/api/agent/query/stream, NDJSON).
// Uno por línea; el terminal `done` trae la respuesta final + metadatos para
// persistir el turno igual que el endpoint bloqueante.
export type StreamEvent =
  | { type: "reasoning"; iteration: number; text: string }
  | { type: "tool_call"; iteration: number; tool_id: string; params?: Record<string, unknown> }
  | {
      type: "tool_result";
      iteration: number;
      tool_id: string;
      status: "ok" | "nonzero" | "error" | "refused" | "blocked";
      exit_code?: number | null;
      run_id?: string;
      // argv literal ejecutado — el comando que el perito ve en el chat.
      argv?: string[] | null;
      summary?: string;
    }
  | { type: "finding"; iteration: number; title: string; severity: string }
  | { type: "final"; iteration: number; text: string; exhausted?: boolean }
  | {
      type: "done";
      reply: string;
      iterations?: number;
      tool_calls?: unknown[];
      evidence_id: string;
      case_id: string;
      os_profile: string;
      executor: { id: ExecutorId; name: string; local: boolean };
      agent: AgentSummary;
    }
  | { type: "error"; detail: string };

export interface AgentSummary {
  id: string;
  name: string;
  version: string;
  os_profile: "unix" | "windows";
  authors: string[];
  // Desde el contrato v1.2 el paquete NO declara backend: el ejecutor lo elige
  // el operador en runtime. `name` es el modelo recomendado para `ollama`.
  model: {
    name: string;
    temperature: number;
    max_iterations: number;
  };
  allowed_tools: string[];
  path: string;
}

// Estado de un maletín (toolkit-windows / toolkit-unix) tal y como lo reporta
// /api/capabilities. `running` es null cuando el api no puede consultarlo (RULE 1:
// entonces `reason` trae el motivo accionable).
export interface MaletinStatus {
  service: string;
  container: string;
  running: boolean | null;
  reason: string | null;
}

// Disponibilidad de una tool del catálogo: en qué maletín(es) vive y, si no está
// disponible, la razón accionable (servicio caído, binario ausente) — RULE 2: nunca
// se sustituye un maletín por otro.
export interface ToolStatus {
  available: boolean;
  toolkits: string[];
  via: string | null;
  reason: string | null;
}

export interface Capabilities {
  platform: string;
  os: string;
  arch: string;
  python: string;
  container_runtime: boolean;
  toolkits: Record<string, MaletinStatus>;
  tools: Record<string, ToolStatus>;
  executors: Record<ExecutorId, ExecutorStatus>;
  agents: { root: string; loaded: AgentSummary[] };
}

export interface QueryResponse {
  status: "llm-loop";
  reply: string;
  iterations?: number;
  // Lista de {tool_id, run_id?, exit_code?, refused?, error?} — una entrada por
  // invocación de tool en este turno. Se persiste en el ChatMessage assistant
  // para que el replay server-side del turno siguiente reconstruya el ledger.
  tool_calls?: unknown[];
  evidence_id: string | null;
  case_id: string;
  os_profile: string;
  executor: { id: ExecutorId; name: string; local: boolean };
  agent: AgentSummary;
}

export interface Case {
  id: string;
  name: string;
  examiner: string;
  created_at: string;
  // El operador ya no lo elige al crear el caso — lo deriva el orquestador
  // del contenido de la evidencia (forensia.triage). `null` hasta que haya
  // evidencia enrutable registrada.
  os_profile: "unix" | "windows" | null;
  status: "active" | "closed";
  notes: string;
}

export interface VerificationRecord {
  verified_at: string;
  verified: boolean;
  current_sha256: string;
}

export interface EvidenceHandle {
  evidence_id: string;
  case_id: string;
  original_path: string;
  sha256: string;
  size: number;
  registered_at: string;
  last_verification: VerificationRecord | null;
  // Huella de triage (forensia.triage + forensia.triage_deep). La UI la compara
  // con el os_profile del caso y pinta el banner de desajuste; NUNCA cambia el
  // caso sola (RULE 2). En una imagen contenedor (.E01/.vmdk/.qcow2/.vhd) el
  // valor lo determina el pase PROFUNDO, que abre la imagen por el maletín.
  detected_os: "unix" | "windows" | "unknown";
  detected_kind: "disk" | "memory" | "container_disk" | "unknown";
}

// Respuesta de POST …/evidence/{id}/redetect-os: la evidencia con su huella
// recalculada y el caso tal como queda después de re-aplicar el enrutado.
export interface RedetectOsResult {
  evidence: EvidenceHandle;
  case: Case;
}

// Registro de evidencia en SEGUNDO PLANO (POST …/evidence/async). El hash-gate
// recorre TODOS los bytes TRES veces (hash del origen → copia inmutable →
// re-hash de la copia): minutos para una imagen grande, que dentro de la
// petición HTTP acaban en 504 y en una copia cortada a medias. El job corre
// desacoplado (cerrar la pestaña no lo aborta) y se sondea por id.
// `bytes_total` es el TRABAJO total (3 × tamaño del conjunto), no el tamaño de
// la evidencia; vale 0 mientras el backend valida, antes de mover un byte.
export interface EvidenceRegisterJob {
  job_id: string;
  case_id: string;
  source_path: string;
  state: "pending" | "running" | "done" | "error";
  phase: "hashing" | "copying" | "verifying" | null;
  // Segmento en curso de un EWF partido (1-based) y total del conjunto.
  seg_index: number;
  seg_count: number;
  bytes_done: number;
  bytes_total: number;
  // Presente solo cuando state === "done".
  evidence_id: string | null;
  // Mensaje accionable cuando state === "error" (RULE 2).
  error: string | null;
  created_at: string;
  finished_at: string | null;
}

export interface CreateCaseRequest {
  name: string;
  examiner: string;
  // Opcional: normalmente se omite y el orquestador lo deriva del contenido
  // de la evidencia al registrarla (auto-detección de SO).
  os_profile?: "unix" | "windows";
  notes?: string;
}

// Edición de metadatos del caso (POST /api/cases/{id}/update). Todos
// opcionales — se manda solo lo que cambia; el backend exige al menos uno
// (RULE 2: un update sin campos es un bug del caller, no un no-op silencioso).
// No incluye os_profile: el anclaje de SO tiene su propio endpoint dedicado.
export interface UpdateCaseRequest {
  name?: string;
  examiner?: string;
  notes?: string;
}

export type VerifyResult = EvidenceHandle & { verified: boolean };

// Metadata de custodia de una evidencia (GET …/evidence/{id}/metadata).
// `read_only_level` es HONESTO: "fs" = solo lectura a nivel de sistema de
// ficheros (chmod 0444); el bloqueo a nivel de bloque es Fase 2 (RULE 2 —
// nunca se anuncia una garantía que no se aplica). `read_only_label` es la
// etiqueta lista para mostrar.
export interface EvidenceMetadata {
  evidence_id: string;
  case_id: string;
  original_basename: string;
  sha256: string;
  size_bytes: number;
  size_human: string;
  registered_at: string;
  read_only_level: "fs";
  read_only_label: string;
  detected_os: "unix" | "windows" | "unknown";
  detected_kind: "disk" | "memory" | "container_disk" | "unknown";
  verification: VerificationRecord | null;
}

// Acta de adquisición estructurada (GET …/evidence/{id}/custody-act). Se
// construye de forma pura desde el baseline + el evento `evidence_register` del
// audit hash-encadenado; no narra nada nuevo (forensia.custody).
export interface CustodyAct {
  generated_at: string;
  tool: { name: string; version: string; component: string; method: string };
  case: {
    id: string;
    name: string;
    examiner: string;
    created_at: string;
    status: "active" | "closed";
    os_profile: "unix" | "windows" | null;
    os_profile_source: string | null;
  };
  evidence: {
    evidence_id: string;
    source_path: string | null;
    original_basename: string | null;
    sha256: string;
    size_bytes: number;
    size_human: string;
    registered_at: string;
    detected_os: "unix" | "windows" | "unknown";
    detected_kind: "disk" | "memory" | "container_disk" | "unknown";
  };
  read_only: { level: "fs"; label: string };
  chain_of_custody: {
    audit_log: string;
    register_entry_hash: string | null;
    register_prev_hash: string | null;
    register_ts_utc: string | null;
    hash_chain_verified: boolean;
  };
  verification: VerificationRecord | null;
}

export interface PersistedChatMessage {
  role: "user" | "assistant" | "system" | "tool";
  content: string;
  ts: string;
  tool_calls: unknown[] | null;
  // Traza de actividad del turno para re-pintar el bloque "✓ N pasos" al recargar.
  activity?: StreamEvent[] | null;
}

export interface AgentFinding {
  id: string;
  case_id: string;
  title: string;
  summary: string;
  severity: "low" | "medium" | "high" | "critical";
  evidence_id: string | null;
  tool_id: string | null;
  run_id: string | null;
  created_at: string;
  // Técnicas ATT&CK que el hallazgo sostiene. Enum cerrada: el backend sólo
  // acepta ids de la semilla del orquestador (ver forensia/mitre/catalog.py).
  mitre_hints: string[];
  // El backend serializa el Finding entero (asdict): estos campos llegan siempre
  // aunque el rail corto no los use. Los pinta la vista Documentos (detalle).
  // Confianza calibrada del agente (0..1); null si no la declaró.
  confidence?: number | null;
  // Cuándo OCURRIÓ el hecho en la evidencia (distinto de created_at, cuándo se
  // registró el hallazgo). ISO-8601 libre; null si no aplica.
  observed_at?: string | null;
  // SHA-256 del output del run que lo sostiene (custodia del derivado).
  artifact_sha256?: string | null;
  // "afirmacion" (afirma algo de la evidencia, exige run_id) | "descarte".
  finding_kind?: string;
}

// ── MITRE ATT&CK ────────────────────────────────────────────────────────────
// El catálogo se deriva de la semilla del orquestador (la enum cerrada que el
// agente puede emitir), NO de una lista transcrita en el frontend.

export interface MitreTechnique {
  id: string;
  name: string;
  // Qué artefacto forense la sostiene (columna «Se sostiene con» de la semilla).
  supported_by: string;
  // "T1547" para "T1547.001"; null si es técnica de primer nivel.
  parent_id: string | null;
  // Nº de sub-técnicas (el catálogo Enterprise enumera padres + conteo; las
  // propuestas del agente sobre una sub-técnica se pintan en su padre).
  sub: number;
}

export interface MitreTactic {
  id: string;
  name: string;
  name_es: string;
  phase: string;
  techniques: MitreTechnique[];
}

// ── Documentos / informes del caso ────────────────────────────────────────
// Espejo de forensia.reports. Un bloque del cuerpo del informe: párrafo,
// sub-encabezado, cita, lista, código, pares clave-valor, tabla o hallazgo.
export interface DocumentBlock {
  t: "p" | "h3" | "quote" | "list" | "code" | "kv" | "table" | "finding";
  text?: string;
  ordered?: boolean;
  items?: string[];
  pairs?: { k: string; v: string }[];
  headers?: string[];
  rows?: string[][];
  // Sólo para finding:
  sev?: "critical" | "high" | "medium" | "low";
  title?: string;
  tags?: string[];
}

export interface DocumentSection {
  num: string;
  title: string;
  blocks: DocumentBlock[];
}

// Ficha del documento en la LISTA (sin el cuerpo de secciones).
export interface DocumentMeta {
  id: string;
  case_id: string;
  title: string;
  type: string;
  evidence_id: string | null;
  status: "draft" | "final";
  created_at: string;
  version: string;
  author: string;
  summary: string;
  sha256: string;
  page_count: number;
}

// Documento completo (ficha + cuerpo).
export interface DocumentFull extends DocumentMeta {
  sections: DocumentSection[];
}

export interface DocumentVerifyResult {
  document_id: string;
  ok: boolean;
  registered_sha256: string;
  recomputed_sha256: string;
}

// Datos opcionales del perito para la síntesis del informe pericial. Todos
// opcionales: sin ellos el backend usa el examinador del caso como perito.
export interface GenerateReportRequest {
  name?: string;
  colegiado?: string;
  organization?: string;
  email?: string;
  version?: string;
}

export interface MitreCatalog {
  available: boolean;
  // Motivo accionable cuando available=false. Nunca hay catálogo "por defecto".
  reason: string | null;
  source: string | null;
  phases: { key: string; label: string }[];
  tactics: MitreTactic[];
}

// Veredicto del perito. `null` = NO EVALUADA (nunca "ausente").
export type MitreStatus = "confirmada" | "sospechosa" | "descartada";

// Dos ejes que no se funden: lo que el agente PROPONE (proposed_by, derivado de
// hallazgos reales) y lo que el operador DICTAMINA (status, persistido y auditado).
export interface MitreCoverageEntry {
  technique_id: string;
  tactic_id: string | null;
  proposed_by: string[];
  status: MitreStatus | null;
  rationale: string;
  adjudicated_at: string | null;
  related_finding_ids: string[];
}

export interface AdjudicateRequest {
  technique_id: string;
  status: MitreStatus | "none";
  rationale: string;
  related_finding_ids?: string[];
}

// Conteo de uso de herramientas por caso (panel "Tools"), agregado del audit log.
export interface ToolUsage {
  tool_id: string;
  total: number;
  ok: number;
  failed: number;
}

// Coste/tokens por ejecutor agregado del audit log (Bug 008 §2 Nivel 0).
// `runs_with_tokens` distingue "el ejecutor no reportó tokens" de un cero real
// (p. ej. Codex hoy no reporta si no se adopta --json).
export interface ExecutorCost {
  executor: string;
  runs: number;
  runs_with_tokens: number;
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
  cost_usd: number;
  response_chars: number;
}

// Estimación PRE-VUELO del análisis (GET /api/cases/{id}/analyze/estimate,
// hallazgo E): rangos + supuestos declarados, NUNCA un número fingido (RULE 2).
// `basis` de cada cantidad dice si sale del histórico real del caso o de una
// heurística documentada. Para Ollama (local) el coste monetario es 0.
export interface AnalysisEstimateRange {
  min: number;
  max: number;
  // tokens/iteración o segundos/iteración usados como base.
  per_iteration: number;
  // "history" = anclado en la media real del caso; "heuristic" = por defecto.
  basis: "history" | "heuristic";
}

export interface AnalysisCostTariff {
  assumed_model: string;
  input_usd_per_mtok: number;
  output_usd_per_mtok: number;
  source: string; // cita de la tarifa (RULE 2: sin cita no se cablea)
}

export interface AnalysisCostEstimate {
  // false → no hay tarifa pública cableada para ese ejecutor cloud; el coste no
  // se inventa (RULE 2). min/max serán null en ese caso.
  available: boolean;
  min: number | null;
  max: number | null;
  currency: string;
  // p. ej. "local, sin coste monetario" para Ollama.
  label: string | null;
  tariff: AnalysisCostTariff | null;
  note: string | null;
}

export interface AnalysisEstimate {
  case_id: string;
  executor: { id: ExecutorId; name: string; local: boolean };
  evidence_id: string | null;
  evidence_size_bytes: number | null;
  evidence_size_human: string | null;
  iterations: { min: number; max: number };
  tokens: AnalysisEstimateRange;
  cost_usd: AnalysisCostEstimate;
  time_seconds: AnalysisEstimateRange;
  basis: string; // resumen humano de en qué se apoya
  disclaimer: string; // aviso de que es orientativo
}

export interface ConfigKeyStatus {
  set: boolean;
  preview: string | null;
}

export interface ConfigSnapshot {
  keys: Record<string, ConfigKeyStatus>;
  config_file: string;
}

// Fichero de la bandeja de evidencias (/api/evidence/sources): `path` es la
// ruta DENTRO del contenedor api (p. ej. /evidence/disco.raw) — es la que se
// envía a registerAsync (el registro en segundo plano que usa la UI).
export interface EvidenceSource {
  name: string;
  path: string;
  size: number;
}

export interface QueryRequest {
  prompt: string;
  os_profile?: string;
  evidence_id?: string;
  case_id?: string;
  // Ejecutor elegido por el OPERADOR para esta petición. Si se omite, el
  // backend solo acepta DEFAULT_EXECUTOR fijado explícitamente en Settings;
  // sin ninguno de los dos responde 422 accionable (RULE 2).
  executor?: ExecutorId;
  session_id?: string;
}

// ── Timeline forense del caso (backend/forensia/timeline) ───────────────────
// Todas las marcas `ts` son UTC, normalizadas a un ISO-8601 con `Z` explícito
// (hallazgo F: la zona horaria nunca se deja implícita).

// Capa 1 — timeline de INVESTIGACIÓN (determinista, siempre disponible): cada
// ejecución de herramienta del audit log y cada hallazgo, en orden cronológico.
export interface TimelineToolRunEvent {
  kind: "tool_run";
  ts: string | null;
  tool_id: string | null;
  run_id: string | null;
  argv: string[];
  exit: number | null;
  status: string;
  evidence_id: string | null;
  artifacts: { relpath: string; sha256: string }[];
  output_files_count: number | null;
}
export interface TimelineFindingEvent {
  kind: "finding";
  ts: string | null;
  finding_id: string;
  title: string;
  summary: string;
  severity: "low" | "medium" | "high" | "critical";
  tool_id: string | null;
  evidence_id: string | null;
  mitre_hints: string[];
}
export type TimelineEvent = TimelineToolRunEvent | TimelineFindingEvent;

export interface InvestigationTimeline {
  case_id: string;
  timezone: string; // "UTC"
  events: TimelineEvent[];
}

// Capa 2 — super-timeline del SISTEMA DE FICHEROS (tsk_fls -m → eventos MACB),
// bajo demanda y asíncrona (registro de jobs).
export interface FsTimelineEvent {
  kind: "fs";
  ts: string;
  path: string;
  macb: string; // p. ej. "m.c.", "macb"
  size: number;
  inode: string;
}
// Un evento MACB que el clasificador determinista marcó como relevante, con el
// porqué (category/reason) y su peso de importancia (1..5).
export interface FsRelevantEvent extends FsTimelineEvent {
  category: string;
  reason: string;
  weight: number;
}
export interface FsTimelineResult {
  timezone: string;
  evidence_id: string;
  os_profile: string;
  fls_run_id: string;
  total_events: number;
  returned: number;
  truncated: boolean;
  events: FsTimelineEvent[];
  // Eventos relevantes (triage forense determinista). Ausentes en super-timelines
  // persistidas antes de esta función → la UI pide regenerar.
  relevant_events?: FsRelevantEvent[];
  total_relevant?: number;
  relevant_returned?: number;
  relevant_truncated?: boolean;
  // Presente en resultados persistidos (cuándo se generó la super-timeline).
  generated_at?: string;
}
// Evento de progreso que el job acumula (`fls` → `mactime` → `done`).
export interface TimelineJobProgress {
  type: string;
  stage?: string;
  message?: string;
}
export interface FsTimelineJob {
  job_id: string;
  case_id: string;
  kind: string;
  status: "running" | "done" | "error" | "cancelled";
  created_at: string;
  finished_at: string | null;
  result: FsTimelineResult | null;
  error: string | null;
  events?: TimelineJobProgress[];
  event_count?: number;
  evidence_id?: string;
  os_profile?: string;
}
