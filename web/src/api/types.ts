// Tipos espejo de los contratos JSON del servicio api (backend/agentopsy/routers/*).
// Convención: snake_case 1:1 con el backend, sin transformaciones en el cliente.

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
// está disponible, `reason` trae la razón accionable, binario ausente,
// credenciales sin montar, Ollama inaccesible, y la UI degrada explícitamente).
export interface ExecutorStatus {
  name: string;
  local: boolean;
  available: boolean;
  reason: string | null;
}

// Un nivel de razonamiento («potencia») tal y como lo declara el catálogo del
// propio CLI. La descripción viene del catálogo, no la escribe Agentopsy.
export interface ReasoningEffort {
  id: string;
  description: string;
}

// Datos ricos de un modelo, cuando el ejecutor tiene una fuente REAL de la que
// leerlos (hoy solo Codex, que cachea su catálogo en CODEX_HOME). `efforts` está
// vacío si ese modelo no declara niveles: entonces no se pinta selector de
// potencia en vez de inventar uno.
export interface ExecutorModelDetail {
  id: string;
  label: string;
  description: string;
  default_effort: string | null;
  efforts: ReasoningEffort[];
}

// Selector de potencia de un ejecutor: dónde se persiste y qué contarle al
// operador. `null` = ese ejecutor no tiene nivel verificado y no se ofrece.
export interface ExecutorReasoning {
  config_key: string;
  note: string;
}

// Modelos que el selector del composer ofrece para un ejecutor
// (/api/executors/{id}/models). Todos son `editable`: el operador elige el modelo
// y Agentopsy lo respeta (Ollama por HTTP; los CLIs cloud como flag --model). La
// lista difiere: Ollama devuelve los modelos REALES instalados y Codex también
// (su CLI cachea el catálogo con la sesión OAuth, sin API key); los demás CLIs
// cloud, solo atajos como sugerencia (`allow_custom` siempre true, se puede
// escribir cualquier id que acepte el CLI). Agentopsy no puede enumerar el
// catálogo de esos sin API key (SECURITY INVARIANT 7); vacío = el modelo por
// defecto del CLI (RULE 2). Lo elegido se persiste por proveedor
// (MODEL_CONFIG_KEY, y REASONING_CONFIG_KEY para la potencia).
export interface ExecutorModels {
  executor: ExecutorId;
  editable: boolean;
  allow_custom: boolean;
  models: string[];
  note: string | null;
  model_details: ExecutorModelDetail[];
  reasoning: ExecutorReasoning | null;
}

// ── Login web de un ejecutor CLI cloud (2026-07-15) ────────────────────────
// El operador conecta Codex/Claude DESDE LA WEB sin abrir una terminal: el
// backend relaya el flujo device/OAuth del propio CLI. La sesión sigue viviendo
// en el volumen agentopsy-cli-auth (SECURITY INVARIANT 7, sin API keys).

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

// GET /api/executors/{id}/login/status, sondeado cada ~2-3 s por el modal.
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
      // argv literal ejecutado, el comando que el perito ve en el chat.
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
// disponible, la razón accionable (servicio caído, binario ausente), RULE 2: nunca
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
  // Lista de {tool_id, run_id?, exit_code?, refused?, error?}, una entrada por
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
  // El operador ya no lo elige al crear el caso, lo deriva el orquestador
  // del contenido de la evidencia (agentopsy.triage). `null` hasta que haya
  // evidencia enrutable registrada.
  os_profile: "unix" | "windows" | null;
  status: "active" | "closed";
  notes: string;
}

// Los flujos de un caso que la interfaz observa para refrescarse sola. El nombre
// es el contrato con `agentopsy.pulse.FLUJOS`: si allí se añade uno, aquí también.
export type CaseStream =
  | "case"
  | "evidence"
  | "findings"
  // El log encadenado: respalda el uso de herramientas Y el timeline de
  // investigación, los dos se agregan a partir de él.
  | "audit"
  | "documents"
  | "graphs"
  | "mitre_proposals"
  | "mitre_verdicts"
  | "timeline"
  | "knowledge"
  | "chats";

// El PULSO del caso: una firma por flujo, más los trabajos de fondo en curso.
// Una firma es OPACA: comparar dos sólo responde «igual» o «distinto». No es un
// contador, no ordena y no se enseña.
export interface CasePulse {
  case_id: string;
  streams: Record<CaseStream, string>;
  jobs: {
    running: number;
    by_kind: Record<string, number>;
  };
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
  // Huella de triage (agentopsy.triage + agentopsy.triage_deep). La UI la compara
  // con el os_profile del caso y pinta el banner de desajuste; NUNCA cambia el
  // caso sola (RULE 2). En una imagen contenedor (.E01/.vmdk/.qcow2/.vhd) el
  // valor lo determina el pase PROFUNDO, que abre la imagen por el maletín.
  detected_os: "unix" | "windows" | "unknown";
  detected_kind: "disk" | "memory" | "container_disk" | "document" | "unknown";
  // Ficheros que respaldan la evidencia: 1 para un fichero unico, N para un set
  // EWF (.E01 ... .E0N), cada uno con su propio hash baseline.
  segment_count: number;
  // Bytes de TODA la evidencia (todos los segmentos sumados). `size` de arriba es
  // el del PRIMER segmento, porque es lo que cubre el hash baseline: en un set de
  // 9 segmentos es una novena parte, asi que el tamano que se ENSENA es este.
  total_size: number;
  segments: EvidenceSegmentRef[];
}

// Un fichero del conjunto, con su propio hash baseline y su tamano.
export interface EvidenceSegmentRef {
  name: string;
  sha256: string;
  size: number;
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
// opcionales, se manda solo lo que cambia; el backend exige al menos uno
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
// ficheros (chmod 0444); el bloqueo a nivel de bloque es Fase 2 (RULE 2,
// nunca se anuncia una garantía que no se aplica). `read_only_label` es la
// etiqueta lista para mostrar.
export interface EvidenceMetadata {
  evidence_id: string;
  case_id: string;
  original_basename: string;
  sha256: string;
  size_bytes: number;
  size_human: string;
  segment_count: number;
  total_size_bytes: number;
  total_size_human: string;
  registered_at: string;
  read_only_level: "fs";
  read_only_label: string;
  detected_os: "unix" | "windows" | "unknown";
  detected_kind: "disk" | "memory" | "container_disk" | "document" | "unknown";
  verification: VerificationRecord | null;
}

// Acta de adquisición estructurada (GET …/evidence/{id}/custody-act). Se
// construye de forma pura desde el baseline + el evento `evidence_register` del
// audit hash-encadenado; no narra nada nuevo (agentopsy.custody).
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
    // El acta atestigua la evidencia COMPLETA: `size_bytes` es el primer segmento
    // (lo que cubre el hash baseline), estos tres son el conjunto entero.
    segment_count: number;
    total_size_bytes: number;
    total_size_human: string;
    registered_at: string;
    detected_os: "unix" | "windows" | "unknown";
    detected_kind: "disk" | "memory" | "container_disk" | "document" | "unknown";
    segments: {
      name: string;
      sha256: string;
      size_bytes: number;
      size_human: string;
    }[];
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
  // acepta ids de la semilla del orquestador (ver agentopsy/mitre/catalog.py).
  mitre_hints: string[];
  // El backend serializa el Finding entero (asdict): estos campos llegan siempre
  // aunque el rail corto no los use. Los pinta la vista Documentos (detalle).
  // Confianza calibrada del agente (0..1); null si no la declaró.
  confidence?: number | null;
  // Cuándo OCURRIÓ el hecho en la evidencia (distinto de created_at, cuándo se
  // registró el hallazgo). ISO-8601 libre; null si no aplica.
  observed_at?: string | null;
  // SHA-256 del output del run que lo sostiene (custodia del derivado). Es un
  // atajo de lectura: la procedencia COMPLETA vive en `references`.
  artifact_sha256?: string | null;
  // "afirmacion" (afirma algo de la evidencia, exige una fuente verificada)
  // | "descarte" (una vía que no aportó) | "limitacion" (algo que NO se pudo
  // examinar; el único tipo que puede citar una ejecución fallida).
  finding_kind?: string;
  // Las FUENTES verificadas del hallazgo. Un hallazgo puede tener varias: un
  // mismo hecho puede sostenerse en el $MFT y en un EVTX.
  references?: FindingReference[];
  // Qué se examinó, con qué herramienta y con qué límite. Obligatorio en un
  // descarte y en una limitación: «no se pudo analizar» y «no se encontró» no
  // son la misma frase.
  alcance_examinado?: string | null;
  // Revisión vigente. Revisar NO sobrescribe: añade una revisión y conserva la
  // anterior, así que un informe que citó la 2 sigue apuntando a lo que citó.
  revision?: number;
  // SHA-256 del contenido canónico de ESTA revisión.
  content_sha256?: string;
  // El content_sha256 de la revisión que esta sustituye; null en la primera.
  supersedes?: string | null;
  motivo_revision?: string | null;
  // "verificada" cuando la procedencia se comprobó al escribirla;
  // "no_verificada" en los hallazgos anteriores al contrato, que se leen pero
  // NO reciben las garantías nuevas.
  provenance_state?: string;
  // Por dónde entró la escritura: "agent" | "rest" | "mcp".
  origin?: string;
}

// El localizador de una cita: dónde, DENTRO del artefacto, está lo que el
// hallazgo afirma. `lineas` es 1-based e inclusivo; `bytes` es 0-based con
// `hasta` exclusivo; `registro` nombra una entrada y no tiene aritmética.
export interface FindingLocator {
  tipo: "lineas" | "bytes" | "registro";
  desde?: number;
  hasta?: number;
  valor?: string;
}

// Una FUENTE del hallazgo, tal y como el backend la persistió.
export interface FindingReference {
  case_id?: string;
  evidence_id: string | null;
  run_id: string;
  tool_id: string;
  artefacto: "stdout" | "stderr" | "fichero";
  relpath: string | null;
  sha256: string;
  localizador: FindingLocator | null;
  extracto: string | null;
  estado: "verificada" | "no_verificada";
  derivada: boolean;
  run_status: string;
  exit_code: number | null;
  resultado_parcial: boolean;
  tool_version?: string | null;
  evidence_baseline_sha256?: string | null;
  motivo_no_verificada?: string | null;
}

// Una fuente ABIERTA AHORA por el backend (GET …/findings/{id}/sources). Es lo
// que la interfaz pinta al «abrir la cita»: la resolución la hace el servidor a
// partir del id del hallazgo, nunca de una ruta que mande el cliente.
export interface ResolvedSource {
  run_id: string | null;
  tool_id: string | null;
  tool_version?: string | null;
  evidence_id: string | null;
  artefacto: string | null;
  relpath: string | null;
  sha256_registrado: string | null;
  sha256?: string;
  anclaje?: "anclado" | "sin_ancla";
  size?: number;
  localizador: FindingLocator | null;
  // VALIDACIÓN TÉCNICA de la fuente. No dice nada sobre si el perito da por
  // buena la interpretación: eso es revisión humana y va aparte.
  // `localizador_invalido`: los bytes casan con su hash, pero la cita señala una
  // posición que no existe en el artefacto. No es lo mismo que estar alterada, y
  // decirlo mal mandaría a mirar donde no está el problema.
  estado:
    | "verificada"
    | "alterada"
    | "ausente"
    | "localizador_invalido"
    | "no_verificable";
  estado_registrado: string;
  motivo?: string;
  // Sólo cuando `estado` es "verificada": enseñar el extracto de una fuente que
  // no verifica sería presentarlo como comprobado.
  extracto?: string | null;
  resultado_parcial: boolean;
  exit_code: number | null;
  evidence_sha256?: string;
  evidence_estado?: string;
  evidence_motivo?: string;
}

export interface FindingSources {
  finding_id: string;
  revision: number;
  content_sha256: string;
  finding_kind: string;
  provenance_state: string;
  alcance_examinado: string | null;
  fuentes: ResolvedSource[];
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
// Espejo de agentopsy.reports. Un bloque del cuerpo del informe: párrafo,
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
  // Línea de PROCEDENCIA del hallazgo (run, confianza, hash del artefacto). El
  // PDF ya la imprimía; la web también debe mostrarla, es lo que permite a un
  // perito contrario reejecutar.
  meta?: string;
  // El RESPALDO del bloque: en qué revisión de qué hallazgo se apoya. Obligatorio
  // en los bloques de los apartados 6 y 9 que afirman sobre la evidencia, y es lo
  // que permite abrir su fuente desde la propia conclusión.
  refs?: BlockCitation[];
  // El bloque declara una LIMITACIÓN con este código, en vez de afirmar un hecho
  // sobre la evidencia. La comprobación de aprobación cruza los códigos
  // declarados con los que el material exige.
  limitacion?: string;
}

// Una cita del contenido: la revisión CONCRETA de un hallazgo, no «el hallazgo».
export interface BlockCitation {
  finding_id: string;
  revision: number;
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
  // Cuándo y quién APROBÓ el documento como final, y sobre qué contenido
  // exacto. null mientras es borrador. NO es una firma criptográfica: es la
  // traza de un acto humano auditado.
  approved_at?: string | null;
  approved_by?: string | null;
  approved_sha256?: string | null;
  // Versión de esquema. 1 son los documentos anteriores al manifiesto de
  // fuentes: se leen y se exportan como borrador, pero no se aprueban con
  // garantías que nunca tuvieron.
  schema_version?: number;
}

// Un BLOQUEO de aprobación: por qué este documento no puede pasar a final.
export interface ApprovalBlocker {
  codigo: string;
  mensaje: string;
  detalle: string;
}

// El estado de una fuente del informe, tal y como la comprobación la ve hoy.
export interface ApprovalSource {
  tipo: "evidencia" | "artefacto" | "hallazgo";
  estado:
    | "verificada"
    | "alterada"
    | "ausente"
    | "superada"
    | "alterado"
    | "revisado"
    | "sin_ancla"
    | "sin_procedencia"
    | "baseline_incoherente"
    | "verificacion_negativa";
  evidence_id?: string;
  run_id?: string;
  referencia?: string;
  finding_id?: string;
  revision?: number;
  revision_vigente?: number;
  sha256?: string;
  sha256_esperado?: string;
  content_sha256?: string;
  content_sha256_esperado?: string;
  anclaje?: string;
  procedencia?: string;
  motivo?: string;
}

// Lo que la pantalla de aprobación pinta ANTES de decidir: la revisión exacta
// que se va a aprobar, el estado de cada fuente y lo que falta.
export interface DocumentChecks {
  document_id: string;
  case_id: string;
  status: "draft" | "final";
  version: string;
  aprobable: boolean;
  sha256_actual: string;
  sha256_registrado: string;
  bloqueos: ApprovalBlocker[];
  fuentes: ApprovalSource[];
  // Las CITAS del contenido: qué bloque se apoya en qué revisión de qué
  // hallazgo, y si ese respaldo está en el manifiesto del informe.
  citas: DocumentCitationState[];
  // Estado del snapshot de procedencia. Los tres digests tienen que coincidir:
  // el recomputado sobre el manifiesto, el que el documento declara y el que
  // quedó anclado en la cadena al crearlo.
  procedencia: {
    schema_version: number;
    digest_declarado: string;
    digest_actual: string;
    digest_anclado: string;
  };
}

// El estado de UNA cita del contenido, tal y como la comprobación la ve hoy.
export interface DocumentCitationState {
  num: string;
  bloque: number;
  finding_id: string;
  revision: number;
  en_manifiesto: boolean;
  estado: string;
}

// La FUENTE de una conclusión, abierta y verificada por el backend. Es el
// recorrido completo: conclusión, revisión de hallazgo, ejecución, artefacto,
// localizador y extracto.
export interface DocumentCitation {
  case_id: string;
  document_id: string;
  finding_id: string;
  revision: number;
  conclusiones: Array<{
    num: string;
    titulo: string;
    bloque: number;
    tipo: string;
    texto: string;
  }>;
  titulo: string;
  resumen: string;
  severidad: string;
  finding_kind: string;
  observed_at: string | null;
  alcance_examinado: string | null;
  provenance_state: string;
  content_sha256: string;
  content_sha256_recomputado: string;
  // El hallazgo dice lo que decía. Falso significa que se ha reescrito, y
  // entonces lo que se lee no es lo que el informe citó.
  integridad_ok: boolean;
  // Si esta revisión estaba en el manifiesto que sostenía el informe.
  en_manifiesto: boolean;
  fuentes: ResolvedSource[];
}

// «Aprobar como final». `sha256` es el hash del contenido que el investigador
// ACABA de revisar: si entre su revisión y esta llamada el contenido cambió, el
// backend no aprueba, porque aprobaría algo que nadie ha mirado.
export interface ApproveDocumentRequest {
  sha256: string;
  approved_by?: string;
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

// «Finalizar investigación»: el ejecutor seleccionado redacta el informe
// pericial COMPLETO (agentopsy.reports.writer). `executor` es obligatorio, es el
// modelo que escribe, y Agentopsy no elige uno por el operador (RULE 2); el
// backend acepta también la selección ya fijada en Configuración
// (DEFAULT_EXECUTOR). Los datos del perito son opcionales: sin ellos figura el
// examinador del caso, y sin `version` se deriva de las revisiones ya
// registradas.
export interface FinalizeInvestigationRequest {
  executor?: ExecutorId;
  name?: string;
  colegiado?: string;
  organization?: string;
  email?: string;
  version?: string;
}

// Job de redacción del informe. Espejo de agentopsy.agent.jobs.Job para el
// `kind: "report"`: la redacción es una llamada larga a un modelo y corre
// desacoplada de la petición HTTP, así que cerrar la pestaña no la aborta.
export interface ReportJob {
  job_id: string;
  case_id: string;
  kind: "report";
  status: "running" | "done" | "error" | "cancelled";
  created_at: string;
  finished_at: string | null;
  error: string | null;
  event_count: number;
  events?: ReportJobEvent[];
  result: {
    doc_id: string;
    title: string;
    version: string;
    page_count: number;
    sha256: string;
  } | null;
  case_name?: string;
  executor?: { id: ExecutorId; name: string; local: boolean };
}

// Progreso OBSERVACIONAL de la redacción: en qué fase está y, al final, qué
// documento salió. No altera el contenido ni la validación.
export interface ReportJobEvent {
  type: "report_phase" | "report_ready";
  phase?: "material" | "redactando" | "validando" | "listo";
  executor?: string;
  prompt_chars?: number;
  version?: string;
  doc_id?: string;
  title?: string;
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

export interface ConfigKeyStatus {
  set: boolean;
  preview: string | null;
  // De qué capa sale el valor: "config" lo guardó el operador en Ajustes,
  // "env" lo fija el despliegue (el compose). Lo guardado GANA sobre el entorno
  // (backend/agentopsy/config.py), y sin este dato las dos cosas se pintan
  // igual aunque no se comporten igual al editarlas.
  source: "config" | "env" | null;
}

export interface ConfigSnapshot {
  keys: Record<string, ConfigKeyStatus>;
  config_file: string;
}

// Fichero de la bandeja de evidencias (/api/evidence/sources): `path` es la
// ruta DENTRO del contenedor api (p. ej. /evidence/disco.raw), es la que se
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

// ── Timeline forense del caso (backend/agentopsy/timeline) ───────────────────
// Todas las marcas `ts` son UTC, normalizadas a un ISO-8601 con `Z` explícito
// (hallazgo F: la zona horaria nunca se deja implícita).

// Capa 1, timeline de INVESTIGACIÓN (determinista, siempre disponible): cada
// ejecución de herramienta del audit log y cada hallazgo, en orden cronológico.
export interface TimelineToolRunEvent {
  kind: "tool_run";
  ts: string | null;
  // Cierre e instante de la ejecución tal y como los registró el log encadenado.
  // `duration_s` es null mientras el run sigue en vuelo o si falta una de las dos
  // marcas: cero se leería como «tardó nada», que es otro dato (RULE 2).
  ts_end: string | null;
  duration_s: number | null;
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

// Capa 4 (la que se ve al entrar), línea de tiempo del INCIDENTE: qué pasó en el
// DISPOSITIVO INVESTIGADO, un evento por hallazgo con `observed_at`. No es la
// cronología del trabajo del agente, que es la capa 1.
export interface IncidentTechnique {
  technique_id: string;
  // Null cuando el catálogo semilla no sitúa la técnica: se enseña con su id y sin
  // táctica, ni se adivina ni se omite (RULE 2).
  technique_name: string | null;
  tactic_id: string | null;
  tactic: string | null;
}
export interface IncidentEvent {
  finding_id: string;
  ts: string; // ISO-8601 UTC normalizado, siempre con Z
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  // Etiqueta en castellano resuelta por el BACKEND (fuente única,
  // agentopsy.timeline.vocabulario): la UI no tiene una segunda tabla.
  severity_label: string;
  evidence_id: string | null;
  run_id: string | null;
  mitre: IncidentTechnique[];
}
export interface IncidentTimeline {
  case_id: string;
  timezone: string; // "UTC"
  eventos: IncidentEvent[];
  total_hallazgos: number;
  // Lo que NO se pudo situar en el eje, contado y declarado: se pinta bajo el raíl y
  // DENTRO de la imagen exportada. Un hallazgo sin fecha es un dato del caso.
  sin_observed_at: number;
  no_parseable: number;
  no_parseable_valores: string[];
  no_parseable_truncado: boolean;
  // Por qué el eje está vacío, cuando lo está. Null si hay eventos.
  message: string | null;
  // Procedencia de la figura, resuelta por el BACKEND: la imagen se dibuja aquí pero
  // su identidad no se reinventa en TypeScript. `export_basename` es la misma función
  // que nombra las dos hojas de cálculo; `exported_at` es el instante de ESTA
  // respuesta, por eso se vuelve a pedir al exportar.
  case_name: string;
  exported_at: string;
  export_basename: string;
}

// Capa 2, super-timeline del SISTEMA DE FICHEROS (tsk_fls -m → eventos MACB),
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

// ── Grafos de relaciones ──────────────────────────────────────────────────────
// Qué se conecta con qué dentro de un hallazgo (y, fundido, dentro del caso).
// Es una PROPUESTA del modelo sobre el texto del hallazgo, no un hecho
// verificado como un hash o un argv auditado, y el backend manda ese aviso con
// el dato (`aviso`) para que la vista no dependa de recordarlo.

export type GraphNodeType = "ip" | "domain" | "hostname" | "user" | "file";

export type GraphEdgeType =
  | "connection"
  | "process_spawn"
  | "network_connection"
  | "lateral_move"
  | "malware"
  | "c2"
  | "exfiltration"
  | "beacon"
  | "persistence"
  | "priv_esc"
  | "rce"
  | "logon"
  | "file_transfer";

// Nodo ya COLOCADO: la geometría la resuelve el backend (`agentopsy.graph.layout`)
// para que la figura sea reproducible y no dependa del navegador.
export interface GraphNode {
  tipo: GraphNodeType;
  valor: string;
  x: number;
  y: number;
  centro?: boolean;
  // Solo en el grafo del caso: qué hallazgos sostienen este nodo, y su grado.
  hallazgos?: string[];
  grado?: number;
  // FUNCIÓN «INVENTARIO»: cierto en un nodo que no participa en ninguna
  // relación, o sea uno de los que van a la banda del pie y no a la red.
  suelto?: boolean;
}

export interface GraphEdge {
  origen: string;
  destino: string;
  tipo: GraphEdgeType;
  nota?: string;
  // Solo en el grafo del caso.
  hallazgos?: string[];
  notas?: string[];
}

// El lienzo lo CALCULA el layout, no es una constante: una figura que no cabe
// hace crecer el `viewBox` en vez de comprimirse en silencio (RULE 2).
export interface GraphCanvas {
  ancho: number;
  alto: number;
}

// Lo que el layout tuvo que hacer para que la figura cupiera. Va con el dato
// porque una figura ampliada o con solapes corregidos no es lo mismo que una
// que salió a la primera, y quien la lleva a un informe tiene derecho a saberlo.
export interface GraphLayoutNote {
  codigo: "lienzo_ampliado" | "solapes_corregidos";
  ancho?: number;
  alto?: number;
  pares?: number;
}

export interface GraphFindingView {
  case_id: string;
  case_name: string;
  // Identidad de la exportación, resuelta por el BACKEND (`export_basename`, la
  // misma función que nombra las dos hojas de cálculo): una imagen que dice
  // cuándo se exportó tiene que decir la verdad, así que el cliente vuelve a
  // pedir la capa al exportar en vez de reinventar el nombre en TypeScript.
  exported_at: string;
  export_basename: string;
  finding_id: string;
  revision: number;
  revisiones: number[];
  created_at: string;
  sha256: string;
  extraction: {
    executor?: string;
    model?: string | null;
    attempts?: number;
    resume?: boolean;
    reopen_reason?: string | null;
    input_tokens?: number;
    output_tokens?: number;
    cost_usd?: number | null;
  };
  aviso: string;
  nodos: GraphNode[];
  relaciones: GraphEdge[];
  lienzo: GraphCanvas;
  notas_layout: GraphLayoutNote[];
  hallazgo: {
    id: string;
    title: string;
    summary: string;
    severity: string;
  } | null;
  // La mitad VERIFICADA de la ficha: sale del hallazgo registrado, no del modelo.
  procedencia: {
    run_id: string | null;
    tool_id: string | null;
    evidence_id: string | null;
    artifact_sha256: string | null;
    observed_at: string | null;
    created_at: string;
  } | null;
}

// FUNCIÓN «INVENTARIO» (grafos, en prueba 2026-09-04). Las entidades que el
// modelo nombró y que no participan en ninguna relación. No es una poda: viajan
// enteras, con su recuento, y se pintan como lista en pantalla y como banda al
// pie del PNG. `lienzo` y `y` van en las coordenadas de la EXPORTACIÓN, que es
// la única figura que las dibuja; el lienzo de la red no las incluye.
export interface GraphInventory {
  total: number;
  en_la_red: number;
  nodos: GraphNode[];
  y: number;
  lienzo: GraphCanvas;
}

// FUNCIÓN «VISTAS» (grafos, en prueba 2026-09-04). Un corte del grafo del caso
// por un eje que el caso YA tiene persistido. `hallazgos` es cuántos entran en
// el corte, no cuántos nodos salen.
export type GraphVistaEje = "tecnica" | "tactica" | "evidencia" | "severidad";

export interface GraphVista {
  id: string;
  eje: GraphVistaEje;
  valor: string;
  etiqueta: string;
  hallazgos: number;
}

export interface GraphCaseView {
  case_id: string;
  case_name: string;
  exported_at: string;
  export_basename: string;
  aviso: string;
  nodos: GraphNode[];
  relaciones: GraphEdge[];
  hallazgos: { id: string; title: string }[];
  lienzo: GraphCanvas;
  notas_layout: GraphLayoutNote[];
  // FUNCIÓN «INVENTARIO»: null cuando toda entidad del caso participa en alguna
  // relación, que es cuando una banda vacía no aportaría nada.
  inventario: GraphInventory | null;
  // FUNCIÓN «VISTAS»: `vista` es el corte APLICADO (null = el caso entero) y
  // `vistas` los cortes que este caso admite.
  vista: GraphVista | null;
  vistas: GraphVista[];
}

export interface GraphSummary {
  finding_id: string;
  title: string;
  revision: number;
  revisiones: number[];
  created_at: string;
  sha256: string;
  n_nodos: number;
  n_relaciones: number;
}

export interface GraphIndex {
  case_id: string;
  aviso: string;
  grafos: GraphSummary[];
  pendientes: string[];
  hallazgos: { id: string; title: string }[];
}

export interface GraphJobEvent {
  type:
    | "graph_finding_start"
    | "graph_finding_done"
    | "graph_finding_error"
    | "graph_phase";
  finding_id?: string;
  title?: string;
  index?: number;
  total?: number;
  phase?: string;
  error?: string;
  n_nodos?: number;
  n_relaciones?: number;
  revision?: number;
}

// Parte del lote. Un hallazgo que falla NO cancela el resto: cada uno lleva su
// resultado y el motivo si no salió.
export interface GraphJobResultRow {
  finding_id: string;
  title: string;
  ok: boolean;
  error?: string;
  revision?: number;
  sha256?: string;
  n_nodos?: number;
  n_relaciones?: number;
}

export interface GraphJob {
  job_id: string;
  case_id: string;
  kind: string;
  status: "running" | "done" | "error" | "cancelled";
  created_at: string;
  finished_at: string | null;
  error: string | null;
  event_count: number;
  events?: GraphJobEvent[];
  result: {
    solicitados: number;
    con_grafo: number;
    sin_grafo: number;
    resultados: GraphJobResultRow[];
    executor: string;
    model: string | null;
  } | null;
  case_name?: string;
  solicitados?: number;
  executor?: { id: ExecutorId; name: string; local: boolean };
}
