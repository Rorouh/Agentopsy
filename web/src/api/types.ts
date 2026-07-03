// Tipos espejo de los contratos JSON del servicio api (backend/forensia/routers/*).
// Convención: snake_case 1:1 con el backend — sin transformaciones en el cliente.

export type ExecutorId = "claude-code" | "codex" | "gemini" | "ollama";

// Estado de un ejecutor tal y como lo reporta /api/capabilities (RULE 2: si no
// está disponible, `reason` trae la razón accionable — binario ausente,
// credenciales sin montar, Ollama inaccesible — y la UI degrada explícitamente).
export interface ExecutorStatus {
  name: string;
  local: boolean;
  available: boolean;
  reason: string | null;
}

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
  os_profile: "unix" | "windows";
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
  // Huella de triage (forensia.triage). La UI la compara con el os_profile del
  // caso y pinta el banner de desajuste; NUNCA cambia el caso sola (RULE 2).
  detected_os: "unix" | "windows" | "unknown";
  detected_kind: "disk" | "memory" | "container_disk" | "unknown";
}

export interface CreateCaseRequest {
  name: string;
  examiner: string;
  os_profile: "unix" | "windows";
  notes?: string;
}

export type VerifyResult = EvidenceHandle & { verified: boolean };

export interface PersistedChatMessage {
  role: "user" | "assistant" | "system" | "tool";
  content: string;
  ts: string;
  tool_calls: unknown[] | null;
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
}

export interface ConfigSnapshot {
  keys: Record<string, ConfigKeyStatus>;
  config_file: string;
}

// Fichero de la bandeja de evidencias (/api/evidence/sources): `path` es la
// ruta DENTRO del contenedor api (p. ej. /evidence/disco.raw) — es la que se
// envía a registerEvidence.
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
