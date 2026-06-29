export interface AgentSummary {
  id: string;
  name: string;
  version: string;
  os_profile: "unix" | "windows";
  authors: string[];
  model: {
    backend: "local" | "cloud";
    name: string;
    temperature: number;
    max_iterations: number;
  };
  allowed_tools: string[];
  path: string;
}

export interface Capabilities {
  platform: string;
  os: string;
  arch: string;
  python: string;
  packaged: boolean;
  tools: Record<string, boolean>;
  models: Record<string, boolean>;
  agents: { root: string; loaded: AgentSummary[] };
}

export interface QueryResponse {
  status: "skeleton" | "success" | "llm-loop" | "demo-ok" | "demo-error";
  reply: string;
  evidence_id: string | null;
  os_profile: string;
  agent: AgentSummary;
  // Present when status="llm-loop": list of {tool_id, run_id?, exit_code?,
  // refused?, error?} entries — one per tool invocation made during this
  // turn. Persisted by ChatPage.send() onto the assistant ChatMessage so
  // the next turn's server-side history replay can build a tool-runs ledger.
  tool_calls?: unknown[];
  iterations?: number;
}

// Backend dataclasses (mirrored 1:1 in snake_case — no transformation at the bridge).
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
  // Triage fingerprint computed by forensia.triage. UI compares it against
  // the case's os_profile and renders a mismatch banner; never used to
  // auto-switch the case (RULE 2).
  detected_os: "unix" | "windows" | "unknown";
  // Evidence shape — disk image, memory dump, container disk, or unknown.
  // The agent system prompt uses this to route to the right playbook section.
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

export interface ConfigKeyStatus {
  set: boolean;
  preview: string | null;
}

export interface ConfigSnapshot {
  keys: Record<string, ConfigKeyStatus>;
  config_file: string;
}

declare global {
  interface Window {
    forensia: {
      connection(): Promise<{ url: string }>;
      health(): Promise<{ status: string; version: string }>;
      capabilities(): Promise<Capabilities>;
      agents(): Promise<{ root: string; agents: AgentSummary[] }>;
      query(req: {
        os_profile?: string;
        evidence_id?: string;
        case_id?: string;
        prompt: string;
        // Chat session id — backend uses it to splice prior history into the
        // agent's messages so the LLM doesn't re-execute tools or lose intent.
        // Default "main" matches CHAT_SESSION_ID.
        session_id?: string;
      }): Promise<QueryResponse>;
      cases: {
        create(body: CreateCaseRequest): Promise<Case>;
        list(): Promise<Case[]>;
        get(caseId: string): Promise<Case>;
        close(caseId: string): Promise<Case>;
        registerEvidence(caseId: string, source_path: string): Promise<EvidenceHandle>;
        listEvidence(caseId: string): Promise<EvidenceHandle[]>;
        verifyEvidence(caseId: string, evidenceId: string): Promise<VerifyResult>;
        pickEvidenceFile(): Promise<string | null>;
        listFindings(caseId: string): Promise<AgentFinding[]>;
        readChat(caseId: string, sessionId: string): Promise<PersistedChatMessage[]>;
        appendChat(
          caseId: string,
          sessionId: string,
          msg: { role: string; content: string; tool_calls?: unknown[] | null }
        ): Promise<PersistedChatMessage>;
      };
      config: {
        get(): Promise<ConfigSnapshot>;
        set(key: string, value: string): Promise<{ key: string; set: boolean; preview: string }>;
        models(): Promise<{ openai: string[] }>;
      };
    };
  }
}
