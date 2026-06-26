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
  status: "skeleton" | "success";
  reply: string;
  evidence_id: string | null;
  os_profile: string;
  agent: AgentSummary;
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
      query(req: { os_profile?: string; evidence_id?: string; case_id?: string; prompt: string }): Promise<QueryResponse>;
      cases: {
        create(body: CreateCaseRequest): Promise<Case>;
        list(): Promise<Case[]>;
        get(caseId: string): Promise<Case>;
        close(caseId: string): Promise<Case>;
        registerEvidence(caseId: string, source_path: string): Promise<EvidenceHandle>;
        listEvidence(caseId: string): Promise<EvidenceHandle[]>;
        verifyEvidence(caseId: string, evidenceId: string): Promise<VerifyResult>;
        pickEvidenceFile(): Promise<string | null>;
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
