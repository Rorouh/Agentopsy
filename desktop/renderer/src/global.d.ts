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

declare global {
  interface Window {
    forensia: {
      connection(): Promise<{ url: string }>;
      health(): Promise<{ status: string; version: string }>;
      capabilities(): Promise<Capabilities>;
      agents(): Promise<{ root: string; agents: AgentSummary[] }>;
      query(req: { os_profile?: string; evidence_id?: string; prompt: string }): Promise<QueryResponse>;
    };
  }
}
