export interface Capabilities {
  platform: string;
  os: string;
  arch: string;
  python: string;
  packaged: boolean;
  tools: Record<string, boolean>;
  models: Record<string, boolean>;
}

declare global {
  interface Window {
    forensia: {
      connection(): Promise<{ url: string }>;
      health(): Promise<{ status: string; version: string }>;
      capabilities(): Promise<Capabilities>;
      query(req: { os_profile?: string; evidence_id?: string; prompt: string }): Promise<{ status: string; reply: string; evidence_id: string; os_profile: string }>;
    };
  }
}
