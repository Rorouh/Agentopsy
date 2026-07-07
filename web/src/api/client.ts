// Cliente HTTP del servicio api, sobre fetch mismo-origen — nginx (producción)
// o el proxy de Vite (desarrollo) reenvían /api hacia api:8000.
//
// Token de sesión: se obtiene UNA vez de GET /api/session (legible solo desde
// el mismo-origen de la UI; ver backend/forensia/routers/session.py) y viaja
// en X-Forensia-Token en cada llamada. Nunca se persiste (ni localStorage ni
// cookies) — vive solo en memoria de la pestaña.

import type {
  AgentFinding,
  AgentSummary,
  Capabilities,
  Case,
  ConfigSnapshot,
  CreateCaseRequest,
  EvidenceHandle,
  EvidenceSource,
  ExecutorId,
  ExecutorModels,
  PersistedChatMessage,
  StreamEvent,
  QueryRequest,
  QueryResponse,
  ToolUsage,
  VerifyResult,
} from "./types";

export class ApiError extends Error {
  readonly status: number;
  readonly detail: string;

  constructor(status: number, detail: string) {
    // El backend responde SIEMPRE con `detail` accionable (RULE 2); lo
    // exponemos tal cual para que las páginas lo muestren sin traducir.
    super(detail || `HTTP ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

async function readDetail(res: Response): Promise<string> {
  try {
    const body = await res.clone().json();
    if (body && typeof body.detail === "string") return body.detail;
    return JSON.stringify(body);
  } catch {
    try {
      return await res.text();
    } catch {
      return res.statusText;
    }
  }
}

let tokenPromise: Promise<string> | null = null;

function getToken(): Promise<string> {
  if (!tokenPromise) {
    tokenPromise = (async () => {
      const res = await fetch("/api/session");
      if (!res.ok) throw new ApiError(res.status, await readDetail(res));
      const body = (await res.json()) as { token: string };
      return body.token;
    })().catch((err) => {
      // El bootstrap falló (api aún arrancando): permite reintentar en la
      // siguiente llamada en vez de cachear el fallo para siempre.
      tokenPromise = null;
      throw err;
    });
  }
  return tokenPromise;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const doFetch = async (token: string) =>
    fetch(path, {
      ...init,
      headers: {
        "X-Forensia-Token": token,
        ...(init?.body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
    });

  let res = await doFetch(await getToken());
  if (res.status === 401) {
    // Token rotado (el servicio api se reinició): re-bootstrap una única vez.
    tokenPromise = null;
    res = await doFetch(await getToken());
  }
  if (!res.ok) throw new ApiError(res.status, await readDetail(res));
  return (await res.json()) as T;
}

function post<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, { method: "POST", body: JSON.stringify(body) });
}

export const api = {
  // Sin token a propósito: es el "¿está vivo el api?" que App usa para pintar
  // el estado de conexión; no debe depender del bootstrap del token.
  async health(): Promise<{ status: string; version: string }> {
    const res = await fetch("/api/health");
    if (!res.ok) throw new ApiError(res.status, await readDetail(res));
    return (await res.json()) as { status: string; version: string };
  },

  capabilities: () => request<Capabilities>("/api/capabilities"),

  agents: () => request<{ root: string; agents: AgentSummary[] }>("/api/agents"),

  query: (req: QueryRequest) => post<QueryResponse>("/api/agent/query", req),

  // Igual que query() pero recibe el progreso del agente en vivo: llama a
  // `onEvent` por cada evento NDJSON (reasoning / tool_call / tool_result /
  // finding / final) y termina con el evento `done`.
  queryStream: async (
    req: QueryRequest,
    onEvent: (ev: StreamEvent) => void,
    signal?: AbortSignal,
  ): Promise<void> => {
    const doFetch = (token: string) =>
      fetch("/api/agent/query/stream", {
        method: "POST",
        headers: { "X-Forensia-Token": token, "Content-Type": "application/json" },
        body: JSON.stringify(req),
        signal,
      });
    let res = await doFetch(await getToken());
    if (res.status === 401) {
      tokenPromise = null;
      res = await doFetch(await getToken());
    }
    if (!res.ok) throw new ApiError(res.status, await readDetail(res));
    if (!res.body) throw new ApiError(0, "el api no devolvió cuerpo de streaming");

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    const flush = (line: string) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      try {
        onEvent(JSON.parse(trimmed) as StreamEvent);
      } catch {
        /* línea parcial o corrupta: se ignora */
      }
    };
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let nl: number;
      while ((nl = buffer.indexOf("\n")) !== -1) {
        flush(buffer.slice(0, nl));
        buffer = buffer.slice(nl + 1);
      }
    }
    flush(buffer);
  },

  // Consentimiento explícito del operador para un ejecutor cloud-backed:
  // queda registrado en el audit.jsonl del caso (SECURITY INVARIANT 7 / RGPD).
  consentCloud: (caseId: string, executor: ExecutorId) =>
    post<{ recorded: boolean; case_id: string; executor: ExecutorId; ts_utc: string }>(
      "/api/agent/cloud-consent",
      { case_id: caseId, executor },
    ),

  cases: {
    create: (body: CreateCaseRequest) => post<Case>("/api/cases", body),
    list: () => request<Case[]>("/api/cases"),
    get: (caseId: string) => request<Case>(`/api/cases/${encodeURIComponent(caseId)}`),
    close: (caseId: string) =>
      post<Case>(`/api/cases/${encodeURIComponent(caseId)}/close`, {}),
    registerEvidence: (caseId: string, source_path: string) =>
      post<EvidenceHandle>(`/api/cases/${encodeURIComponent(caseId)}/evidence`, {
        source_path,
      }),
    listEvidence: (caseId: string) =>
      request<EvidenceHandle[]>(`/api/cases/${encodeURIComponent(caseId)}/evidence`),
    verifyEvidence: (caseId: string, evidenceId: string) =>
      post<VerifyResult>(
        `/api/cases/${encodeURIComponent(caseId)}/evidence/${encodeURIComponent(evidenceId)}/verify`,
        {},
      ),
    listFindings: (caseId: string) =>
      request<AgentFinding[]>(`/api/cases/${encodeURIComponent(caseId)}/findings`),
    listToolUsage: (caseId: string) =>
      request<ToolUsage[]>(`/api/cases/${encodeURIComponent(caseId)}/tool-usage`),
    readChat: (caseId: string, sessionId: string) =>
      request<PersistedChatMessage[]>(
        `/api/cases/${encodeURIComponent(caseId)}/chats/${encodeURIComponent(sessionId)}`,
      ),
    appendChat: (
      caseId: string,
      sessionId: string,
      msg: { role: string; content: string; tool_calls?: unknown[] | null },
    ) =>
      post<PersistedChatMessage>(
        `/api/cases/${encodeURIComponent(caseId)}/chats/${encodeURIComponent(sessionId)}/messages`,
        { role: msg.role, content: msg.content, tool_calls: msg.tool_calls ?? null },
      ),
  },

  evidence: {
    // Bandeja de entrada (./evidence del host, /evidence en el api). El
    // operador ELIGE el fichero — la web no tiene diálogo nativo (RULE 2:
    // nunca "el único" ni "el más reciente").
    listSources: () => request<{ sources: EvidenceSource[] }>("/api/evidence/sources"),
  },

  config: {
    get: () => request<ConfigSnapshot>("/api/config"),
    set: (key: string, value: string) =>
      post<{ key: string; set: boolean; preview: string }>("/api/config", { key, value }),
    executors: () => request<{ executors: ExecutorId[] }>("/api/config/executors"),
  },

  // Modelos que ofrece el selector del composer para un ejecutor (solo `ollama`
  // devuelve lista editable; los CLIs cloud gestionan su modelo — RULE 2).
  executorModels: (id: ExecutorId) =>
    request<ExecutorModels>(`/api/executors/${id}/models`),
};
