// Cliente HTTP del servicio api, sobre fetch mismo-origen — nginx (producción)
// o el proxy de Vite (desarrollo) reenvían /api hacia api:8000.
//
// Token de sesión: se obtiene UNA vez de GET /api/session (legible solo desde
// el mismo-origen de la UI; ver backend/forensia/routers/session.py) y viaja
// en X-Forensia-Token en cada llamada. Nunca se persiste (ni localStorage ni
// cookies) — vive solo en memoria de la pestaña.

import type {
  AdjudicateRequest,
  AgentFinding,
  AgentJob,
  AnalysisEstimate,
  MitreCatalog,
  MitreCoverageEntry,
  ExecutorCost,
  AgentSummary,
  Capabilities,
  Case,
  ConfigSnapshot,
  CreateCaseRequest,
  CustodyAct,
  DocumentMeta,
  DocumentFull,
  DocumentVerifyResult,
  GenerateReportRequest,
  EvidenceHandle,
  EvidenceMetadata,
  EvidenceSource,
  ExecutorId,
  FsTimelineJob,
  InvestigationTimeline,
  ExecutorLoginCapability,
  ExecutorLoginStart,
  ExecutorLoginStatus,
  ExecutorModels,
  PersistedChatMessage,
  StreamEvent,
  QueryRequest,
  QueryResponse,
  ToolUsage,
  UpdateCaseRequest,
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

// Descarga binaria/textual con el token en cabecera (un <a href> no puede
// llevarlo) y la dispara desde un blob mismo-origen. El nombre de fichero sale
// del Content-Disposition del backend; `fallback` si el servidor no lo manda.
async function download(path: string, fallback: string): Promise<void> {
  const token = await getToken();
  const res = await fetch(path, { headers: { "X-Forensia-Token": token } });
  if (!res.ok) throw new ApiError(res.status, await readDetail(res));
  const blob = await res.blob();
  const cd = res.headers.get("Content-Disposition") ?? "";
  const match = /filename="?([^"]+?)"?(?:;|$)/.exec(cd);
  const name = match ? match[1] : fallback;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// Subida multipart con PROGRESO. Se usa XHR y no fetch porque solo XHR expone
// `upload.onprogress` (fetch no reporta el progreso de subida). Reintenta UNA
// vez si el token rotó (401), igual que `request`.
function upload<T>(
  path: string,
  file: File,
  onProgress?: (fraction: number) => void,
): Promise<T> {
  const attempt = (token: string) =>
    new Promise<T>((resolve, reject) => {
      const form = new FormData();
      // El navegador fija el Content-Type multipart (con boundary) solo; nunca
      // lo ponemos a mano.
      form.append("file", file, file.name);
      const xhr = new XMLHttpRequest();
      xhr.open("POST", path);
      xhr.setRequestHeader("X-Forensia-Token", token);
      xhr.upload.onprogress = (e) => {
        if (onProgress && e.lengthComputable) onProgress(e.loaded / e.total);
      };
      xhr.onload = () => {
        const text = xhr.responseText;
        if (xhr.status >= 200 && xhr.status < 300) {
          try {
            resolve(JSON.parse(text) as T);
          } catch {
            reject(new ApiError(xhr.status, "Respuesta no válida del servidor."));
          }
          return;
        }
        let detail = xhr.statusText;
        try {
          const body = JSON.parse(text);
          if (body && typeof body.detail === "string") detail = body.detail;
        } catch {
          if (text) detail = text;
        }
        reject(new ApiError(xhr.status, detail));
      };
      xhr.onerror = () => reject(new ApiError(0, "Error de red durante la subida."));
      xhr.send(form);
    });

  return getToken()
    .then(attempt)
    .catch(async (err) => {
      if (err instanceof ApiError && err.status === 401) {
        tokenPromise = null;
        return attempt(await getToken());
      }
      throw err;
    });
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

  // Análisis en SEGUNDO PLANO: arranca un job y devuelve su id al instante; el
  // análisis sigue aunque el cliente se desconecte. Se sondea con getJob.
  analyze: (req: QueryRequest) =>
    post<{ job_id: string; status: string; case_id: string }>("/api/agent/analyze", req),
  getJob: (jobId: string, since = 0) =>
    request<AgentJob>(`/api/agent/jobs/${encodeURIComponent(jobId)}?since=${since}`),
  listCaseJobs: (caseId: string) =>
    request<AgentJob[]>(`/api/cases/${encodeURIComponent(caseId)}/agent/jobs`),

  // Estimación HONESTA (rangos + supuestos) del coste de lanzar un análisis
  // ANTES de lanzarlo (hallazgo E). `executor` es obligatorio (RULE 2); un id
  // desconocido → 422. `evidenceId` es opcional (enriquece con el tamaño).
  analyzeEstimate: (caseId: string, executor: ExecutorId, evidenceId?: string) => {
    const qs = new URLSearchParams({ executor });
    if (evidenceId) qs.set("evidence_id", evidenceId);
    return request<AnalysisEstimate>(
      `/api/cases/${encodeURIComponent(caseId)}/analyze/estimate?${qs.toString()}`,
    );
  },

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

  // Catálogo ATT&CK (enum cerrada derivada de la semilla del orquestador).
  // Global, no por caso: es dato de referencia, no evidencia.
  mitre: {
    catalog: () => request<MitreCatalog>("/api/mitre/catalog"),
  },
  cases: {
    create: (body: CreateCaseRequest) => post<Case>("/api/cases", body),
    list: () => request<Case[]>("/api/cases"),
    get: (caseId: string) => request<Case>(`/api/cases/${encodeURIComponent(caseId)}`),
    close: (caseId: string) =>
      post<Case>(`/api/cases/${encodeURIComponent(caseId)}/close`, {}),
    reopen: (caseId: string) =>
      post<Case>(`/api/cases/${encodeURIComponent(caseId)}/reopen`, {}),
    update: (caseId: string, body: UpdateCaseRequest) =>
      post<Case>(`/api/cases/${encodeURIComponent(caseId)}/update`, body),
    // Anclaje MANUAL del os_profile por el operador (RULE 2: acción explícita,
    // nunca adivinada) — cuando el triage quedó ambiguo/sin determinar. Devuelve
    // el caso actualizado; queda registrado en el audit log del caso.
    anchorProfile: (caseId: string, os_profile: "unix" | "windows") =>
      post<Case>(`/api/cases/${encodeURIComponent(caseId)}/os-profile`, { os_profile }),
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
    // Metadata de custodia de una evidencia (hash baseline, tamaño legible,
    // nivel de solo-lectura HONESTO, última verificación).
    evidenceMetadata: (caseId: string, evidenceId: string) =>
      request<EvidenceMetadata>(
        `/api/cases/${encodeURIComponent(caseId)}/evidence/${encodeURIComponent(evidenceId)}/metadata`,
      ),
    // Acta de adquisición estructurada (cadena de custodia hash-encadenada).
    custodyAct: (caseId: string, evidenceId: string) =>
      request<CustodyAct>(
        `/api/cases/${encodeURIComponent(caseId)}/evidence/${encodeURIComponent(evidenceId)}/custody-act`,
      ),
    listFindings: (caseId: string) =>
      request<AgentFinding[]>(`/api/cases/${encodeURIComponent(caseId)}/findings`),
    listToolUsage: (caseId: string) =>
      request<ToolUsage[]>(`/api/cases/${encodeURIComponent(caseId)}/tool-usage`),
    listExecutorCost: (caseId: string) =>
      request<ExecutorCost[]>(`/api/cases/${encodeURIComponent(caseId)}/executor-cost`),

    // ── Timeline forense del caso ───────────────────────────────────────────
    // Capa 1: timeline de investigación (determinista) — ejecuciones de tool del
    // audit log + hallazgos, en orden cronológico UTC.
    timeline: (caseId: string) =>
      request<InvestigationTimeline>(`/api/cases/${encodeURIComponent(caseId)}/timeline`),
    // Capa 2: arranca la super-timeline del sistema de ficheros (tsk_fls -m) en
    // SEGUNDO PLANO y devuelve el job; se sondea con getFsTimelineJob.
    startFsTimeline: (caseId: string, evidenceId: string) =>
      post<FsTimelineJob>(`/api/cases/${encodeURIComponent(caseId)}/timeline/filesystem`, {
        evidence_id: evidenceId,
      }),
    getFsTimelineJob: (caseId: string, jobId: string, since = 0) =>
      request<FsTimelineJob>(
        `/api/cases/${encodeURIComponent(caseId)}/timeline/filesystem/jobs/${encodeURIComponent(
          jobId,
        )}?since=${since}`,
      ),
    // Cobertura ATT&CK del caso: propuestas del agente + dictámenes del operador.
    listMitreCoverage: (caseId: string) =>
      request<MitreCoverageEntry[]>(`/api/cases/${encodeURIComponent(caseId)}/mitre`),
    // Dictamen del perito sobre una técnica. Queda en el log hash-encadenado.
    adjudicateMitre: (caseId: string, body: AdjudicateRequest) =>
      post<{ coverage: MitreCoverageEntry[] }>(
        `/api/cases/${encodeURIComponent(caseId)}/mitre`,
        body,
      ),
    // Export CSV de la cobertura ATT&CK del caso (0 propuestas → cabecera + 0 filas).
    exportMitreCsv: (caseId: string) =>
      download(
        `/api/cases/${encodeURIComponent(caseId)}/mitre/export.csv`,
        `mitre-coverage-${caseId}.csv`,
      ),
    // Export del layer del ATT&CK Navigator (formato 4.5) para cargarlo en el
    // Navigator oficial: colorea las técnicas propuestas/adjudicadas del caso.
    exportMitreNavigator: (caseId: string) =>
      download(
        `/api/cases/${encodeURIComponent(caseId)}/mitre/navigator`,
        `mitre-navigator-${caseId}.json`,
      ),
    // Export CSV del timeline de investigación (tool runs + hallazgos, orden UTC).
    exportTimelineCsv: (caseId: string) =>
      download(
        `/api/cases/${encodeURIComponent(caseId)}/timeline/export.csv`,
        `timeline-${caseId}.csv`,
      ),
    readChat: (caseId: string, sessionId: string) =>
      request<PersistedChatMessage[]>(
        `/api/cases/${encodeURIComponent(caseId)}/chats/${encodeURIComponent(sessionId)}`,
      ),
    appendChat: (
      caseId: string,
      sessionId: string,
      msg: {
        role: string;
        content: string;
        tool_calls?: unknown[] | null;
        activity?: unknown[] | null;
      },
    ) =>
      post<PersistedChatMessage>(
        `/api/cases/${encodeURIComponent(caseId)}/chats/${encodeURIComponent(sessionId)}/messages`,
        {
          role: msg.role,
          content: msg.content,
          tool_calls: msg.tool_calls ?? null,
          activity: msg.activity ?? null,
        },
      ),

    // ── Documentos / informes del caso ──────────────────────────────────────
    listDocuments: (caseId: string) =>
      request<DocumentMeta[]>(`/api/cases/${encodeURIComponent(caseId)}/documents`),
    getDocument: (caseId: string, docId: string) =>
      request<DocumentFull>(
        `/api/cases/${encodeURIComponent(caseId)}/documents/${encodeURIComponent(docId)}`,
      ),
    // Síntesis "con un clic": el backend redacta el informe pericial desde los
    // hallazgos / custodia / MITRE reales del caso y lo persiste como borrador.
    generateReport: (caseId: string, perito: GenerateReportRequest) =>
      post<DocumentFull>(
        `/api/cases/${encodeURIComponent(caseId)}/documents/generate`,
        perito,
      ),
    verifyDocument: (caseId: string, docId: string) =>
      post<DocumentVerifyResult>(
        `/api/cases/${encodeURIComponent(caseId)}/documents/${encodeURIComponent(docId)}/verify`,
        {},
      ),
    signDocument: (caseId: string, docId: string) =>
      post<DocumentFull>(
        `/api/cases/${encodeURIComponent(caseId)}/documents/${encodeURIComponent(docId)}/sign`,
        {},
      ),
    deleteDocument: (caseId: string, docId: string) =>
      request<{ deleted: boolean }>(
        `/api/cases/${encodeURIComponent(caseId)}/documents/${encodeURIComponent(docId)}`,
        { method: "DELETE" },
      ),
    // Descarga el PDF real con el token en cabecera (un <a href> no puede) y
    // dispara la descarga desde un blob mismo-origen.
    downloadDocumentPdf: async (caseId: string, docId: string, filename: string) => {
      const token = await getToken();
      const res = await fetch(
        `/api/cases/${encodeURIComponent(caseId)}/documents/${encodeURIComponent(docId)}/pdf`,
        { headers: { "X-Forensia-Token": token } },
      );
      if (!res.ok) throw new ApiError(res.status, await readDetail(res));
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    },
  },

  evidence: {
    // Bandeja de entrada (./evidence del host, /evidence en el api). El
    // operador ELIGE el fichero — la web no tiene diálogo nativo (RULE 2:
    // nunca "el único" ni "el más reciente").
    listSources: () => request<{ sources: EvidenceSource[] }>("/api/evidence/sources"),
    // Subida del perito: deposita el fichero en la bandeja (NO lo registra —
    // eso es un paso aparte, con el hash-gate). `onProgress` va de 0 a 1.
    uploadSource: (file: File, onProgress?: (fraction: number) => void) =>
      upload<EvidenceSource>("/api/evidence/upload", file, onProgress),
  },

  config: {
    get: () => request<ConfigSnapshot>("/api/config"),
    set: (key: string, value: string) =>
      post<{ key: string; set: boolean; preview: string }>("/api/config", { key, value }),
    executors: () => request<{ executors: ExecutorId[] }>("/api/config/executors"),
  },

  // Modelos que ofrece el selector del composer para un ejecutor. Ollama devuelve
  // los instalados; los CLIs cloud, atajos + texto libre (allow_custom) que se
  // pasan como --model — FORENSIA no puede enumerar su catálogo sin API key
  // (SECURITY 7). El modelo elegido se persiste por proveedor (MODEL_CONFIG_KEY).
  executorModels: (id: ExecutorId) =>
    request<ExecutorModels>(`/api/executors/${id}/models`),

  // Login web de un ejecutor CLI cloud (Codex/Claude). Todos los POST llevan el
  // token de sesión (SECURITY INVARIANT 3). El código de un solo uso solo viaja
  // en la respuesta de `startLogin` y en la memoria de la pestaña — nunca se
  // persiste ni se registra.
  executorLogin: {
    // Capacidad de relay de los ejecutores cloud (batch, para Ajustes).
    capabilities: () =>
      request<{ executors: Record<ExecutorId, ExecutorLoginCapability> }>(
        "/api/executors/login-capabilities",
      ),
    start: (id: ExecutorId) =>
      post<ExecutorLoginStart>(`/api/executors/${id}/login`, {}),
    status: (id: ExecutorId) =>
      request<ExecutorLoginStatus>(`/api/executors/${id}/login/status`),
    submitCode: (id: ExecutorId, code: string) =>
      post<{ ok: boolean; executor: ExecutorId }>(`/api/executors/${id}/login/code`, { code }),
    cancel: (id: ExecutorId) =>
      post<{ ok: boolean; executor: ExecutorId }>(`/api/executors/${id}/login/cancel`, {}),
  },
};
