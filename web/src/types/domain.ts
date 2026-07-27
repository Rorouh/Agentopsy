// Contratos de dominio para el frontend de Agentopsy.
// Estos tipos son el "contrato" que el backend/lógica deberá satisfacer cuando
// se conecten las APIs reales (ver forensia/routers/* en el backend). Hoy solo
// se usan con datos mock (ver src/mocks/frontendPreviewData.ts).

export type CaseStatus = "open" | "closed" | "archived";

export interface CaseSummary {
  id: string;
  name: string;
  examiner: string;
  createdAt: string; // ISO date
  status: CaseStatus;
  evidenceCount: number;
  description?: string;
}

export type EvidenceKind = "vmdk" | "raw" | "ram" | "other";
export type EvidenceStatus = "pending" | "hashing" | "verified" | "error";

export interface EvidenceFile {
  id: string;
  name: string;
  kind: EvidenceKind;
  sizeBytes: number;
  sha256: string | null; // null mientras status !== "verified"
  status: EvidenceStatus;
  addedAt: string; // ISO date
  osProfile?: string; // perfil de SO usado para parametrizar el agente (p. ej. "windows11-x64")
}

export type ReportDocumentStatus = "draft" | "final";

export interface ReportDocument {
  id: string;
  title: string;
  evidenceId: string;
  status: ReportDocumentStatus;
  createdAt: string; // ISO date
  sha256: string;
  pageCount: number;
  summary: string;
}

export type TimelineSeverity = "low" | "medium" | "high" | "critical";

export interface TimelineEvent {
  id: string;
  timestamp: string; // ISO date
  source: string; // herramienta forense / artefacto de origen
  severity: TimelineSeverity;
  description: string;
  evidenceId: string;
}


export interface InvestigationFinding {
  id: string;
  title: string;
  summary: string;
  severity: TimelineSeverity;
  evidenceId: string;
}

export interface GuideStep {
  step: number;
  title: string;
  description: string;
}

// Estado de carga genérico para secciones que dependan de datos asíncronos
// reales (hoy solo `caps`/`version` en App.tsx vienen de una llamada real al
// servicio api). Útil como contrato visual: "idle/loading/ready/error".
export type LoadState = "idle" | "loading" | "ready" | "error";
