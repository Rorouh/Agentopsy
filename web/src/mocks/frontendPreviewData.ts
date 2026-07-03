// Mock data para la demo visual navegable del sidebar (sin backend real).
// Separado deliberadamente de los componentes: cuando el backend/lógica esté
// listo, estos arrays se sustituyen por datos venidos de forensia/routers/*
// sin tocar el JSX de las páginas (que reciben props, no importan este módulo
// directamente salvo en el punto de montaje en App.tsx).

import type {
  CaseSummary,
  EvidenceFile,
  ReportDocument,
  TimelineEvent,
  MitreTechniqueMatch,
  InvestigationFinding,
  GuideStep,
} from "../types/domain";

export const mockActiveCase: CaseSummary = {
  id: "case-2026-014",
  name: "Caso 2026-014 · Estación de trabajo comprometida",
  examiner: "S. Bravo",
  createdAt: "2026-06-18T09:12:00Z",
  status: "open",
  evidenceCount: 3,
  description: "Imagen forense de disco + volcado de memoria de un equipo Windows 11 con sospecha de exfiltración.",
};

export const mockEvidenceFiles: EvidenceFile[] = [
  {
    id: "ev-001",
    name: "workstation-disk.E01",
    kind: "raw",
    sizeBytes: 128_849_018_880,
    sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    status: "verified",
    addedAt: "2026-06-18T09:14:00Z",
    osProfile: "windows11-x64",
  },
  {
    id: "ev-002",
    name: "memory-dump.raw",
    kind: "ram",
    sizeBytes: 17_179_869_184,
    sha256: "1c8bfe8f801d79745c4631be1fad7413cb6efe4845ada74ca8ad95fa3bba8a9f",
    status: "verified",
    addedAt: "2026-06-18T09:20:00Z",
  },
  {
    id: "ev-003",
    name: "laptop-suspect.vmdk",
    kind: "vmdk",
    sizeBytes: 64_424_509_440,
    sha256: null,
    status: "hashing",
    addedAt: "2026-06-24T08:02:00Z",
  },
];

// Evidencia activa de demostración: la pieza que las pantallas de
// Investigación/Timeline/Documentos/MITRE asumen como "seleccionada" para
// mostrar visualmente la dependencia caso → evidencia → análisis.
export const mockActiveEvidence: EvidenceFile = mockEvidenceFiles[0];

export const mockReportDocuments: ReportDocument[] = [
  {
    id: "doc-001",
    title: "Informe preliminar — Línea temporal de acceso",
    evidenceId: "ev-001",
    status: "draft",
    createdAt: "2026-06-20T11:00:00Z",
    sha256: "4a44dc15364204a80fe80e9039455cc1608281820fe2b24f1e5233ade6af1dd5",
    pageCount: 8,
    summary: "Reconstrucción de accesos al sistema entre el 14 y el 18 de junio, con foco en cuentas de servicio.",
  },
  {
    id: "doc-002",
    title: "Informe final — Memoria volátil",
    evidenceId: "ev-002",
    status: "final",
    createdAt: "2026-06-22T16:40:00Z",
    sha256: "2c624232cdd221771294dfbb310aca000a0df6ac8b66b696d90ef06fdefb64a3",
    pageCount: 14,
    summary: "Procesos activos, conexiones de red y artefactos de inyección detectados en el volcado de RAM.",
  },
];

export const mockTimelineEvents: TimelineEvent[] = [
  {
    id: "tl-001",
    timestamp: "2026-06-14T02:13:00Z",
    source: "Volatility3 (pslist)",
    severity: "high",
    description: "Proceso desconocido 'svhost.exe' (PID 4421) iniciado fuera de horario laboral.",
    evidenceId: "ev-002",
  },
  {
    id: "tl-002",
    timestamp: "2026-06-14T02:15:00Z",
    source: "TSK (fls)",
    severity: "critical",
    description: "Creación de archivo oculto en %APPDATA% con extensión doble (.pdf.exe).",
    evidenceId: "ev-001",
  },
  {
    id: "tl-003",
    timestamp: "2026-06-15T19:48:00Z",
    source: "RegRipper",
    severity: "medium",
    description: "Nueva entrada de persistencia en Run key de HKCU.",
    evidenceId: "ev-001",
  },
  {
    id: "tl-004",
    timestamp: "2026-06-17T07:02:00Z",
    source: "bulk_extractor",
    severity: "low",
    description: "Patrón de dirección de correo externo encontrado en espacio no asignado.",
    evidenceId: "ev-001",
  },
];

export const mockFindings: InvestigationFinding[] = [
  {
    id: "find-001",
    title: "Persistencia vía Run key",
    summary: "Entrada de registro apuntando a binario en %APPDATA% no firmado.",
    severity: "high",
    evidenceId: "ev-001",
  },
  {
    id: "find-002",
    title: "Proceso inyectado en memoria",
    summary: "Hueco de memoria consistente con técnica de process hollowing sobre svchost.exe.",
    severity: "critical",
    evidenceId: "ev-002",
  },
];

export const mockMitreMatches: MitreTechniqueMatch[] = [
  {
    id: "mitre-001",
    tacticId: "TA0003",
    tacticName: "Persistence",
    techniqueId: "T1547.001",
    techniqueName: "Boot or Logon Autostart Execution: Registry Run Keys",
    confidence: 82,
    status: "correlated",
    relatedFindingIds: ["find-001"],
  },
  {
    id: "mitre-002",
    tacticId: "TA0005",
    tacticName: "Defense Evasion",
    techniqueId: "T1055",
    techniqueName: "Process Injection",
    confidence: 67,
    status: "correlated",
    relatedFindingIds: ["find-002"],
  },
  {
    id: "mitre-003",
    tacticId: "TA0010",
    tacticName: "Exfiltration",
    techniqueId: "T1041",
    techniqueName: "Exfiltration Over C2 Channel",
    confidence: 0,
    status: "pending",
    relatedFindingIds: [],
  },
];

export const guideSteps: GuideStep[] = [
  { step: 1, title: "Crear caso / repositorio", description: "Registra un nuevo caso y define el examinador responsable antes de tocar evidencia." },
  { step: 2, title: "Registrar evidencia", description: "Sube la imagen forense o el volcado de memoria; FORENSIA calcula el hash baseline y lo deja en solo lectura." },
  { step: 3, title: "Investigar con el agente", description: "Conversa con el agente de IA, que ejecuta el maletín de herramientas forenses sobre la evidencia verificada." },
  { step: 4, title: "Revisar el timeline", description: "Reconstruye la secuencia de eventos detectados por las distintas herramientas, ordenados cronológicamente." },
  { step: 5, title: "Visualizar documentos/reportes", description: "Consulta los informes generados, con su metadata de integridad (hash, fecha, evidencia de origen)." },
  { step: 6, title: "Correlacionar con MITRE ATT&CK", description: "Vincula los hallazgos con tácticas y técnicas conocidas para dar contexto al informe final." },
];
