// Navegación centralizada del sidebar. Añadir una pantalla nueva = añadir una
// entrada aquí + un case en el switch de App.tsx.
// No depende de React Router ni de ninguna librería de estado externa:
// App.tsx mantiene un único `activeView: ViewId` en estado local.
//
// Rediseño 2026-07 (docs/diseno/rediseno-2026-07/): el sidebar deja de ser un
// menú de secciones y pasa a ser el ESTADO DEL CASO, cinco fases en escalera
// más dos utilidades. Las etiquetas cambian; los VALORES de `ViewId` NO:
// `initialView()` en App.tsx descarta de localStorage cualquier id desconocido,
// así que renombrar `document-viewer` → `report` mandaría a la vista por defecto
// a todo el que tuviera la app abierta, sin ganancia funcional.

export type ViewId =
  | "guide"
  | "repository"
  | "document-viewer"
  | "timeline"
  | "investigation"
  | "findings"
  | "graphs"
  | "mitre"
  | "settings";

export type NavSection = "primary" | "secondary";

export interface NavItem {
  id: ViewId;
  label: string;
  section: NavSection;
}

// Las siete fases del caso, en el orden del flujo pericial: registrar la
// evidencia → investigarla → correlacionar → reconstruir la cronología →
// consultar los hallazgos (Documentos) → extraer los grafos de relaciones →
// redactar el informe.
export interface PhaseItem {
  id: ViewId;
  label: string;
  // Alimenta el eyebrow de la cabecera contextual: «Fase N de 7».
  index: number;
}

// «Documentos» (galería de hallazgos con detalle) e «Informe pericial» (el
// informe final firmable, con sus borradores) son fases SEPARADAS: la primera
// es la lectura de los hallazgos que persiste el agente; la segunda, el
// entregable definitivo. «Grafos» va entre las dos porque es material del
// informe que se elabora a partir de los hallazgos ya leídos, y porque cuesta
// dinero: se decide y se lanza aparte, no de paso mientras se redacta.
export const PHASES: PhaseItem[] = [
  { id: "repository", label: "Evidencia", index: 1 },
  { id: "investigation", label: "Investigación", index: 2 },
  { id: "mitre", label: "Correlación ATT&CK", index: 3 },
  { id: "timeline", label: "Timeline", index: 4 },
  { id: "findings", label: "Documentos", index: 5 },
  { id: "graphs", label: "Grafos", index: 6 },
  { id: "document-viewer", label: "Informe pericial", index: 7 },
];

export const UTILITIES: NavItem[] = [
  { id: "settings", label: "Configuración", section: "secondary" },
  { id: "guide", label: "Guía", section: "secondary" },
];

export const NAV_ITEMS: NavItem[] = [
  ...PHASES.map((p) => ({ id: p.id, label: p.label, section: "primary" as const })),
  ...UTILITIES,
];

// Eyebrow y título que pinta la cabecera contextual del armazón cuando la
// página no publica los suyos.
export function viewEyebrow(view: ViewId): string {
  const phase = PHASES.find((p) => p.id === view);
  return phase ? `Fase ${phase.index} de ${PHASES.length}` : "Servicio";
}

export function viewLabel(view: ViewId): string {
  return NAV_ITEMS.find((n) => n.id === view)?.label ?? "";
}

// El flujo real empieza por el caso: primero se crea/selecciona y se registra
// evidencia; investigar sin caso solo puede degradar (RULE 2).
export const DEFAULT_VIEW: ViewId = "repository";
