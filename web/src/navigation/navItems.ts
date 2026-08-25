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

import type { MessageKey } from "../i18n/en";

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
  labelKey: MessageKey;
  section: NavSection;
}

// Las siete fases del caso, en el orden del flujo pericial: registrar la
// evidencia → investigarla → correlacionar → reconstruir la cronología →
// consultar los hallazgos → extraer los grafos de relaciones → redactar el
// informe.
export interface PhaseItem {
  id: ViewId;
  labelKey: MessageKey;
  // Alimenta el eyebrow de la cabecera contextual: «Fase N de 7».
  index: number;
}

// «Hallazgos» (la galería con su detalle) e «Informe pericial» (el informe final
// firmable, con sus borradores) son fases SEPARADAS: la primera es la lectura de
// lo que persiste el agente; la segunda, el entregable definitivo. «Grafos» va entre las dos porque es material del
// informe que se elabora a partir de los hallazgos ya leídos, y porque cuesta
// dinero: se decide y se lanza aparte, no de paso mientras se redacta.
export const PHASES: PhaseItem[] = [
  { id: "repository", labelKey: "nav.repository", index: 1 },
  { id: "investigation", labelKey: "nav.investigation", index: 2 },
  { id: "mitre", labelKey: "nav.mitre", index: 3 },
  { id: "timeline", labelKey: "nav.timeline", index: 4 },
  { id: "findings", labelKey: "nav.findings", index: 5 },
  { id: "graphs", labelKey: "nav.graphs", index: 6 },
  { id: "document-viewer", labelKey: "nav.report", index: 7 },
];

export const UTILITIES: NavItem[] = [
  { id: "settings", labelKey: "nav.settings", section: "secondary" },
  { id: "guide", labelKey: "nav.guide", section: "secondary" },
];

export const NAV_ITEMS: NavItem[] = [
  ...PHASES.map((p) => ({ id: p.id, labelKey: p.labelKey, section: "primary" as const })),
  ...UTILITIES,
];

// Eyebrow y título que pinta la cabecera contextual del armazón cuando la
// página no publica los suyos.
//
// El eyebrow sitúa la vista DENTRO del flujo pericial, así que sólo tiene algo
// que decir en una fase. Las utilidades (Configuración, Guía) devuelven cadena
// vacía y el armazón no pinta la línea: rotularlas «Servicio» no informaba de
// nada que el propio título no dijera ya.
export function viewPhase(view: ViewId): PhaseItem | undefined {
  return PHASES.find((p) => p.id === view);
}

export function viewLabelKey(view: ViewId): MessageKey | undefined {
  return NAV_ITEMS.find((n) => n.id === view)?.labelKey;
}

// El flujo real empieza por el caso: primero se crea/selecciona y se registra
// evidencia; investigar sin caso solo puede degradar (RULE 2).
export const DEFAULT_VIEW: ViewId = "repository";
