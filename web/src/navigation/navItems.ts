// Navegación centralizada del sidebar. Añadir una pantalla nueva = añadir una
// entrada aquí + un case en el switch de App.tsx (+ un icono en Sidebar.tsx).
// No depende de React Router ni de ninguna librería de estado externa:
// App.tsx mantiene un único `activeView: ViewId` en estado local.

export type ViewId =
  | "guide"
  | "repository"
  | "document-viewer"
  | "timeline"
  | "investigation"
  | "mitre"
  | "system"
  | "settings";

export type NavSection = "primary" | "secondary";

export interface NavItem {
  id: ViewId;
  label: string;
  section: NavSection;
}

export const NAV_ITEMS: NavItem[] = [
  { id: "guide", label: "Guía", section: "primary" },
  { id: "repository", label: "Casos y evidencias", section: "primary" },
  { id: "investigation", label: "Investigación", section: "primary" },
  { id: "timeline", label: "Timeline", section: "primary" },
  { id: "document-viewer", label: "Documentos", section: "primary" },
  { id: "mitre", label: "MITRE ATT&CK", section: "primary" },
  { id: "system", label: "Estado del Sistema", section: "secondary" },
  { id: "settings", label: "Configuración", section: "secondary" },
];

export const DEFAULT_VIEW: ViewId = "guide";
