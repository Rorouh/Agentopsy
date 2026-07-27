import type { ReactNode } from "react";
import { usePublishShellHeader } from "../layout/shellHeader";

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  actions?: ReactNode; // CTAs de flujo entre pantallas (ver onNavigate en App.tsx)
}

// Rediseño 2026-07: la cabecera ya no se pinta dentro de la página — hay UNA
// sola, la del armazón (AppShell), con su eyebrow de fase. Este componente
// conserva su API para no tocar las ocho páginas que lo usan, pero en vez de
// renderizar publica su contenido en la cabecera del armazón.
export function PageHeader({ title, subtitle, actions }: PageHeaderProps) {
  usePublishShellHeader({ title, meta: subtitle, action: actions }, [title, subtitle]);
  return null;
}
