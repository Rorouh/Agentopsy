import type { ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { ErrorState } from "../ui/ErrorState";
import { useShellHeader } from "./shellHeader";
import { viewEyebrow, viewLabel, type ViewId } from "../navigation/navItems";

interface AppShellProps {
  activeView: ViewId;
  onViewChange: (view: ViewId) => void;
  error: string;
  children: ReactNode;
}

// Rediseño 2026-07: UNA cabecera contextual para toda la app (eyebrow de fase ·
// título · meta · acción). Las páginas publican su contenido con `PageHeader`;
// el armazón solo lo pinta — no decide cuándo una acción procede (RULE 3).
export function AppShell({ activeView, onViewChange, error, children }: AppShellProps) {
  const { payload } = useShellHeader();

  return (
    <div className="app">
      <Sidebar activeView={activeView} onViewChange={onViewChange} />
      <main className="main-content">
        <header className="shell-header">
          <div className="shell-header-titles">
            <div className="eyebrow">{viewEyebrow(activeView)}</div>
            <h1 className="shell-header-title">{payload?.title ?? viewLabel(activeView)}</h1>
          </div>
          <div className="shell-header-right">
            {payload?.meta && <div className="shell-header-meta">{payload.meta}</div>}
            {payload?.action && <div className="shell-header-action">{payload.action}</div>}
          </div>
        </header>
        <div className="shell-body">
          {error && <ErrorState message={error} />}
          {children}
        </div>
      </main>
    </div>
  );
}
