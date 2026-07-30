import { useState, type ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { ErrorState } from "../ui/ErrorState";
import { useShellHeader } from "./shellHeader";
import { CaseSearchModal } from "../components/CaseSearchModal";
import { NewCaseModal } from "../components/NewCaseModal";
import { useActiveCase } from "../state/activeCase";
import { viewEyebrow, viewLabel, type ViewId } from "../navigation/navItems";

interface AppShellProps {
  activeView: ViewId;
  onViewChange: (view: ViewId) => void;
  error: string;
  children: ReactNode;
}

// Rediseño 2026-07: UNA cabecera contextual para toda la app (eyebrow de fase ·
// título · meta · acción). Las páginas publican su contenido con `PageHeader`;
// el armazón solo lo pinta, no decide cuándo una acción procede (RULE 3).
//
// La gestión del caso también sube aquí: el bloque de caso del sidebar está
// siempre visible, así que «cambiar caso» y «Nuevo caso» tienen que funcionar
// desde cualquier vista, no solo desde Evidencia.
export function AppShell({ activeView, onViewChange, error, children }: AppShellProps) {
  const { payload } = useShellHeader();
  const {
    cases,
    activeCaseId,
    setActiveCaseId,
    phase,
    error: casesError,
    reload,
    upsertCase,
  } = useActiveCase();
  const [searchOpen, setSearchOpen] = useState(false);
  const [newCaseOpen, setNewCaseOpen] = useState(false);

  return (
    <div className="app">
      <Sidebar
        activeView={activeView}
        onViewChange={onViewChange}
        onOpenCaseSearch={() => setSearchOpen(true)}
        onOpenNewCase={() => setNewCaseOpen(true)}
      />
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

      <CaseSearchModal
        open={searchOpen}
        onClose={() => setSearchOpen(false)}
        cases={cases}
        activeCaseId={activeCaseId}
        onSelect={setActiveCaseId}
        error={phase === "error" ? casesError : null}
        onRetry={() => void reload()}
        onCaseUpdated={upsertCase}
        onCaseDeleted={reload}
      />

      <NewCaseModal
        open={newCaseOpen}
        onClose={() => setNewCaseOpen(false)}
        onCreated={(c) => {
          upsertCase(c);
          setActiveCaseId(c.id);
          // Crear el caso encadena con el paso siguiente del flujo: registrar
          // evidencia. Es lo que hace el mock al guardar.
          onViewChange("repository");
        }}
      />
    </div>
  );
}
