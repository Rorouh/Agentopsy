import { useEffect, useState } from "react";
import { api } from "./api/client";
import type { Capabilities } from "./api/types";
import { ThemeProvider } from "./ThemeProvider";
import { ActiveCaseProvider } from "./state/activeCase";
import { CasePulseProvider } from "./state/casePulse";
import { CaseEvidenceProvider } from "./state/caseEvidence";
import { AppShell } from "./layout/AppShell";
import { ShellHeaderProvider } from "./layout/shellHeader";
import { DEFAULT_VIEW, NAV_ITEMS, type ViewId } from "./navigation/navItems";

import { GuidePage } from "./pages/GuidePage";
import { RepositoryPage } from "./pages/RepositoryPage";
import { DocumentsPage } from "./pages/DocumentsPage";
import { TimelinePage } from "./pages/TimelinePage";
import { InvestigationPage } from "./pages/InvestigationPage";
import { FindingsPage } from "./pages/FindingsPage";
import { GraphsPage } from "./pages/GraphsPage";
import { MitreAttackPage } from "./pages/MitreAttackPage";
import { SettingsPage } from "./pages/SettingsPage";

// Recuerda la vista activa entre recargas: si no, un F5 desde el Chat vuelve a
// "Casos y evidencias" y parece que se perdió la conversación (los mensajes SÍ
// están persistidos en el store; sólo se había reseteado la vista).
const VIEW_STORAGE_KEY = "forensia-active-view";

function initialView(): ViewId {
  try {
    const saved = localStorage.getItem(VIEW_STORAGE_KEY);
    if (saved && NAV_ITEMS.some((n) => n.id === saved)) return saved as ViewId;
  } catch {
    /* localStorage no disponible: cae a la vista por defecto */
  }
  return DEFAULT_VIEW;
}

export function App() {
  const [caps, setCaps] = useState<Capabilities | null>(null);
  const [error, setError] = useState<string>("");
  const [activeView, setActiveView] = useState<ViewId>(initialView);

  // Persiste la vista activa para que la recarga te devuelva donde estabas.
  useEffect(() => {
    try {
      localStorage.setItem(VIEW_STORAGE_KEY, activeView);
    } catch {
      /* ignora si localStorage no está disponible */
    }
  }, [activeView]);

  const refreshCaps = async () => {
    try {
      const c = await api.capabilities();
      setCaps(c);
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    }
  };

  useEffect(() => {
    // La versión que devuelve /health ya no se pinta en ninguna vista; la
    // llamada se conserva porque es la que detecta que el api no responde y
    // enciende el banner de error del armazón.
    api
      .health()
      .catch((e) => setError(String(e instanceof Error ? e.message : e)));
    refreshCaps();
  }, []);

  return (
    <ThemeProvider>
      <ActiveCaseProvider>
      <CasePulseProvider>
      <CaseEvidenceProvider>
      <ShellHeaderProvider>
      <AppShell activeView={activeView} onViewChange={setActiveView} error={error}>
        {/* Las ocho vistas llaman al backend real (forensia/routers/*). El caso
            activo y su lista los sirve ActiveCaseProvider, y la evidencia de ese
            caso CaseEvidenceProvider, que además gobierna el registro en segundo
            plano: por eso vive aquí arriba y no en la vista de Evidencia, que se
            destruye al cambiar de vista. La cabecera de cada vista se publica en
            el armazón con usePublishShellHeader. */}
        {activeView === "guide" && <GuidePage onNavigate={setActiveView} />}
        {activeView === "repository" && <RepositoryPage onNavigate={setActiveView} />}
        {activeView === "document-viewer" && <DocumentsPage />}
        {activeView === "timeline" && <TimelinePage />}
        {activeView === "investigation" && (
          <InvestigationPage caps={caps} onNavigate={setActiveView} onCapsRefresh={refreshCaps} />
        )}
        {activeView === "findings" && <FindingsPage onNavigate={setActiveView} />}
        {activeView === "graphs" && <GraphsPage />}
        {activeView === "mitre" && (
          <MitreAttackPage />
        )}
        {activeView === "settings" && (
          <SettingsPage caps={caps} onCapsRefresh={refreshCaps} />
        )}
      </AppShell>
      </ShellHeaderProvider>
      </CaseEvidenceProvider>
      </CasePulseProvider>
      </ActiveCaseProvider>
    </ThemeProvider>
  );
}
