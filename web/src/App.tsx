import { useEffect, useState } from "react";
import { api } from "./api/client";
import type { Capabilities } from "./api/types";
import { ThemeProvider } from "./ThemeProvider";
import { ActiveCaseProvider } from "./state/activeCase";
import { AppShell } from "./layout/AppShell";
import { DEFAULT_VIEW, NAV_ITEMS, type ViewId } from "./navigation/navItems";

import { GuidePage } from "./pages/GuidePage";
import { RepositoryPage } from "./pages/RepositoryPage";
import { DocumentsPage } from "./pages/DocumentsPage";
import { TimelinePage } from "./pages/TimelinePage";
import { InvestigationPage } from "./pages/InvestigationPage";
import { MitreAttackPage } from "./pages/MitreAttackPage";
import { SystemStatusPage } from "./pages/SystemStatusPage";
import { SettingsPage } from "./pages/SettingsPage";

import { guideSteps } from "./mocks/frontendPreviewData";

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
  const [version, setVersion] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [activeView, setActiveView] = useState<ViewId>(initialView);

  const isConnected = !error && !!version;

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
    api
      .health()
      .then((h) => setVersion(h.version))
      .catch((e) => setError(String(e instanceof Error ? e.message : e)));
    refreshCaps();
  }, []);

  return (
    <ThemeProvider>
      <ActiveCaseProvider>
      <AppShell activeView={activeView} onViewChange={setActiveView} error={error}>
        {/* Demo visual con mock data — ver src/mocks/frontendPreviewData.ts.
            Cuando exista backend real, cada página recibirá sus props desde
            llamadas a forensia/routers/* en lugar de los arrays mock. */}
        {activeView === "guide" && <GuidePage steps={guideSteps} onNavigate={setActiveView} />}
        {activeView === "repository" && <RepositoryPage onNavigate={setActiveView} />}
        {activeView === "document-viewer" && <DocumentsPage />}
        {activeView === "timeline" && <TimelinePage />}
        {activeView === "investigation" && (
          <InvestigationPage caps={caps} onNavigate={setActiveView} onCapsRefresh={refreshCaps} />
        )}
        {activeView === "mitre" && (
          <MitreAttackPage />
        )}
        {activeView === "system" && (
          <SystemStatusPage caps={caps} isConnected={isConnected} version={version} />
        )}
        {activeView === "settings" && (
          <SettingsPage
            caps={caps}
            version={version}
            onNavigate={setActiveView}
            onCapsRefresh={refreshCaps}
          />
        )}
      </AppShell>
      </ActiveCaseProvider>
    </ThemeProvider>
  );
}
