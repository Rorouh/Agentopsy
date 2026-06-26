import { useEffect, useState } from "react";
import type { Capabilities } from "./global";
import { ThemeProvider } from "./ThemeProvider";
import { AppShell } from "./layout/AppShell";
import { DEFAULT_VIEW, type ViewId } from "./navigation/navItems";

import { GuidePage } from "./pages/GuidePage";
import { RepositoryPage } from "./pages/RepositoryPage";
import { DocumentViewerPage } from "./pages/DocumentViewerPage";
import { TimelinePage } from "./pages/TimelinePage";
import { InvestigationPage } from "./pages/InvestigationPage";
import { MitreAttackPage } from "./pages/MitreAttackPage";
import { SystemStatusPage } from "./pages/SystemStatusPage";
import { SettingsPage } from "./pages/SettingsPage";

import {
  mockActiveCase,
  mockActiveEvidence,
  mockEvidenceFiles,
  mockReportDocuments,
  mockTimelineEvents,
  mockFindings,
  mockMitreMatches,
  guideSteps,
} from "./mocks/frontendPreviewData";

export function App() {
  const [caps, setCaps] = useState<Capabilities | null>(null);
  const [version, setVersion] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [activeView, setActiveView] = useState<ViewId>(DEFAULT_VIEW);

  const isConnected = !error && !!version;

  useEffect(() => {
    window.forensia
      .health()
      .then((h) => setVersion(h.version))
      .catch((e) => setError(String(e)));
    window.forensia
      .capabilities()
      .then(setCaps)
      .catch((e) => setError(String(e)));
  }, []);

  return (
    <ThemeProvider>
      <AppShell
        activeView={activeView}
        onViewChange={setActiveView}
        isConnected={isConnected}
        version={version}
        error={error}
      >
        {/* Demo visual con mock data — ver src/mocks/frontendPreviewData.ts.
            Cuando exista backend real, cada página recibirá sus props desde
            llamadas a forensia/routers/* en lugar de los arrays mock. */}
        {activeView === "guide" && <GuidePage steps={guideSteps} onNavigate={setActiveView} />}
        {activeView === "repository" && <RepositoryPage onNavigate={setActiveView} />}
        {activeView === "document-viewer" && (
          <DocumentViewerPage
            activeCase={mockActiveCase}
            activeEvidence={mockActiveEvidence}
            documents={mockReportDocuments}
            onNavigate={setActiveView}
          />
        )}
        {activeView === "timeline" && (
          <TimelinePage
            activeCase={mockActiveCase}
            activeEvidence={mockActiveEvidence}
            events={mockTimelineEvents}
            onNavigate={setActiveView}
          />
        )}
        {activeView === "investigation" && (
          <InvestigationPage
            caps={caps}
            activeCase={mockActiveCase}
            activeEvidence={mockActiveEvidence}
            findings={mockFindings}
            onNavigate={setActiveView}
          />
        )}
        {activeView === "mitre" && (
          <MitreAttackPage activeCase={mockActiveCase} activeEvidence={mockActiveEvidence} matches={mockMitreMatches} />
        )}
        {activeView === "system" && <SystemStatusPage caps={caps} />}
        {activeView === "settings" && (
          <SettingsPage caps={caps} version={version} activeCase={mockActiveCase} onNavigate={setActiveView} />
        )}
      </AppShell>
    </ThemeProvider>
  );
}
