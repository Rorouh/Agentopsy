import { useEffect, useState } from "react";
import type { Capabilities } from "./global";
import { ThemeProvider } from "./ThemeProvider";
import { AppShell } from "./layout/AppShell";
import { ChatPage } from "./pages/ChatPage";
import { SystemStatusPage } from "./pages/SystemStatusPage";

export function App() {
  const [caps, setCaps] = useState<Capabilities | null>(null);
  const [version, setVersion] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [activeTab, setActiveTab] = useState<"chat" | "system">("chat");

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
        activeTab={activeTab}
        onTabChange={setActiveTab}
        isConnected={isConnected}
        version={version}
        error={error}
      >
        {activeTab === "chat"
          ? <ChatPage caps={caps} />
          : <SystemStatusPage caps={caps} />}
      </AppShell>
    </ThemeProvider>
  );
}
