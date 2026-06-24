import type { ReactNode } from "react";
import { ThemeToggle } from "../ThemeToggle";
import { Sidebar } from "./Sidebar";

type Tab = "chat" | "system";

interface AppShellProps {
  activeTab: Tab;
  onTabChange: (tab: Tab) => void;
  isConnected: boolean;
  version: string;
  error: string;
  children: ReactNode;
}

export function AppShell({ activeTab, onTabChange, isConnected, version, error, children }: AppShellProps) {
  return (
    <div className="app">
      <Sidebar
        activeTab={activeTab}
        onTabChange={onTabChange}
        isConnected={isConnected}
        version={version}
      />
      <main className="main-content">
        <div className="topbar"><ThemeToggle /></div>
        {error && (
          <div style={{ color: "#ff6b6b", marginBottom: 16, fontFamily: "var(--font-mono)", fontSize: 13 }}>
            Error de conexión: {error}
          </div>
        )}
        {children}
      </main>
    </div>
  );
}
