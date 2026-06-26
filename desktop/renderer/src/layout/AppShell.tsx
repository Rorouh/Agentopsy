import type { ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { ErrorState } from "../ui/ErrorState";
import type { ViewId } from "../navigation/navItems";

interface AppShellProps {
  activeView: ViewId;
  onViewChange: (view: ViewId) => void;
  isConnected: boolean;
  version: string;
  error: string;
  children: ReactNode;
}

export function AppShell({ activeView, onViewChange, isConnected, version, error, children }: AppShellProps) {
  return (
    <div className="app">
      <Sidebar
        activeView={activeView}
        onViewChange={onViewChange}
        isConnected={isConnected}
        version={version}
      />
      <main className="main-content">
        {error && <ErrorState message={error} />}
        {children}
      </main>
    </div>
  );
}
