import type { ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { ErrorState } from "../ui/ErrorState";
import type { ViewId } from "../navigation/navItems";

interface AppShellProps {
  activeView: ViewId;
  onViewChange: (view: ViewId) => void;
  error: string;
  children: ReactNode;
}

export function AppShell({ activeView, onViewChange, error, children }: AppShellProps) {
  return (
    <div className="app">
      <Sidebar activeView={activeView} onViewChange={onViewChange} />
      <main className="main-content">
        {error && <ErrorState message={error} />}
        {children}
      </main>
    </div>
  );
}
