import type { } from "../global";

type Tab = "chat" | "system";

interface SidebarProps {
  activeTab: Tab;
  onTabChange: (tab: Tab) => void;
  isConnected: boolean;
  version: string;
}

export function Sidebar({ activeTab, onTabChange, isConnected, version }: SidebarProps) {
  return (
    <aside className="sidebar">
      <div className="brand-section">
        <div className="brand-dot" />
        <span className="brand-name">FORENSIA</span>
      </div>

      <div className="nav-list">
        <button
          className={`nav-item ${activeTab === "chat" ? "active" : ""}`}
          onClick={() => onTabChange("chat")}
        >
          <svg
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            style={{ marginRight: 8 }}
          >
            <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
          </svg>
          Chat de IA
        </button>
        <button
          className={`nav-item ${activeTab === "system" ? "active" : ""}`}
          onClick={() => onTabChange("system")}
        >
          <svg
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            style={{ marginRight: 8 }}
          >
            <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
            <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
            <line x1="6" y1="6" x2="6.01" y2="6" />
            <line x1="6" y1="18" x2="6.01" y2="18" />
          </svg>
          Estado del Sistema
        </button>
      </div>

      <div className="sidebar-footer">
        <div className="system-status-indicator">
          <div className="status-label-group">
            <span className={`status-dot ${isConnected ? "" : "offline"}`} />
            <span>{isConnected ? "Conectado" : "Sin Conexión"}</span>
          </div>
          <span className="app-version">{version ? `v${version}` : "offline"}</span>
        </div>
      </div>
    </aside>
  );
}
