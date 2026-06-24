import type { Capabilities } from "../global";

interface SystemStatusPageProps {
  caps: Capabilities | null;
}

export function SystemStatusPage({ caps }: SystemStatusPageProps) {
  return (
    <div>
      <h2 className="system-title">Estado del Sistema</h2>
      <p className="system-subtitle">Visualiza el entorno de ejecución, modelos activos y herramientas cargadas en FORENSIA.</p>

      {caps ? (
        <div className="status-grid">
          <div className="status-card">
            <h3>Plataforma</h3>
            <div className="status-card-body">
              <div className="status-row">
                <span className="status-row-label">Sistema Operativo</span>
                <span className="status-row-value">{caps.os}</span>
              </div>
              <div className="status-row">
                <span className="status-row-label">Arquitectura</span>
                <span className="status-row-value">{caps.arch}</span>
              </div>
              <div className="status-row">
                <span className="status-row-label">Python Sidecar</span>
                <span className="status-row-value">{caps.python}</span>
              </div>
              <div className="status-row">
                <span className="status-row-label">Empaquetado (Producción)</span>
                <span className="status-row-value">{caps.packaged ? "Sí" : "No (Modo Dev)"}</span>
              </div>
            </div>
          </div>

          <div className="status-card">
            <h3>Modelos Disponibles</h3>
            <div className="status-card-body">
              {Object.entries(caps.models).map(([k, v]) => (
                <div className="status-row" key={k}>
                  <span className="status-row-label">{k}</span>
                  <span className="status-row-value" style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <span className={`status-dot ${v ? "" : "offline"}`} />
                    {v ? "Disponible" : "No Disponible"}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="status-card full-width">
            <h3>Maletín Forense (Resolución Bundled → PATH)</h3>
            <div className="tools-grid">
              {Object.entries(caps.tools).map(([k, v]) => (
                <div className="tool-indicator" key={k} style={{ opacity: v ? 1 : 0.5 }}>
                  <span className={`dot ${v ? "" : "inactive"}`} />
                  <span className="tool-name" title={k}>{k}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : (
        <div style={{ color: "var(--fg-dim)" }}>Obteniendo capacidades del sidecar backend...</div>
      )}
    </div>
  );
}
