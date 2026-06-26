import type { Capabilities } from "../global";
import { Card } from "../ui/Card";
import { StatusDot } from "../ui/StatusDot";
import { PageHeader } from "../ui/PageHeader";
import { KeyValueList } from "../ui/KeyValueList";
import { LoadingState } from "../ui/LoadingState";

interface SystemStatusPageProps {
  caps: Capabilities | null;
}

export function SystemStatusPage({ caps }: SystemStatusPageProps) {
  return (
    <div>
      <PageHeader
        title="Estado del Sistema"
        subtitle="Visualiza el entorno de ejecución, modelos activos y herramientas cargadas en FORENSIA."
      />

      {caps ? (
        <div className="status-grid">
          <Card>
            <h3>Plataforma</h3>
            <KeyValueList
              items={[
                { label: "Sistema Operativo", value: caps.os },
                { label: "Arquitectura", value: caps.arch },
                { label: "Python Sidecar", value: caps.python },
                { label: "Empaquetado (Producción)", value: caps.packaged ? "Sí" : "No (Modo Dev)" },
              ]}
            />
          </Card>

          <Card>
            <h3>Modelos Disponibles</h3>
            <KeyValueList
              items={Object.entries(caps.models).map(([k, v]) => ({
                label: k,
                value: (
                  <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <StatusDot online={v} />
                    {v ? "Disponible" : "No Disponible"}
                  </span>
                ),
              }))}
            />
          </Card>

          <Card fullWidth>
            <h3>Maletín Forense (Resolución Bundled → PATH)</h3>
            <div className="tools-grid">
              {Object.entries(caps.tools).map(([k, v]) => (
                <div className="tool-indicator" key={k} style={{ opacity: v ? 1 : 0.5 }}>
                  <span className={`dot ${v ? "" : "inactive"}`} />
                  <span className="tool-name" title={k}>{k}</span>
                </div>
              ))}
            </div>
          </Card>
        </div>
      ) : (
        <LoadingState label="Obteniendo capacidades del sidecar backend…" />
      )}
    </div>
  );
}
