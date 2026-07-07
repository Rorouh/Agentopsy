import type { Capabilities } from "../api/types";
import { Card } from "../ui/Card";
import { StatusDot } from "../ui/StatusDot";
import { PageHeader } from "../ui/PageHeader";
import { KeyValueList } from "../ui/KeyValueList";
import { LoadingState } from "../ui/LoadingState";

interface SystemStatusPageProps {
  caps: Capabilities | null;
  // Estado de conexión + versión del api: antes vivían en el footer del
  // sidebar; ahora esta página es su único punto de consulta.
  isConnected?: boolean;
  version?: string;
}

export function SystemStatusPage({ caps, isConnected, version }: SystemStatusPageProps) {
  return (
    <div>
      <PageHeader
        title="Estado del Sistema"
        subtitle="Visualiza el entorno de ejecución, los ejecutores de IA y las herramientas cargadas en FORENSIA."
      />

      {caps ? (
        <div className="status-grid">
          <Card>
            <h3>Plataforma</h3>
            <KeyValueList
              items={[
                {
                  label: "Conexión con el api",
                  value: (
                    <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <StatusDot online={isConnected === true} />
                      {isConnected ? "Conectado" : "Sin conexión"}
                    </span>
                  ),
                },
                { label: "Versión", value: version ? `v${version}` : "—" },
                { label: "Sistema Operativo", value: caps.os },
                { label: "Arquitectura", value: caps.arch },
                { label: "Python (servicio api)", value: caps.python },
              ]}
            />
          </Card>

          <Card>
            <h3>Ejecutores de IA</h3>
            <KeyValueList
              items={Object.entries(caps.executors).map(([id, status]) => ({
                label: `${status.name}${status.local ? " (local)" : ""}`,
                value: (
                  <span
                    style={{ display: "flex", alignItems: "center", gap: 6 }}
                    title={status.available ? id : status.reason ?? ""}
                  >
                    <StatusDot online={status.available} />
                    {status.available ? "Disponible" : "No disponible"}
                  </span>
                ),
              }))}
            />
          </Card>

          <Card fullWidth>
            <h3>Maletines forenses (toolkit-windows / toolkit-unix)</h3>
            <KeyValueList
              items={Object.values(caps.toolkits).map((m) => ({
                label: m.service,
                value: (
                  <span
                    style={{ display: "flex", alignItems: "center", gap: 6 }}
                    title={m.running === true ? m.container : m.reason ?? ""}
                  >
                    <StatusDot online={m.running === true} />
                    {m.running === true
                      ? "En ejecución"
                      : m.running === false
                        ? "Detenido / inaccesible"
                        : "No consultable desde el api"}
                  </span>
                ),
              }))}
            />
          </Card>

          <Card fullWidth>
            <h3>Herramientas del catálogo (por maletín)</h3>
            <div className="tools-grid">
              {Object.entries(caps.tools).map(([k, v]) => (
                <div
                  className="tool-indicator"
                  key={k}
                  style={{ opacity: v.available ? 1 : 0.5 }}
                  title={v.available ? `${k} — ${v.toolkits.join(", ")}` : v.reason ?? k}
                >
                  <span className={`dot ${v.available ? "" : "inactive"}`} />
                  <span className="tool-name">{k}</span>
                </div>
              ))}
            </div>
          </Card>
        </div>
      ) : (
        <LoadingState label="Obteniendo capacidades del servicio api…" />
      )}
    </div>
  );
}
