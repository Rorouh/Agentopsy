import type { Capabilities } from "../global";
import type { CaseSummary } from "../types/domain";
import type { ViewId } from "../navigation/navItems";
import { useTheme } from "../ThemeProvider";
import { ThemeToggle } from "../ThemeToggle";
import { PageHeader } from "../ui/PageHeader";
import { PageSection } from "../ui/PageSection";
import { KeyValueList } from "../ui/KeyValueList";
import { Button } from "../ui/Button";
import { StatusDot } from "../ui/StatusDot";
import { EmptyState } from "../ui/EmptyState";
import { LoadingState } from "../ui/LoadingState";

interface SettingsPageProps {
  caps: Capabilities | null;
  version: string;
  activeCase: CaseSummary;
  onNavigate?: (view: ViewId) => void;
}

export function SettingsPage({ caps, version, activeCase, onNavigate }: SettingsPageProps) {
  const { theme } = useTheme();

  return (
    <div>
      <PageHeader
        title="Configuración"
        subtitle="Preferencias del operador, del informe y diagnóstico del entorno local. Nada de esto se envía a ningún servidor por defecto."
      />

      <div className="settings-grid">
        {/* Apariencia — única sección con persistencia real (localStorage vía ThemeProvider) */}
        <PageSection title="Apariencia" fullWidth={false}>
          <p style={{ fontFamily: "var(--font-sans)", fontSize: 13, color: "var(--text-secondary)", marginTop: 0 }}>
            El tema se guarda en este equipo y se aplica a toda la aplicación.
          </p>
          <ThemeToggle />
          <div className="settings-current-theme">Tema actual: {theme === "light" ? "Claro" : "Oscuro"}</div>
        </PageSection>

        {/* Operador — mock form, integración futura: forensia.settings.operator */}
        <PageSection title="Operador" fullWidth={false}>
          <div className="form-grid">
            <div className="form-field full-width">
              <label className="form-label">Nombre del examinador</label>
              <input className="form-input" defaultValue={activeCase.examiner} disabled />
            </div>
            <div className="form-field">
              <label className="form-label">Organización</label>
              <input className="form-input" placeholder="Universidad / equipo forense" disabled />
            </div>
            <div className="form-field">
              <label className="form-label">Rol / cargo</label>
              <input className="form-input" placeholder="Analista forense" disabled />
            </div>
          </div>
          <p style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "var(--text-muted)", marginBottom: 0 }}>
            Esta metadata se incluirá como cabecera de los informes generados.
          </p>
        </PageSection>

        {/* Reportes — preferencias mock de exportación */}
        <PageSection title="Reportes" fullWidth={false}>
          <div className="settings-toggle-row">
            <input type="checkbox" defaultChecked disabled />
            <div>
              <div className="settings-toggle-title">Incluir timeline</div>
              <div className="settings-toggle-desc">Adjunta la línea de tiempo de eventos en el informe final.</div>
            </div>
          </div>
          <div className="settings-toggle-row">
            <input type="checkbox" defaultChecked disabled />
            <div>
              <div className="settings-toggle-title">Incluir hashes de evidencia</div>
              <div className="settings-toggle-desc">SHA-256 de cada evidencia y artefacto generado, para trazabilidad.</div>
            </div>
          </div>
          <div className="settings-toggle-row">
            <input type="checkbox" defaultChecked disabled />
            <div>
              <div className="settings-toggle-title">Incluir mapeo MITRE ATT&amp;CK</div>
              <div className="settings-toggle-desc">Tácticas y técnicas correlacionadas con los hallazgos.</div>
            </div>
          </div>
          <div className="form-field" style={{ marginTop: 12 }}>
            <label className="form-label">Formato de exportación</label>
            <select className="form-select" defaultValue="pdf" disabled>
              <option value="pdf">PDF</option>
              <option value="docx">Word (.docx)</option>
              <option value="json">JSON (estructurado)</option>
            </select>
          </div>
        </PageSection>

        {/* Modelos / IA — lee de caps.models si está disponible, sin selección real */}
        <PageSection title="Modelos / IA" fullWidth={false}>
          {caps ? (
            <KeyValueList
              items={Object.entries(caps.models).map(([name, available]) => ({
                label: name,
                value: (
                  <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <StatusDot online={available} />
                    {available ? "Disponible" : "No disponible"}
                  </span>
                ),
              }))}
            />
          ) : (
            <LoadingState label="Consultando modelos del sidecar…" />
          )}
          <p style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "var(--text-muted)", marginTop: 10, marginBottom: 0 }}>
            La selección de modelo por caso no está implementada todavía; hoy el agente usa el modelo local por defecto.
          </p>
        </PageSection>

        {/* Seguridad y privacidad — conceptual, sin lógica funcional */}
        <PageSection title="Seguridad y privacidad" fullWidth={false}>
          <div className="settings-toggle-row">
            <input type="checkbox" checked disabled />
            <div>
              <div className="settings-toggle-title">Modo local-first / offline-first</div>
              <div className="settings-toggle-desc">Por defecto, ningún dato de evidencia sale de este equipo. El modelo local (Ollama) es el predeterminado.</div>
            </div>
          </div>
          <div className="settings-toggle-row">
            <input type="checkbox" disabled />
            <div>
              <div className="settings-toggle-title">Permitir modelos en la nube (opt-in por caso)</div>
              <div className="settings-toggle-desc">
                Requeriría consentimiento explícito y redacción de datos personales antes de enviar cualquier contenido. No funcional en este skeleton.
              </div>
            </div>
          </div>
        </PageSection>

        {/* Diagnóstico — resumen condensado, SystemStatusPage mantiene el detalle completo */}
        <PageSection title="Diagnóstico" fullWidth={false}>
          {caps ? (
            <>
              <KeyValueList
                items={[
                  { label: "Versión", value: version ? `v${version}` : "—" },
                  { label: "Sistema Operativo", value: caps.os },
                  { label: "Arquitectura", value: caps.arch },
                  { label: "Python Sidecar", value: caps.python },
                  { label: "Empaquetado", value: caps.packaged ? "Sí (producción)" : "No (modo dev)" },
                  { label: "Herramientas detectadas", value: `${Object.values(caps.tools).filter(Boolean).length} / ${Object.keys(caps.tools).length}` },
                ]}
              />
              {onNavigate && (
                <div className="cta-row">
                  <Button variant="chip" onClick={() => onNavigate("system")}>Ver detalle completo →</Button>
                </div>
              )}
            </>
          ) : (
            <EmptyState title="Sin conexión con el sidecar" description="No se pudo obtener el diagnóstico del entorno local." />
          )}
        </PageSection>

        {/* Acerca de / licencia */}
        <PageSection title="Acerca de" fullWidth={false}>
          <KeyValueList
            items={[
              { label: "Producto", value: "FORENSIA" },
              { label: "Versión", value: version ? `v${version}` : "no conectado" },
              { label: "Tipo de proyecto", value: "TFM académico" },
              { label: "Validez legal", value: "Sin certificación legal — uso académico" },
            ]}
          />
          <p style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "var(--text-muted)", marginTop: 10, marginBottom: 0 }}>
            Equipo y licencia: ver README.md del repositorio.
          </p>
        </PageSection>
      </div>
    </div>
  );
}
