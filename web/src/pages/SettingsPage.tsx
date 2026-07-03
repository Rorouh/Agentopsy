import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import type { Capabilities, ConfigSnapshot, ExecutorId, ExecutorStatus } from "../api/types";
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
  onCapsRefresh?: () => Promise<void> | void;
}

// Claves editables del backend (allowlist cerrada de routers/config.py).
// Desde el pivote 2026-07-02 NO hay secretos: el proyecto no maneja API keys
// (SECURITY INVARIANT 7) — los ejecutores CLI se autentican con la sesión del
// volumen forensia-cli-auth (seeded desde el host o login en el contenedor).
type EditableKey =
  | "DEFAULT_EXECUTOR"
  | "OLLAMA_HOST"
  | "OLLAMA_MODEL"
  | "FORENSIA_EXECUTOR_TIMEOUT";

const KEY_LABELS: Record<Exclude<EditableKey, "DEFAULT_EXECUTOR">, string> = {
  OLLAMA_HOST: "Ollama host",
  OLLAMA_MODEL: "Modelo de Ollama",
  FORENSIA_EXECUTOR_TIMEOUT: "Timeout de ejecutor (s)",
};

const KEY_HINTS: Record<Exclude<EditableKey, "DEFAULT_EXECUTOR">, string> = {
  OLLAMA_HOST:
    "URL http(s) del servicio Ollama. En el compose ya llega por entorno (http://ollama:11434); esta clave cubre ejecuciones standalone.",
  OLLAMA_MODEL:
    "Tag del modelo local, p. ej. llama3.1:8b. Si no lo fijas, el ejecutor ollama usa el modelo que recomienda el paquete del agente.",
  FORENSIA_EXECUTOR_TIMEOUT:
    "Segundos que una petición al ejecutor puede tardar antes de abortarse (y auditarse) como timeout. Sin fijar: 120 s. Súbelo si tu modelo local responde lento.",
};

export function SettingsPage({
  caps,
  version,
  activeCase,
  onNavigate,
  onCapsRefresh,
}: SettingsPageProps) {
  const { theme } = useTheme();
  const [configSnapshot, setConfigSnapshot] = useState<ConfigSnapshot | null>(null);
  const [draft, setDraft] = useState<Record<EditableKey, string>>({
    DEFAULT_EXECUTOR: "",
    OLLAMA_HOST: "",
    OLLAMA_MODEL: "",
    FORENSIA_EXECUTOR_TIMEOUT: "",
  });
  const [savingKey, setSavingKey] = useState<EditableKey | null>(null);
  const [configError, setConfigError] = useState<string | null>(null);

  const refreshConfig = useCallback(async () => {
    try {
      const snap = await api.config.get();
      setConfigSnapshot(snap);
    } catch (err) {
      setConfigError(String(err instanceof Error ? err.message : err));
    }
  }, []);

  useEffect(() => {
    refreshConfig();
  }, [refreshConfig]);

  const saveKey = useCallback(
    async (key: EditableKey, rawValue?: string) => {
      const value = (rawValue ?? draft[key]).trim();
      if (!value) return;
      setSavingKey(key);
      setConfigError(null);
      try {
        await api.config.set(key, value);
        setDraft((prev) => ({ ...prev, [key]: "" }));
        await refreshConfig();
        if (onCapsRefresh) await onCapsRefresh();
      } catch (err) {
        setConfigError(String(err instanceof Error ? err.message : err));
      } finally {
        setSavingKey(null);
      }
    },
    [draft, refreshConfig, onCapsRefresh]
  );

  const executors: [ExecutorId, ExecutorStatus][] = caps
    ? (Object.entries(caps.executors) as [ExecutorId, ExecutorStatus][])
    : [];
  const currentDefault = configSnapshot?.keys.DEFAULT_EXECUTOR?.preview ?? "";

  return (
    <div>
      <PageHeader
        title="Configuración"
        subtitle="Preferencias del operador, del informe y diagnóstico del stack. FORENSIA no guarda ningún secreto: no hay API keys en ninguna parte."
      />

      <div className="settings-grid">
        {/* Apariencia — única sección con persistencia real (localStorage vía ThemeProvider) */}
        <PageSection title="Apariencia" fullWidth={false}>
          <p style={{ fontFamily: "var(--font-sans)", fontSize: 13, color: "var(--text-secondary)", marginTop: 0 }}>
            El tema se guarda en este navegador y se aplica a toda la aplicación.
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

        {/* Ejecutores / IA — estado de los 4 ejecutores + DEFAULT_EXECUTOR + Ollama.
            RULE 2: el operador fija cada valor; fijar DEFAULT_EXECUTOR aquí es un
            acto explícito del usuario (inventarlo el código sí violaría la regla). */}
        <PageSection title="Ejecutores / IA" fullWidth={false}>
          {caps ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {executors.map(([id, status]) => (
                <div key={id}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <StatusDot online={status.available} />
                    <strong style={{ fontSize: 13 }}>{status.name}</strong>
                    <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                      {id} · {status.local ? "100 % local" : "cloud (suscripción propia)"}
                    </span>
                  </div>
                  {!status.available && status.reason && (
                    <div
                      style={{
                        fontFamily: "var(--font-sans)",
                        fontSize: 11,
                        color: "var(--text-muted)",
                        margin: "2px 0 0 20px",
                      }}
                    >
                      {status.reason}
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <LoadingState label="Consultando capacidades del servicio api…" />
          )}

          {!configSnapshot ? (
            <LoadingState label="Consultando configuración…" />
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 14, marginTop: 16 }}>
              <div className="form-field full-width">
                <label className="form-label">
                  Ejecutor por defecto (DEFAULT_EXECUTOR)
                  {configSnapshot.keys.DEFAULT_EXECUTOR?.set ? (
                    <span style={{ marginLeft: 6, color: "var(--success)" }}>
                      ● {currentDefault}
                    </span>
                  ) : (
                    <span style={{ marginLeft: 6, color: "var(--text-muted)" }}>
                      ○ sin fijar
                    </span>
                  )}
                </label>
                <select
                  className="form-select"
                  value={draft.DEFAULT_EXECUTOR}
                  disabled={savingKey === "DEFAULT_EXECUTOR"}
                  onChange={(e) => {
                    const value = e.target.value;
                    setDraft((prev) => ({ ...prev, DEFAULT_EXECUTOR: value }));
                    if (value) saveKey("DEFAULT_EXECUTOR", value);
                  }}
                >
                  <option value="">
                    {currentDefault
                      ? `Actual: ${currentDefault} — elige otro…`
                      : "Selecciona un ejecutor…"}
                  </option>
                  {executors.map(([id, status]) => (
                    <option key={id} value={id} disabled={!status.available} title={status.reason ?? ""}>
                      {status.name}
                      {status.available ? "" : " — no disponible"}
                    </option>
                  ))}
                </select>
                <p style={{ fontFamily: "var(--font-sans)", fontSize: 11, color: "var(--text-muted)", margin: "4px 0 0 0" }}>
                  Opcional. Si no lo fijas, cada consulta exige elegir ejecutor (RULE 2:
                  FORENSIA nunca elige uno por ti). Los no disponibles muestran su razón al pasar el cursor.
                </p>
              </div>

              {(Object.keys(KEY_LABELS) as (keyof typeof KEY_LABELS)[]).map((key) => {
                const status = configSnapshot.keys[key];
                return (
                  <div key={key} className="form-field full-width">
                    <label className="form-label">
                      {KEY_LABELS[key]}
                      {status?.set ? (
                        <span style={{ marginLeft: 6, color: "var(--success)" }}>
                          ● {status.preview}
                        </span>
                      ) : (
                        <span style={{ marginLeft: 6, color: "var(--text-muted)" }}>
                          ○ sin fijar
                        </span>
                      )}
                    </label>
                    <div style={{ display: "flex", gap: 8 }}>
                      <input
                        className="form-input"
                        type="text"
                        placeholder={status?.set ? status.preview ?? "" : "(sin definir)"}
                        value={draft[key]}
                        onChange={(e) =>
                          setDraft((prev) => ({ ...prev, [key]: e.target.value }))
                        }
                        style={{ flex: 1 }}
                      />
                      <Button
                        variant="chip"
                        disabled={savingKey === key || !draft[key].trim()}
                        onClick={() => saveKey(key)}
                      >
                        {savingKey === key ? "Guardando…" : "Guardar"}
                      </Button>
                    </div>
                    <p style={{ fontFamily: "var(--font-sans)", fontSize: 11, color: "var(--text-muted)", margin: "4px 0 0 0" }}>
                      {KEY_HINTS[key]}
                    </p>
                  </div>
                );
              })}

              <p style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: "var(--text-muted)", margin: 0 }}>
                La configuración se guarda en <code>{configSnapshot.config_file}</code>.
                Ninguna de estas claves es un secreto.
              </p>
            </div>
          )}

          {configError && (
            <div className="error-state" style={{ marginTop: 10 }}>
              <strong>No se pudo guardar:</strong> {configError}
            </div>
          )}
        </PageSection>

        {/* Seguridad y privacidad */}
        <PageSection title="Seguridad y privacidad" fullWidth={false}>
          <div className="settings-toggle-row">
            <input type="checkbox" checked disabled />
            <div>
              <div className="settings-toggle-title">Ollama = opción 100 % local</div>
              <div className="settings-toggle-desc">
                Con el ejecutor Ollama ningún dato del caso sale de esta máquina. FORENSIA
                no fija un ejecutor por defecto: la elección es siempre del operador.
              </div>
            </div>
          </div>
          <div className="settings-toggle-row">
            <input type="checkbox" checked disabled />
            <div>
              <div className="settings-toggle-title">Ejecutores cloud: aviso + consentimiento auditado</div>
              <div className="settings-toggle-desc">
                Al elegir Claude Code, Codex o Gemini CLI, el contenido derivado del caso
                sale al proveedor bajo tu propia suscripción (la evidencia puede contener
                datos personales reales → RGPD). La UI exige confirmarlo una vez por caso
                y ejecutor, y el consentimiento queda registrado en el audit log del caso.
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
                  { label: "Python (servicio api)", value: caps.python },
                  { label: "Ejecutores disponibles", value: `${executors.filter(([, s]) => s.available).length} / ${executors.length}` },
                  { label: "Herramientas detectadas", value: `${Object.values(caps.tools).filter((t) => t.available).length} / ${Object.keys(caps.tools).length}` },
                ]}
              />
              {onNavigate && (
                <div className="cta-row">
                  <Button variant="chip" onClick={() => onNavigate("system")}>Ver detalle completo →</Button>
                </div>
              )}
            </>
          ) : (
            <EmptyState title="Sin conexión con el servicio api" description="No se pudo obtener el diagnóstico del stack." />
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
