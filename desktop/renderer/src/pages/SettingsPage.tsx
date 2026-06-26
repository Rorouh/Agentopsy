import { useCallback, useEffect, useState } from "react";
import type { Capabilities, ConfigSnapshot } from "../global";
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

type EditableKey =
  | "MODEL_BACKEND"
  | "MODEL_NAME"
  | "OLLAMA_HOST"
  | "ANTHROPIC_API_KEY"
  | "OPENAI_API_KEY";

const EDITABLE_KEYS: EditableKey[] = [
  "MODEL_BACKEND",
  "MODEL_NAME",
  "OLLAMA_HOST",
  "ANTHROPIC_API_KEY",
  "OPENAI_API_KEY",
];

const KEY_LABELS: Record<EditableKey, string> = {
  MODEL_BACKEND: "Backend del modelo",
  MODEL_NAME: "Modelo activo",
  OLLAMA_HOST: "Ollama host (local)",
  ANTHROPIC_API_KEY: "Anthropic API key",
  OPENAI_API_KEY: "OpenAI API key",
};

const KEY_HINTS: Record<EditableKey, string> = {
  MODEL_BACKEND: "Valores admitidos: `local` o `cloud`.",
  MODEL_NAME:
    "OpenAI: elige uno de la lista. Ollama: escribe el tag local (p. ej. llama3.1:8b).",
  OLLAMA_HOST: "URL completa, p. ej. http://localhost:11434.",
  ANTHROPIC_API_KEY: "Clave Anthropic. ≥16 chars. Solo se envía al sidecar local.",
  OPENAI_API_KEY: "Clave OpenAI. ≥16 chars. Solo se envía al sidecar local.",
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
  const [openaiModels, setOpenaiModels] = useState<string[]>([]);
  const [draft, setDraft] = useState<Record<EditableKey, string>>({
    MODEL_BACKEND: "",
    MODEL_NAME: "",
    OLLAMA_HOST: "",
    ANTHROPIC_API_KEY: "",
    OPENAI_API_KEY: "",
  });
  const [savingKey, setSavingKey] = useState<EditableKey | null>(null);
  const [configError, setConfigError] = useState<string | null>(null);

  const refreshConfig = useCallback(async () => {
    try {
      const snap = await window.forensia.config.get();
      setConfigSnapshot(snap);
    } catch (err) {
      setConfigError(String(err instanceof Error ? err.message : err));
    }
  }, []);

  useEffect(() => {
    refreshConfig();
    window.forensia.config
      .models()
      .then((res) => setOpenaiModels(res.openai))
      .catch(() => setOpenaiModels([]));
  }, [refreshConfig]);

  const saveKey = useCallback(
    async (key: EditableKey) => {
      const value = draft[key].trim();
      if (!value) return;
      setSavingKey(key);
      setConfigError(null);
      try {
        await window.forensia.config.set(key, value);
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

        {/* Modelos / IA — form real contra /api/config (RULE 2: el operador define cada valor). */}
        <PageSection title="Modelos / IA" fullWidth={false}>
          {caps && (
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
          )}
          <p
            style={{
              fontFamily: "var(--font-sans)",
              fontSize: 12,
              color: "var(--text-muted)",
              marginTop: 10,
              marginBottom: 12,
            }}
          >
            Las claves se guardan en{" "}
            <code>{configSnapshot?.config_file ?? "~/.forensia/config.json"}</code>. Las
            API keys nunca vuelven a salir del sidecar — al leerlas, FORENSIA solo
            muestra los primeros 4 caracteres y la longitud.
          </p>

          {!configSnapshot ? (
            <LoadingState label="Consultando configuración del sidecar…" />
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              {EDITABLE_KEYS.map((key) => {
                const status = configSnapshot.keys[key];
                const placeholder = status?.set ? status.preview ?? "" : "(sin definir)";
                const backendIsCloud =
                  configSnapshot.keys.MODEL_BACKEND?.preview === "cloud" ||
                  draft.MODEL_BACKEND === "cloud";
                const isModelDropdown =
                  key === "MODEL_NAME" && backendIsCloud && openaiModels.length > 0;
                return (
                  <div key={key} className="form-field full-width">
                    <label className="form-label">
                      {KEY_LABELS[key]}
                      {status?.set ? (
                        <span style={{ marginLeft: 6, color: "var(--success)" }}>
                          ● configurada
                        </span>
                      ) : (
                        <span style={{ marginLeft: 6, color: "var(--text-muted)" }}>
                          ○ no configurada
                        </span>
                      )}
                    </label>
                    <div style={{ display: "flex", gap: 8 }}>
                      {isModelDropdown ? (
                        <select
                          className="form-select"
                          value={draft[key]}
                          onChange={(e) =>
                            setDraft((prev) => ({ ...prev, [key]: e.target.value }))
                          }
                          style={{ flex: 1 }}
                        >
                          <option value="">
                            {status?.set
                              ? `Actual: ${status.preview}`
                              : "Selecciona un modelo OpenAI…"}
                          </option>
                          {openaiModels.map((m) => (
                            <option key={m} value={m}>
                              {m}
                            </option>
                          ))}
                        </select>
                      ) : (
                        <input
                          className="form-input"
                          type={
                            key === "ANTHROPIC_API_KEY" || key === "OPENAI_API_KEY"
                              ? "password"
                              : "text"
                          }
                          placeholder={placeholder}
                          value={draft[key]}
                          onChange={(e) =>
                            setDraft((prev) => ({ ...prev, [key]: e.target.value }))
                          }
                          style={{ flex: 1 }}
                        />
                      )}
                      <Button
                        variant="chip"
                        disabled={savingKey === key || !draft[key].trim()}
                        onClick={() => saveKey(key)}
                      >
                        {savingKey === key ? "Guardando…" : "Guardar"}
                      </Button>
                    </div>
                    <p
                      style={{
                        fontFamily: "var(--font-sans)",
                        fontSize: 11,
                        color: "var(--text-muted)",
                        margin: "4px 0 0 0",
                      }}
                    >
                      {KEY_HINTS[key]}
                    </p>
                  </div>
                );
              })}
            </div>
          )}

          {configError && (
            <div className="error-state" style={{ marginTop: 10 }}>
              <strong>No se pudo guardar:</strong> {configError}
            </div>
          )}
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
