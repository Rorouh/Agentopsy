import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import type { Capabilities, ConfigSnapshot, ExecutorId, ExecutorStatus } from "../api/types";
import type { ViewId } from "../navigation/navItems";
import { useTheme } from "../ThemeProvider";
import { ThemeToggle } from "../ThemeToggle";
import { PageHeader } from "../ui/PageHeader";
import { KeyValueList } from "../ui/KeyValueList";
import { Button } from "../ui/Button";
import { EmptyState } from "../ui/EmptyState";
import { LoadingState } from "../ui/LoadingState";
import { ExecutorLoginModal } from "../components/ExecutorLoginModal";

interface SettingsPageProps {
  caps: Capabilities | null;
  version: string;
  onNavigate?: (view: ViewId) => void;
  onCapsRefresh?: () => Promise<void> | void;
}

type TabId = "executors" | "operator" | "appearance" | "system";

const TABS: { id: TabId; label: string }[] = [
  { id: "executors", label: "Ejecutores / IA" },
  { id: "operator", label: "Operador y reportes" },
  { id: "appearance", label: "Apariencia" },
  { id: "system", label: "Sistema" },
];

// Claves editables del backend (allowlist cerrada de routers/config.py).
// Desde el pivote 2026-07-02 NO hay secretos: el proyecto no maneja API keys
// (SECURITY INVARIANT 7) — los ejecutores CLI se autentican con la sesión del
// volumen forensia-cli-auth (seeded desde el host o login en el contenedor).
type EditableKey =
  | "DEFAULT_EXECUTOR"
  | "OLLAMA_HOST"
  | "OLLAMA_MODEL"
  | "CLAUDE_CODE_MODEL"
  | "CODEX_MODEL"
  | "GEMINI_MODEL"
  | "FORENSIA_EXECUTOR_TIMEOUT";

const KEY_LABELS: Record<Exclude<EditableKey, "DEFAULT_EXECUTOR">, string> = {
  OLLAMA_HOST: "Ollama host",
  OLLAMA_MODEL: "Modelo de Ollama",
  CLAUDE_CODE_MODEL: "Modelo de Claude Code",
  CODEX_MODEL: "Modelo de Codex CLI",
  GEMINI_MODEL: "Modelo de Gemini CLI",
  FORENSIA_EXECUTOR_TIMEOUT: "Timeout de ejecutor (s)",
};

const CLOUD_MODEL_HINT =
  "Id que se pasa al CLI como --model (p. ej. opus, gpt-5.5). FORENSIA no puede enumerar el catálogo sin API key (SECURITY 7); déjalo vacío para usar el modelo por defecto del CLI. También se elige desde el chat.";

const KEY_HINTS: Record<Exclude<EditableKey, "DEFAULT_EXECUTOR">, string> = {
  OLLAMA_HOST:
    "URL http(s) del servicio Ollama. En el compose ya llega por entorno (http://ollama:11434); esta clave cubre ejecuciones standalone.",
  OLLAMA_MODEL:
    "Tag del modelo local, p. ej. llama3.1:8b. Si no lo fijas, el ejecutor ollama usa el modelo que recomienda el paquete del agente.",
  CLAUDE_CODE_MODEL: CLOUD_MODEL_HINT,
  CODEX_MODEL: CLOUD_MODEL_HINT,
  GEMINI_MODEL: CLOUD_MODEL_HINT,
  FORENSIA_EXECUTOR_TIMEOUT:
    "Segundos que una petición al ejecutor puede tardar antes de abortarse (y auditarse) como timeout. Sin fijar: 120 s. Súbelo si tu modelo local responde lento.",
};

const SAVED_MS = 2000;

export function SettingsPage({ caps, version, onNavigate, onCapsRefresh }: SettingsPageProps) {
  const { theme } = useTheme();
  const [activeTab, setActiveTab] = useState<TabId>("executors");
  const [configSnapshot, setConfigSnapshot] = useState<ConfigSnapshot | null>(null);
  const [draft, setDraft] = useState<Record<EditableKey, string>>({
    DEFAULT_EXECUTOR: "",
    OLLAMA_HOST: "",
    OLLAMA_MODEL: "",
    CLAUDE_CODE_MODEL: "",
    CODEX_MODEL: "",
    GEMINI_MODEL: "",
    FORENSIA_EXECUTOR_TIMEOUT: "",
  });
  const [savingKey, setSavingKey] = useState<EditableKey | null>(null);
  const [savedKey, setSavedKey] = useState<EditableKey | null>(null);
  const [configError, setConfigError] = useState<string | null>(null);
  const [refreshingCaps, setRefreshingCaps] = useState(false);
  // Ejecutor cuyo modal de login web está abierto (null = ninguno).
  const [loginExecutor, setLoginExecutor] = useState<ExecutorId | null>(null);

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
        setSavedKey(key);
        window.setTimeout(() => setSavedKey((prev) => (prev === key ? null : prev)), SAVED_MS);
      } catch (err) {
        setConfigError(String(err instanceof Error ? err.message : err));
      } finally {
        setSavingKey(null);
      }
    },
    [draft, refreshConfig, onCapsRefresh]
  );

  const refreshCaps = useCallback(async () => {
    if (!onCapsRefresh) return;
    setRefreshingCaps(true);
    try {
      await onCapsRefresh();
    } finally {
      setRefreshingCaps(false);
    }
  }, [onCapsRefresh]);

  const executors: [ExecutorId, ExecutorStatus][] = caps
    ? (Object.entries(caps.executors) as [ExecutorId, ExecutorStatus][])
    : [];
  const currentDefault = configSnapshot?.keys.DEFAULT_EXECUTOR?.preview ?? "";

  return (
    <div>
      <PageHeader
        title="Configuración"
        subtitle="Ejecutores de IA, datos del operador, apariencia y diagnóstico del stack. FORENSIA no guarda ningún secreto: no hay API keys en ninguna parte."
      />

      <div className="settings-tabs" role="tablist" aria-label="Secciones de configuración">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            id={`settings-tab-${tab.id}`}
            role="tab"
            type="button"
            aria-selected={activeTab === tab.id}
            aria-controls={`settings-panel-${tab.id}`}
            className={`settings-tab ${activeTab === tab.id ? "active" : ""}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* ── Ejecutores / IA ──────────────────────────────────────────────── */}
      {activeTab === "executors" && (
        <div
          id="settings-panel-executors"
          role="tabpanel"
          aria-labelledby="settings-tab-executors"
          className="settings-panel"
        >
          <div className="settings-form">
            {/* Estado de los 4 ejecutores — viene de caps.executors (RULE 2:
                los no disponibles muestran la razón accionable, nunca se ocultan). */}
            {caps ? (
              <div className="settings-exec-status">
                <div className="settings-exec-status-title">EJECUTORES / IA</div>
                {executors.map(([id, status]) => (
                  <div key={id} className="settings-exec-row">
                    <div className="settings-exec-row-main">
                      <span className="settings-exec-name">
                        {status.name}{" "}
                        <span className="settings-exec-scope">
                          {id} · {status.local ? "100 % local" : "cloud (suscripción propia)"}
                        </span>
                      </span>
                      <span
                        className={`settings-exec-badge ${status.available ? "available" : "unavailable"}`}
                      >
                        <span className="settings-exec-dot" />
                        {status.available ? "Disponible" : "No disponible"}
                      </span>
                    </div>
                    {!status.available && status.reason && (
                      <div className="settings-exec-reason">{status.reason}</div>
                    )}
                    {/* Login web para los ejecutores CLI cloud no disponibles:
                        conecta Codex/Claude sin abrir terminal. Ollama (local) no
                        tiene login, así que solo se ofrece a los no-locales. */}
                    {!status.available && !status.local && (
                      <div className="settings-exec-connect">
                        <Button variant="chip" onClick={() => setLoginExecutor(id)}>
                          Conectar {status.name} →
                        </Button>
                      </div>
                    )}
                  </div>
                ))}
                <p className="settings-exec-hint">
                  Los ejecutores CLI (Claude Code, Codex, Gemini) se autentican con tu propia
                  sesión, guardada en el volumen <code>forensia-cli-auth</code> del stack —
                  nunca con API keys. La sesión se siembra una vez desde el host o iniciando
                  sesión dentro del contenedor (p. ej.{" "}
                  <code>docker compose exec -it api claude auth login</code>); no sale de tu
                  máquina, no se registra en logs y se revoca con{" "}
                  <code>docker compose down -v</code>. Ollama es la opción 100 % local.
                </p>
              </div>
            ) : (
              <LoadingState label="Consultando capacidades del servicio api…" />
            )}

            <div className="settings-save-row" style={{ marginTop: 0 }}>
              <Button variant="chip" disabled={refreshingCaps || !onCapsRefresh} onClick={refreshCaps}>
                {refreshingCaps ? "Actualizando…" : "Actualizar estado"}
              </Button>
              <span className="field-hint">
                Reconsulta capabilities tras iniciar sesión en un CLI o levantar Ollama.
              </span>
            </div>

            {!configSnapshot ? (
              <LoadingState label="Consultando configuración…" />
            ) : (
              <>
                {/* RULE 2: el operador fija cada valor; fijar DEFAULT_EXECUTOR aquí es
                    un acto explícito del usuario (inventarlo el código sí violaría la regla). */}
                <div className="form-field">
                  <label className="form-label" htmlFor="default-executor">
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
                    id="default-executor"
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
                  <span className="field-hint">
                    Opcional. Si no lo fijas, cada consulta exige elegir ejecutor (RULE 2:
                    FORENSIA nunca elige uno por ti). Los no disponibles muestran su razón al
                    pasar el cursor.
                  </span>
                  {savedKey === "DEFAULT_EXECUTOR" && (
                    <span className="settings-saved" aria-live="polite">✓ Guardado</span>
                  )}
                </div>

                {(Object.keys(KEY_LABELS) as (keyof typeof KEY_LABELS)[]).map((key) => {
                  const status = configSnapshot.keys[key];
                  return (
                    <div key={key} className="form-field">
                      <label className="form-label" htmlFor={`config-${key}`}>
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
                          id={`config-${key}`}
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
                          variant="primary"
                          disabled={savingKey === key || !draft[key].trim()}
                          onClick={() => saveKey(key)}
                        >
                          {savingKey === key ? (
                            <>
                              <span className="spinner" aria-hidden="true" /> Guardando…
                            </>
                          ) : (
                            "Guardar"
                          )}
                        </Button>
                      </div>
                      <span className="field-hint">{KEY_HINTS[key]}</span>
                      {savedKey === key && (
                        <span className="settings-saved" aria-live="polite">✓ Guardado</span>
                      )}
                    </div>
                  );
                })}

                <span className="field-hint">
                  La configuración se guarda en <code>{configSnapshot.config_file}</code>.
                  Ninguna de estas claves es un secreto.
                </span>
              </>
            )}

            {configError && (
              <div className="settings-form-error" role="alert" aria-live="polite">
                No se pudo guardar: {configError}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Operador y reportes ──────────────────────────────────────────── */}
      {activeTab === "operator" && (
        <div
          id="settings-panel-operator"
          role="tabpanel"
          aria-labelledby="settings-tab-operator"
          className="settings-panel"
        >
          <div className="settings-form">
            <div className="demo-banner">
              ⚠ Vista previa · estos campos aún no se persisten en el backend; se
              incluirán como cabecera de los informes cuando la generación real exista.
            </div>

            <div className="form-field">
              <label className="form-label" htmlFor="operator-name">Nombre del examinador</label>
              <input
                id="operator-name"
                className="form-input"
                placeholder="Nombre completo"
                disabled
              />
            </div>
            <div className="form-field">
              <label className="form-label" htmlFor="operator-org">Organización</label>
              <input
                id="operator-org"
                className="form-input"
                placeholder="Organización o institución (opcional)"
                disabled
              />
            </div>
            <div className="form-field">
              <label className="form-label" htmlFor="operator-role">Rol / cargo</label>
              <input
                id="operator-role"
                className="form-input"
                placeholder="Rol profesional (opcional)"
                disabled
              />
            </div>

            <div>
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
            </div>

            <div className="form-field">
              <label className="form-label" htmlFor="report-format">Formato de exportación</label>
              <select id="report-format" className="form-select" defaultValue="pdf" disabled>
                <option value="pdf">PDF</option>
                <option value="docx">Word (.docx)</option>
                <option value="json">JSON (estructurado)</option>
              </select>
            </div>
          </div>
        </div>
      )}

      {/* ── Apariencia ───────────────────────────────────────────────────── */}
      {activeTab === "appearance" && (
        <div
          id="settings-panel-appearance"
          role="tabpanel"
          aria-labelledby="settings-tab-appearance"
          className="settings-panel"
        >
          <div className="settings-form">
            <div className="form-field">
              <label className="form-label" id="theme-label">Tema</label>
              <div aria-labelledby="theme-label">
                <ThemeToggle />
              </div>
              <span className="field-hint">
                Tema actual: {theme === "light" ? "Claro" : "Oscuro"}. Se guarda en este
                navegador (localStorage) y se aplica a toda la aplicación.
              </span>
            </div>
          </div>
        </div>
      )}

      {/* ── Sistema ──────────────────────────────────────────────────────── */}
      {activeTab === "system" && (
        <div
          id="settings-panel-system"
          role="tabpanel"
          aria-labelledby="settings-tab-system"
          className="settings-panel"
        >
          <div className="settings-form">
            {caps ? (
              <div className="form-field">
                <label className="form-label">Diagnóstico</label>
                <KeyValueList
                  items={[
                    { label: "Producto", value: "FORENSIA" },
                    { label: "Versión", value: version ? `v${version}` : "—" },
                    { label: "Python (servicio api)", value: caps.python },
                    { label: "Ejecutores disponibles", value: `${executors.filter(([, s]) => s.available).length} / ${executors.length}` },
                    { label: "Herramientas detectadas", value: `${Object.values(caps.tools).filter((t) => t.available).length} / ${Object.keys(caps.tools).length}` },
                  ]}
                />
                {onNavigate && (
                  <div className="cta-row">
                    <Button variant="chip" onClick={() => onNavigate("system")}>
                      Ver Estado del Sistema completo →
                    </Button>
                  </div>
                )}
              </div>
            ) : (
              <EmptyState
                title="Sin conexión con el servicio api"
                description="No se pudo obtener el diagnóstico del stack."
              />
            )}
          </div>
        </div>
      )}

      {loginExecutor && (
        <ExecutorLoginModal
          executorId={loginExecutor}
          executorName={caps?.executors[loginExecutor]?.name ?? loginExecutor}
          open={loginExecutor !== null}
          onClose={() => setLoginExecutor(null)}
          onConnected={refreshCaps}
        />
      )}
    </div>
  );
}
