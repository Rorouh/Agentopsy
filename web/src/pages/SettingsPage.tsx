import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import type {
  Capabilities,
  ConfigSnapshot,
  ExecutorId,
  ExecutorModels,
  ExecutorStatus,
} from "../api/types";
import type { ViewId } from "../navigation/navItems";
import { useTheme } from "../ThemeProvider";
import { usePublishShellHeader } from "../layout/shellHeader";
import { ExecutorLoginModal } from "../components/ExecutorLoginModal";
import { Icon } from "../ui/Icon";

interface SettingsPageProps {
  caps: Capabilities | null;
  onNavigate?: (view: ViewId) => void;
  onCapsRefresh?: () => Promise<void> | void;
}

type TabId = "executors" | "system" | "appearance";

const TABS: { id: TabId; label: string }[] = [
  { id: "executors", label: "Motor de análisis" },
  { id: "system", label: "Sistema · Maletín" },
  { id: "appearance", label: "Apariencia" },
];

// Clave de configuración del modelo POR proveedor (espejo de
// backend/forensia/executors/__init__.py MODEL_CONFIG_KEY).
const MODEL_CONFIG_KEY: Record<ExecutorId, string> = {
  "claude-code": "CLAUDE_CODE_MODEL",
  codex: "CODEX_MODEL",
  gemini: "GEMINI_MODEL",
  ollama: "OLLAMA_MODEL",
};

const TIMEOUT_OPTIONS = [60, 120, 300];
const SAVED_MS = 2000;

export function SettingsPage({ caps, onCapsRefresh }: SettingsPageProps) {
  const { theme, setTheme } = useTheme();
  const [activeTab, setActiveTab] = useState<TabId>("executors");
  const [config, setConfig] = useState<ConfigSnapshot | null>(null);
  const [configError, setConfigError] = useState<string | null>(null);
  const [savingKey, setSavingKey] = useState<string | null>(null);
  const [savedKey, setSavedKey] = useState<string | null>(null);
  const [refreshingCaps, setRefreshingCaps] = useState(false);
  // Fila de motor desplegada. null = todas plegadas.
  const [openEngine, setOpenEngine] = useState<ExecutorId | null>(null);
  const [models, setModels] = useState<Partial<Record<ExecutorId, ExecutorModels>>>({});
  const [modelDraft, setModelDraft] = useState("");
  const [ollamaHostDraft, setOllamaHostDraft] = useState("");
  // Ejecutor cuyo modal de login web está abierto (null = ninguno).
  const [loginExecutor, setLoginExecutor] = useState<ExecutorId | null>(null);

  const refreshConfig = useCallback(async () => {
    try {
      setConfig(await api.config.get());
    } catch (err) {
      setConfigError(String(err instanceof Error ? err.message : err));
    }
  }, []);

  useEffect(() => {
    void refreshConfig();
  }, [refreshConfig]);

  // Los modelos del proveedor se piden al desplegar su fila, no de golpe al
  // montar: son cuatro llamadas que casi nunca se miran todas.
  useEffect(() => {
    if (!openEngine || models[openEngine]) return;
    let alive = true;
    api
      .executorModels(openEngine)
      .then((m) => {
        if (alive) setModels((prev) => ({ ...prev, [openEngine]: m }));
      })
      .catch(() => {
        /* el backend degrada; la fila muestra solo la razón */
      });
    return () => {
      alive = false;
    };
  }, [openEngine, models]);

  const saveKey = useCallback(
    async (key: string, value: string) => {
      setSavingKey(key);
      setConfigError(null);
      try {
        await api.config.set(key, value.trim());
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
    [refreshConfig, onCapsRefresh],
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

  usePublishShellHeader(
    {
      title: "Configuración",
      // Sin meta: la versión del api y el «sin secretos» seguían visibles en la
      // pestaña Sistema / Maletín, que es donde se consultan a propósito.
      action: onCapsRefresh ? (
        <button type="button" disabled={refreshingCaps} onClick={() => void refreshCaps()}>
          {refreshingCaps ? "Actualizando…" : "Actualizar estado"}
        </button>
      ) : undefined,
    },
    [refreshingCaps, onCapsRefresh],
  );

  const executors: [ExecutorId, ExecutorStatus][] = caps
    ? (Object.entries(caps.executors) as [ExecutorId, ExecutorStatus][])
    : [];
  const defaultExecutor = config?.keys.DEFAULT_EXECUTOR?.preview ?? "";
  const timeoutValue = Number(config?.keys.FORENSIA_EXECUTOR_TIMEOUT?.preview ?? "") || null;

  return (
    <div className="settings">
      <div className="settings-bar">
        <div className="tab-row" role="tablist" aria-label="Secciones de configuración">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              id={`settings-tab-${tab.id}`}
              role="tab"
              type="button"
              aria-selected={activeTab === tab.id}
              aria-controls={`settings-panel-${tab.id}`}
              className={`tab${activeTab === tab.id ? " is-active" : ""}`}
              onClick={() => setActiveTab(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      <div className="view-scroll settings-scroll">
        <div className="view-stack settings-stack">
          {/* ── Motor de análisis ────────────────────────────────────────── */}
          {activeTab === "executors" && (
            <div
              id="settings-panel-executors"
              role="tabpanel"
              aria-labelledby="settings-tab-executors"
              className="view-stack settings-stack"
            >
              <div className="section-stack">
                <div className="settings-lede">
                  Quién ejecuta el análisis. Elige uno: Agentopsy no lo hace por ti.
                </div>

                {!caps ? (
                  <div className="loading-state">
                    <span className="spinner" aria-hidden="true" />
                    <span>Consultando capacidades del servicio api…</span>
                  </div>
                ) : (
                  <div className="engine-rows">
                    {executors.map(([id, status]) => {
                      const open = openEngine === id;
                      const isDefault = defaultExecutor === id;
                      const providerModels = models[id];
                      const configured = config?.keys[MODEL_CONFIG_KEY[id]]?.preview ?? "";
                      const modelLabel = status.available
                        ? configured || "por defecto"
                        : "conectar →";
                      // Potencia (nivel de razonamiento): solo la ofrecen los
                      // ejecutores que declaran clave, y los niveles dependen
                      // del MODELO elegido: no hay una lista global válida.
                      const reasoning = providerModels?.reasoning ?? null;
                      const efforts =
                        providerModels?.model_details?.find((d) => d.id === configured)?.efforts ??
                        [];
                      const configuredEffort = reasoning
                        ? (config?.keys[reasoning.config_key]?.preview ?? "")
                        : "";
                      // Guardado un nivel que el modelo actual no admite: se
                      // avisa en vez de corregirlo por detrás (RULE 2).
                      const effortMismatch =
                        configuredEffort !== "" &&
                        efforts.length > 0 &&
                        !efforts.some((e) => e.id === configuredEffort);
                      return (
                        <div key={id}>
                          <button
                            type="button"
                            className={`engine-row${open ? " is-open" : ""}`}
                            aria-expanded={open}
                            onClick={() => {
                              setOpenEngine(open ? null : id);
                              setModelDraft(configured);
                              setOllamaHostDraft(config?.keys.OLLAMA_HOST?.preview ?? "");
                            }}
                          >
                            <span className={`dot${status.available ? " dot--ok" : ""}`} />
                            <span
                              className={`engine-name${status.available ? "" : " is-off"}`}
                              // La razón completa de por qué está caído ya no ocupa el
                              // panel, pero sigue consultable aquí sin salir de la vista.
                              title={status.available ? undefined : status.reason ?? undefined}
                            >
                              {status.name}
                            </span>
                            <span
                              className={`engine-scope${status.local ? " is-local" : ""}`}
                            >
                              {status.local ? "local" : "nube"}
                            </span>
                            {isDefault && <span className="engine-default">por defecto</span>}
                            <span
                              className={`engine-model${status.available ? "" : " is-off"}`}
                            >
                              {modelLabel}
                            </span>
                            <span className="engine-caret">{open ? "–" : "+"}</span>
                          </button>

                          {open && (
                            <div className="engine-panel">
                              {/* RULE 2: un ejecutor no disponible NUNCA se oculta:
                                  sigue listado, con su punto apagado y el botón de
                                  conectar. Lo que ya no se vuelca aquí es el texto
                                  completo de `status.reason`: son varios párrafos con
                                  los comandos de login, y su sitio es el modal que
                                  abre «Conectar», no la lista. Queda accesible como
                                  title del bloque. */}
                              {status.available && (
                                <div className="engine-note">
                                  {status.local
                                    ? "No sale nada de tu máquina."
                                    : "Usa tu propia suscripción; el prompt sale a ese proveedor."}
                                </div>
                              )}

                              {status.available && providerModels?.editable && (
                                <>
                                  {/* `note` es un DIAGNÓSTICO, no una explicación de
                                      uso: sólo llega cuando la lista de modelos vino
                                      vacía o incompleta y hay que decir por qué (el
                                      catálogo de Codex que no se pudo leer, Ollama que
                                      no responde). Por eso se pinta siempre que exista
                                      (RULE 2, la razón accionable no se oculta). */}
                                  {providerModels.note && (
                                    <div className="engine-note">{providerModels.note}</div>
                                  )}
                                  <div className="engine-models">
                                    {id !== "ollama" && (
                                      <button
                                        type="button"
                                        className={`chip-option${!configured ? " is-on" : ""}`}
                                        disabled={savingKey === MODEL_CONFIG_KEY[id]}
                                        onClick={() => void saveKey(MODEL_CONFIG_KEY[id], "")}
                                      >
                                        Por defecto del CLI
                                      </button>
                                    )}
                                    {(providerModels.models ?? []).map((m) => (
                                      <button
                                        key={m}
                                        type="button"
                                        className={`chip-option${m === configured ? " is-on" : ""}`}
                                        disabled={savingKey === MODEL_CONFIG_KEY[id]}
                                        onClick={() => void saveKey(MODEL_CONFIG_KEY[id], m)}
                                      >
                                        {m}
                                      </button>
                                    ))}
                                  </div>
                                  {(providerModels.allow_custom ?? true) && (
                                    <div className="engine-custom">
                                      <label
                                        className="visually-hidden"
                                        htmlFor={`model-${id}`}
                                      >
                                        Id de modelo para {status.name}
                                      </label>
                                      <input
                                        id={`model-${id}`}
                                        className="field-input field-input--sm"
                                        value={modelDraft}
                                        onChange={(e) => setModelDraft(e.target.value)}
                                        placeholder={
                                          id === "ollama"
                                            ? "otro modelo (p. ej. qwen2.5:7b-instruct)"
                                            : "id de modelo (p. ej. opus, gpt-5.5)"
                                        }
                                      />
                                      <button
                                        type="button"
                                        className="link-action"
                                        disabled={
                                          savingKey === MODEL_CONFIG_KEY[id] || !modelDraft.trim()
                                        }
                                        onClick={() =>
                                          void saveKey(MODEL_CONFIG_KEY[id], modelDraft)
                                        }
                                      >
                                        Guardar
                                      </button>
                                      {savedKey === MODEL_CONFIG_KEY[id] && (
                                        <span className="tag tag--ok" aria-live="polite">
                                          <Icon name="check" size={12} /> guardado
                                        </span>
                                      )}
                                    </div>
                                  )}

                                  {reasoning && (
                                    <>
                                      <div className="eyebrow engine-sublabel">Potencia</div>
                                      {efforts.length === 0 ? (
                                        <div className="engine-note">
                                          {configured
                                            ? `El catálogo no declara niveles de razonamiento para ${configured}.`
                                            : "Elige antes un modelo: los niveles disponibles dependen de él."}
                                        </div>
                                      ) : (
                                        <>
                                          <div className="engine-models">
                                            <button
                                              type="button"
                                              className={`chip-option${!configuredEffort ? " is-on" : ""}`}
                                              disabled={savingKey === reasoning.config_key}
                                              onClick={() =>
                                                void saveKey(reasoning.config_key, "")
                                              }
                                            >
                                              Por defecto del CLI
                                            </button>
                                            {efforts.map((eff) => (
                                              <button
                                                key={eff.id}
                                                type="button"
                                                className={`chip-option${eff.id === configuredEffort ? " is-on" : ""}`}
                                                title={eff.description}
                                                disabled={savingKey === reasoning.config_key}
                                                onClick={() =>
                                                  void saveKey(reasoning.config_key, eff.id)
                                                }
                                              >
                                                {eff.id}
                                              </button>
                                            ))}
                                          </div>
                                          {effortMismatch && (
                                            <div className="engine-note">
                                              El nivel guardado (<code>{configuredEffort}</code>) no
                                              lo admite {configured}: el turno fallaría. Elige uno
                                              de los de arriba.
                                            </div>
                                          )}
                                        </>
                                      )}
                                      <div className="engine-note">{reasoning.note}</div>
                                    </>
                                  )}
                                </>
                              )}

                              {status.available && providerModels && !providerModels.editable && (
                                <div className="engine-note">
                                  {providerModels.note ??
                                    "El modelo lo gestiona el CLI de este proveedor."}
                                </div>
                              )}

                              {/* El host de Ollama sigue siendo configurable: en el
                                  compose llega por entorno, pero una ejecución
                                  standalone lo necesita. */}
                              {id === "ollama" && (
                                <div className="engine-custom">
                                  <label className="visually-hidden" htmlFor="ollama-host">
                                    Ollama host
                                  </label>
                                  <input
                                    id="ollama-host"
                                    className="field-input field-input--sm"
                                    value={ollamaHostDraft}
                                    onChange={(e) => setOllamaHostDraft(e.target.value)}
                                    placeholder="http://ollama:11434"
                                  />
                                  <button
                                    type="button"
                                    className="link-action"
                                    disabled={
                                      savingKey === "OLLAMA_HOST" || !ollamaHostDraft.trim()
                                    }
                                    onClick={() => void saveKey("OLLAMA_HOST", ollamaHostDraft)}
                                  >
                                    Guardar host
                                  </button>
                                </div>
                              )}

                              {status.available ? (
                                <>
                                  <button
                                    type="button"
                                    className="link-action"
                                    disabled={isDefault || savingKey === "DEFAULT_EXECUTOR"}
                                    onClick={() => void saveKey("DEFAULT_EXECUTOR", id)}
                                  >
                                    {isDefault ? "es el motor por defecto" : "usar por defecto"}
                                  </button>
                                  {/* Reconectar SIEMPRE alcanzable en los ejecutores cloud, no
                                      solo cuando el sondeo los da por caídos: el CLI puede
                                      seguir diciendo que hay sesión (`claude auth status`
                                      devuelve loggedIn: true) con un token ya caducado, y
                                      entonces el fallo solo aparece al lanzar la corrida. Sin
                                      esto, la única salida era la terminal. */}
                                  {!status.local && (
                                    <button
                                      type="button"
                                      className="link-action"
                                      onClick={() => setLoginExecutor(id)}
                                    >
                                      Renovar sesión de {status.name}
                                    </button>
                                  )}
                                </>
                              ) : !status.local ? (
                                <button
                                  type="button"
                                  className="link-action"
                                  onClick={() => setLoginExecutor(id)}
                                >
                                  Conectar {status.name} →
                                </button>
                              ) : (
                                <span className="engine-note">
                                  Levanta el servicio ollama del compose para usarlo.
                                </span>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              <div className="settings-inline">
                <div className="eyebrow settings-inline-label">Tiempo máximo</div>
                <div className="engine-models">
                  {TIMEOUT_OPTIONS.map((v) => (
                    <button
                      key={v}
                      type="button"
                      className={`chip-option${timeoutValue === v ? " is-on" : ""}`}
                      disabled={savingKey === "FORENSIA_EXECUTOR_TIMEOUT"}
                      onClick={() => void saveKey("FORENSIA_EXECUTOR_TIMEOUT", String(v))}
                    >
                      {v} s
                    </button>
                  ))}
                </div>
              </div>

              {configError && (
                <div className="error-state" role="alert" aria-live="polite">
                  No se pudo guardar: {configError}
                </div>
              )}

              <div className="settings-foot">
                sin API keys · sesiones y ajustes solo en tu máquina
                {config ? ` · ${config.config_file}` : ""}
              </div>
            </div>
          )}

          {/* ── Sistema · Maletín ────────────────────────────────────────── */}
          {activeTab === "system" && (
            <div
              id="settings-panel-system"
              role="tabpanel"
              aria-labelledby="settings-tab-system"
              className="view-stack settings-stack"
            >
              {!caps ? (
                <div className="empty-rail">
                  <div className="empty-rail-title">Sin conexión con el servicio api</div>
                  <div className="empty-rail-body">
                    No se pudo obtener el diagnóstico del stack. Comprueba que el compose está
                    levantado.
                  </div>
                </div>
              ) : (
                <>
                  <div className="section-stack">
                    <div className="rule-label">
                      <span className="eyebrow eyebrow--section">Maletines</span>
                      <span className="rule" />
                    </div>
                    <div className="toolkit-rows">
                      {Object.values(caps.toolkits).map((m) => (
                        <div className="toolkit-row" key={m.service}>
                          <span className={`dot${m.running === true ? " dot--ok" : ""}`} />
                          <span className="toolkit-name">{m.service}</span>
                          <span
                            className={`tag${m.running === true ? " tag--ok" : " tag--muted"}`}
                            title={m.running === true ? m.container : m.reason ?? ""}
                          >
                            {m.running === true
                              ? "en ejecución"
                              : m.running === false
                                ? "detenido / inaccesible"
                                : "no consultable desde el api"}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="section-stack">
                    <div className="rule-label">
                      <span className="eyebrow eyebrow--section">Herramientas del catálogo</span>
                      <span className="rule" />
                    </div>
                    <div className="tool-chips">
                      {Object.entries(caps.tools).map(([k, v]) => (
                        <span
                          className={`tool-chip${v.available ? "" : " is-off"}`}
                          key={k}
                          title={v.available ? `${k}: ${v.toolkits.join(", ")}` : v.reason ?? k}
                        >
                          <span className={`dot${v.available ? " dot--ok" : ""}`} />
                          {k}
                        </span>
                      ))}
                    </div>
                  </div>

                </>
              )}
            </div>
          )}

          {/* ── Apariencia ───────────────────────────────────────────────── */}
          {activeTab === "appearance" && (
            <div
              id="settings-panel-appearance"
              role="tabpanel"
              aria-labelledby="settings-tab-appearance"
              className="view-stack settings-stack"
            >
              <div className="section-stack">
                <div className="rule-label">
                  <span className="eyebrow eyebrow--section">Tema</span>
                  <span className="rule" />
                </div>
                <div className="theme-choices" role="group" aria-label="Tema de la interfaz">
                  {(["light", "dark"] as const).map((t) => (
                    <button
                      key={t}
                      type="button"
                      className={`theme-choice${theme === t ? " is-active" : ""}`}
                      aria-pressed={theme === t}
                      onClick={() => setTheme(t)}
                    >
                      {t === "light" ? "Claro" : "Oscuro"}
                    </button>
                  ))}
                </div>
                <div className="field-hint">
                  Se guarda en este navegador y se aplica a toda la aplicación.
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {loginExecutor && (
        <ExecutorLoginModal
          executorId={loginExecutor}
          executorName={caps?.executors[loginExecutor]?.name ?? loginExecutor}
          open={loginExecutor !== null}
          onClose={() => setLoginExecutor(null)}
          onConnected={refreshCaps}
          // Si el ejecutor YA sale como disponible, lo que el operador ha
          // pedido es RENOVAR: el backend rechazaría el login de otro modo,
          // y esa negativa es la que dejaba la terminal como única salida.
          force={caps?.executors[loginExecutor]?.available ?? false}
        />
      )}
    </div>
  );
}
