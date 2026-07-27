import { useEffect, useMemo, useRef, useState } from "react";
import { ApiError, api } from "../api/client";
import type {
  AgentSummary,
  Capabilities,
  Case,
  EvidenceHandle,
  ExecutorId,
  ExecutorModels,
  ExecutorStatus,
  StreamEvent,
} from "../api/types";
import { ExecutorLoginModal } from "../components/ExecutorLoginModal";

// Markdown mínimo del turno del agente. SEC INV 8: se pinta como TEXTO — en
// todo web/src no hay un solo dangerouslySetInnerHTML, y esta pantalla es la
// tentación número uno de romperlo.
function renderInline(text: string) {
  const parts = text.split(/(\*\*.*?\*\*|`.*?`)/g);
  return parts.map((part, i) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return <strong key={i}>{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith("`") && part.endsWith("`")) {
      return (
        <code key={i} className="inline-code">
          {part.slice(1, -1)}
        </code>
      );
    }
    return part;
  });
}

function formatMessageContent(content: string) {
  return content.split("\n").map((line, idx) => {
    const text = line.trim();
    if (text.startsWith("* ") || text.startsWith("- ")) {
      return <li key={idx}>{renderInline(text.substring(2))}</li>;
    }
    const numMatch = text.match(/^(\d+)\.\s+(.*)/);
    if (numMatch) {
      return (
        <li key={idx} value={parseInt(numMatch[1], 10)}>
          {renderInline(numMatch[2])}
        </li>
      );
    }
    if (text.startsWith("### ")) return <h4 key={idx}>{renderInline(text.substring(4))}</h4>;
    if (text.startsWith("## ")) return <h3 key={idx}>{renderInline(text.substring(3))}</h3>;
    if (text.startsWith("# ")) return <h3 key={idx}>{renderInline(text.substring(2))}</h3>;
    if (text === "") return <div key={idx} className="turn-gap" />;
    return <p key={idx}>{renderInline(line)}</p>;
  });
}

// Instrucciones de arranque del mock: verbos del oficio, no botones de demo.
const QUICK_PROMPTS = [
  "buscar persistencia",
  "analizar conexiones de red",
  "generar timeline del sistema de ficheros",
  "redactar informe",
];

const SEVERITY_LABEL: Record<string, string> = {
  low: "Baja",
  medium: "Media",
  high: "Alta",
  critical: "Crítica",
};

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  // Hora del turno (ISO). La columna izquierda de la transcripción.
  at?: string;
  pending?: boolean;
  // Progreso en vivo del agente (streaming): eventos acumulados + si sigue en curso.
  activity?: StreamEvent[];
  streaming?: boolean;
}

function clockOf(at: string | undefined): string {
  if (!at) return "";
  const d = new Date(at);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString("es-ES", { hour12: false });
}

// Bloque «Cadena de ejecución»: lo que el agente EJECUTÓ, con el argv literal.
// No es la intención declarada por el LLM — es el comando que corrió y quedó en
// el log de auditoría encadenado (FORENSIC INVARIANT 4).
function ToolChain({ activity, streaming }: { activity: StreamEvent[]; streaming: boolean }) {
  const steps = activity.filter((e) => e.type === "tool_call").length;
  if (activity.length === 0 && !streaming) return null;

  return (
    <div className="toolchain">
      <div className="toolchain-head">
        <span>Cadena de ejecución</span>
        <span>
          {steps} paso{steps === 1 ? "" : "s"} · {streaming ? "en curso" : "registrada"}
        </span>
      </div>
      {activity.map((ev, i) => {
        if (ev.type === "reasoning") {
          return (
            <div className="toolchain-line toolchain-line--dim" key={i}>
              {ev.text}
            </div>
          );
        }
        if (ev.type === "tool_call") {
          const params = ev.params
            ? Object.entries(ev.params)
                .map(([k, v]) => `${k}=${String(v)}`)
                .join(" ")
            : "";
          return (
            <div className="toolchain-line toolchain-line--dim" key={i}>
              ▸ {ev.tool_id}
              {params ? ` ${params.length > 90 ? `${params.slice(0, 89)}…` : params}` : ""}
            </div>
          );
        }
        if (ev.type === "tool_result") {
          const ok = ev.status === "ok";
          const cmd = ev.argv && ev.argv.length ? ev.argv.join(" ") : "";
          return (
            <div className="toolchain-line" key={i}>
              <span className={ok ? "toolchain-ok" : "toolchain-err"}>{ok ? "✓" : "✗"}</span>
              &nbsp;&nbsp;
              {cmd || ev.status}
              <span className="toolchain-note">
                {" — "}
                {ev.summary ?? ev.status}
                {ev.status === "nonzero" && ev.exit_code != null ? ` (exit ${ev.exit_code})` : ""}
              </span>
            </div>
          );
        }
        return null;
      })}
    </div>
  );
}

// One session id per case is enough for v1 — múltiples investigaciones por caso
// se introducen cuando el flujo lo pida explícitamente.
const CHAT_SESSION_ID = "main";

// Config key que persiste el modelo elegido POR proveedor (espejo de
// backend/forensia/executors/__init__.py MODEL_CONFIG_KEY).
const MODEL_CONFIG_KEY: Record<ExecutorId, string> = {
  "claude-code": "CLAUDE_CODE_MODEL",
  codex: "CODEX_MODEL",
  gemini: "GEMINI_MODEL",
  ollama: "OLLAMA_MODEL",
};

interface ChatPageProps {
  caps: Capabilities | null;
  activeCase?: Case | null;
  activeEvidence?: EvidenceHandle | null;
  // Se llama al terminar cada query() (bien o mal) para que la página que
  // envuelve (Investigación) refresque hallazgos, tools y coste.
  onTurnComplete?: () => void;
  // Refresca capabilities en App tras conectar un ejecutor CLI desde el selector.
  onCapsRefresh?: () => Promise<void> | void;
  // Propaga el caso actualizado tras anclar su os_profile manualmente.
  onCaseUpdated?: (updated: Case) => void;
}

export function ChatPage({
  caps,
  activeCase,
  activeEvidence,
  onTurnComplete,
  onCapsRefresh,
  onCaseUpdated,
}: ChatPageProps) {
  const [msgs, setMsgs] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);

  // Ejecutor elegido por el operador para esta sesión. Se preselecciona con
  // DEFAULT_EXECUTOR solo si el usuario lo fijó EXPLÍCITAMENTE en Configuración
  // (agencia del operador — RULE 2); nunca se inventa uno. El vacío inicial es
  // deliberado: no es un hueco que haya que "arreglar" con un ?? "ollama".
  const [executor, setExecutor] = useState<ExecutorId | "">("");

  // Anclaje MANUAL del os_profile del caso (RULE 2: acción explícita del
  // operador) cuando el triage no lo determinó.
  const [anchoring, setAnchoring] = useState<"unix" | "windows" | null>(null);
  const [anchorError, setAnchorError] = useState<string | null>(null);

  const [openMenu, setOpenMenu] = useState<null | "provider" | "model">(null);
  const [loginExecutor, setLoginExecutor] = useState<ExecutorId | null>(null);
  const [modelByProvider, setModelByProvider] = useState<Partial<Record<ExecutorId, string>>>({});
  const [modelDraft, setModelDraft] = useState<string>("");
  const [modelSaving, setModelSaving] = useState(false);
  const [providerModels, setProviderModels] = useState<ExecutorModels | null>(null);
  const [modelsLoading, setModelsLoading] = useState(false);

  const logRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const actionsRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api.config
      .get()
      .then((snap) => {
        const def = snap.keys.DEFAULT_EXECUTOR;
        if (def?.set && def.preview) {
          setExecutor((prev) => prev || (def.preview as ExecutorId));
        }
        // Recupera el último modelo elegido de cada proveedor.
        const restored: Partial<Record<ExecutorId, string>> = {};
        (Object.keys(MODEL_CONFIG_KEY) as ExecutorId[]).forEach((id) => {
          const mdl = snap.keys[MODEL_CONFIG_KEY[id]];
          if (mdl?.set && mdl.preview) restored[id] = mdl.preview;
        });
        setModelByProvider(restored);
      })
      .catch(() => {
        /* sin config aún — el operador elige a mano */
      });
  }, []);

  // El selector de modelos cambia con el proveedor: al elegir ejecutor, pide sus
  // modelos (Ollama devuelve los instalados; los CLIs cloud, la nota de RULE 2).
  useEffect(() => {
    if (!executor) {
      setProviderModels(null);
      return;
    }
    let alive = true;
    setModelsLoading(true);
    api
      .executorModels(executor)
      .then((m) => {
        if (alive) setProviderModels(m);
      })
      .catch(() => {
        if (alive) setProviderModels(null);
      })
      .finally(() => {
        if (alive) setModelsLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [executor]);

  useEffect(() => {
    if (!openMenu) return;
    const onDown = (e: MouseEvent) => {
      if (actionsRef.current && !actionsRef.current.contains(e.target as Node)) {
        setOpenMenu(null);
      }
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [openMenu]);

  // Persiste la elección de modelo del proveedor ACTUAL. Un valor vacío la
  // limpia (cloud → por defecto del CLI; Ollama → modelo del paquete) — RULE 2:
  // Agentopsy nunca se inventa uno.
  const saveModel = async (value: string) => {
    if (!executor) return;
    const v = value.trim();
    const key = MODEL_CONFIG_KEY[executor];
    setModelSaving(true);
    try {
      await api.config.set(key, v);
      setModelByProvider((prev) => {
        const next = { ...prev };
        if (v) next[executor] = v;
        else delete next[executor];
        return next;
      });
      setOpenMenu(null);
    } catch {
      /* el backend degrada (id inválido, etc.); se deja el menú abierto */
    } finally {
      setModelSaving(false);
    }
  };

  // Al elegir proveedor lo recordamos como DEFAULT_EXECUTOR (agencia del
  // operador — no un default inventado; RULE 2).
  const selectExecutor = (id: ExecutorId) => {
    setExecutor(id);
    setOpenMenu(null);
    api.config.set("DEFAULT_EXECUTOR", id).catch(() => {
      /* persistencia best-effort */
    });
  };

  // Fuente de verdad de la selección de agente: el os_profile del CASO, no el
  // del host. `null` = el orquestador aún no lo ha derivado — no es un error.
  const activeProfile: "unix" | "windows" | null = activeCase
    ? activeCase.os_profile
    : caps?.os === "windows"
      ? "windows"
      : "unix";
  const activeAgent: AgentSummary | null = useMemo(() => {
    const loaded = caps?.agents?.loaded ?? [];
    return loaded.find((a) => a.os_profile === activeProfile) ?? null;
  }, [caps, activeProfile]);

  const executorEntries: [ExecutorId, ExecutorStatus][] = caps
    ? (Object.entries(caps.executors) as [ExecutorId, ExecutorStatus][])
    : [];
  const executorStatus: ExecutorStatus | null =
    executor && caps ? caps.executors[executor] ?? null : null;

  const anchorProfile = async (profile: "unix" | "windows") => {
    if (!activeCase || anchoring) return;
    setAnchoring(profile);
    setAnchorError(null);
    try {
      const updated = await api.cases.anchorProfile(activeCase.id, profile);
      if (onCaseUpdated) onCaseUpdated(updated);
      if (onCapsRefresh) await onCapsRefresh();
    } catch (err) {
      setAnchorError(
        err instanceof ApiError ? err.detail : String(err instanceof Error ? err.message : err),
      );
    } finally {
      setAnchoring(null);
    }
  };

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [msgs]);

  // Sondeo del análisis en segundo plano. `pollRef` marca el sondeo activo para
  // cancelarlo al desmontar / cambiar de caso sin tocar estado de un componente
  // que ya no está.
  const pollRef = useRef<{ cancelled: boolean } | null>(null);
  useEffect(
    () => () => {
      if (pollRef.current) pollRef.current.cancelled = true;
    },
    [],
  );

  const patchLast = (patch: Partial<ChatMessage>) =>
    setMsgs((prev) => {
      if (prev.length === 0) return prev;
      const next = [...prev];
      next[next.length - 1] = { ...next[next.length - 1], ...patch };
      return next;
    });

  const pushActivity = (ev: StreamEvent) =>
    setMsgs((prev) => {
      if (prev.length === 0) return prev;
      const next = [...prev];
      const last = next[next.length - 1];
      next[next.length - 1] = { ...last, activity: [...(last.activity ?? []), ev] };
      return next;
    });

  // Engancha a un análisis en segundo plano (nuevo o reanudado) y SONDEA su
  // estado hasta terminar. Si el cliente se fue, el job siguió vivo en el
  // servidor y esto vuelve a engancharse: una desconexión no lo aborta.
  const drivePoll = async (caseId: string, jobId: string) => {
    const token = { cancelled: false };
    pollRef.current = token;
    setBusy(true);
    let reply = "";
    let tools: unknown[] | null = null;
    let cursor = 0; // eventos de progreso ya pintados en el chat
    const collected: StreamEvent[] = []; // para persistir la traza con el mensaje
    const startedAt = Date.now();
    patchLast({ streaming: true });
    try {
      while (!token.cancelled) {
        const job = await api.getJob(jobId, cursor);
        (job.events ?? []).forEach((ev) => {
          pushActivity(ev);
          collected.push(ev);
        });
        cursor += job.events?.length ?? 0;

        if (job.status === "done") {
          reply = job.result?.reply ?? "";
          tools = (job.result?.tool_calls as unknown[]) ?? null;
          break;
        }
        if (job.status === "error") {
          reply = job.error ?? "El análisis en segundo plano falló.";
          break;
        }
        const s = Math.round((Date.now() - startedAt) / 1000);
        patchLast({
          content:
            `Analizando en segundo plano · ${s}s · puedes cerrar la pestaña y ` +
            "volver: el análisis no se detiene y los hallazgos se guardan en caliente.",
        });
        if (onCapsRefresh) await onCapsRefresh();
        await new Promise((r) => setTimeout(r, 2500));
      }
    } catch (e) {
      reply = e instanceof ApiError ? e.detail : String(e instanceof Error ? e.message : e);
    }
    if (token.cancelled) return; // desmontado o caso cambiado: no toques estado
    patchLast({ content: reply, pending: false, streaming: false });
    setBusy(false);
    pollRef.current = null;
    if (reply) {
      api.cases
        .appendChat(caseId, CHAT_SESSION_ID, {
          role: "assistant",
          content: reply,
          tool_calls: tools,
          activity: collected.length ? collected : null,
        })
        .catch(() => {
          /* best-effort */
        });
    }
    if (onTurnComplete) onTurnComplete();
  };

  useEffect(() => {
    if (!activeCase) {
      setMsgs([]);
      return;
    }
    const caseId = activeCase.id;
    let cancelled = false;
    api.cases
      .readChat(caseId, CHAT_SESSION_ID)
      .then((history) => {
        if (cancelled) return;
        setMsgs(
          history
            .filter((m) => m.role === "user" || m.role === "assistant")
            .map((m) => ({
              role: m.role as "user" | "assistant",
              content: m.content,
              at: m.ts,
              activity: m.activity ?? undefined,
            })),
        );
      })
      .catch(() => {
        // Aún no hay sesión previa: conversación en blanco.
        if (!cancelled) setMsgs([]);
      })
      .finally(async () => {
        // Si quedó un análisis corriendo (el perito cerró la pestaña y volvió),
        // reengánchate y muestra su progreso.
        if (cancelled || pollRef.current) return;
        try {
          const jobs = await api.listCaseJobs(caseId);
          const running = jobs.find((j) => j.status === "running");
          if (running && !cancelled && !pollRef.current) {
            setMsgs((prev) => [
              ...prev,
              {
                role: "assistant",
                content: "Reanudando análisis en curso…",
                at: new Date().toISOString(),
                pending: true,
                streaming: false,
                activity: [],
              },
            ]);
            void drivePoll(caseId, running.job_id);
          }
        } catch {
          /* best-effort */
        }
      });
    return () => {
      cancelled = true;
    };
    // drivePoll/patchLast son estables en la práctica; sólo re-corre al cambiar de caso.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeCase?.id]);

  const send = async () => {
    const text = input.trim();
    if (!text || busy || !activeCase) return;
    const caseId = activeCase.id;
    const now = new Date().toISOString();
    setInput("");
    setBusy(true);
    setMsgs((prev) => [
      ...prev,
      { role: "user", content: text, at: now },
      {
        role: "assistant",
        content: "Lanzando análisis en segundo plano…",
        at: now,
        pending: true,
        streaming: false,
        activity: [],
      },
    ]);

    // Persiste el turno del perito de entrada: una desconexión no puede borrar
    // lo que pidió. El del agente se persiste al terminar el job (drivePoll).
    api.cases.appendChat(caseId, CHAT_SESSION_ID, { role: "user", content: text }).catch(() => {
      /* persistencia best-effort; el estado de la UI sigue */
    });

    try {
      // Arranca el análisis en SEGUNDO PLANO: la petición vuelve al instante con
      // un job_id; el análisis sigue en el servidor aunque el cliente se
      // desconecte. `drivePoll` sondea.
      const { job_id } = await api.analyze({
        prompt: text,
        // El backend resuelve el os_profile del caso; esta clave se ignora si se
        // manda. activeProfile puede ser null (SO aún sin determinar).
        evidence_id: activeEvidence?.evidence_id ?? "",
        case_id: caseId,
        executor: executor || undefined,
        session_id: CHAT_SESSION_ID,
      });
      await drivePoll(caseId, job_id);
    } catch (e) {
      // Falló el ARRANQUE (validación: ejecutor/evidencia/perfil). El backend
      // responde con un detail accionable (RULE 2); se muestra tal cual.
      const friendly =
        e instanceof ApiError
          ? e.detail
          : "No se pudo lanzar el análisis. ¿Está levantado el compose?";
      patchLast({ content: friendly, pending: false, streaming: false });
      setBusy(false);
      if (onTurnComplete) onTurnComplete();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void send();
    }
  };

  const sendDisabled = !input.trim() || busy;
  const agentLabel = activeAgent?.id ?? (activeProfile ? `forensia-${activeProfile}` : "agentopsy");

  const providerLabel = executor ? executorStatus?.name ?? executor : "Elige ejecutor";
  // El modelo recomendado del paquete solo aplica a Ollama (modelo local).
  const recommendedModel = activeAgent?.model.name ?? "";
  const configuredModel = executor ? modelByProvider[executor] ?? "" : "";
  const effectiveModel = configuredModel || (executor === "ollama" ? recommendedModel : "");
  const modelEditable = providerModels?.editable ?? false;
  const modelLabel = !executor
    ? ""
    : effectiveModel || (executor === "ollama" ? "modelo" : "por defecto");

  return (
    <div className="chat-column">
      <div className="transcript" ref={logRef}>
        <div className="transcript-inner">
          {msgs.length === 0 && (
            <div className="turn">
              <div className="turn-time" />
              <div className="turn-body">
                <div className="empty-rail">
                  <div className="empty-rail-title">La investigación empieza aquí</div>
                  <div className="empty-rail-body">
                    Escribe una instrucción para el agente. Ejecutará el maletín forense sobre
                    la evidencia verificada y dejará cada comando en el log de auditoría
                    encadenado.
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Anclaje de perfil: NO es decoración. Sin os_profile el orquestador
              no puede rutar a ningún sub-agente y la RULE 2 prohíbe elegir uno
              en silencio: el operador tiene que anclarlo. Este es el único
              punto de la UI desde el que puede. */}
          {activeProfile === null && (
            <div className="turn">
              <div className="turn-time" />
              <div className="turn-body">
                <div className="note-rail">
                  El sistema operativo de este caso aún no está determinado — regístrale una
                  evidencia para que el orquestador lo derive, o ánclalo manualmente:
                  <div className="anchor-actions">
                    <button
                      type="button"
                      className="chip-option"
                      disabled={!!anchoring}
                      onClick={() => void anchorProfile("unix")}
                    >
                      {anchoring === "unix" ? "Anclando…" : "unix"}
                    </button>
                    <button
                      type="button"
                      className="chip-option"
                      disabled={!!anchoring}
                      onClick={() => void anchorProfile("windows")}
                    >
                      {anchoring === "windows" ? "Anclando…" : "windows"}
                    </button>
                  </div>
                  {anchorError && (
                    <div className="anchor-error">No se pudo anclar: {anchorError}</div>
                  )}
                </div>
              </div>
            </div>
          )}

          {msgs.map((msg, i) =>
            msg.role === "user" ? (
              <div className="turn" key={i}>
                <div className="turn-time">{clockOf(msg.at)}</div>
                <div className="turn-body turn-body--user">
                  <div className="turn-role">Perito</div>
                  <div className="turn-said">{msg.content}</div>
                </div>
              </div>
            ) : (
              <div className="turn" key={i}>
                <div className="turn-time">{clockOf(msg.at)}</div>
                <div className="turn-body turn-body--agent">
                  <div className="turn-role">{agentLabel}</div>

                  {msg.streaming && (
                    <div className="turn-running">
                      <span className="turn-running-dot" aria-hidden="true" />
                      {(() => {
                        const last = msg.activity?.[msg.activity.length - 1];
                        if (last?.type === "tool_call") return `ejecutando ${last.tool_id}`;
                        if (last?.type === "reasoning") return "razonando";
                        if (last?.type === "tool_result") return "procesando resultado";
                        if (last?.type === "finding") return "registrando hallazgo";
                        return "trabajando";
                      })()}
                    </div>
                  )}

                  {(msg.activity?.length || msg.streaming) && (
                    <ToolChain activity={msg.activity ?? []} streaming={!!msg.streaming} />
                  )}

                  {msg.content && (
                    <div className={`turn-prose${msg.pending ? " is-pending" : ""}`}>
                      {formatMessageContent(msg.content)}
                    </div>
                  )}

                  {/* Hallazgos registrados EN CALIENTE durante el turno. */}
                  {(msg.activity ?? [])
                    .filter((e) => e.type === "finding")
                    .map((e, k) =>
                      e.type === "finding" ? (
                        <div className="finding-strip" key={k}>
                          <span className="tag tag--box">
                            {SEVERITY_LABEL[e.severity] ?? e.severity}
                          </span>
                          <span className="finding-strip-title">{e.title}</span>
                          <span className="finding-strip-meta">registrado en el caso</span>
                        </div>
                      ) : null,
                    )}
                </div>
              </div>
            ),
          )}
        </div>
      </div>

      <div className="composer-bar">
        <div className="composer-inner">
          <textarea
            ref={inputRef}
            className="composer-input"
            placeholder="Escribe una instrucción para el agente…"
            rows={1}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
          />

          <div className="composer-row" ref={actionsRef}>
            {/* Proveedor (ejecutor). Los NO disponibles se muestran, no se
                ocultan: deshabilitados, con la razón accionable de capabilities
                y su acción de conexión si son CLI cloud (RULE 2). */}
            <div className="composer-menu-wrap">
              <button
                type="button"
                className={`composer-pick${executor ? "" : " is-empty"}`}
                title="Ejecutor del análisis"
                onClick={() => setOpenMenu(openMenu === "provider" ? null : "provider")}
              >
                {providerLabel}
                {executorStatus?.local ? " · local" : ""}
                {modelLabel ? ` · ${modelLabel}` : ""}
              </button>
              {openMenu === "provider" && (
                <div className="composer-popover">
                  <div className="composer-popover-title">Ejecutor</div>
                  {executorEntries.length === 0 && (
                    <div className="composer-popover-note">consultando capacidades…</div>
                  )}
                  {executorEntries.map(([id, status]) =>
                    status.available ? (
                      <button
                        key={id}
                        type="button"
                        className={`composer-popover-item${id === executor ? " is-active" : ""}`}
                        onClick={() => selectExecutor(id)}
                      >
                        <span>
                          {status.name}
                          {status.local ? " · local" : " · nube"}
                        </span>
                        {id === executor && <span aria-hidden>✓</span>}
                      </button>
                    ) : (
                      <div
                        key={id}
                        className="composer-popover-item is-disabled"
                        title={status.reason ?? "No disponible"}
                      >
                        <span>
                          {status.name} — no disponible
                        </span>
                        {!status.local && (
                          <button
                            type="button"
                            className="link-action"
                            onClick={() => {
                              setLoginExecutor(id);
                              setOpenMenu(null);
                            }}
                          >
                            Conectar
                          </button>
                        )}
                      </div>
                    ),
                  )}
                </div>
              )}
            </div>

            {/* Modelo — la lista depende del proveedor. */}
            <div className="composer-menu-wrap">
              <button
                type="button"
                className="composer-pick composer-pick--quiet"
                title={executor ? "Modelo del proveedor" : "Elige primero un ejecutor"}
                disabled={!executor}
                onClick={() => {
                  setModelDraft(effectiveModel);
                  setOpenMenu(openMenu === "model" ? null : "model");
                }}
              >
                modelo
              </button>
              {openMenu === "model" && (
                <div className="composer-popover">
                  <div className="composer-popover-title">
                    Modelo · {executorStatus?.name ?? executor}
                  </div>
                  {modelsLoading && <div className="composer-popover-note">cargando modelos…</div>}
                  {!modelsLoading && !modelEditable && (
                    <div className="composer-popover-note">
                      {providerModels?.note ?? "El modelo lo gestiona el CLI de este proveedor."}
                    </div>
                  )}
                  {!modelsLoading && modelEditable && (
                    <>
                      {providerModels?.note && (
                        <div className="composer-popover-note">{providerModels.note}</div>
                      )}
                      {executor !== "ollama" && (
                        <button
                          type="button"
                          className={`composer-popover-item${!configuredModel ? " is-active" : ""}`}
                          disabled={modelSaving}
                          onClick={() => void saveModel("")}
                        >
                          <span>Por defecto del CLI</span>
                          {!configuredModel && <span aria-hidden>✓</span>}
                        </button>
                      )}
                      {(providerModels?.models ?? []).map((m) => (
                        <button
                          key={m}
                          type="button"
                          className={`composer-popover-item${m === effectiveModel ? " is-active" : ""}`}
                          disabled={modelSaving}
                          onClick={() => void saveModel(m)}
                        >
                          <span>{m}</span>
                          {m === recommendedModel && (
                            <span className="composer-popover-tag">recomendado</span>
                          )}
                        </button>
                      ))}
                      {(providerModels?.allow_custom ?? true) && (
                        <div className="composer-popover-input">
                          <input
                            className="field-input field-input--sm"
                            value={modelDraft}
                            onChange={(e) => setModelDraft(e.target.value)}
                            placeholder={
                              executor === "ollama"
                                ? "otro modelo (p. ej. qwen2.5:7b-instruct)"
                                : "id de modelo (p. ej. opus, gpt-5.5)"
                            }
                            onKeyDown={(e) => {
                              if (e.key === "Enter") {
                                e.preventDefault();
                                void saveModel(modelDraft);
                              }
                            }}
                          />
                          <button
                            type="button"
                            className="link-action"
                            disabled={modelSaving || !modelDraft.trim()}
                            onClick={() => void saveModel(modelDraft)}
                          >
                            {modelSaving ? "…" : "OK"}
                          </button>
                        </div>
                      )}
                      <div className="composer-popover-note">
                        Se guarda como <code>{executor ? MODEL_CONFIG_KEY[executor] : ""}</code>.
                      </div>
                    </>
                  )}
                </div>
              )}
            </div>

            <span className="composer-tip">Enter envía · Shift+Enter salta línea</span>

            <button
              type="button"
              className="action-invert composer-send"
              onClick={() => void send()}
              disabled={sendDisabled}
            >
              {busy ? "Analizando…" : "Enviar"}
            </button>
          </div>

          <div className="quick-prompts">
            {QUICK_PROMPTS.map((q) => (
              <button
                key={q}
                type="button"
                className="quick-prompt"
                onClick={() => {
                  setInput(q);
                  inputRef.current?.focus();
                }}
              >
                {q}
              </button>
            ))}
          </div>
        </div>
      </div>

      {loginExecutor && (
        <ExecutorLoginModal
          executorId={loginExecutor}
          executorName={caps?.executors[loginExecutor]?.name ?? loginExecutor}
          open={loginExecutor !== null}
          onClose={() => setLoginExecutor(null)}
          onConnected={async () => {
            // Refresca capabilities y preselecciona el ejecutor recién conectado.
            if (onCapsRefresh) await onCapsRefresh();
            setExecutor(loginExecutor);
          }}
        />
      )}
    </div>
  );
}
