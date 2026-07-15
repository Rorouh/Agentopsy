import { useEffect, useMemo, useRef, useState } from "react";
import { ApiError, api } from "../api/client";
import type {
  AgentSummary,
  AnalysisEstimate,
  Capabilities,
  Case,
  EvidenceHandle,
  ExecutorId,
  ExecutorModels,
  ExecutorStatus,
  StreamEvent,
} from "../api/types";
import { Button } from "../ui/Button";
import { ExecutorLoginModal } from "../components/ExecutorLoginModal";

function renderBoldText(text: string) {
  // Simple regex to parse **bold** and `code`
  const parts = text.split(/(\*\*.*?\*\*|`.*?`)/g);
  return parts.map((part, i) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return (
        <strong key={i} style={{ fontWeight: 650, color: "var(--text-primary)" }}>
          {part.slice(2, -2)}
        </strong>
      );
    }
    if (part.startsWith("`") && part.endsWith("`")) {
      return (
        <code
          key={i}
          style={{
            fontFamily: "var(--font-mono)",
            background: "rgba(255, 255, 255, 0.08)",
            padding: "2px 5px",
            borderRadius: 4,
            fontSize: "0.9em",
          }}
        >
          {part.slice(1, -1)}
        </code>
      );
    }
    return part;
  });
}

function formatMessageContent(content: string) {
  const lines = content.split("\n");
  return lines.map((line, idx) => {
    const text = line.trim();
    if (text.startsWith("* ") || text.startsWith("- ")) {
      const inner = text.substring(2);
      return (
        <li key={idx} style={{ marginBottom: 4 }}>
          {renderBoldText(inner)}
        </li>
      );
    }
    const numMatch = text.match(/^(\d+)\.\s+(.*)/);
    if (numMatch) {
      return (
        <li key={idx} style={{ marginBottom: 4 }} value={parseInt(numMatch[1], 10)}>
          {renderBoldText(numMatch[2])}
        </li>
      );
    }
    if (text.startsWith("### ")) {
      return (
        <h4 key={idx} style={{ color: "var(--text-primary)", marginTop: 12, marginBottom: 6 }}>
          {renderBoldText(text.substring(4))}
        </h4>
      );
    }
    if (text.startsWith("## ")) {
      return (
        <h3
          key={idx}
          style={{
            color: "var(--text-primary)",
            marginTop: 14,
            marginBottom: 8,
            borderBottom: "1px solid var(--border)",
            paddingBottom: 4,
          }}
        >
          {renderBoldText(text.substring(3))}
        </h3>
      );
    }
    if (text.startsWith("# ")) {
      return (
        <h2 key={idx} style={{ color: "var(--text-primary)", marginTop: 16, marginBottom: 10 }}>
          {renderBoldText(text.substring(2))}
        </h2>
      );
    }
    if (text === "") return <div key={idx} style={{ height: 8 }} />;
    return (
      <p key={idx} style={{ margin: "0 0 10px 0" }}>
        {renderBoldText(line)}
      </p>
    );
  });
}

const QUICK_CHIPS = [
  { label: "Analizar evidencia", prefill: "Analiza el volcado " },
  { label: "Listar herramientas", prefill: "¿Qué herramientas tengo disponibles?" },
  { label: "Ver logs de auditoría", prefill: "¿Cómo funciona la cadena de custodia de los logs?" },
  { label: "Búsqueda forense", prefill: "Realiza una búsqueda forense de " },
];

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  pending?: boolean;
  // Progreso en vivo del agente (streaming): eventos acumulados + si sigue en curso.
  activity?: StreamEvent[];
  streaming?: boolean;
}

// Una línea del log de actividad (estilo Claude Code: árbol monoespaciado).
function ActivityLine({ ev }: { ev: StreamEvent }) {
  if (ev.type === "reasoning") {
    return <div className="al al-reason">· {ev.text}</div>;
  }
  if (ev.type === "tool_call") {
    const params = ev.params
      ? Object.entries(ev.params)
          .map(([k, v]) => `${k}=${String(v)}`)
          .join(" ")
      : "";
    const shown = params.length > 90 ? params.slice(0, 89) + "…" : params;
    return (
      <div className="al al-call">
        ▸ <strong>{ev.tool_id}</strong>
        {shown ? ` ${shown}` : ""}
      </div>
    );
  }
  if (ev.type === "tool_result") {
    const ok = ev.status === "ok";
    const cmd = ev.argv && ev.argv.length ? ev.argv.join(" ") : "";
    const shownCmd = cmd.length > 110 ? cmd.slice(0, 109) + "…" : cmd;
    return (
      <div className={`al ${ok ? "al-ok" : "al-err"}`}>
        {"  "}
        {ok ? "✓" : "✗"} {shownCmd && <code className="al-cmd">{shownCmd}</code>}{" "}
        {ev.summary ?? ev.status}
        {ev.status === "nonzero" && ev.exit_code != null ? ` (exit ${ev.exit_code})` : ""}
      </div>
    );
  }
  if (ev.type === "finding") {
    return (
      <div className="al al-find">
        {"  "}★ [{ev.severity}] {ev.title}
      </div>
    );
  }
  return null;
}

// Bloque de actividad del agente: cabecera con spinner mientras trabaja (● …),
// colapsable ("✓ N pasos") al terminar. Estilo Claude Code.
function AgentActivity({ activity, streaming }: { activity: StreamEvent[]; streaming: boolean }) {
  const lines = activity.map((ev, i) => <ActivityLine key={i} ev={ev} />);
  const steps = activity.filter((e) => e.type === "tool_call").length;

  if (streaming) {
    const last = activity[activity.length - 1];
    let status = "trabajando";
    if (last?.type === "tool_call") status = `ejecutando ${last.tool_id}`;
    else if (last?.type === "reasoning") status = "razonando";
    else if (last?.type === "tool_result") status = "procesando resultado";
    else if (last?.type === "finding") status = "registrando hallazgo";
    return (
      <div className="agent-activity">
        <div className="agent-activity-header live">
          <span className="agent-activity-dot" />
          {status}…
        </div>
        {lines.length > 0 && <div className="agent-activity-body">{lines}</div>}
      </div>
    );
  }
  if (!activity.length) return null;
  return (
    <details className="agent-activity">
      <summary className="agent-activity-header">
        ✓ {steps} paso{steps === 1 ? "" : "s"} · ver actividad
      </summary>
      <div className="agent-activity-body">{lines}</div>
    </details>
  );
}

// One session id per case is enough for v1 — múltiples investigaciones por caso
// se introducen cuando el flujo lo pida explícitamente.
const CHAT_SESSION_ID = "main";

// Config key que persiste el modelo elegido POR proveedor (espejo de
// backend/forensia/executors/__init__.py MODEL_CONFIG_KEY). Así FORENSIA recuerda
// el último modelo de cada ejecutor entre recargas.
const MODEL_CONFIG_KEY: Record<ExecutorId, string> = {
  "claude-code": "CLAUDE_CODE_MODEL",
  codex: "CODEX_MODEL",
  gemini: "GEMINI_MODEL",
  ollama: "OLLAMA_MODEL",
};

// Recordatorio UX de consentimientos ya registrados (la VERDAD está en el
// audit.jsonl del caso, donde /api/agent/cloud-consent lo apendó).
const consentStorageKey = (caseId: string, executor: string) =>
  `forensia-cloud-consent:${caseId}:${executor}`;

function hasStoredConsent(caseId: string, executor: string): boolean {
  try {
    return localStorage.getItem(consentStorageKey(caseId, executor)) === "1";
  } catch {
    return false;
  }
}

interface ChatPageProps {
  caps: Capabilities | null;
  // Optional case context. When provided, the chat anchors queries to the
  // case's os_profile (instead of the host's) and to the registered evidence's
  // evidence_id (instead of an empty string). When absent, falls back to the
  // legacy behaviour for backward compat with any standalone use of ChatPage.
  activeCase?: Case | null;
  activeEvidence?: EvidenceHandle | null;
  // Called whenever a query() finishes (success or error) so the surrounding
  // page (Investigation) can refresh side-channel state like findings.
  onTurnComplete?: () => void;
  // Refresca capabilities en App tras conectar un ejecutor CLI desde el selector.
  onCapsRefresh?: () => Promise<void> | void;
}

export function ChatPage({
  caps,
  activeCase,
  activeEvidence,
  onTurnComplete,
  onCapsRefresh,
}: ChatPageProps) {
  const [msgs, setMsgs] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);

  // Ejecutor elegido por el operador para esta sesión. Se preselecciona con
  // DEFAULT_EXECUTOR solo si el usuario lo fijó EXPLÍCITAMENTE en Settings
  // (agencia del operador — RULE 2); nunca se inventa uno.
  const [executor, setExecutor] = useState<ExecutorId | "">("");
  const [consents, setConsents] = useState<Record<string, boolean>>({});
  const [consentBusy, setConsentBusy] = useState(false);
  const [consentError, setConsentError] = useState<string | null>(null);

  // Composer option menus (proveedor / modelo) y el modelo elegido para Ollama.
  const [openMenu, setOpenMenu] = useState<null | "provider" | "model">(null);
  // Ejecutor cloud no disponible cuyo modal de login web está abierto.
  const [loginExecutor, setLoginExecutor] = useState<ExecutorId | null>(null);
  // Modelo elegido por proveedor (persistido en config; recuerda el último).
  const [modelByProvider, setModelByProvider] = useState<Partial<Record<ExecutorId, string>>>({});
  const [modelDraft, setModelDraft] = useState<string>("");
  const [modelSaving, setModelSaving] = useState(false);
  // Modelos que ofrece el ejecutor elegido (Ollama: lista real; cloud: nota).
  const [providerModels, setProviderModels] = useState<ExecutorModels | null>(null);
  const [modelsLoading, setModelsLoading] = useState(false);

  // Estimación PRE-VUELO del análisis (hallazgo E): rangos honestos de
  // iteraciones/tokens/coste/tiempo con supuestos declarados, ANTES de lanzar.
  const [estimate, setEstimate] = useState<AnalysisEstimate | null>(null);
  const [estimateError, setEstimateError] = useState<string | null>(null);

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

  // Estimación pre-vuelo: al elegir caso + ejecutor (y opcionalmente evidencia)
  // pedimos el rango honesto de tokens/coste/tiempo para avisar ANTES de lanzar.
  useEffect(() => {
    if (!activeCase || !executor) {
      setEstimate(null);
      setEstimateError(null);
      return;
    }
    let alive = true;
    setEstimateError(null);
    api
      .analyzeEstimate(activeCase.id, executor as ExecutorId, activeEvidence?.evidence_id)
      .then((e) => {
        if (alive) setEstimate(e);
      })
      .catch((err) => {
        if (!alive) return;
        setEstimate(null);
        setEstimateError(
          err instanceof ApiError ? err.detail : "No se pudo estimar el coste.",
        );
      });
    return () => {
      alive = false;
    };
  }, [activeCase?.id, executor, activeEvidence?.evidence_id]);

  // Cerrar el menú abierto al hacer clic fuera del grupo de acciones.
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

  // Persist the operator's model choice for the CURRENT provider. An empty value
  // clears it (cloud → CLI default; Ollama → package model) — RULE 2: FORENSIA
  // never invents one. The backend accepts "" as an unset for the model keys.
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

  // Al elegir proveedor lo recordamos como DEFAULT_EXECUTOR (agencia del operador
  // — no un default inventado; RULE 2). Best-effort: si falla, la selección de la
  // sesión sigue viva aunque no se persista.
  const selectExecutor = (id: ExecutorId) => {
    setExecutor(id);
    setOpenMenu(null);
    api.config.set("DEFAULT_EXECUTOR", id).catch(() => {
      /* persistencia best-effort */
    });
  };

  // Source of truth for the agent selection: the CASE's os_profile, not the
  // host's. Only when no case is open we fall back to host detection. RULE 2 in
  // the backend: /api/agent/query returns 503 if there is no package for the
  // requested profile — we surface that explicitly instead of inventing a default.
  // `null` means the orchestrator hasn't derived it yet (no routable evidence
  // registered on the case) — not an error, just "not yet".
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
  const isCloud = executorStatus !== null && !executorStatus.local;
  const consentGiven =
    !isCloud ||
    !activeCase ||
    !executor ||
    consents[consentStorageKey(activeCase.id, executor)] === true ||
    hasStoredConsent(activeCase.id, executor);
  // Con caso + ejecutor cloud, el envío queda bloqueado hasta que el operador
  // confirme el aviso (el consentimiento se registra en el audit del caso).
  const sendBlockedByConsent = isCloud && !!activeCase && !consentGiven;

  const acceptCloudConsent = async () => {
    if (!activeCase || !executor) return;
    setConsentBusy(true);
    setConsentError(null);
    try {
      await api.consentCloud(activeCase.id, executor as ExecutorId);
      try {
        localStorage.setItem(consentStorageKey(activeCase.id, executor), "1");
      } catch {
        /* el registro real ya está en el audit */
      }
      setConsents((prev) => ({ ...prev, [consentStorageKey(activeCase.id, executor)]: true }));
    } catch (err) {
      setConsentError(
        err instanceof ApiError ? err.detail : String(err instanceof Error ? err.message : err)
      );
    } finally {
      setConsentBusy(false);
    }
  };

  // Auto-scroll chat to bottom
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [msgs]);

  // Load persisted chat history when the active case changes. A 404 (no session
  // file yet) means "fresh conversation" — not an error to surface.
  // Sondeo del análisis en segundo plano. `pollRef` marca el sondeo activo para
  // cancelarlo al desmontar / cambiar de caso sin tocar estado de un componente ido.
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

  // Engancha a un análisis en segundo plano (nuevo o reanudado) y SONDEA su
  // estado hasta terminar, pintando el progreso (segundos · nº de hallazgos que
  // se van registrando en caliente). Si el cliente se fue, el job siguió vivo en
  // el servidor y esto vuelve a engancharse; una desconexión no lo aborta.
  const pushActivity = (ev: StreamEvent) =>
    setMsgs((prev) => {
      if (prev.length === 0) return prev;
      const next = [...prev];
      const last = next[next.length - 1];
      next[next.length - 1] = { ...last, activity: [...(last.activity ?? []), ev] };
      return next;
    });

  const drivePoll = async (caseId: string, jobId: string) => {
    const token = { cancelled: false };
    pollRef.current = token;
    setBusy(true);
    let reply = "";
    let tools: unknown[] | null = null;
    let cursor = 0; // eventos de progreso ya pintados en el chat
    const collected: StreamEvent[] = []; // para persistir la traza con el mensaje
    const startedAt = Date.now();
    // Mantén la cabecera "en vivo" y muestra el feed de actividad (comando +
    // hallazgo) según llegan, aunque sondeemos en vez de recibir un stream.
    patchLast({ streaming: true });
    try {
      while (!token.cancelled) {
        const job = await api.getJob(jobId, cursor);
        // Pinta los eventos NUEVOS (tool_call con argv, tool_result, finding…).
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
          // Persistir la traza de actividad para re-pintar "✓ N pasos" al recargar.
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
        const restored: ChatMessage[] = history
          .filter((m) => m.role === "user" || m.role === "assistant")
          .map((m) => ({
            role: m.role as "user" | "assistant",
            content: m.content,
            // Re-pinta el bloque colapsable de actividad si se persistió.
            activity: m.activity ?? undefined,
          }));
        setMsgs(restored);
      })
      .catch(() => {
        // No prior session yet — start empty.
        if (!cancelled) setMsgs([]);
      })
      .finally(async () => {
        // Robustez: si quedó un análisis corriendo en segundo plano (el perito
        // cerró la pestaña y volvió), reengánchate a él y muestra su progreso.
        if (cancelled || pollRef.current) return;
        try {
          const jobs = await api.listCaseJobs(caseId);
          const running = jobs.find((j) => j.status === "running");
          if (running && !cancelled && !pollRef.current) {
            setMsgs((prev) => [
              ...prev,
              { role: "assistant", content: "Reanudando análisis en curso…", pending: true, streaming: false, activity: [] },
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
    if (!text || busy || sendBlockedByConsent || !activeCase) return;
    const caseId = activeCase.id;
    setInput("");
    setBusy(true);
    setMsgs((prev) => [...prev, { role: "user", content: text }]);
    setMsgs((prev) => [
      ...prev,
      { role: "assistant", content: "Lanzando análisis en segundo plano…", pending: true, streaming: false, activity: [] },
    ]);

    // Persist user turn upfront so a disconnect doesn't erase what the analyst
    // asked. La asistente se persiste al terminar el job (en drivePoll).
    api.cases
      .appendChat(caseId, CHAT_SESSION_ID, { role: "user", content: text })
      .catch(() => {
        /* persistence best-effort; UI state stays */
      });

    try {
      // Arranca el análisis en SEGUNDO PLANO: la petición vuelve al instante con
      // un job_id; el análisis sigue en el servidor aunque el cliente se
      // desconecte (RULE: robustez para evidencia grande). `drivePoll` sondea.
      const { job_id } = await api.analyze({
        prompt: text,
        // El backend resuelve el os_profile del caso; esta clave se ignora si
        // se manda. activeProfile puede ser null (SO aún sin determinar).
        evidence_id: activeEvidence?.evidence_id ?? "",
        case_id: caseId,
        executor: executor || undefined,
        session_id: CHAT_SESSION_ID,
      });
      await drivePoll(caseId, job_id);
    } catch (e) {
      // Falló el ARRANQUE (validación: ejecutor/evidencia/consentimiento). El
      // backend responde con detail accionable (RULE 2); se muestra tal cual.
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
      send();
    }
  };

  const handleChipClick = (prefill: string) => {
    setInput(prefill);
    inputRef.current?.focus();
  };

  // Selector de ejecutor: los cuatro del pivote, visibles siempre en la sesión.
  // Los no disponibles se deshabilitan y el tooltip lleva la razón accionable
  // que reporta capabilities (RULE 2: degradación explícita, nunca sustituto).

  const cloudNotice = isCloud && (
    <div
      className="profile-mismatch-banner"
      style={{ marginBottom: 8 }}
    >
      <span className="profile-mismatch-banner-icon" aria-hidden="true">⚠</span>
      <div className="profile-mismatch-banner-body">
        <div className="profile-mismatch-banner-title">
          Ejecutor cloud: {executorStatus?.name} — el contenido derivado del caso saldrá al proveedor
        </div>
        <div>
          Los prompts incluyen contenido derivado de la evidencia (que puede contener
          datos personales reales → RGPD) y se envían bajo tu propia suscripción.
          La alternativa 100 % local es <code>ollama</code>.
          {activeCase ? (
            consentGiven ? (
              <> Consentimiento registrado en el audit de <strong>{activeCase.name}</strong>.</>
            ) : (
              <>
                {" "}
                <Button
                  variant="chip"
                  disabled={consentBusy}
                  onClick={acceptCloudConsent}
                  style={{ marginTop: 6 }}
                >
                  {consentBusy
                    ? "Registrando…"
                    : "Acepto — registrar consentimiento en el audit del caso"}
                </Button>
              </>
            )
          ) : (
            <> Abre un caso para registrar el consentimiento y poder consultar.</>
          )}
          {consentError && (
            <div style={{ marginTop: 6 }}>
              <strong>No se pudo registrar:</strong> {consentError}
            </div>
          )}
        </div>
      </div>
    </div>
  );

  // Aviso PRE-VUELO (hallazgo E): rango orientativo de tokens/coste/tiempo con
  // supuestos declarados, para que el operador sepa a qué se compromete ANTES de
  // lanzar. No es un presupuesto; el envío sigue siendo la confirmación (y para
  // cloud, además, el consentimiento de arriba).
  const fmtTime = (s: number) =>
    s < 90 ? `${s} s` : `${Math.round(s / 60)} min`;
  const costText = estimate
    ? !estimate.cost_usd.available
      ? "no disponible"
      : estimate.cost_usd.tariff === null
        ? estimate.cost_usd.label ?? "0 USD"
        : `${estimate.cost_usd.min?.toFixed(4)}–${estimate.cost_usd.max?.toFixed(4)} USD`
    : "";
  const estimateNotice = estimate && (
    <div className="profile-mismatch-banner" style={{ marginBottom: 8 }}>
      <span className="profile-mismatch-banner-icon" aria-hidden="true">≈</span>
      <div className="profile-mismatch-banner-body">
        <div className="profile-mismatch-banner-title">
          Estimación previa · {estimate.executor.name}
          {estimate.evidence_size_human
            ? ` · evidencia ${estimate.evidence_size_human}`
            : ""}
        </div>
        <div>
          <strong>Iteraciones</strong> {estimate.iterations.min}–
          {estimate.iterations.max} · <strong>Tokens</strong>{" "}
          {estimate.tokens.min.toLocaleString()}–
          {estimate.tokens.max.toLocaleString()} · <strong>Tiempo</strong>{" "}
          {fmtTime(estimate.time_seconds.min)}–{fmtTime(estimate.time_seconds.max)} ·{" "}
          <strong>Coste</strong> {costText}
          <div style={{ marginTop: 4, opacity: 0.8 }}>
            Base: {estimate.basis}
            {estimate.cost_usd.tariff
              ? ` Tarifa: ${estimate.cost_usd.tariff.source}`
              : ""}
          </div>
          {estimate.cost_usd.note && (
            <div style={{ marginTop: 4 }}>{estimate.cost_usd.note}</div>
          )}
          <div style={{ marginTop: 4, opacity: 0.8 }}>{estimate.disclaimer}</div>
        </div>
      </div>
    </div>
  );
  const estimateErrorNotice = estimateError && (
    <div className="profile-mismatch-banner" style={{ marginBottom: 8 }}>
      <span className="profile-mismatch-banner-icon" aria-hidden="true">⚠</span>
      <div className="profile-mismatch-banner-body">
        <div className="profile-mismatch-banner-title">
          No se pudo estimar el coste
        </div>
        <div>{estimateError}</div>
      </div>
    </div>
  );

  const sendDisabled = !input.trim() || busy || sendBlockedByConsent;
  const sendTitle = sendBlockedByConsent
    ? "Confirma el aviso del ejecutor cloud para poder enviar"
    : undefined;

  const providerLabel = executor ? executorStatus?.name ?? executor : "Proveedor";
  // El modelo recomendado del paquete solo aplica a Ollama (modelo local).
  const recommendedModel = activeAgent?.model.name ?? "";
  const configuredModel = executor ? modelByProvider[executor] ?? "" : "";
  const effectiveModel = configuredModel || (executor === "ollama" ? recommendedModel : "");
  const modelEditable = providerModels?.editable ?? false;
  const modelLabel = !executor
    ? "Modelo"
    : effectiveModel || (executor === "ollama" ? "Modelo" : "por defecto");

  const composerFooter = (
    <div className="composer-footer">
      <div className="composer-left">
        {/* Adjuntar evidencia — maqueta (aún sin funcionalidad) */}
        <button
          type="button"
          className="composer-opt composer-opt--icon"
          title="Adjuntar evidencia (próximamente)"
          aria-label="Adjuntar evidencia"
          onClick={() => {
            /* mock: pendiente de cablear la subida/selección de evidencia */
          }}
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48" />
          </svg>
        </button>
        <span className="composer-tip">Enter para enviar · Shift+Enter para nueva línea</span>
      </div>

      <div className="composer-actions" ref={actionsRef}>
        {/* Proveedor (ejecutor) — funcional */}
        <div className="composer-opt-wrap">
          <button
            type="button"
            className={`composer-opt${openMenu === "provider" ? " active" : ""}`}
            title="Proveedor de ejecución"
            onClick={() => setOpenMenu(openMenu === "provider" ? null : "provider")}
          >
            <span className="composer-opt-label">
              {providerLabel}
              {executorStatus?.local ? " ⌂" : ""}
            </span>
            <span className="composer-opt-caret">▾</span>
          </button>
          {openMenu === "provider" && (
            <div className="composer-popover">
              <div className="composer-popover-title">Proveedor</div>
              {executorEntries.length === 0 && (
                <div className="composer-popover-note">consultando capacidades…</div>
              )}
              {executorEntries.map(([id, status]) =>
                status.available ? (
                  <button
                    key={id}
                    type="button"
                    className={`composer-popover-item${id === executor ? " active" : ""}`}
                    onClick={() => selectExecutor(id)}
                  >
                    <span>
                      {status.name}
                      {status.local ? " ⌂" : ""}
                    </span>
                    {id === executor && <span aria-hidden>✓</span>}
                  </button>
                ) : (
                  // No disponible. Los CLI cloud (no locales) ofrecen conectar
                  // desde aquí (login web); Ollama (local) solo muestra la razón.
                  <div
                    key={id}
                    className="composer-popover-item disabled"
                    title={status.reason ?? "No disponible"}
                  >
                    <span>
                      {status.name}
                      {status.local ? " ⌂" : ""} — no disponible
                    </span>
                    {!status.local && (
                      <button
                        type="button"
                        className="chip"
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

        {/* Modelo — funcional; la lista depende del proveedor */}
        <div className="composer-opt-wrap">
          <button
            type="button"
            className={`composer-opt${openMenu === "model" ? " active" : ""}`}
            title={executor ? "Modelo del proveedor" : "Elige primero un proveedor"}
            disabled={!executor}
            onClick={() => {
              setModelDraft(effectiveModel);
              setOpenMenu(openMenu === "model" ? null : "model");
            }}
          >
            <span className="composer-opt-label">{modelLabel}</span>
            <span className="composer-opt-caret">▾</span>
          </button>
          {openMenu === "model" && (
            <div className="composer-popover">
              <div className="composer-popover-title">
                Modelo · {executorStatus?.name ?? executor}
              </div>
              {modelsLoading && <div className="composer-popover-note">cargando modelos…</div>}
              {!modelsLoading && !modelEditable && (
                <div className="composer-popover-note">
                  {providerModels?.note ??
                    "El modelo lo gestiona el CLI de este proveedor."}
                </div>
              )}
              {!modelsLoading && modelEditable && (
                <>
                  {/* Nota del backend: para Ollama solo si no hay modelos; para
                      los CLIs cloud explica que la lista son atajos + texto libre. */}
                  {providerModels?.note && (
                    <div className="composer-popover-note">{providerModels.note}</div>
                  )}
                  {executor !== "ollama" &&
                    (providerModels?.models ?? []).length === 0 &&
                    !providerModels?.note && (
                      <div className="composer-popover-note">
                        Escribe el id del modelo abajo.
                      </div>
                    )}
                  {/* Cloud: volver al modelo por defecto del CLI (limpia la clave). */}
                  {executor !== "ollama" && (
                    <button
                      type="button"
                      className={`composer-popover-item${!configuredModel ? " active" : ""}`}
                      disabled={modelSaving}
                      onClick={() => saveModel("")}
                    >
                      <span>Por defecto del CLI</span>
                      {!configuredModel && <span aria-hidden>✓</span>}
                    </button>
                  )}
                  {(providerModels?.models ?? []).map((m) => (
                    <button
                      key={m}
                      type="button"
                      className={`composer-popover-item${m === effectiveModel ? " active" : ""}`}
                      disabled={modelSaving}
                      onClick={() => saveModel(m)}
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
                            saveModel(modelDraft);
                          }
                        }}
                      />
                      <Button
                        variant="chip"
                        disabled={modelSaving || !modelDraft.trim()}
                        onClick={() => saveModel(modelDraft)}
                      >
                        {modelSaving ? "…" : "OK"}
                      </Button>
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

        {/* Enviar */}
        <Button variant="icon" onClick={send} disabled={sendDisabled} title={sendTitle}>
          <svg
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <line x1="22" y1="2" x2="11" y2="13" />
            <polygon points="22 2 15 22 11 13 2 9 22 2" />
          </svg>
        </Button>
      </div>
    </div>
  );

  return (
    <div className="chat-container">
      {msgs.length === 0 ? (
        // Welcome / empty state
        <div className="chat-welcome">
          <div className="welcome-title">¿Qué analizamos hoy?</div>

          <div className="agent-badge" title={activeAgent?.path ?? ""}>
            {activeAgent ? (
              <>
                <span className="agent-badge-dot agent-badge-dot--ok" />
                Agente activo: <strong>{activeAgent.name}</strong>{" "}
                <span className="agent-badge-meta">
                  v{activeAgent.version} · {activeAgent.os_profile} · modelo local
                  recomendado: {activeAgent.model.name}
                </span>
              </>
            ) : activeProfile === null ? (
              <>
                <span className="agent-badge-dot agent-badge-dot--warn" />
                El sistema operativo de este caso aún no está determinado —
                regístrale una evidencia para que el orquestador lo derive.
              </>
            ) : (
              <>
                <span className="agent-badge-dot agent-badge-dot--warn" />
                Sin agente para perfil <code>{activeProfile}</code>. Suelta su
                carpeta en <code>agentes/</code> y reinicia FORENSIA.
              </>
            )}
          </div>

          {/* Composer inside welcome */}
          <div className="composer-wrapper" style={{ width: "100%" }}>
            {cloudNotice}
            {estimateNotice}
            {estimateErrorNotice}
            <div className="composer">
              <textarea
                ref={inputRef}
                className="composer-textarea"
                placeholder="Escribe una consulta sobre el caso"
                rows={1}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
              />
              {composerFooter}
            </div>
          </div>

          <div className="quick-chips">
            {QUICK_CHIPS.map((chip, i) => (
              <Button
                key={i}
                variant="chip"
                onClick={() => handleChipClick(chip.prefill)}
              >
                {chip.label}
              </Button>
            ))}
          </div>
        </div>
      ) : (
        // Conversation Flow
        <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
          <div className="chat-messages" ref={logRef}>
            {msgs.map((msg, i) => (
              <div key={i} className={`msg-wrapper ${msg.role}`}>
                {msg.role === "assistant" ? (
                  <div>
                    {(msg.activity?.length || msg.streaming) && (
                      <AgentActivity activity={msg.activity ?? []} streaming={!!msg.streaming} />
                    )}
                    {msg.content && (
                      <div style={{ opacity: msg.pending ? 0.6 : 1 }}>
                        {formatMessageContent(msg.content)}
                      </div>
                    )}
                  </div>
                ) : (
                  <span>{msg.content}</span>
                )}
              </div>
            ))}
          </div>

          <div className="composer-wrapper">
            {cloudNotice}
            {estimateNotice}
            {estimateErrorNotice}
            <div className="composer">
              <textarea
                ref={inputRef}
                className="composer-textarea"
                placeholder="Escribe una consulta sobre el caso"
                rows={1}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
              />
              {composerFooter}
            </div>
          </div>
        </div>
      )}

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
