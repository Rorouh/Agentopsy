import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
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
import { Icon } from "../ui/Icon";

// Markdown mínimo del turno del agente. SEC INV 8: se pinta como TEXTO, en
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

// ── Bloques ────────────────────────────────────────────────────────────────
// El agente responde en markdown: las correlaciones ATT&CK y los inventarios de
// artefactos llegan SIEMPRE como tabla, y una tabla en crudo (`| a | b |` línea
// a línea) es ilegible para el perito. El parser va por bloques, no por líneas:
// una tabla, una lista o un bloque de código son una unidad.

const isTableRow = (s: string) => s.startsWith("|") && s.endsWith("|") && s.length > 2;
// La fila de guiones es lo que CONVIERTE un bloque de pipes en tabla; sin ella
// son párrafos que casualmente llevan pipes y se pintan como tales.
const isTableDivider = (s: string) => isTableRow(s) && /^\|[\s:|-]*-[\s:|-]*\|$/.test(s);

// `| a | b |` → ["a", "b"]. Los pipes de los extremos no son celdas.
const splitRow = (s: string) => s.slice(1, -1).split("|").map((c) => c.trim());

type CellAlign = "left" | "center" | "right";
const alignOf = (spec: string): CellAlign => {
  const left = spec.startsWith(":");
  const right = spec.endsWith(":");
  return left && right ? "center" : right ? "right" : "left";
};

const BULLET = /^[*-]\s+(.*)/;
const NUMBERED = /^(\d+)[.)]\s+(.*)/;
const HEADING = /^(#{1,6})\s+(.*)/;
const RULE = /^(-{3,}|_{3,}|\*{3,})$/;

function formatMessageContent(content: string) {
  const lines = content.split("\n");
  const out: ReactNode[] = [];
  let i = 0;

  while (i < lines.length) {
    const text = lines[i].trim();

    // Bloque de código cercado. Se conserva la indentación literal: suele ser
    // salida de herramienta, y ahí un espacio significa algo.
    if (text.startsWith("```")) {
      const body: string[] = [];
      i += 1;
      while (i < lines.length && !lines[i].trim().startsWith("```")) {
        body.push(lines[i]);
        i += 1;
      }
      i += 1; // el cierre (o el fin del texto, si el turno se cortó)
      out.push(
        <pre className="turn-code" key={out.length}>
          {body.join("\n")}
        </pre>,
      );
      continue;
    }

    // Tabla: cabecera + fila de guiones + cuerpo hasta la primera línea que ya
    // no es fila.
    if (isTableRow(text) && i + 1 < lines.length && isTableDivider(lines[i + 1].trim())) {
      const head = splitRow(text);
      const aligns = splitRow(lines[i + 1].trim()).map(alignOf);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && isTableRow(lines[i].trim())) {
        rows.push(splitRow(lines[i].trim()));
        i += 1;
      }
      out.push(
        <div className="turn-table-wrap" key={out.length}>
          <table className="turn-table">
            <thead>
              <tr>
                {head.map((c, k) => (
                  <th key={k} style={{ textAlign: aligns[k] ?? "left" }}>
                    {renderInline(c)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, k) => (
                <tr key={k}>
                  {/* Se recorre la CABECERA, no la fila: una fila corta deja
                      celdas vacías en su sitio en vez de descuadrar la tabla. */}
                  {head.map((_, c) => (
                    <td key={c} style={{ textAlign: aligns[c] ?? "left" }}>
                      {renderInline(r[c] ?? "")}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>,
      );
      continue;
    }

    // Lista: se agrupan las líneas consecutivas en UN <ul>/<ol>, que es lo que
    // les da sangría y marcador de verdad.
    if (BULLET.test(text) || NUMBERED.test(text)) {
      const ordered = NUMBERED.test(text);
      const items: { value?: number; text: string }[] = [];
      while (i < lines.length) {
        const t = lines[i].trim();
        const num = NUMBERED.exec(t);
        const bullet = BULLET.exec(t);
        if (ordered && num) items.push({ value: parseInt(num[1], 10), text: num[2] });
        else if (!ordered && bullet) items.push({ text: bullet[1] });
        else break;
        i += 1;
      }
      const children = items.map((it, k) => (
        <li key={k} value={it.value}>
          {renderInline(it.text)}
        </li>
      ));
      out.push(
        ordered ? (
          <ol className="turn-list" key={out.length}>
            {children}
          </ol>
        ) : (
          <ul className="turn-list" key={out.length}>
            {children}
          </ul>
        ),
      );
      continue;
    }

    const heading = HEADING.exec(text);
    if (heading) {
      const Tag = heading[1].length <= 2 ? "h3" : "h4";
      out.push(<Tag key={out.length}>{renderInline(heading[2])}</Tag>);
      i += 1;
      continue;
    }

    if (RULE.test(text)) {
      out.push(<hr className="turn-hr" key={out.length} />);
      i += 1;
      continue;
    }

    if (text === "") {
      out.push(<div className="turn-gap" key={out.length} />);
      i += 1;
      continue;
    }

    out.push(<p key={out.length}>{renderInline(text)}</p>);
    i += 1;
  }

  return out;
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
  // `created_at` del JOB en el servidor (ISO). Es el ancla del cronómetro: el
  // tiempo transcurrido se mide contra el arranque REAL del análisis, no contra
  // el momento en que este cliente empezó a sondear. Por eso el contador
  // sobrevive a cambiar de sección, recargar la pestaña o reengancharse a un
  // análisis que ya venía corriendo.
  jobStartedAt?: string;
}

function clockOf(at: string | undefined): string {
  if (!at) return "";
  const d = new Date(at);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString("es-ES", { hour12: false });
}

function formatElapsed(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  if (m < 60) return `${m}m ${String(s).padStart(2, "0")}s`;
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m`;
}

// Cronómetro del análisis en curso. Cuenta desde `since` (el `created_at` del
// job en el servidor), así que dar un rodeo por ATT&CK y volver no lo reinicia:
// el ancla vive en el backend, no en el montaje de este componente.
function ElapsedSince({ since }: { since: string }) {
  const startedAt = Date.parse(since);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, []);

  // Sin ancla parseable no inventamos un cero que parecería «acaba de empezar»
  // (RULE 2: nada de valores fabricados), simplemente no se pinta el contador.
  if (Number.isNaN(startedAt)) return null;
  const seconds = Math.max(0, Math.round((now - startedAt) / 1000));
  return <span className="turn-elapsed">{formatElapsed(seconds)}</span>;
}

// Bloque «Cadena de ejecución»: lo que el agente EJECUTÓ, con el argv literal.
// No es la intención declarada por el LLM, es el comando que corrió y quedó en
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
                {" · "}
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

// One session id per case is enough for v1, múltiples investigaciones por caso
// se introducen cuando el flujo lo pida explícitamente.
const CHAT_SESSION_ID = "main";

// Alto máximo del compositor, en LÍNEAS. Un prompt forense real es largo (una
// lista de artefactos a correlacionar, un fragmento de log pegado): la caja
// crece con el texto hasta aquí y a partir de ahí scrollea por dentro, para no
// comerse la transcripción. Espejo de `max-height` en `.composer-input`.
const COMPOSER_MAX_ROWS = 10;

// Margen (px) por debajo del final de la transcripción dentro del cual se
// considera que el perito «está al final» y el scroll sigue pegado. Más que
// un par de píxeles porque el navegador redondea y porque un turno recién
// pintado puede desplazar el fondo un poco.
const STICK_TO_BOTTOM_PX = 72;

// Config key que persiste el modelo elegido POR proveedor (espejo de
// backend/forensia/executors/__init__.py MODEL_CONFIG_KEY).
const MODEL_CONFIG_KEY: Record<ExecutorId, string> = {
  "claude-code": "CLAUDE_CODE_MODEL",
  codex: "CODEX_MODEL",
  gemini: "GEMINI_MODEL",
  ollama: "OLLAMA_MODEL",
};

// Config key que persiste la POTENCIA (nivel de razonamiento) por proveedor
// (espejo de backend/forensia/executors/__init__.py REASONING_CONFIG_KEY). Solo
// aparece el ejecutor cuyo nivel se ha verificado contra su binario real; un
// proveedor ausente no lleva nivel y lo decide su CLI (RULE 2).
const REASONING_CONFIG_KEY: Partial<Record<ExecutorId, string>> = {
  codex: "CODEX_REASONING_EFFORT",
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
  // DEFAULT_EXECUTOR solo si el usuario lo fijó EXPLÍCITAMENTE en Configuración
  // (agencia del operador, RULE 2); nunca se inventa uno. El vacío inicial es
  // deliberado: no es un hueco que haya que "arreglar" con un ?? "ollama".
  const [executor, setExecutor] = useState<ExecutorId | "">("");

  const [openMenu, setOpenMenu] = useState<null | "provider" | "model">(null);
  const [loginExecutor, setLoginExecutor] = useState<ExecutorId | null>(null);
  const [modelByProvider, setModelByProvider] = useState<Partial<Record<ExecutorId, string>>>({});
  // Potencia (nivel de razonamiento) elegida, por proveedor. Solo la tienen los
  // que declaran clave en el backend; el resto ni pinta el selector.
  const [effortByProvider, setEffortByProvider] = useState<Partial<Record<ExecutorId, string>>>({});
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
        // Y la última potencia elegida de los que la tienen.
        const efforts: Partial<Record<ExecutorId, string>> = {};
        (Object.keys(REASONING_CONFIG_KEY) as ExecutorId[]).forEach((id) => {
          const key = REASONING_CONFIG_KEY[id];
          const eff = key ? snap.keys[key] : undefined;
          if (eff?.set && eff.preview) efforts[id] = eff.preview;
        });
        setEffortByProvider(efforts);
      })
      .catch(() => {
        /* sin config aún, el operador elige a mano */
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
  // limpia (cloud → por defecto del CLI; Ollama → modelo del paquete), RULE 2:
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

  // Persiste la POTENCIA del proveedor actual. Vacío = la que tenga configurada
  // su CLI. El menú NO se cierra: la potencia se suele ajustar justo después de
  // cambiar de modelo, y cerrar obligaría a reabrir para verlo aplicado.
  const saveEffort = async (value: string) => {
    if (!executor) return;
    const key = REASONING_CONFIG_KEY[executor];
    if (!key) return;
    const v = value.trim();
    setModelSaving(true);
    try {
      await api.config.set(key, v);
      setEffortByProvider((prev) => {
        const next = { ...prev };
        if (v) next[executor] = v;
        else delete next[executor];
        return next;
      });
    } catch {
      /* el backend degrada (nivel desconocido); se deja el menú abierto */
    } finally {
      setModelSaving(false);
    }
  };

  // Al elegir proveedor lo recordamos como DEFAULT_EXECUTOR (agencia del
  // operador, no un default inventado; RULE 2).
  const selectExecutor = (id: ExecutorId) => {
    setExecutor(id);
    setOpenMenu(null);
    api.config.set("DEFAULT_EXECUTOR", id).catch(() => {
      /* persistencia best-effort */
    });
  };

  // Fuente de verdad de la selección de agente: el os_profile del CASO, no el
  // del host. `null` = el orquestador aún no lo ha derivado, no es un error.
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

  // ── Compositor autoexpandible ─────────────────────────────────────────────
  // El alto se recalcula en cada cambio del texto: primero `auto`, para que
  // `scrollHeight` mida el contenido REAL (sin eso la caja nunca decrece al
  // borrar), y luego se topa en COMPOSER_MAX_ROWS líneas. El tope se mide con
  // la línea de texto EFECTIVA del elemento, no con un px fijo: así sigue
  // siendo 10 líneas si cambia la tipografía o el tema.
  useLayoutEffect(() => {
    const el = inputRef.current;
    if (!el) return;
    el.style.height = "auto";
    const cs = window.getComputedStyle(el);
    const lineHeight = parseFloat(cs.lineHeight) || parseFloat(cs.fontSize) * 1.6;
    const padding = parseFloat(cs.paddingTop) + parseFloat(cs.paddingBottom);
    const border = parseFloat(cs.borderTopWidth) + parseFloat(cs.borderBottomWidth);
    // `scrollHeight` de una caja border-box incluye el padding pero no el
    // borde; el alto que fijamos sí incluye ambos.
    const maxScroll = lineHeight * COMPOSER_MAX_ROWS + padding;
    const overflows = el.scrollHeight > Math.ceil(maxScroll);
    el.style.height = `${Math.min(el.scrollHeight, maxScroll) + border}px`;
    el.style.overflowY = overflows ? "auto" : "hidden";
  }, [input]);

  // ── Scroll de la transcripción ────────────────────────────────────────────
  // El auto-scroll está PEGADO al final sólo mientras el perito esté al final.
  // En cuanto sube a releer (típico: releer el argv de un `fls` mientras el
  // agente sigue trabajando) se despega y NADA lo vuelve a bajar hasta que él
  // vuelva al final o pulse «bajar al final». Antes se forzaba el fondo en cada
  // repintado de `msgs`, y como el turno en curso se repinta cada 2.5s era
  // imposible leer hacia arriba durante una ejecución.
  const stickToBottomRef = useRef(true);
  const [atBottom, setAtBottom] = useState(true);

  const isNearBottom = (el: HTMLDivElement) =>
    el.scrollHeight - el.scrollTop - el.clientHeight <= STICK_TO_BOTTOM_PX;

  const onTranscriptScroll = useCallback(() => {
    const el = logRef.current;
    if (!el) return;
    const near = isNearBottom(el);
    stickToBottomRef.current = near;
    setAtBottom(near);
  }, []);

  const scrollToBottom = useCallback(() => {
    const el = logRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
    stickToBottomRef.current = true;
    setAtBottom(true);
  }, []);

  useLayoutEffect(() => {
    const el = logRef.current;
    if (!el || !stickToBottomRef.current) return;
    el.scrollTop = el.scrollHeight;
  }, [msgs]);

  // Al cambiar de caso la conversación es otra: se vuelve a empezar por el
  // final, que es donde el perito lo dejó.
  useEffect(() => {
    stickToBottomRef.current = true;
    setAtBottom(true);
  }, [activeCase?.id]);

  // Sondeo del análisis en segundo plano. `pollRef` marca el sondeo activo para
  // cancelarlo al desmontar / cambiar de caso sin tocar estado de un componente
  // que ya no está.
  const pollRef = useRef<{ cancelled: boolean } | null>(null);
  // Id del job en curso, para que el botón «Parar» sepa cuál cancelar.
  const jobIdRef = useRef<string | null>(null);
  const [stopping, setStopping] = useState(false);
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
    jobIdRef.current = jobId;
    setBusy(true);
    let reply = "";
    let tools: unknown[] | null = null;
    let cursor = 0; // eventos de progreso ya pintados en el chat
    const collected: StreamEvent[] = []; // para persistir la traza con el mensaje
    let anchored = false; // ¿ya se fijó el ancla del cronómetro?
    patchLast({ streaming: true });
    try {
      while (!token.cancelled) {
        const job = await api.getJob(jobId, cursor);
        // El cronómetro se ancla al `created_at` DEL JOB (hora del servidor),
        // no al momento en que este cliente empezó a sondear: cambiar de
        // sección desmonta el chat y al volver se reengancha, y con el ancla
        // local el contador volvía a cero mientras el análisis seguía.
        if (!anchored) {
          anchored = true;
          patchLast({
            jobStartedAt: job.created_at,
            content:
              "Analizando en segundo plano · puedes cambiar de sección o cerrar la " +
              "pestaña: el análisis no se detiene y los hallazgos se guardan en caliente.",
          });
        }
        (job.events ?? []).forEach((ev) => {
          pushActivity(ev);
          collected.push(ev);
        });
        cursor += job.events?.length ?? 0;

        if (job.status === "done" || job.status === "cancelled") {
          reply =
            job.result?.reply ??
            (job.status === "cancelled" ? "Análisis detenido por el operador." : "");
          tools = (job.result?.tool_calls as unknown[]) ?? null;
          break;
        }
        if (job.status === "error") {
          reply = job.error ?? "El análisis en segundo plano falló.";
          break;
        }
        if (onCapsRefresh) await onCapsRefresh();
        await new Promise((r) => setTimeout(r, 2500));
      }
    } catch (e) {
      reply = e instanceof ApiError ? e.detail : String(e instanceof Error ? e.message : e);
    }
    jobIdRef.current = null;
    setStopping(false);
    if (token.cancelled) return; // desmontado o caso cambiado: no toques estado
    patchLast({ content: reply, pending: false, streaming: false, jobStartedAt: undefined });
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
                // El turno se sella con la hora a la que ARRANCÓ el análisis,
                // no con la de este reenganche: al volver de otra sección la
                // transcripción sigue siendo un acta cronológica.
                at: running.created_at,
                pending: true,
                streaming: false,
                activity: [],
                jobStartedAt: running.created_at,
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

  // Botón «Parar»: pide al backend detener el análisis en curso. La parada es
  // COOPERATIVA, el loop del agente termina entre iteraciones conservando lo
  // persistido en caliente (findings, grafo, artefactos). El sondeo verá el
  // estado `cancelled` y cerrará el turno con el mensaje de parada.
  const onStop = async () => {
    const jobId = jobIdRef.current;
    if (!jobId || stopping) return;
    setStopping(true);
    patchLast({ content: "Deteniendo el análisis…" });
    try {
      await api.cancelJob(jobId);
    } catch {
      // Si el job ya había terminado, el sondeo lo cerrará igualmente.
      setStopping(false);
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
  // Potencia: los niveles los declara el catálogo POR MODELO, así que sin
  // modelo elegido no hay lista que ofrecer (no existe una global correcta).
  const reasoning = providerModels?.reasoning ?? null;
  const efforts =
    providerModels?.model_details?.find((d) => d.id === effectiveModel)?.efforts ?? [];
  const configuredEffort = executor ? effortByProvider[executor] ?? "" : "";
  const effortMismatch =
    configuredEffort !== "" && efforts.length > 0 && !efforts.some((e) => e.id === configuredEffort);

  return (
    <div className="chat-column">
      <div className="transcript" ref={logRef} onScroll={onTranscriptScroll}>
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

          {/* El chat NO pregunta el sistema operativo. La determinación es
              forense y automática: `forensia.triage` la deriva del CONTENIDO de
              la evidencia (cabeceras, sectores de arranque y, en imágenes
              contenedor, el disco des-encapsulado dentro del maletín). El caso
              ambiguo que el triage no puede cerrar se resuelve en Evidencia,
              junto a la huella que lo justifica, no interrumpiendo la
              investigación con una pregunta que el sistema debe saber responder. */}

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
                      {msg.jobStartedAt && <ElapsedSince since={msg.jobStartedAt} />}
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

        {/* Sólo aparece cuando el perito se ha despegado del final. Es la
            contrapartida honesta de no arrastrarlo hacia abajo: puede leer
            hacia arriba con el agente trabajando y volver cuando quiera. */}
        {!atBottom && (
          <button
            type="button"
            className="transcript-jump"
            onClick={scrollToBottom}
            title="Volver al final de la conversación"
          >
            ↓ Ir al final{busy ? " · análisis en curso" : ""}
          </button>
        )}
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
                        {id === executor && <Icon name="check" size={12} />}
                      </button>
                    ) : (
                      <div
                        key={id}
                        className="composer-popover-item is-disabled"
                        title={status.reason ?? "No disponible"}
                      >
                        <span>
                          {status.name}: no disponible
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

            {/* Modelo, la lista depende del proveedor. */}
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
                          {!configuredModel && <Icon name="check" size={12} />}
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

                      {reasoning && (
                        <>
                          <div className="composer-popover-title">Potencia</div>
                          {efforts.length === 0 ? (
                            <div className="composer-popover-note">
                              {effectiveModel
                                ? `El catálogo no declara niveles para ${effectiveModel}.`
                                : "Elige antes un modelo: los niveles dependen de él."}
                            </div>
                          ) : (
                            <>
                              <button
                                type="button"
                                className={`composer-popover-item${!configuredEffort ? " is-active" : ""}`}
                                disabled={modelSaving}
                                onClick={() => void saveEffort("")}
                              >
                                <span>Por defecto del CLI</span>
                                {!configuredEffort && <Icon name="check" size={12} />}
                              </button>
                              {efforts.map((eff) => (
                                <button
                                  key={eff.id}
                                  type="button"
                                  className={`composer-popover-item${eff.id === configuredEffort ? " is-active" : ""}`}
                                  title={eff.description}
                                  disabled={modelSaving}
                                  onClick={() => void saveEffort(eff.id)}
                                >
                                  <span>{eff.id}</span>
                                  {eff.id === configuredEffort && <Icon name="check" size={12} />}
                                </button>
                              ))}
                              {effortMismatch && (
                                <div className="composer-popover-note">
                                  {effectiveModel} no admite «{configuredEffort}»: el turno
                                  fallaría. Elige uno de los de arriba.
                                </div>
                              )}
                            </>
                          )}
                          <div className="composer-popover-note">{reasoning.note}</div>
                        </>
                      )}
                    </>
                  )}
                </div>
              )}
            </div>

            <span className="composer-tip">Enter envía · Shift+Enter salta línea</span>

            {busy ? (
              <button
                type="button"
                className="action-stop composer-send"
                onClick={() => void onStop()}
                disabled={!jobIdRef.current || stopping}
                title="Detener el análisis en curso (conserva lo ya registrado)"
              >
                {stopping ? "Deteniendo…" : "■"}
              </button>
            ) : (
              <button
                type="button"
                className="action-invert composer-send"
                onClick={() => void send()}
                disabled={sendDisabled}
              >
                Enviar
              </button>
            )}
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
