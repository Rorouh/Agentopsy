import { useEffect, useMemo, useRef, useState } from "react";
import type { AgentSummary, Capabilities, Case, EvidenceHandle } from "../global";
import { Button } from "../ui/Button";

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
}

// One session id per case is enough for v1 — múltiples investigaciones por caso
// se introducen cuando el flujo lo pida explícitamente.
const CHAT_SESSION_ID = "main";

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
}

export function ChatPage({ caps, activeCase, activeEvidence, onTurnComplete }: ChatPageProps) {
  const [msgs, setMsgs] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);

  const logRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Source of truth for the agent selection: the CASE's os_profile, not the
  // host's. Only when no case is open we fall back to host detection. RULE 2 in
  // the backend: /api/agent/query returns 503 if there is no package for the
  // requested profile — we surface that explicitly instead of inventing a default.
  const activeProfile: "unix" | "windows" = activeCase
    ? activeCase.os_profile
    : caps?.os === "windows"
      ? "windows"
      : "unix";
  const activeAgent: AgentSummary | null = useMemo(() => {
    const loaded = caps?.agents?.loaded ?? [];
    return loaded.find((a) => a.os_profile === activeProfile) ?? null;
  }, [caps, activeProfile]);

  // Auto-scroll chat to bottom
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [msgs]);

  // Load persisted chat history when the active case changes. A 404 (no session
  // file yet) means "fresh conversation" — not an error to surface.
  useEffect(() => {
    if (!activeCase) {
      setMsgs([]);
      return;
    }
    let cancelled = false;
    window.forensia.cases
      .readChat(activeCase.id, CHAT_SESSION_ID)
      .then((history) => {
        if (cancelled) return;
        const restored: ChatMessage[] = history
          .filter((m) => m.role === "user" || m.role === "assistant")
          .map((m) => ({ role: m.role as "user" | "assistant", content: m.content }));
        setMsgs(restored);
      })
      .catch(() => {
        // No prior session yet — start empty.
        if (!cancelled) setMsgs([]);
      });
    return () => {
      cancelled = true;
    };
  }, [activeCase?.id]);

  const send = async () => {
    const text = input.trim();
    if (!text || busy) return;
    setInput("");
    setBusy(true);
    setMsgs((prev) => [...prev, { role: "user", content: text }]);

    // Add typing state
    setMsgs((prev) => [...prev, { role: "assistant", content: "Pensando...", pending: true }]);

    // Persist user turn upfront so a crash/disconnect during query() doesn't
    // erase what the analyst asked. The assistant turn gets appended below
    // once the response (or the error) is known.
    if (activeCase) {
      window.forensia.cases
        .appendChat(activeCase.id, CHAT_SESSION_ID, { role: "user", content: text })
        .catch(() => {
          /* persistence best-effort; UI state stays */
        });
    }

    let assistantReply = "";
    // Captured per-turn so the assistant ChatMessage we persist below carries
    // the tool ledger; without it the backend can't replay "what you already
    // ran" into the next turn's context.
    let toolCalls: unknown[] | null = null;
    try {
      const res = await window.forensia.query({
        prompt: text,
        os_profile: activeProfile,
        evidence_id: activeEvidence?.evidence_id ?? "",
        case_id: activeCase?.id,
        session_id: CHAT_SESSION_ID,
      });
      assistantReply = res.reply;
      toolCalls = res.tool_calls ?? null;
      setMsgs((prev) => {
        const next = [...prev];
        next[next.length - 1] = { role: "assistant", content: res.reply };
        return next;
      });
    } catch (e) {
      const msg = String(e);
      const friendly = /503/.test(msg)
        ? `No hay agente cargado para el perfil \`${activeProfile}\`. Suelta su carpeta dentro de \`agentes/\` y reinicia FORENSIA.`
        : "Error: No se pudo conectar con el agente de IA.";
      assistantReply = friendly;
      setMsgs((prev) => {
        const next = [...prev];
        next[next.length - 1] = { role: "assistant", content: friendly };
        return next;
      });
    } finally {
      setBusy(false);
      if (activeCase && assistantReply) {
        window.forensia.cases
          .appendChat(activeCase.id, CHAT_SESSION_ID, {
            role: "assistant",
            content: assistantReply,
            tool_calls: toolCalls,
          })
          .catch(() => {
            /* best-effort */
          });
      }
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

  return (
    <div className="chat-container">
      {msgs.length === 0 ? (
        // Welcome / empty state
        <div className="chat-welcome">
          <div className="welcome-title">Bueno Santi a trabajar ...</div>

          <div className="agent-badge" title={activeAgent?.path ?? ""}>
            {activeAgent ? (
              <>
                <span className="agent-badge-dot agent-badge-dot--ok" />
                Agente activo: <strong>{activeAgent.name}</strong>{" "}
                <span className="agent-badge-meta">
                  v{activeAgent.version} · {activeAgent.os_profile} ·{" "}
                  {activeAgent.model.backend}/{activeAgent.model.name}
                </span>
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
            <div className="composer">
              <textarea
                ref={inputRef}
                className="composer-textarea"
                placeholder="Pregunta a FORENSIA sobre tu caso..."
                rows={1}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
              />
              <div className="composer-footer">
                <span className="composer-tip">Enter para enviar · Shift+Enter para nueva línea</span>
                <Button variant="icon" onClick={send} disabled={!input.trim() || busy}>
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
                  <div style={{ opacity: msg.pending ? 0.6 : 1 }}>
                    {formatMessageContent(msg.content)}
                  </div>
                ) : (
                  <span>{msg.content}</span>
                )}
              </div>
            ))}
          </div>

          <div className="composer-wrapper">
            <div className="composer">
              <textarea
                ref={inputRef}
                className="composer-textarea"
                placeholder="Haz una pregunta o consulta forense..."
                rows={1}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
              />
              <div className="composer-footer">
                <span className="composer-tip">Enter para enviar · Shift+Enter para nueva línea</span>
                <Button variant="icon" onClick={send} disabled={!input.trim() || busy}>
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
          </div>
        </div>
      )}
    </div>
  );
}
