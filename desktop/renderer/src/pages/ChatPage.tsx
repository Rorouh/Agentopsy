import { useEffect, useRef, useState } from "react";
import type { Capabilities } from "../global";

function getGreeting() {
  const hr = new Date().getHours();
  if (hr >= 6 && hr < 12) return "Buenos días";
  if (hr >= 12 && hr < 20) return "Buenas tardes";
  return "Buenas noches";
}

function renderBoldText(text: string) {
  // Simple regex to parse **bold** and `code`
  const parts = text.split(/(\*\*.*?\*\*|`.*?`)/g);
  return parts.map((part, i) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return (
        <strong key={i} style={{ fontWeight: 650, color: "#ffffff" }}>
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
        <h4 key={idx} style={{ color: "#ffffff", marginTop: 12, marginBottom: 6 }}>
          {renderBoldText(text.substring(4))}
        </h4>
      );
    }
    if (text.startsWith("## ")) {
      return (
        <h3
          key={idx}
          style={{
            color: "#ffffff",
            marginTop: 14,
            marginBottom: 8,
            borderBottom: "1px solid #1f252e",
            paddingBottom: 4,
          }}
        >
          {renderBoldText(text.substring(3))}
        </h3>
      );
    }
    if (text.startsWith("# ")) {
      return (
        <h2 key={idx} style={{ color: "#ffffff", marginTop: 16, marginBottom: 10 }}>
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

interface ChatPageProps {
  caps: Capabilities | null;
}

export function ChatPage({ caps }: ChatPageProps) {
  const [msgs, setMsgs] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);

  const logRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Auto-scroll chat to bottom
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [msgs]);

  const send = async () => {
    const text = input.trim();
    if (!text || busy) return;
    setInput("");
    setBusy(true);
    setMsgs((prev) => [...prev, { role: "user", content: text }]);

    // Add typing state
    setMsgs((prev) => [...prev, { role: "assistant", content: "Pensando...", pending: true }]);

    try {
      const res = await window.forensia.query({
        prompt: text,
        os_profile: caps?.os || "unix",
        evidence_id: "",
      });
      setMsgs((prev) => {
        const next = [...prev];
        next[next.length - 1] = { role: "assistant", content: res.reply };
        return next;
      });
    } catch (e) {
      setMsgs((prev) => {
        const next = [...prev];
        next[next.length - 1] = { role: "assistant", content: "Error: No se pudo conectar con el agente de IA." };
        return next;
      });
    } finally {
      setBusy(false);
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
                <button className="send-btn" onClick={send} disabled={!input.trim() || busy}>
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
                </button>
              </div>
            </div>
          </div>

          <div className="quick-chips">
            {QUICK_CHIPS.map((chip, i) => (
              <button
                key={i}
                className="chip"
                onClick={() => handleChipClick(chip.prefill)}
              >
                {chip.label}
              </button>
            ))}
          </div>
        </div>
      ) : (
        // Conversation Flow
        <div style={{ display: "flex", flexDirection: "column", height: "100%", justifyContent: "space-between" }}>
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
                <button className="send-btn" onClick={send} disabled={!input.trim() || busy}>
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
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
