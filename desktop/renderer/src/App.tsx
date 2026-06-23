import { useEffect, useRef, useState } from "react";
import type { Capabilities } from "./global";

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

export function App() {
  const [caps, setCaps] = useState<Capabilities | null>(null);
  const [version, setVersion] = useState<string>("");
  const [error, setError] = useState<string>("");
  
  // Navigation: "chat" or "system"
  const [activeTab, setActiveTab] = useState<"chat" | "system">("chat");

  // Chat States
  const [msgs, setMsgs] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);

  const logRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    window.forensia
      .health()
      .then((h) => setVersion(h.version))
      .catch((e) => setError(String(e)));
    window.forensia
      .capabilities()
      .then(setCaps)
      .catch((e) => setError(String(e)));
  }, []);

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

  const isConnected = !error && !!version;

  return (
    <div className="app">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div className="brand-section">
          <div className="brand-dot" />
          <span className="brand-name">FORENSIA</span>
        </div>

        <div className="nav-list">
          <button
            className={`nav-item ${activeTab === "chat" ? "active" : ""}`}
            onClick={() => setActiveTab("chat")}
          >
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              style={{ marginRight: 8 }}
            >
              <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
            </svg>
            Chat de IA
          </button>
          <button
            className={`nav-item ${activeTab === "system" ? "active" : ""}`}
            onClick={() => setActiveTab("system")}
          >
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              style={{ marginRight: 8 }}
            >
              <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
              <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
              <line x1="6" y1="6" x2="6.01" y2="6" />
              <line x1="6" y1="18" x2="6.01" y2="18" />
            </svg>
            Estado del Sistema
          </button>
        </div>

        <div className="sidebar-footer">
          <div className="system-status-indicator">
            <div className="status-label-group">
              <span className={`status-dot ${isConnected ? "" : "offline"}`} />
              <span>{isConnected ? "Conectado" : "Sin Conexión"}</span>
            </div>
            <span className="app-version">{version ? `v${version}` : "offline"}</span>
          </div>
        </div>
      </aside>

      {/* Main Workspace */}
      <main className="main-content">
        {error && (
          <div style={{ color: "#ff6b6b", marginBottom: 16, fontFamily: "var(--font-mono)", fontSize: 13 }}>
            Error de conexión: {error}
          </div>
        )}

        {activeTab === "chat" ? (
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
        ) : (
          // System Status (Relocated dashboard grid)
          <div>
            <h2 className="system-title">Estado del Sistema</h2>
            <p className="system-subtitle">Visualiza el entorno de ejecución, modelos activos y herramientas cargadas en FORENSIA.</p>

            {caps ? (
              <div className="status-grid">
                <div className="status-card">
                  <h3>Plataforma</h3>
                  <div className="status-card-body">
                    <div className="status-row">
                      <span className="status-row-label">Sistema Operativo</span>
                      <span className="status-row-value">{caps.os}</span>
                    </div>
                    <div className="status-row">
                      <span className="status-row-label">Arquitectura</span>
                      <span className="status-row-value">{caps.arch}</span>
                    </div>
                    <div className="status-row">
                      <span className="status-row-label">Python Sidecar</span>
                      <span className="status-row-value">{caps.python}</span>
                    </div>
                    <div className="status-row">
                      <span className="status-row-label">Empaquetado (Producción)</span>
                      <span className="status-row-value">{caps.packaged ? "Sí" : "No (Modo Dev)"}</span>
                    </div>
                  </div>
                </div>

                <div className="status-card">
                  <h3>Modelos Disponibles</h3>
                  <div className="status-card-body">
                    {Object.entries(caps.models).map(([k, v]) => (
                      <div className="status-row" key={k}>
                        <span className="status-row-label">{k}</span>
                        <span className="status-row-value" style={{ display: "flex", alignItems: "center", gap: 6 }}>
                          <span className={`status-dot ${v ? "" : "offline"}`} />
                          {v ? "Disponible" : "No Disponible"}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="status-card full-width">
                  <h3>Maletín Forense (Resolución Bundled → PATH)</h3>
                  <div className="tools-grid">
                    {Object.entries(caps.tools).map(([k, v]) => (
                      <div className="tool-indicator" key={k} style={{ opacity: v ? 1 : 0.5 }}>
                        <span className={`dot ${v ? "" : "inactive"}`} />
                        <span className="tool-name" title={k}>{k}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div style={{ color: "var(--fg-dim)" }}>Obteniendo capacidades del sidecar backend...</div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
