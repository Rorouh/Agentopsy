import { useEffect, useState } from "react";

import type { Capabilities } from "./global";

const card: React.CSSProperties = {
  background: "#15181d",
  border: "1px solid #2a2f37",
  borderRadius: 10,
  padding: "14px 18px",
};

export function App() {
  const [caps, setCaps] = useState<Capabilities | null>(null);
  const [version, setVersion] = useState<string>("");
  const [error, setError] = useState<string>("");

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

  return (
    <div
      style={{
        fontFamily: "system-ui, sans-serif",
        background: "#0d0f12",
        color: "#e6e8eb",
        minHeight: "100vh",
        padding: 32,
      }}
    >
      <h1 style={{ margin: 0, letterSpacing: 1 }}>
        FORENSIA <span style={{ opacity: 0.5, fontSize: 14 }}>v{version}</span>
      </h1>
      <p style={{ opacity: 0.6, marginTop: 4 }}>
        Análisis forense post-mortem asistido por IA — esqueleto E2E
      </p>

      {error && <pre style={{ color: "#ff6b6b" }}>{error}</pre>}

      {caps && (
        <div style={{ display: "grid", gap: 16, gridTemplateColumns: "1fr 1fr", marginTop: 24 }}>
          <div style={card}>
            <h3 style={{ marginTop: 0 }}>Plataforma</h3>
            <div>OS: {caps.os} · arch: {caps.arch}</div>
            <div>Python: {caps.python}</div>
            <div>Empaquetado: {caps.packaged ? "sí" : "no (dev)"}</div>
          </div>
          <div style={card}>
            <h3 style={{ marginTop: 0 }}>Modelos</h3>
            {Object.entries(caps.models).map(([k, v]) => (
              <div key={k}>
                {v ? "🟢" : "⚪"} {k}
              </div>
            ))}
          </div>
          <div style={{ ...card, gridColumn: "1 / 3" }}>
            <h3 style={{ marginTop: 0 }}>Maletín forense (resolución bundled → PATH)</h3>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 6 }}>
              {Object.entries(caps.tools).map(([k, v]) => (
                <div key={k} style={{ opacity: v ? 1 : 0.45 }}>
                  {v ? "🟢" : "⚪"} {k}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
