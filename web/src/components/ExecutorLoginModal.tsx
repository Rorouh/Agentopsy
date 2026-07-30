import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api/client";
import type { ExecutorId, ExecutorLoginCapability, ExecutorLoginStart } from "../api/types";
import { Modal } from "../ui/Modal";

// Conecta un ejecutor CLI cloud (Codex/Claude) DESDE LA WEB, sin abrir terminal.
// El backend relaya el flujo device/OAuth del propio CLI; este modal muestra la
// URL + código, sondea el estado, y, para Claude, reenvía el código pegado.
//
// Degradación explícita (RULE 2): si el CLI no puede relayarse (Gemini, cuyo
// login individual rechaza Google), se muestra el comando manual exacto y un
// botón «Comprobar», nunca un spinner que no termina.

interface ExecutorLoginModalProps {
  executorId: ExecutorId;
  executorName: string;
  open: boolean;
  onClose: () => void;
  // Refresca capabilities en el padre cuando el ejecutor pasa a Disponible.
  onConnected: () => Promise<void> | void;
}

type Phase = "loading" | "relay-unsupported" | "waiting" | "logged_in" | "error";

const POLL_MS = 2500;

export function ExecutorLoginModal({
  executorId,
  executorName,
  open,
  onClose,
  onConnected,
}: ExecutorLoginModalProps) {
  const [phase, setPhase] = useState<Phase>("loading");
  const [capability, setCapability] = useState<ExecutorLoginCapability | null>(null);
  const [start, setStart] = useState<ExecutorLoginStart | null>(null);
  const [reason, setReason] = useState<string | null>(null);
  const [codeDraft, setCodeDraft] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [copied, setCopied] = useState<"url" | "code" | null>(null);
  const [checking, setChecking] = useState(false);

  const pollRef = useRef<number | null>(null);
  const startedRelayRef = useRef(false);

  const stopPolling = useCallback(() => {
    if (pollRef.current !== null) {
      window.clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const finishConnected = useCallback(async () => {
    stopPolling();
    setPhase("logged_in");
    await onConnected();
    window.setTimeout(() => onClose(), 1200);
  }, [onConnected, onClose, stopPolling]);

  const poll = useCallback(async () => {
    try {
      const st = await api.executorLogin.status(executorId);
      if (st.state === "logged_in") {
        await finishConnected();
      } else if (st.state === "error" || st.state === "expired") {
        stopPolling();
        setPhase("error");
        setReason(st.reason ?? "El login terminó sin completarse.");
      }
      // "waiting" → seguimos sondeando.
    } catch (err) {
      stopPolling();
      setPhase("error");
      setReason(err instanceof Error ? err.message : String(err));
    }
  }, [executorId, finishConnected, stopPolling]);

  const beginRelay = useCallback(async () => {
    setPhase("loading");
    setReason(null);
    try {
      const res = await api.executorLogin.start(executorId);
      startedRelayRef.current = true;
      setStart(res);
      setPhase("waiting");
      stopPolling();
      pollRef.current = window.setInterval(poll, POLL_MS);
    } catch (err) {
      setPhase("error");
      setReason(err instanceof Error ? err.message : String(err));
    }
  }, [executorId, poll, stopPolling]);

  // Al abrir: consulta la capacidad de relay y arranca el flujo adecuado.
  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setPhase("loading");
    setStart(null);
    setReason(null);
    setCodeDraft("");
    startedRelayRef.current = false;
    (async () => {
      try {
        const caps = await api.executorLogin.capabilities();
        if (cancelled) return;
        const cap = caps.executors[executorId] ?? null;
        setCapability(cap);
        if (cap && !cap.relay_supported) {
          setPhase("relay-unsupported");
          setReason(cap.reason);
          return;
        }
        await beginRelay();
      } catch (err) {
        if (cancelled) return;
        setPhase("error");
        setReason(err instanceof Error ? err.message : String(err));
      }
    })();
    return () => {
      cancelled = true;
    };
    // beginRelay depende solo de executorId (estable mientras el modal está abierto).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, executorId]);

  // Al cerrar/desmontar: para el sondeo y reapea el proceso de login si quedó vivo.
  useEffect(() => {
    if (open) return;
    stopPolling();
    if (startedRelayRef.current && phase !== "logged_in") {
      startedRelayRef.current = false;
      api.executorLogin.cancel(executorId).catch(() => {
        /* best-effort: el backend igualmente lo reapea por deadline/atexit */
      });
    }
  }, [open, phase, executorId, stopPolling]);

  const copy = useCallback(async (what: "url" | "code", value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(what);
      window.setTimeout(() => setCopied((c) => (c === what ? null : c)), 1500);
    } catch {
      /* clipboard bloqueado: el operador puede seleccionar el texto a mano */
    }
  }, []);

  const submitCode = useCallback(async () => {
    const code = codeDraft.trim();
    if (!code) return;
    setSubmitting(true);
    setReason(null);
    try {
      await api.executorLogin.submitCode(executorId, code);
      setCodeDraft("");
      // El sondeo en curso reflejará el cambio a logged_in; forzamos uno ya.
      await poll();
    } catch (err) {
      setReason(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  }, [codeDraft, executorId, poll]);

  const checkNow = useCallback(async () => {
    setChecking(true);
    setReason(null);
    try {
      const st = await api.executorLogin.status(executorId);
      if (st.state === "logged_in") {
        await finishConnected();
      } else {
        setReason(st.reason ?? "Aún no hay sesión iniciada.");
      }
    } catch (err) {
      setReason(err instanceof Error ? err.message : String(err));
    } finally {
      setChecking(false);
    }
  }, [executorId, finishConnected]);

  return (
    <Modal open={open} title={`Conectar ${executorName}`} onClose={onClose}>
      <div className="exec-login" style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        {phase === "loading" && (
          <div className="exec-login-loading">
            <span className="spinner" aria-hidden="true" /> Iniciando el login de {executorName}…
          </div>
        )}

        {phase === "relay-unsupported" && capability && (
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <p className="field-hint">
              El login de <strong>{executorName}</strong> no puede completarse desde la web.
              {reason ? ` ${reason}` : ""}
            </p>
            <div className="field">
              <label className="eyebrow">Ejecuta este comando en una terminal</label>
              <div style={{ display: "flex", gap: 8, alignItems: "stretch" }}>
                <code
                  style={{
                    flex: 1,
                    padding: "8px 10px",
                    background: "var(--surface-2, rgba(127,127,127,0.12))",
                    borderRadius: 6,
                    overflowX: "auto",
                    whiteSpace: "nowrap",
                  }}
                >
                  {capability.manual_command}
                </code>
                <button type="button" className="link-action" onClick={() => copy("url", capability.manual_command)}>
                  {copied === "url" ? "✓" : "Copiar"}
                </button>
              </div>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button type="button" className="action-invert" disabled={checking} onClick={checkNow}>
                {checking ? (
                  <>
                    <span className="spinner" aria-hidden="true" /> Comprobando…
                  </>
                ) : (
                  "Comprobar"
                )}
              </button>
              <button type="button" className="link-action" onClick={onClose}>
                Cerrar
              </button>
            </div>
            {reason && (
              <div className="error-state" role="status" aria-live="polite">
                {reason}
              </div>
            )}
          </div>
        )}

        {phase === "waiting" && start && (
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <div className="field">
              <label className="eyebrow">1 · Abre esta URL en tu navegador</label>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <a
                  href={start.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ flex: 1, overflowX: "auto", whiteSpace: "nowrap" }}
                >
                  {start.url}
                </a>
                <button type="button" className="link-action" onClick={() => copy("url", start.url)}>
                  {copied === "url" ? "✓" : "Copiar"}
                </button>
              </div>
            </div>

            {start.code && (
              <div className="field">
                <label className="eyebrow">2 · Introduce este código EN EL NAVEGADOR</label>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <code
                    style={{
                      flex: 1,
                      fontSize: 23,
                      letterSpacing: 2,
                      padding: "8px 10px",
                      background: "var(--surface-2, rgba(127,127,127,0.12))",
                      borderRadius: 6,
                    }}
                  >
                    {start.code}
                  </code>
                  <button type="button" className="link-action" onClick={() => copy("code", start.code!)}>
                    {copied === "code" ? "✓" : "Copiar"}
                  </button>
                </div>
                <span className="field-hint">
                  El código caduca en ~15 min. No lo compartas con nadie.
                </span>
              </div>
            )}

            {start.needs_code_input && (
              <div className="field">
                <label className="eyebrow" htmlFor="exec-login-code">
                  {start.code ? "3" : "2"} · Pega aquí el código que te da el navegador
                </label>
                <div style={{ display: "flex", gap: 8 }}>
                  <input
                    id="exec-login-code"
                    className="field-input field-input--sm"
                    type="text"
                    autoComplete="off"
                    spellCheck={false}
                    placeholder="Código de la página de autorización"
                    value={codeDraft}
                    onChange={(e) => setCodeDraft(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") submitCode();
                    }}
                    style={{ flex: 1 }}
                  />
                  <button
                    type="button"
                    className="action-invert"
                    disabled={submitting || !codeDraft.trim()}
                    onClick={submitCode}
                  >
                    {submitting ? (
                      <>
                        <span className="spinner" aria-hidden="true" /> Enviando…
                      </>
                    ) : (
                      "Enviar código"
                    )}
                  </button>
                </div>
              </div>
            )}

            <div className="exec-login-status" style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span className="spinner" aria-hidden="true" />
              <span className="field-hint">
                Esperando a que completes el acceso en el navegador…
              </span>
            </div>

            {reason && (
              <div className="error-state" role="alert" aria-live="polite">
                {reason}
              </div>
            )}

            <div>
              <button type="button" className="link-action" onClick={onClose}>
                Cancelar
              </button>
            </div>
          </div>
        )}

        {phase === "logged_in" && (
          <div className="exec-login-ok" role="status" aria-live="polite">
            ✓ {executorName} conectado. La sesión persiste en el volumen{" "}
            <code>forensia-cli-auth</code>.
          </div>
        )}

        {phase === "error" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div className="error-state" role="alert" aria-live="polite">
              {reason ?? "No se pudo completar el login."}
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button type="button" className="action-invert" onClick={beginRelay}>
                Reintentar
              </button>
              <button type="button" className="link-action" disabled={checking} onClick={checkNow}>
                {checking ? "Comprobando…" : "Comprobar"}
              </button>
              <button type="button" className="link-action" onClick={onClose}>
                Cerrar
              </button>
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
}
