import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import type {
  AgentFinding,
  Capabilities,
  Case,
  EvidenceHandle,
  ExecutorCost,
  ToolUsage,
} from "../api/types";
import type { ViewId } from "../navigation/navItems";
import { useActiveCase, useActiveCaseFrom } from "../state/activeCase";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { ChatPage } from "./ChatPage";

interface InvestigationPageProps {
  caps: Capabilities | null;
  onNavigate?: (view: ViewId) => void;
  // Refresca capabilities en App (p. ej. tras conectar un ejecutor CLI desde el
  // selector del chat) para que la fila pase a Disponible sin recargar.
  onCapsRefresh?: () => Promise<void> | void;
}

type Phase = "loading" | "ready" | "no-case" | "error";

const SEVERITY_VARIANT: Record<AgentFinding["severity"], "low" | "medium" | "high" | "critical"> = {
  low: "low",
  medium: "medium",
  high: "high",
  critical: "critical",
};

const SEVERITY_LABEL: Record<AgentFinding["severity"], string> = {
  low: "Baja",
  medium: "Media",
  high: "Alta",
  critical: "Crítica",
};

// Envuelve el ChatPage añadiendo contexto real de caso/evidencia + el panel
// lateral de hallazgos que el agente persiste vía `record_finding`. El panel se
// refresca tras cada turno del chat (ChatPage llama onTurnComplete en finally).
export function InvestigationPage({ caps, onNavigate, onCapsRefresh }: InvestigationPageProps) {
  const [cases, setCases] = useState<Case[]>([]);
  // Caso activo GLOBAL (compartido con Casos / Timeline / Documentos / MITRE).
  const { setActiveCaseId } = useActiveCase();
  const activeCase = useActiveCaseFrom(cases);
  const [activeEvidence, setActiveEvidence] = useState<EvidenceHandle | null>(null);
  const [findings, setFindings] = useState<AgentFinding[]>([]);
  const [toolUsage, setToolUsage] = useState<ToolUsage[]>([]);
  const [executorCost, setExecutorCost] = useState<ExecutorCost[]>([]);
  const [phase, setPhase] = useState<Phase>("loading");
  const [error, setError] = useState<string | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(true);

  const refreshFindings = useCallback(async (caseId: string) => {
    try {
      const list = await api.cases.listFindings(caseId);
      setFindings(list);
    } catch {
      // 404 = sin findings.jsonl aún. No es error, es estado vacío.
      setFindings([]);
    }
  }, []);

  const refreshToolUsage = useCallback(async (caseId: string) => {
    try {
      setToolUsage(await api.cases.listToolUsage(caseId));
    } catch {
      // Sin audit.jsonl aún → sin herramientas ejecutadas. Estado vacío, no error.
      setToolUsage([]);
    }
    try {
      setExecutorCost(await api.cases.listExecutorCost(caseId));
    } catch {
      setExecutorCost([]);
    }
  }, []);

  // Carga la LISTA de casos una vez. El contexto del caso activo (evidencia,
  // hallazgos, tools, coste) lo gobierna el efecto de abajo, keyed en
  // activeCase.id, para que cambiar de caso — aquí o en otra vista — recargue
  // todo uniformemente (incluido el chat, que recarga su historial por prop).
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const list = await api.cases.list();
        if (cancelled) return;
        setCases(list);
        setPhase(list.length === 0 ? "no-case" : "ready");
      } catch (err) {
        if (cancelled) return;
        setError(String(err instanceof Error ? err.message : err));
        setPhase("error");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Contexto del caso activo: evidencia + hallazgos + tools + coste. Se recarga
  // al cambiar de caso (desde esta vista o cualquier otra).
  useEffect(() => {
    const caseId = activeCase?.id;
    if (!caseId) {
      setActiveEvidence(null);
      setFindings([]);
      setToolUsage([]);
      setExecutorCost([]);
      return;
    }
    let cancelled = false;
    setActiveEvidence(null);
    (async () => {
      try {
        const evidences = await api.cases.listEvidence(caseId);
        if (!cancelled) setActiveEvidence(evidences.length > 0 ? evidences[0] : null);
      } catch {
        if (!cancelled) setActiveEvidence(null);
      }
      if (cancelled) return;
      await refreshFindings(caseId);
      if (cancelled) return;
      await refreshToolUsage(caseId);
    })();
    return () => {
      cancelled = true;
    };
  }, [activeCase?.id, refreshFindings, refreshToolUsage]);

  const onTurnComplete = useCallback(() => {
    if (activeCase) {
      refreshFindings(activeCase.id);
      refreshToolUsage(activeCase.id);
    }
  }, [activeCase, refreshFindings, refreshToolUsage]);

  // El chat ancla un os_profile antes ambiguo; refrescamos el caso en la lista
  // para que la UI pase a "perfil unix/windows" sin recargar.
  const onCaseUpdated = useCallback((updated: Case) => {
    setCases((prev) => prev.map((c) => (c.id === updated.id ? updated : c)));
  }, []);

  if (phase === "loading") {
    return (
      <div style={{ height: "100%", display: "flex", flexDirection: "column" }}>
        <div className="loading-state">
          <span className="spinner" aria-hidden="true" />
          <span>Cargando contexto del caso…</span>
        </div>
      </div>
    );
  }

  if (phase === "error") {
    return (
      <div style={{ height: "100%", display: "flex", flexDirection: "column" }}>
        <div className="error-state">
          <strong>No se pudo cargar el caso activo:</strong> {error}
        </div>
      </div>
    );
  }

  if (phase === "no-case" || !activeCase) {
    return (
      <div style={{ height: "100%", display: "flex", flexDirection: "column", gap: 16 }}>
        <div className="empty-state" style={{ padding: 28 }}>
          Aún no hay ningún caso abierto. Crea uno desde <strong>Casos y evidencias</strong>{" "}
          antes de empezar a investigar.
        </div>
        {onNavigate && (
          <div>
            <Button variant="chip" onClick={() => onNavigate("repository")}>
              Ir a Casos y evidencias →
            </Button>
          </div>
        )}
      </div>
    );
  }

  const evidenceLabel = activeEvidence
    ? `${activeEvidence.original_path.split("/").pop() ?? activeEvidence.original_path}`
    : "sin evidencia registrada todavía";

  // RULE 2: detected_os NEVER auto-switches the case. We only surface the
  // disagreement and tell the operator which profile would be appropriate.
  // "unknown" is not a mismatch — triage was inconclusive, not contradictory.
  // A case whose os_profile is still null (not yet derived) is not a
  // mismatch either — it's "not yet", not "contradicts".
  const profileMismatch =
    activeCase.os_profile != null &&
    activeEvidence != null &&
    activeEvidence.detected_os !== "unknown" &&
    activeEvidence.detected_os !== activeCase.os_profile
      ? activeEvidence.detected_os
      : null;

  return (
    <div
      style={{
        height: "100%",
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
      }}
    >
      {profileMismatch && (
        <div className="profile-mismatch-banner">
          <span className="profile-mismatch-banner-icon" aria-hidden="true">⚠</span>
          <div className="profile-mismatch-banner-body">
            <div className="profile-mismatch-banner-title">
              Desajuste de perfil — el agente activo no es el adecuado para esta evidencia
            </div>
            <div>
              El caso declara <code>perfil = {activeCase.os_profile}</code> pero el triage de Agentopsy
              identificó la evidencia como <code>{profileMismatch}</code>. El agente del caso
              (<code>forensia-{activeCase.os_profile}</code>) se negará a invocar herramientas hasta
              que cierres este caso y lo reabras con <code>perfil = {profileMismatch}</code> para que
              lo lleve <code>forensia-{profileMismatch}</code>. Agentopsy no cambia el perfil por ti
              (RULE 2 — la decisión es del operador).
            </div>
          </div>
        </div>
      )}

      <div
        className="investigation-layout"
        style={{
          flex: 1,
          minHeight: 0,
          gridTemplateColumns: sidebarOpen ? "1fr 300px" : "1fr 28px",
        }}
      >
        <ChatPage
          caps={caps}
          activeCase={activeCase}
          activeEvidence={activeEvidence}
          onTurnComplete={onTurnComplete}
          onCapsRefresh={onCapsRefresh}
          onCaseUpdated={onCaseUpdated}
        />

        <div
          className="investigation-sidebar"
          style={{ overflow: "hidden", minWidth: 0 }}
        >
          {/* Toggle collapse/expand */}
          <button
            onClick={() => setSidebarOpen((o) => !o)}
            title={sidebarOpen ? "Colapsar panel" : "Expandir panel"}
            style={{
              alignSelf: "flex-end",
              flexShrink: 0,
              width: 24,
              height: 24,
              border: "1px solid var(--border)",
              borderRadius: 4,
              background: "var(--inset)",
              color: "var(--text-muted)",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: 13,
              lineHeight: 1,
              padding: 0,
              transition: "color 0.15s, border-color 0.15s",
            }}
            onMouseEnter={(e) => {
              (e.currentTarget as HTMLButtonElement).style.color = "var(--text-primary)";
              (e.currentTarget as HTMLButtonElement).style.borderColor = "var(--text-muted)";
            }}
            onMouseLeave={(e) => {
              (e.currentTarget as HTMLButtonElement).style.color = "var(--text-muted)";
              (e.currentTarget as HTMLButtonElement).style.borderColor = "var(--border)";
            }}
          >
            {sidebarOpen ? "›" : "‹"}
          </button>

          {sidebarOpen && (<>
        <div className="findings-panel case-panel">
          <div
            className="findings-panel-title"
            style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}
          >
            <span>Caso activo</span>
            <Badge variant={activeCase.status === "active" ? "low" : "neutral"}>
              {activeCase.status === "active" ? "Abierto" : "Cerrado"}
            </Badge>
          </div>
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 6,
              fontSize: 12,
              color: "var(--text-muted)",
              padding: "4px 2px",
            }}
          >
            {cases.length > 1 && (
              <select
                className="case-picker"
                aria-label="Caso activo"
                style={{ maxWidth: "100%", marginBottom: 2 }}
                value={activeCase.id}
                onChange={(e) => setActiveCaseId(e.target.value)}
              >
                {cases.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                    {c.os_profile ? ` · ${c.os_profile}` : ""}
                  </option>
                ))}
              </select>
            )}
            <div style={{ fontWeight: 600, fontSize: 13, color: "var(--text-primary)" }}>
              {activeCase.name}
            </div>
            <div>{activeCase.examiner}</div>
            <div>
              perfil <strong>{activeCase.os_profile ?? "sin determinar"}</strong>
            </div>
            <div>
              evidencia <strong>{evidenceLabel}</strong>
            </div>
            {activeEvidence && (
              <div>
                SHA-256 <code>{activeEvidence.sha256.slice(0, 8)}…</code>
              </div>
            )}
            {activeEvidence && activeEvidence.detected_os !== "unknown" && (
              <div>
                detectado <strong>{activeEvidence.detected_os}</strong>
                {activeEvidence.detected_kind !== "unknown" && (
                  <> / <strong>{activeEvidence.detected_kind}</strong></>
                )}
              </div>
            )}
          </div>
        </div>
        <div className="findings-panel">
          <div className="findings-panel-title">
            Hallazgos del caso ({findings.length})
          </div>
          {findings.length === 0 ? (
            <div className="empty-state" style={{ padding: "20px 12px" }}>
              Aún no hay hallazgos registrados. El agente los irá apilando aquí a medida que
              vaya analizando con sus herramientas.
            </div>
          ) : (
            findings.map((f) => (
              <div className="finding-card" key={f.id}>
                <div className="finding-card-title">{f.title}</div>
                <div className="finding-card-summary">{f.summary}</div>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <Badge variant={SEVERITY_VARIANT[f.severity]}>
                    {SEVERITY_LABEL[f.severity]}
                  </Badge>
                  {f.tool_id && (
                    <code style={{ fontSize: 11, color: "var(--text-muted)" }}>
                      {f.tool_id}
                    </code>
                  )}
                  {f.run_id && (
                    <code
                      style={{ fontSize: 11, color: "var(--text-muted)" }}
                      title={f.run_id}
                    >
                      run {f.run_id.slice(0, 8)}
                    </code>
                  )}
                </div>
              </div>
            ))
          )}
        </div>

        <div className="findings-panel tools-panel">
          <div className="findings-panel-title">
            Tools ({toolUsage.reduce((n, t) => n + t.total, 0)})
          </div>
          {toolUsage.length === 0 ? (
            <div className="empty-state" style={{ padding: "20px 12px" }}>
              Aún no se ha ejecutado ninguna herramienta. Aparecerán aquí con su número de
              usos cuando el agente las invoque.
            </div>
          ) : (
            toolUsage.map((t) => (
              <div className="tool-usage-row" key={t.tool_id}>
                <span className="tool-usage-name">{t.tool_id}</span>
                <span className="tool-usage-meta">
                  {t.ok > 0 && <Badge variant="low">{t.ok} ok</Badge>}
                  {t.failed > 0 && (
                    <Badge variant="high">
                      {t.failed} fallo{t.failed > 1 ? "s" : ""}
                    </Badge>
                  )}
                  <span className="tool-usage-count">×{t.total}</span>
                </span>
              </div>
            ))
          )}
        </div>

        <ExecutorCostPanel rows={executorCost} />
          </>)}
        </div>
      </div>
    </div>
  );
}

// Comparativa de coste/tokens por ejecutor (Bug 008 §2 Nivel 0). Forma: magnitud
// (tokens por ejecutor) → barras horizontales; la IDENTIDAD la lleva la etiqueta
// de fila, así que un solo tono de acento basta (no una paleta categórica). Los
// valores van direct-labeled; un ejecutor que no reportó tokens se marca como tal,
// nunca como un cero falso.
function ExecutorCostPanel({ rows }: { rows: ExecutorCost[] }) {
  const withTokens = rows.filter((r) => r.runs_with_tokens > 0);
  const totalTokens = rows.reduce((n, r) => n + r.total_tokens, 0);
  const totalCost = rows.reduce((n, r) => n + r.cost_usd, 0);
  const max = Math.max(1, ...withTokens.map((r) => r.total_tokens));

  return (
    <div className="findings-panel cost-panel">
      <div className="findings-panel-title">
        Coste por ejecutor
        {totalTokens > 0 && (
          <span className="cost-panel-total">
            {totalTokens.toLocaleString("es-ES")} tok
            {totalCost > 0 ? ` · $${totalCost.toFixed(4)}` : ""}
          </span>
        )}
      </div>

      {rows.length === 0 ? (
        <div className="empty-state" style={{ padding: "20px 12px" }}>
          Sin ejecuciones registradas todavía. El coste en tokens aparece por
          ejecutor cuando el agente corre sobre el caso.
        </div>
      ) : (
        <div className="cost-rows">
          {rows.map((r) => {
            const reported = r.runs_with_tokens > 0;
            return (
              <div className="cost-row" key={r.executor}>
                <div className="cost-row-head">
                  <span className="cost-row-name">{r.executor}</span>
                  <span className="cost-row-value">
                    {reported ? (
                      <>
                        {r.total_tokens.toLocaleString("es-ES")} tok
                        {r.cost_usd > 0 && (
                          <span className="cost-row-usd"> · ${r.cost_usd.toFixed(4)}</span>
                        )}
                      </>
                    ) : (
                      <span
                        className="cost-row-unreported"
                        title="Este ejecutor no reporta tokens en su envelope (p. ej. Codex sin --json)."
                      >
                        no reportado
                      </span>
                    )}
                  </span>
                </div>
                <div className="cost-bar-track">
                  <div
                    className={`cost-bar-fill${reported ? "" : " cost-bar-fill--none"}`}
                    style={{ width: reported ? `${(r.total_tokens / max) * 100}%` : "0%" }}
                  />
                </div>
                <div className="cost-row-sub">
                  {r.runs} {r.runs === 1 ? "ejecución" : "ejecuciones"}
                  {reported && (
                    <>
                      {" · "}
                      {r.input_tokens.toLocaleString("es-ES")} in /{" "}
                      {r.output_tokens.toLocaleString("es-ES")} out
                    </>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
