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
  const [activeCase, setActiveCase] = useState<Case | null>(null);
  const [activeEvidence, setActiveEvidence] = useState<EvidenceHandle | null>(null);
  const [findings, setFindings] = useState<AgentFinding[]>([]);
  const [toolUsage, setToolUsage] = useState<ToolUsage[]>([]);
  const [executorCost, setExecutorCost] = useState<ExecutorCost[]>([]);
  const [phase, setPhase] = useState<Phase>("loading");
  const [error, setError] = useState<string | null>(null);

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

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const list = await api.cases.list();
        if (cancelled) return;
        if (list.length === 0) {
          setPhase("no-case");
          return;
        }
        const newest = list[0];
        setActiveCase(newest);
        const evidences = await api.cases.listEvidence(newest.id);
        if (cancelled) return;
        if (evidences.length > 0) {
          setActiveEvidence(evidences[0]);
        }
        await refreshFindings(newest.id);
        await refreshToolUsage(newest.id);
        if (cancelled) return;
        setPhase("ready");
      } catch (err) {
        if (cancelled) return;
        setError(String(err instanceof Error ? err.message : err));
        setPhase("error");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [refreshFindings, refreshToolUsage]);

  const onTurnComplete = useCallback(() => {
    if (activeCase) {
      refreshFindings(activeCase.id);
      refreshToolUsage(activeCase.id);
    }
  }, [activeCase, refreshFindings, refreshToolUsage]);

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
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          gap: 12,
          marginBottom: 4,
          flexShrink: 0,
        }}
      >
        <div style={{ flex: 1 }}>
          <div className="context-banner">
            <div className="context-banner-main">
              Caso activo: <strong>{activeCase.name}</strong>
              <span className="context-banner-evidence">
                {" · "}
                {activeCase.examiner}
                {" · perfil "}
                <strong>{activeCase.os_profile ?? "sin determinar"}</strong>
                {" · evidencia: "}
                <strong>{evidenceLabel}</strong>
                {activeEvidence && (
                  <>
                    {" · SHA-256 "}
                    <code>{activeEvidence.sha256.slice(0, 8)}…</code>
                    {activeEvidence.detected_os !== "unknown" && (
                      <>
                        {" · detectado "}
                        <strong>{activeEvidence.detected_os}</strong>
                        {activeEvidence.detected_kind !== "unknown" && (
                          <> / <strong>{activeEvidence.detected_kind}</strong></>
                        )}
                      </>
                    )}
                  </>
                )}
              </span>
            </div>
            <Badge variant={activeCase.status === "active" ? "low" : "neutral"}>
              {activeCase.status === "active" ? "Abierto" : "Cerrado"}
            </Badge>
          </div>
        </div>
        {onNavigate && (
          <Button
            variant="chip"
            onClick={() => onNavigate("timeline")}
            style={{ flexShrink: 0 }}
          >
            Ver Timeline →
          </Button>
        )}
      </div>

      {profileMismatch && (
        <div className="profile-mismatch-banner">
          <span className="profile-mismatch-banner-icon" aria-hidden="true">⚠</span>
          <div className="profile-mismatch-banner-body">
            <div className="profile-mismatch-banner-title">
              Desajuste de perfil — el agente activo no es el adecuado para esta evidencia
            </div>
            <div>
              El caso declara <code>perfil = {activeCase.os_profile}</code> pero el triage de FORENSIA
              identificó la evidencia como <code>{profileMismatch}</code>. El agente del caso
              (<code>forensia-{activeCase.os_profile}</code>) se negará a invocar herramientas hasta
              que cierres este caso y lo reabras con <code>perfil = {profileMismatch}</code> para que
              lo lleve <code>forensia-{profileMismatch}</code>. FORENSIA no cambia el perfil por ti
              (RULE 2 — la decisión es del operador).
            </div>
          </div>
        </div>
      )}

      <div className="investigation-layout" style={{ flex: 1, minHeight: 0 }}>
        <ChatPage
          caps={caps}
          activeCase={activeCase}
          activeEvidence={activeEvidence}
          onTurnComplete={onTurnComplete}
          onCapsRefresh={onCapsRefresh}
        />

        <div className="investigation-sidebar">
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
