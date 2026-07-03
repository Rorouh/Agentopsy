import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import type { AgentFinding, Capabilities, Case, EvidenceHandle } from "../api/types";
import type { ViewId } from "../navigation/navItems";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { ChatPage } from "./ChatPage";

interface InvestigationPageProps {
  caps: Capabilities | null;
  onNavigate?: (view: ViewId) => void;
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
export function InvestigationPage({ caps, onNavigate }: InvestigationPageProps) {
  const [activeCase, setActiveCase] = useState<Case | null>(null);
  const [activeEvidence, setActiveEvidence] = useState<EvidenceHandle | null>(null);
  const [findings, setFindings] = useState<AgentFinding[]>([]);
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
  }, [refreshFindings]);

  const onTurnComplete = useCallback(() => {
    if (activeCase) refreshFindings(activeCase.id);
  }, [activeCase, refreshFindings]);

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
  const profileMismatch =
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
                <strong>{activeCase.os_profile}</strong>
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
        />

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
      </div>
    </div>
  );
}
