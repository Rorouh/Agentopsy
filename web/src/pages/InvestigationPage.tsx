import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import type { AgentFinding, Capabilities, Case, ToolUsage } from "../api/types";
import type { ViewId } from "../navigation/navItems";
import { useActiveCase } from "../state/activeCase";
import { useCaseEvidence } from "../state/caseEvidence";
import { useCaseStream } from "../state/casePulse";
import { usePublishShellHeader } from "../layout/shellHeader";
import { ChatPage } from "./ChatPage";

interface InvestigationPageProps {
  caps: Capabilities | null;
  onNavigate?: (view: ViewId) => void;
  // Refresca capabilities en App (p. ej. tras conectar un ejecutor CLI desde el
  // selector del chat) para que la fila pase a Disponible sin recargar.
  onCapsRefresh?: () => Promise<void> | void;
}

const SEVERITY_LABEL: Record<AgentFinding["severity"], string> = {
  low: "baja",
  medium: "media",
  high: "alta",
  critical: "crítica",
};

// FASE 2 · Investigación. Envuelve el chat con el panel de contexto: hallazgos
// que el agente persiste vía `record_finding` y herramientas usadas. El panel se
// refresca tras cada turno (ChatPage llama a onTurnComplete en su finally).
export function InvestigationPage({ caps, onNavigate, onCapsRefresh }: InvestigationPageProps) {
  const { activeCase, phase: casesPhase, error: casesError } = useActiveCase();
  // La evidencia del caso viene del store compartido, no de una lectura propia al
  // montar: registrar una imagen mientras el perito está en esta vista tiene que
  // llegar hasta aquí. Con la lectura local, el chat seguía mandando
  // `evidence_id` vacío hasta que se recargaba la página.
  const { evidence } = useCaseEvidence();
  // El panel de contexto se refresca tras cada turno del chat, pero un análisis
  // en SEGUNDO PLANO sigue corriendo cuando el perito se va a otra sección y
  // vuelve: el pulso es lo que lo mantiene al día en ese caso.
  const revPanel = useCaseStream("findings", "audit");
  const [findings, setFindings] = useState<AgentFinding[]>([]);
  const [toolUsage, setToolUsage] = useState<ToolUsage[]>([]);
  const [panelOpen, setPanelOpen] = useState(true);

  const refreshFindings = useCallback(async (caseId: string) => {
    try {
      setFindings(await api.cases.listFindings(caseId));
    } catch {
      // 404 = sin findings.jsonl aún. No es error, es estado vacío.
      setFindings([]);
    }
  }, []);

  const refreshToolUsage = useCallback(async (caseId: string) => {
    try {
      setToolUsage(await api.cases.listToolUsage(caseId));
    } catch {
      // Sin audit.jsonl aún → sin herramientas ejecutadas. Vacío, no error.
      setToolUsage([]);
    }
  }, []);

  // Contexto del caso activo: hallazgos + herramientas. Se recarga al cambiar de
  // caso (desde el sidebar o cualquier otra vista). La evidencia no se pide aquí,
  // la sirve el store.
  useEffect(() => {
    const caseId = activeCase?.id;
    if (!caseId) {
      setFindings([]);
      setToolUsage([]);
      return;
    }
    let cancelled = false;
    (async () => {
      await refreshFindings(caseId);
      if (cancelled) return;
      await refreshToolUsage(caseId);
    })();
    return () => {
      cancelled = true;
    };
  }, [activeCase?.id, revPanel, refreshFindings, refreshToolUsage]);

  const activeEvidence = evidence.length > 0 ? evidence[0] : null;

  const onTurnComplete = useCallback(() => {
    if (activeCase) {
      void refreshFindings(activeCase.id);
      void refreshToolUsage(activeCase.id);
    }
  }, [activeCase, refreshFindings, refreshToolUsage]);

  const evidenceName = activeEvidence
    ? activeEvidence.original_path.split("/").pop() ?? activeEvidence.original_path
    : null;

  usePublishShellHeader(
    {
      title: "Investigación",
      meta: activeCase
        ? evidenceName
          ? `${evidenceName} · ${activeEvidence?.sha256.slice(0, 8)}`
          : "sin evidencia registrada todavía"
        : "sin caso seleccionado",
      action:
        onNavigate && activeCase ? (
          <button type="button" onClick={() => onNavigate("mitre")}>
            Pasar a ATT&amp;CK →
          </button>
        ) : undefined,
    },
    [activeCase?.id, evidenceName, activeEvidence?.sha256],
  );

  if (casesPhase === "loading") {
    return (
      <div className="view-scroll">
        <div className="loading-state">
          <span className="spinner" aria-hidden="true" />
          <span>Cargando contexto del caso…</span>
        </div>
      </div>
    );
  }

  if (casesPhase === "error") {
    return (
      <div className="view-scroll">
        <div className="error-state">
          <strong>No se pudo cargar el caso activo:</strong> {casesError}
        </div>
      </div>
    );
  }

  if (!activeCase) {
    return (
      <div className="view-scroll">
        <div className="empty-rail">
          <div className="empty-rail-title">Sin caso abierto</div>
          <div className="empty-rail-body">
            Abre uno con «Nuevo caso» en el lateral y regístrale evidencia antes de investigar:
            el agente solo trabaja sobre un handle hash-verificado.
          </div>
        </div>
        {onNavigate && (
          <div className="cta-row">
            <button type="button" className="link-action" onClick={() => onNavigate("repository")}>
              Ir a Evidencia →
            </button>
          </div>
        )}
      </div>
    );
  }

  // RULE 2: detected_os NUNCA cambia el caso solo. Solo se expone el desacuerdo
  // y se dice qué perfil correspondería. "unknown" no es un desajuste, el
  // triage fue inconcluyente, no contradictorio. Un caso con os_profile todavía
  // null tampoco lo es: es «aún no», no «contradice».
  const profileMismatch =
    activeCase.os_profile != null &&
    activeEvidence != null &&
    activeEvidence.detected_os !== "unknown" &&
    activeEvidence.detected_os !== activeCase.os_profile
      ? activeEvidence.detected_os
      : null;

  const toolTotal = toolUsage.reduce((n, t) => n + t.total, 0);

  return (
    <div className="investigation">
      {profileMismatch && (
        <div className="mismatch-banner">
          <strong>
            Desajuste de perfil: el agente activo no es el adecuado para esta evidencia.
          </strong>{" "}
          El caso declara <code>perfil = {activeCase.os_profile}</code> pero la determinación
          sobre el contenido de la evidencia dice <code>{profileMismatch}</code>. El agente del
          caso (<code>forensia-{activeCase.os_profile}</code>) se negará a invocar herramientas
          mientras siga el desacuerdo. Resuélvelo en <strong>Evidencia → Sistema operativo</strong>:
          al anclar el perfil, Agentopsy re-enruta solo al sub-agente que corresponde. No lo
          cambia por ti (RULE 2, un desacuerdo lo decide el operador, no el programa).
        </div>
      )}

      <div className={`inv-grid${panelOpen ? "" : " is-collapsed"}`}>
        <ChatPage
          caps={caps}
          activeCase={activeCase}
          activeEvidence={activeEvidence}
          onTurnComplete={onTurnComplete}
          onCapsRefresh={onCapsRefresh}
        />

        <aside className="inv-aside">
          <button
            type="button"
            className="inv-aside-toggle"
            title="Colapsar o expandir el panel de contexto"
            aria-expanded={panelOpen}
            onClick={() => setPanelOpen((o) => !o)}
          >
            {panelOpen ? "›" : "‹"}
          </button>

          {panelOpen && (
            <div className="inv-panel">
              {/* Los dos bloques se reparten la altura del raíl y cada uno
                  scrollea POR DENTRO: el encabezado siempre visible, y una
                  lista larga de hallazgos ya no empuja Herramientas fuera de
                  la pantalla. */}
              <section className="inv-block">
                <div className="eyebrow">
                  Hallazgos · {String(findings.length).padStart(2, "0")}
                </div>
                <div className="inv-block-scroll">
                  {findings.length === 0 ? (
                    <div className="inv-empty">
                      Aún no hay hallazgos. El agente los irá apilando aquí a medida que analice.
                    </div>
                  ) : (
                    findings.map((f) => (
                      <div
                        className={`finding-rail${
                          f.severity === "critical" || f.severity === "high" ? " is-hot" : ""
                        }`}
                        key={f.id}
                      >
                        <div className="finding-rail-title">{f.title}</div>
                        <div className="finding-rail-summary">{f.summary}</div>
                        <div className="finding-rail-meta">
                          {SEVERITY_LABEL[f.severity]}
                          {f.tool_id ? ` · ${f.tool_id}` : ""}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </section>

              <section className="inv-block">
                <div className="eyebrow">
                  Herramientas · {String(toolTotal).padStart(2, "0")}
                </div>
                <div className="inv-block-scroll">
                  {toolUsage.length === 0 ? (
                    <div className="inv-empty">
                      Aún no se ha ejecutado ninguna herramienta. Aparecerán aquí con su número de
                      usos cuando el agente las invoque.
                    </div>
                  ) : (
                    toolUsage.map((t) => (
                      <div className="usage-row" key={t.tool_id}>
                        <span>{t.tool_id}</span>
                        <span className="usage-count">
                          {t.ok > 0 ? `${t.ok} ok` : ""}
                          {t.failed > 0 ? `${t.ok > 0 ? " · " : ""}${t.failed} fallo${t.failed > 1 ? "s" : ""}` : ""}
                        </span>
                      </div>
                    ))
                  )}
                </div>
              </section>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}
