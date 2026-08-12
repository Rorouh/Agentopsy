import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import type { AgentFinding, Capabilities, Case, ToolUsage } from "../api/types";
import type { ViewId } from "../navigation/navItems";
import { useActiveCase } from "../state/activeCase";
import { useCaseEvidence } from "../state/caseEvidence";
import { useCaseStream } from "../state/casePulse";
import { usePublishShellHeader } from "../layout/shellHeader";
import { Icon } from "../ui/Icon";
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
      // La evidencia ya no viaja aquí: vive en el panel derecho, donde cabe
      // entera y puede decir además si está verificada. La cabecera se queda
      // con el título y la salida de fase.
      meta: activeCase ? undefined : "sin caso seleccionado",
      action:
        onNavigate && activeCase ? (
          // Apagada mientras no haya nada que correlacionar: siendo la única
          // superficie llena de la vista, invitaba a salir de la pantalla antes
          // de haber hecho nada en ella.
          <button
            type="button"
            disabled={findings.length === 0}
            title={
              findings.length === 0
                ? "Todavía no hay hallazgos que correlacionar"
                : undefined
            }
            onClick={() => onNavigate("mitre")}
          >
            Pasar a ATT&amp;CK →
          </button>
        ) : undefined,
    },
    [activeCase?.id, findings.length],
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
            title={panelOpen ? "Plegar el panel de contexto" : "Desplegar el panel de contexto"}
            aria-label={
              panelOpen ? "Plegar el panel de contexto" : "Desplegar el panel de contexto"
            }
            aria-expanded={panelOpen}
            onClick={() => setPanelOpen((o) => !o)}
          >
            <Icon name={panelOpen ? "panel-collapse" : "panel-expand"} size={15} />
          </button>

          {panelOpen && (
            <div className="inv-panel">
              {/* La evidencia encabeza el panel: es el estado de ESTA
                  investigación, igual que los contadores. Bajó de la cabecera
                  porque allí se cortaba y no cabía decir si está verificada,
                  que es el dato que autoriza a empezar. */}
              <section className="inv-evidence">
                <div className="eyebrow">Evidencia</div>
                {evidenceName ? (
                  <>
                    <div className="inv-evidence-name">{evidenceName}</div>
                    <div className="inv-evidence-meta">
                      sha {activeEvidence?.sha256.slice(0, 8)}
                      {activeEvidence?.last_verification?.verified && (
                        <>
                          {" · "}
                          <span className="inv-evidence-ok">verificada</span>
                        </>
                      )}
                    </div>
                  </>
                ) : (
                  <div className="inv-evidence-meta">ninguna registrada</div>
                )}
              </section>

              {/* Los dos bloques se reparten la altura del raíl y cada uno
                  scrollea POR DENTRO: el encabezado siempre visible, y una
                  lista larga de hallazgos ya no empuja Herramientas fuera de
                  la pantalla. */}
              <section className="inv-block">
                {/* Sin relleno de ceros: «00» se lee como un reloj, no como un
                    contador a cero. */}
                <div className="eyebrow">Hallazgos · {findings.length}</div>
                <div className="inv-block-scroll">
                  {findings.length === 0 ? (
                    <div className="inv-empty">Sin hallazgos.</div>
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
                <div className="eyebrow">Herramientas · {toolTotal}</div>
                <div className="inv-block-scroll">
                  {toolUsage.length === 0 ? (
                    <div className="inv-empty">Ninguna ejecutada.</div>
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
