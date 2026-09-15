import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import type { AgentFinding, Capabilities, Case, ToolUsage } from "../api/types";
import type { ViewId } from "../navigation/navItems";
import { useActiveCase } from "../state/activeCase";
import { useCaseEvidence } from "../state/caseEvidence";
import { useCaseStream } from "../state/casePulse";
import { usePublishShellHeader } from "../layout/shellHeader";
import { useLang, type MessageKey } from "../i18n";
import { Icon } from "../ui/Icon";
import { DETECTED_KIND_KEY, evidenceFileName } from "../utils/evidence";
import { ChatPage } from "./ChatPage";

interface InvestigationPageProps {
  caps: Capabilities | null;
  onNavigate?: (view: ViewId) => void;
  // Refresca capabilities en App (p. ej. tras conectar un ejecutor CLI desde el
  // selector del chat) para que la fila pase a Disponible sin recargar.
  onCapsRefresh?: () => Promise<void> | void;
}

const SEVERITY_KEY: Record<AgentFinding["severity"], MessageKey> = {
  low: "severity.low",
  medium: "severity.medium",
  high: "severity.high",
  critical: "severity.critical",
};

// FASE 2 · Investigación. Envuelve el chat con el panel de contexto: hallazgos
// que el agente persiste vía `record_finding` y herramientas usadas. El panel se
// refresca tras cada turno (ChatPage llama a onTurnComplete en su finally).
export function InvestigationPage({ caps, onNavigate, onCapsRefresh }: InvestigationPageProps) {
  const { activeCase, phase: casesPhase, error: casesError } = useActiveCase();
  // La evidencia del caso viene del store compartido, no de una lectura propia al
  // montar: registrar una imagen mientras el perito está en esta vista tiene que
  // llegar hasta aquí sin recargar la página.
  //
  // TODAS las evidencias del caso son el alcance de la investigación, por igual:
  // aquí no hay una evidencia «activa» ni primaria. Antes se tomaba `evidence[0]`
  // (la última registrada), el backend la usaba por defecto y acababan atribuidos
  // a ella hallazgos que salían de las demás.
  const { evidence } = useCaseEvidence();
  // El panel de contexto se refresca tras cada turno del chat, pero un análisis
  // en SEGUNDO PLANO sigue corriendo cuando el perito se va a otra sección y
  // vuelve: el pulso es lo que lo mantiene al día en ese caso.
  const { t, tn } = useLang();
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

  const onTurnComplete = useCallback(() => {
    if (activeCase) {
      void refreshFindings(activeCase.id);
      void refreshToolUsage(activeCase.id);
    }
  }, [activeCase, refreshFindings, refreshToolUsage]);

  usePublishShellHeader(
    {
      title: t("nav.investigation"),
      // La evidencia ya no viaja aquí: vive en el panel derecho, donde cabe
      // entera y puede decir además si está verificada. La cabecera se queda
      // con el título y la salida de fase.
      meta: activeCase ? undefined : t("common.noCase"),
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
                ? t("inv.nothingToCorrelate")
                : undefined
            }
            onClick={() => onNavigate("mitre")}
          >
            {t("inv.goToAttack")} →
          </button>
        ) : undefined,
    },
    [activeCase?.id, findings.length, t],
  );

  if (casesPhase === "loading") {
    return (
      <div className="view-scroll">
        <div className="loading-state">
          <span className="spinner" aria-hidden="true" />
          <span>{t("inv.loadingContext")}</span>
        </div>
      </div>
    );
  }

  if (casesPhase === "error") {
    return (
      <div className="view-scroll">
        <div className="error-state">
          <strong>{t("findings.loadCaseFailed")}</strong> {casesError}
        </div>
      </div>
    );
  }

  if (!activeCase) {
    return (
      <div className="view-scroll">
        <div className="empty-rail">
          <div className="empty-rail-title">{t("findings.noCase")}</div>
          <div className="empty-rail-body">{t("inv.noCaseBody")}</div>
        </div>
        {onNavigate && (
          <div className="cta-row">
            <button type="button" className="link-action" onClick={() => onNavigate("repository")}>
              {t("findings.goToEvidence")} →
            </button>
          </div>
        )}
      </div>
    );
  }

  // RULE 2: detected_os NUNCA cambia el caso solo. Solo se expone el desacuerdo
  // y se dice qué perfil correspondería. "unknown" no es un desajuste, el
  // triage fue inconcluyente, no contradictorio. Un caso con os_profile todavía
  // null tampoco lo es: es «aún no», no «contradice». Se revisan TODAS las
  // evidencias del caso, no una: el aviso nombra las que desentonan.
  const mismatched =
    activeCase.os_profile != null
      ? evidence.filter(
          (e) => e.detected_os !== "unknown" && e.detected_os !== activeCase.os_profile,
        )
      : [];

  const toolTotal = toolUsage.reduce((n, u) => n + u.total, 0);

  return (
    <div className="investigation">
      {mismatched.length > 0 && (
        <div className="mismatch-banner">
          <strong>{t("inv.mismatchLead")}</strong>{" "}
          {t("inv.mismatchBodyA")} <code>{activeCase.os_profile}</code>{" "}
          {t("inv.mismatchBodyB")}{" "}
          {mismatched.map((e, i) => (
            <span key={e.evidence_id}>
              {i > 0 ? ", " : ""}
              <code>{evidenceFileName(e)}</code>: <code>{e.detected_os}</code>
            </span>
          ))}
          . {t("inv.mismatchBodyC")}{" "}
          (<code>agentopsy-{activeCase.os_profile}</code>) {t("inv.mismatchBodyD")}{" "}
          <strong>{t("inv.mismatchPath")}</strong>: {t("inv.mismatchBodyE")}
        </div>
      )}

      <div className={`inv-grid${panelOpen ? "" : " is-collapsed"}`}>
        <ChatPage
          caps={caps}
          activeCase={activeCase}
          evidence={evidence}
          onTurnComplete={onTurnComplete}
          onCapsRefresh={onCapsRefresh}
        />

        <aside className="inv-aside">
          <button
            type="button"
            className="inv-aside-toggle"
            title={t(panelOpen ? "inv.collapsePanel" : "inv.expandPanel")}
            aria-label={t(panelOpen ? "inv.collapsePanel" : "inv.expandPanel")}
            aria-expanded={panelOpen}
            onClick={() => setPanelOpen((o) => !o)}
          >
            <Icon name={panelOpen ? "panel-collapse" : "panel-expand"} size={15} />
          </button>

          {panelOpen && (
            <div className="inv-panel">
              {/* Las evidencias encabezan el panel: son el alcance de ESTA
                  investigación, igual que los contadores. TODAS, sin una
                  primaria: el agente las analiza por igual salvo que el perito
                  pida en su mensaje centrarse en alguna. Cada una dice si está
                  verificada, que es el dato que autoriza a empezar. */}
              <section className="inv-evidence">
                <div className="eyebrow">
                  {t("inv.evidences")} · {evidence.length}
                </div>
                {evidence.length === 0 ? (
                  <div className="inv-evidence-meta">{t("inv.noneRegistered")}</div>
                ) : (
                  <>
                    <ul className="inv-evidence-list">
                      {evidence.map((e) => (
                        <li className="inv-evidence-item" key={e.evidence_id}>
                          <div className="inv-evidence-name">{evidenceFileName(e)}</div>
                          <div className="inv-evidence-meta">
                            {t(DETECTED_KIND_KEY[e.detected_kind])} · sha {e.sha256.slice(0, 8)}
                            {e.last_verification?.verified && (
                              <>
                                {" · "}
                                <span className="inv-evidence-ok">{t("inv.verified")}</span>
                              </>
                            )}
                          </div>
                        </li>
                      ))}
                    </ul>
                    {evidence.length > 1 && (
                      <div className="inv-evidence-scope">{t("inv.scopeNote")}</div>
                    )}
                  </>
                )}
              </section>

              {/* Los dos bloques se reparten la altura del raíl y cada uno
                  scrollea POR DENTRO: el encabezado siempre visible, y una
                  lista larga de hallazgos ya no empuja Herramientas fuera de
                  la pantalla. */}
              <section className="inv-block">
                {/* Sin relleno de ceros: «00» se lee como un reloj, no como un
                    contador a cero. */}
                <div className="eyebrow">{t("nav.findings")} · {findings.length}</div>
                <div className="inv-block-scroll">
                  {findings.length === 0 ? (
                    <div className="inv-empty">{t("inv.noFindings")}</div>
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
                          {t(SEVERITY_KEY[f.severity])}
                          {f.tool_id ? ` · ${f.tool_id}` : ""}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </section>

              <section className="inv-block">
                <div className="eyebrow">{t("inv.tools")} · {toolTotal}</div>
                <div className="inv-block-scroll">
                  {toolUsage.length === 0 ? (
                    <div className="inv-empty">{t("inv.noneRun")}</div>
                  ) : (
                    toolUsage.map((u) => (
                      <div className="usage-row" key={u.tool_id}>
                        <span>{u.tool_id}</span>
                        <span className="usage-count">
                          {u.ok > 0 ? `${u.ok} ok` : ""}
                          {u.failed > 0
                            ? `${u.ok > 0 ? " · " : ""}${tn("count.failures", u.failed)}`
                            : ""}
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
