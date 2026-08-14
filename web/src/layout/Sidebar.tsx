import type { Case } from "../api/types";
import { useActiveCase } from "../state/activeCase";
import { useCaseFacts } from "../state/caseFacts";
import { PHASES, UTILITIES, type ViewId } from "../navigation/navItems";
import { Icon } from "../ui/Icon";

interface SidebarProps {
  activeView: ViewId;
  onViewChange: (view: ViewId) => void;
  // «cambiar caso» y «Nuevo caso» viven ahora en el sidebar, pero los diálogos
  // siguen siendo los de la vista de evidencia: el armazón solo los dispara.
  onOpenCaseSearch?: () => void;
  onOpenNewCase?: () => void;
}

// Estado de una fase DEL CASO, independiente de la vista abierta.
type PhaseState = "done" | "current" | "next" | "pending";

const STATUS_LABEL: Record<Case["status"], string> = {
  active: "abierto",
  closed: "cerrado",
};

export function Sidebar({
  activeView,
  onViewChange,
  onOpenCaseSearch,
  onOpenNewCase,
}: SidebarProps) {
  // El caso activo lo sirve el store global: el sidebar no vuelve a pedirlo al
  // api ni mantiene una copia que pueda quedarse vieja tras editar el caso. Las
  // cifras salen del MISMO hook que la Guía, para que no se contradigan.
  const { activeCase } = useActiveCase();
  const facts = useCaseFacts();

  // Estado del CASO por fase. Sin caso, todo pendiente: no hay nada que
  // presumir.
  //
  // Cada fase se da por HECHA cuando el caso tiene su producto, y la cifra que lo
  // dice es siempre real (RULE 2). Correlación ATT&CK y Timeline se quedaban
  // fuera: la primera no pasaba nunca de «next» y la segunda estaba fijada a
  // «pending», así que sus dos círculos no se rellenaban jamás por mucho que la
  // sección tuviera contenido. Ahora la correlación está hecha cuando la matriz
  // tiene al menos una técnica tocada, y el timeline cuando la capa del
  // incidente, que es la que se lleva al informe, sitúa al menos un evento en el
  // eje.
  const phaseState = (id: ViewId): PhaseState => {
    if (!activeCase || !facts.loaded) return "pending";
    switch (id) {
      case "repository":
        return facts.evidenceTotal > 0 ? "done" : "current";
      case "investigation":
        if (facts.evidenceTotal === 0) return "pending";
        return facts.findings > 0 ? "done" : "current";
      case "mitre":
        if (facts.findings === 0) return "pending";
        return facts.mitreTechniques > 0 ? "done" : "next";
      case "timeline":
        if (facts.findings === 0) return "pending";
        return facts.incidentEvents > 0 ? "done" : "next";
      case "findings":
        return facts.findings > 0 ? "done" : "pending";
      case "graphs":
        if (facts.findings === 0) return "pending";
        return facts.graphs > 0 ? "done" : "next";
      case "document-viewer":
        return facts.documents > 0 ? "done" : "pending";
      default:
        return "pending";
    }
  };

  const phaseMeta = (id: ViewId): string => {
    if (!activeCase || !facts.loaded) return "";
    switch (id) {
      case "repository":
        if (facts.evidenceTotal === 0) return "sin evidencia";
        return `${facts.evidenceTotal} ${facts.evidenceTotal === 1 ? "fichero" : "ficheros"} · ${facts.evidenceVerified} verificados`;
      case "investigation":
        if (facts.findings === 0) return "sin hallazgos";
        return `${facts.findings} ${facts.findings === 1 ? "hallazgo" : "hallazgos"}`;
      case "mitre": {
        if (facts.findings === 0) return "";
        if (facts.mitreTechniques === 0) return "hallazgos por correlacionar";
        const tecnicas = `${facts.mitreTechniques} ${facts.mitreTechniques === 1 ? "técnica" : "técnicas"}`;
        // Los dos ejes se enuncian por separado, nunca fundidos: una técnica
        // propuesta por el agente no es un dictamen del perito.
        return facts.mitreAdjudicated === 0
          ? `${tecnicas} · sin dictaminar`
          : `${tecnicas} · ${facts.mitreAdjudicated} con dictamen`;
      }
      case "timeline": {
        if (facts.findings === 0) return "";
        // Lo que no se puede situar en el eje viaja CONTADO, aquí también: un
        // hallazgo sin fecha explica por qué la fase no está hecha.
        if (facts.incidentEvents === 0) {
          if (facts.incidentUndated === 0) return "sin eventos en el eje";
          return `${facts.incidentUndated} sin fecha situable`;
        }
        const eventos = `${facts.incidentEvents} ${facts.incidentEvents === 1 ? "evento" : "eventos"}`;
        return facts.incidentUndated === 0
          ? eventos
          : `${eventos} · ${facts.incidentUndated} sin fecha`;
      }
      case "findings":
        if (facts.findings === 0) return "sin hallazgos";
        return `${facts.findings} ${facts.findings === 1 ? "hallazgo" : "hallazgos"}`;
      case "graphs":
        if (facts.findings === 0) return "";
        if (facts.graphs === 0) return "sin grafos";
        return `${facts.graphs} de ${facts.findings} con grafo`;
      case "document-viewer":
        if (facts.documents === 0) return "sin documentos";
        return `${facts.documents} ${facts.documents === 1 ? "documento" : "documentos"}`;
      default:
        return "";
    }
  };

  return (
    <aside className="sidebar">
      <div className="brand-section">
        <div className="brand-name">AGENTOPSY</div>
      </div>

      {/* Elegir caso y crear caso son el MISMO momento, así que viven juntos y
          en un solo control. El nombre es el selector: la posición más el icono
          ya dicen «esto se cambia», de modo que la etiqueta «Caso» sobraba. El
          perfil (unix/windows) tampoco se repite aquí: su sitio es Evidencia,
          junto a la huella de triage que lo justifica. Y el estado sólo se
          enuncia cuando es CERRADO: abierto es lo normal y no explica nada,
          cerrado es lo que explica que no te deje registrar evidencia. */}
      <div className="sidebar-case">
        <button
          type="button"
          className="case-picker-row"
          onClick={onOpenCaseSearch}
          disabled={!onOpenCaseSearch}
          // El nombre completo, por si ni con dos renglones cabe.
          title={activeCase ? `${activeCase.name} · cambiar de caso` : "Elegir un caso"}
        >
          <span className={`case-picker-name${activeCase ? "" : " is-empty"}`}>
            {activeCase ? activeCase.name : "Elige un caso"}
          </span>
          {activeCase?.status === "closed" && (
            <span className="case-picker-closed">{STATUS_LABEL.closed}</span>
          )}
          <svg
            className="case-picker-icon"
            width="15"
            height="15"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <polyline points="8 9 12 5 16 9" />
            <polyline points="16 15 12 19 8 15" />
          </svg>
        </button>

        {onOpenNewCase && (
          <button type="button" className="case-new-action" onClick={onOpenNewCase}>
            <svg
              width="13"
              height="13"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              aria-hidden="true"
            >
              <line x1="12" y1="5" x2="12" y2="19" />
              <line x1="5" y1="12" x2="19" y2="12" />
            </svg>
            crear caso
          </button>
        )}
      </div>

      <div className="sidebar-phases">
        <div className="eyebrow">Fases del caso</div>
        {/* DOS señales independientes: el PUNTO dice dónde está el CASO y no
            depende de la vista abierta; la FILA (barra izquierda + peso de la
            etiqueta) dice dónde estás TÚ. */}
        <div className="phase-rail">
          {PHASES.map((p, i) => {
            const state = phaseState(p.id);
            const selected = activeView === p.id;
            const meta = phaseMeta(p.id);
            return (
              <div className="phase-row" key={p.id}>
                <div className="phase-marker">
                  <span className={`phase-dot phase-dot--${state}`}>
                    {state === "done" && <Icon name="check" size={10} />}
                  </span>
                  {i < PHASES.length - 1 && (
                    <span className={`phase-line ${state === "done" ? "is-done" : ""}`} />
                  )}
                </div>
                <button
                  type="button"
                  className={`phase-button phase-button--${state} ${selected ? "is-selected" : ""}`}
                  aria-current={selected ? "page" : undefined}
                  onClick={() => onViewChange(p.id)}
                >
                  <span className="phase-label">{p.label}</span>
                  {meta && <span className="phase-meta">{meta}</span>}
                </button>
              </div>
            );
          })}
        </div>
      </div>

      <div className="sidebar-utilities">
        {UTILITIES.map((u) => (
          <button
            type="button"
            key={u.id}
            className={`utility-item ${activeView === u.id ? "is-active" : ""}`}
            aria-current={activeView === u.id ? "page" : undefined}
            onClick={() => onViewChange(u.id)}
          >
            {u.label}
          </button>
        ))}
      </div>

    </aside>
  );
}
