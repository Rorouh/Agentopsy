import type { Case } from "../api/types";
import { useActiveCase } from "../state/activeCase";
import { useCaseFacts } from "../state/caseFacts";
import { useTheme } from "../ThemeProvider";
import { PHASES, UTILITIES, type ViewId } from "../navigation/navItems";

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
  const { theme, toggle } = useTheme();
  const facts = useCaseFacts();

  // Estado del CASO por fase. Sin caso, todo pendiente: no hay nada que
  // presumir. Timeline no expone hoy un contador barato de super-timeline
  // generada, así que se queda sin meta (TODO) en vez de fingir una.
  const phaseState = (id: ViewId): PhaseState => {
    if (!activeCase || !facts.loaded) return "pending";
    switch (id) {
      case "repository":
        return facts.evidenceTotal > 0 ? "done" : "current";
      case "investigation":
        if (facts.evidenceTotal === 0) return "pending";
        return facts.findings > 0 ? "done" : "current";
      case "mitre":
        return facts.findings > 0 ? "next" : "pending";
      case "timeline":
        return "pending";
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
      case "mitre":
        return facts.findings > 0 ? "hallazgos por correlacionar" : "";
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
        <div className="brand-tagline">Análisis post-mortem</div>
      </div>

      <div className="sidebar-case">
        <div className="eyebrow">Caso</div>
        {activeCase ? (
          <>
            <div className="sidebar-case-name">{activeCase.name}</div>
            <div className="sidebar-case-meta">
              {activeCase.os_profile ?? "perfil sin determinar"}
              {" · "}
              {STATUS_LABEL[activeCase.status]}
            </div>
          </>
        ) : (
          <div className="sidebar-case-meta">Sin caso seleccionado</div>
        )}
        {onOpenCaseSearch && (
          <button type="button" className="sidebar-case-action" onClick={onOpenCaseSearch}>
            {activeCase ? "cambiar caso" : "seleccionar caso"}
          </button>
        )}
      </div>

      {onOpenNewCase && (
        <div className="sidebar-newcase">
          <button type="button" className="btn-newcase" onClick={onOpenNewCase}>
            <svg
              width="15"
              height="15"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
            >
              <line x1="12" y1="5" x2="12" y2="19" />
              <line x1="5" y1="12" x2="19" y2="12" />
            </svg>
            Nuevo caso
          </button>
        </div>
      )}

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
                    {state === "done" ? "✓" : ""}
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

      <div className="sidebar-theme">
        <button type="button" className="theme-toggle" onClick={toggle} title="Cambiar el tema">
          {theme === "dark" ? "○ claro" : "● oscuro"}
        </button>
      </div>
    </aside>
  );
}
