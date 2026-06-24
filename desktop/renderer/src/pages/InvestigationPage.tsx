import type { Capabilities } from "../global";
import type { CaseSummary, EvidenceFile, InvestigationFinding } from "../types/domain";
import type { ViewId } from "../navigation/navItems";
import { ChatPage } from "./ChatPage";
import { Badge } from "../ui/Badge";
import { ContextBanner } from "../ui/ContextBanner";
import { Button } from "../ui/Button";

interface InvestigationPageProps {
  caps: Capabilities | null;
  activeCase: CaseSummary;
  activeEvidence: EvidenceFile;
  findings: InvestigationFinding[];
  onNavigate?: (view: ViewId) => void;
}

const SEVERITY_LABEL: Record<InvestigationFinding["severity"], string> = {
  low: "Baja",
  medium: "Media",
  high: "Alta",
  critical: "Crítica",
};

// Envuelve el ChatPage existente (que ya habla con el sidecar vía window.forensia)
// añadiendo el framing de caso/evidencia y un panel lateral de hallazgos. El chat
// en sí no se toca: sigue siendo la única pieza con lógica de red real.
export function InvestigationPage({ caps, activeCase, activeEvidence, findings, onNavigate }: InvestigationPageProps) {
  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12, marginBottom: 4 }}>
        <div style={{ flex: 1 }}>
          <ContextBanner activeCase={activeCase} activeEvidence={activeEvidence} />
        </div>
        {onNavigate && (
          <Button variant="chip" onClick={() => onNavigate("timeline")} style={{ flexShrink: 0 }}>
            Ver Timeline →
          </Button>
        )}
      </div>

      <div className="investigation-layout" style={{ flex: 1, minHeight: 0 }}>
        <ChatPage caps={caps} />

        <div className="findings-panel">
          <div className="findings-panel-title">Hallazgos del caso</div>
          {findings.length === 0 ? (
            <div className="empty-state" style={{ padding: "20px 12px" }}>
              Aún no hay hallazgos registrados. Aparecerán aquí a medida que el agente los detecte.
            </div>
          ) : (
            findings.map((f) => (
              <div className="finding-card" key={f.id}>
                <div className="finding-card-title">{f.title}</div>
                <div className="finding-card-summary">{f.summary}</div>
                <Badge variant={f.severity}>{SEVERITY_LABEL[f.severity]}</Badge>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
