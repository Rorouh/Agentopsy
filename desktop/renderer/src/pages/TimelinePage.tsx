import { useMemo, useState } from "react";
import type { CaseSummary, EvidenceFile, TimelineEvent, TimelineSeverity } from "../types/domain";
import type { ViewId } from "../navigation/navItems";
import { Card } from "../ui/Card";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { EmptyState } from "../ui/EmptyState";
import { PageHeader } from "../ui/PageHeader";
import { ContextBanner } from "../ui/ContextBanner";
import { formatDate } from "../utils/format";

interface TimelinePageProps {
  activeCase: CaseSummary;
  activeEvidence?: EvidenceFile;
  events: TimelineEvent[];
  onNavigate?: (view: ViewId) => void;
}

const SEVERITY_LABEL: Record<TimelineSeverity, string> = {
  low: "Baja",
  medium: "Media",
  high: "Alta",
  critical: "Crítica",
};

const SEVERITY_FILTERS: (TimelineSeverity | "all")[] = ["all", "low", "medium", "high", "critical"];

export function TimelinePage({ activeCase, activeEvidence, events, onNavigate }: TimelinePageProps) {
  const [filter, setFilter] = useState<TimelineSeverity | "all">("all");

  const filtered = useMemo(
    () => (filter === "all" ? events : events.filter((e) => e.severity === filter)),
    [events, filter],
  );

  return (
    <div>
      <PageHeader
        title="Timeline de eventos"
        subtitle="Secuencia cronológica de hallazgos extraídos por las herramientas forenses sobre la evidencia seleccionada."
        actions={
          onNavigate && (
            <Button variant="chip" onClick={() => onNavigate("document-viewer")}>
              Ver Documentos →
            </Button>
          )
        }
      />

      <ContextBanner activeCase={activeCase} activeEvidence={activeEvidence} />

      {!activeEvidence ? (
        <EmptyState
          title="Ninguna evidencia seleccionada"
          description="Selecciona una evidencia verificada en Casos y evidencias para construir su línea de tiempo."
        />
      ) : (
        <>
          <div className="filters-row">
            {SEVERITY_FILTERS.map((f) => (
              <Button key={f} variant="chip" className={filter === f ? "active" : ""} onClick={() => setFilter(f)}>
                {f === "all" ? "Todas" : SEVERITY_LABEL[f]}
              </Button>
            ))}
          </div>

          <Card fullWidth>
            {filtered.length === 0 ? (
              <EmptyState title="No hay eventos con ese filtro de severidad" />
            ) : (
              <div className="timeline-list">
                {filtered.map((ev) => (
                  <div className="timeline-item" key={ev.id}>
                    <div className="timeline-item-header">
                      <span className="timeline-time">{formatDate(ev.timestamp)}</span>
                      <span className="timeline-source">{ev.source}</span>
                      <Badge variant={ev.severity}>{SEVERITY_LABEL[ev.severity]}</Badge>
                    </div>
                    <p className="timeline-desc">{ev.description}</p>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
