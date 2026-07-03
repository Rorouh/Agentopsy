import type { CaseSummary, EvidenceFile, MitreTechniqueMatch } from "../types/domain";
import { Card } from "../ui/Card";
import { Badge } from "../ui/Badge";
import { EmptyState } from "../ui/EmptyState";
import { PageHeader } from "../ui/PageHeader";
import { ContextBanner } from "../ui/ContextBanner";

interface MitreAttackPageProps {
  activeCase: CaseSummary;
  activeEvidence?: EvidenceFile;
  matches: MitreTechniqueMatch[];
}

export function MitreAttackPage({ activeCase, activeEvidence, matches }: MitreAttackPageProps) {
  const correlated = matches.filter((m) => m.status === "correlated");
  const pending = matches.filter((m) => m.status === "pending");

  return (
    <div>
      <PageHeader
        title="MITRE ATT&CK"
        subtitle="Mapeo de los hallazgos de la investigación a tácticas y técnicas del framework MITRE ATT&CK."
      />

      <ContextBanner activeCase={activeCase} activeEvidence={activeEvidence} />

      {matches.length === 0 ? (
        <EmptyState
          title="Pendiente de correlación"
          description="Aún no hay hallazgos suficientes para correlacionar con tácticas/técnicas MITRE ATT&CK."
        />
      ) : (
        <>
          <div className="mitre-grid">
            {correlated.map((m) => (
              <Card key={m.id}>
                <div className="mitre-card-header">
                  <div>
                    <div className="mitre-tactic">{m.tacticId} · {m.tacticName}</div>
                    <div className="mitre-technique-id">{m.techniqueId}</div>
                  </div>
                  <Badge variant="success">Correlado</Badge>
                </div>
                <div className="mitre-technique-name">{m.techniqueName}</div>
                <div className="confidence-row">
                  <div className="confidence-bar">
                    <div className="confidence-fill" style={{ width: `${m.confidence}%` }} />
                  </div>
                  <span className="confidence-label">{m.confidence}% confianza</span>
                </div>
                <div style={{ marginTop: 10, fontFamily: "var(--font-sans)", fontSize: 12, color: "var(--text-muted)" }}>
                  {m.relatedFindingIds.length} hallazgo(s) vinculado(s)
                </div>
              </Card>
            ))}
          </div>

          {pending.length > 0 && (
            <>
              <div style={{ height: 16 }} />
              <Card fullWidth>
                <h3>Pendientes de correlación</h3>
                <div className="file-list">
                  {pending.map((m) => (
                    <div className="file-row" key={m.id}>
                      <div className="file-row-main">
                        <div>
                          <div className="file-row-name">{m.tacticId} · {m.techniqueId} — {m.techniqueName}</div>
                          <div className="file-row-meta">{m.tacticName}</div>
                        </div>
                      </div>
                      <Badge variant="neutral">Pendiente de correlación</Badge>
                    </div>
                  ))}
                </div>
              </Card>
            </>
          )}
        </>
      )}
    </div>
  );
}
