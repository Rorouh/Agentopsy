import type { CaseSummary, EvidenceFile } from "../types/domain";
import type { ViewId } from "../navigation/navItems";
import { Card } from "../ui/Card";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { PageHeader } from "../ui/PageHeader";
import { ContextBanner } from "../ui/ContextBanner";
import { MetricCard } from "../ui/MetricCard";
import { formatBytes, formatDate, shortHash } from "../utils/format";

interface RepositoryPageProps {
  activeCase: CaseSummary;
  activeEvidence: EvidenceFile;
  evidenceFiles: EvidenceFile[];
  onNavigate?: (view: ViewId) => void;
}

const STATUS_BADGE: Record<EvidenceFile["status"], { variant: "neutral" | "medium" | "success" | "critical"; label: string }> = {
  pending: { variant: "neutral", label: "Pendiente" },
  hashing: { variant: "medium", label: "Calculando hash…" },
  verified: { variant: "success", label: "Verificado" },
  error: { variant: "critical", label: "Error" },
};

export function RepositoryPage({ activeCase, activeEvidence, evidenceFiles, onNavigate }: RepositoryPageProps) {
  const verifiedCount = evidenceFiles.filter((e) => e.status === "verified").length;
  const pendingCount = evidenceFiles.filter((e) => e.status !== "verified").length;

  return (
    <div>
      <PageHeader
        title="Casos y evidencias"
        subtitle="Crea el caso, registra la evidencia y deja que FORENSIA calcule el hash baseline antes de exponerla a cualquier herramienta."
        actions={
          onNavigate && (
            <Button variant="chip" onClick={() => onNavigate("investigation")}>
              Investigar este caso →
            </Button>
          )
        }
      />

      <ContextBanner activeCase={activeCase} activeEvidence={activeEvidence} />

      <div className="metric-row">
        <MetricCard label="Evidencias registradas" value={String(evidenceFiles.length)} />
        <MetricCard label="Verificadas (hash OK)" value={String(verifiedCount)} variant="success" />
        <MetricCard label="Pendientes / en proceso" value={String(pendingCount)} variant={pendingCount > 0 ? "warning" : "neutral"} />
      </div>

      <div className="status-grid">
        {/* Formulario mock de nuevo caso — integración futura: forensia.cases.create() */}
        <Card>
          <h3>Nuevo caso</h3>
          <div className="form-grid">
            <div className="form-field full-width">
              <label className="form-label">Nombre del caso</label>
              <input className="form-input" defaultValue={activeCase.name} disabled />
            </div>
            <div className="form-field">
              <label className="form-label">Examinador</label>
              <input className="form-input" defaultValue={activeCase.examiner} disabled />
            </div>
            <div className="form-field">
              <label className="form-label">Estado</label>
              <select className="form-select" defaultValue={activeCase.status} disabled>
                <option value="open">Abierto</option>
                <option value="closed">Cerrado</option>
                <option value="archived">Archivado</option>
              </select>
            </div>
            <div className="form-field full-width">
              <label className="form-label">Descripción</label>
              <textarea className="form-textarea" rows={3} defaultValue={activeCase.description} disabled />
            </div>
          </div>
          <div className="cta-row">
            <Button variant="chip" disabled>Guardar caso (mock)</Button>
          </div>
        </Card>

        {/* Dropzone visual — integración futura: forensia.evidence.ingest(file) */}
        <Card>
          <h3>Registrar evidencia</h3>
          <div className="dropzone">
            <div className="dropzone-title">Arrastra una imagen forense aquí</div>
            <div className="dropzone-hint">.E01 · .raw · .vmdk · volcado de memoria — solo lectura desde el origen</div>
            <div className="cta-row" style={{ justifyContent: "center" }}>
              <Button variant="chip" disabled>Seleccionar archivo (mock)</Button>
            </div>
          </div>
        </Card>

        <Card fullWidth>
          <h3>Evidencias del caso ({evidenceFiles.length})</h3>
          {evidenceFiles.length === 0 ? (
            <div className="empty-state">Aún no hay evidencia registrada en este caso.</div>
          ) : (
            <div className="file-list">
              {evidenceFiles.map((ev) => {
                const status = STATUS_BADGE[ev.status];
                const isActive = ev.id === activeEvidence.id;
                return (
                  <div className="file-row" key={ev.id} style={isActive ? { borderColor: "var(--accent)" } : undefined}>
                    <div className="file-row-main">
                      <div>
                        <div className="file-row-name">
                          {ev.name} {isActive && <Badge variant="low">Activa</Badge>}
                        </div>
                        <div className="file-row-meta">
                          {ev.kind.toUpperCase()} · {formatBytes(ev.sizeBytes)} · añadido {formatDate(ev.addedAt)}
                        </div>
                      </div>
                    </div>
                    <div className="file-row-side">
                      <span className="file-row-hash" title={ev.sha256 ?? undefined}>SHA-256: {shortHash(ev.sha256)}</span>
                      <Badge variant={status.variant}>{status.label}</Badge>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
