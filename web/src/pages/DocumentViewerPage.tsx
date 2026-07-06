import { useState } from "react";
import type { CaseSummary, EvidenceFile, ReportDocument } from "../types/domain";
import type { ViewId } from "../navigation/navItems";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { EmptyState } from "../ui/EmptyState";
import { PageHeader } from "../ui/PageHeader";
import { ContextBanner } from "../ui/ContextBanner";
import { formatDate, shortHash } from "../utils/format";

interface DocumentViewerPageProps {
  activeCase: CaseSummary;
  activeEvidence?: EvidenceFile;
  documents: ReportDocument[];
  onNavigate?: (view: ViewId) => void;
}

export function DocumentViewerPage({ activeCase, activeEvidence, documents, onNavigate }: DocumentViewerPageProps) {
  const [selectedId, setSelectedId] = useState<string | null>(documents[0]?.id ?? null);
  const selected = documents.find((d) => d.id === selectedId) ?? null;

  return (
    <div>
      <PageHeader
        title="Documentos"
        subtitle="Informes y reportes generados a partir de la evidencia analizada, con su metadata de integridad."
        actions={
          onNavigate && (
            <Button variant="chip" onClick={() => onNavigate("mitre")}>
              Ver correlación MITRE →
            </Button>
          )
        }
      />

      <ContextBanner activeCase={activeCase} activeEvidence={activeEvidence} />
      <div className="demo-banner">⚠ Vista demo · los documentos mostrados son datos de ejemplo hasta que el agente genere informes reales.</div>

      {documents.length === 0 ? (
        <EmptyState
          title="No hay documentos generados todavía"
          description="Los informes aparecerán aquí una vez el agente complete un análisis sobre evidencia verificada."
        />
      ) : (
        <div className="doc-layout">
          <div className="doc-list-panel">
            {documents.map((doc) => (
              <button
                key={doc.id}
                className={`doc-list-item ${doc.id === selectedId ? "active" : ""}`}
                onClick={() => setSelectedId(doc.id)}
              >
                <div className="doc-list-item-title">{doc.title}</div>
                <div className="doc-list-item-meta">{formatDate(doc.createdAt)} · {doc.status === "final" ? "Final" : "Borrador"}</div>
              </button>
            ))}
          </div>

          <div className="doc-viewer-panel">
            {selected ? (
              <>
                <div className="doc-meta-row">
                  <span>Evidencia: <strong>{selected.evidenceId}</strong></span>
                  <span>Fecha: <strong>{formatDate(selected.createdAt)}</strong></span>
                  <span>Hash: <strong title={selected.sha256}>{shortHash(selected.sha256)}</strong></span>
                  <span>Páginas: <strong>{selected.pageCount}</strong></span>
                  <Badge variant={selected.status === "final" ? "success" : "neutral"}>
                    {selected.status === "final" ? "Final" : "Borrador"}
                  </Badge>
                </div>
                <h3 style={{ marginTop: 0 }}>{selected.title}</h3>
                <p className="doc-body-text">{selected.summary}</p>
                <p className="doc-body-text" style={{ color: "var(--text-muted)" }}>
                  {/* Punto de integración: el contenido completo del informe se cargará vía
                      forensia.reports.get(selected.id) cuando exista el backend real. */}
                  Vista previa de demostración — el contenido completo del informe se renderizará aquí cuando se conecte el backend.
                </p>
              </>
            ) : (
              <EmptyState title="Selecciona un documento de la lista" />
            )}
          </div>
        </div>
      )}
    </div>
  );
}
