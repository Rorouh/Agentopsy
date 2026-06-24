import type { GuideStep } from "../types/domain";
import type { ViewId } from "../navigation/navItems";
import { Card } from "../ui/Card";
import { PageHeader } from "../ui/PageHeader";
import { Button } from "../ui/Button";

interface GuidePageProps {
  steps: GuideStep[];
  onNavigate?: (view: ViewId) => void;
}

export function GuidePage({ steps, onNavigate }: GuidePageProps) {
  return (
    <div>
      <PageHeader
        title="Guía de uso"
        subtitle="Flujo recomendado para llevar un caso desde la ingesta de evidencia hasta el informe final."
        actions={
          onNavigate && (
            <Button variant="chip" onClick={() => onNavigate("repository")}>
              Empezar: crear caso →
            </Button>
          )
        }
      />

      <Card fullWidth>
        <h3>Flujo de trabajo</h3>
        <div className="guide-steps">
          {steps.map((s) => (
            <div className="guide-step" key={s.step}>
              <div className="guide-step-number">{s.step}</div>
              <div>
                <div className="guide-step-title">{s.title}</div>
                <div className="guide-step-desc">{s.description}</div>
              </div>
            </div>
          ))}
        </div>
      </Card>

      <div style={{ height: 16 }} />

      <div className="status-grid">
        <Card>
          <h3>Principios forenses</h3>
          <div className="status-card-body" style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6 }}>
            La evidencia nunca se toca directamente: todo acceso pasa por un handle hash-verificado y de solo lectura
            a nivel de bloque. Cada acción queda en un log de auditoría encadenado por hash.
          </div>
        </Card>
        <Card>
          <h3>Alcance académico</h3>
          <div className="status-card-body" style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6 }}>
            FORENSIA es post-mortem y de escritorio: no realiza forensia en vivo ni adquisición desde el equipo
            original. Sin validez legal certificada, pero con rigor forense real.
          </div>
        </Card>
      </div>
    </div>
  );
}
