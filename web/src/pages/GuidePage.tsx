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

      <Card fullWidth>
        <h3>Ejecutor de IA: iniciar sesión</h3>
        <div className="status-card-body" style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6 }}>
          <p style={{ marginTop: 0 }}>
            FORENSIA no usa API keys. <strong>Ollama</strong> funciona sin nada más (100 % local). Para un
            ejecutor cloud (Claude Code, Codex CLI o Gemini CLI) necesitas tu propia sesión: en el primer
            arranque el stack intenta reutilizar la del host, y si no la hay inicias sesión <strong>una única
            vez dentro del contenedor</strong> (la sesión persiste en el volumen <code>forensia-cli-auth</code>):
          </p>
          <pre style={{ background: "var(--surface-2, rgba(127,127,127,0.12))", padding: 12, borderRadius: 8, overflowX: "auto", fontSize: 12 }}>
            <code>{`docker compose exec -it api claude auth login          # Claude Code
docker compose exec -it api codex login --device-auth  # Codex CLI (device-code)
docker compose exec -it -e NO_BROWSER=true api gemini  # Gemini CLI (URL + código)`}</code>
          </pre>
          <p style={{ marginBottom: 0 }}>
            Comprueba el estado en <strong>Configuración → Ejecutores / IA</strong>. Para revocar la sesión:
            <code> docker compose down -v</code>. Elegir un ejecutor cloud envía contenido derivado del caso a
            ese proveedor bajo tu cuenta; la aplicación lo advierte y lo registra en el audit log.
          </p>
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
