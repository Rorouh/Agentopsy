import type { ViewId } from "../navigation/navItems";
import { usePublishShellHeader } from "../layout/shellHeader";
import { useActiveCase } from "../state/activeCase";
import { useCaseFacts } from "../state/caseFacts";

interface GuidePageProps {
  onNavigate?: (view: ViewId) => void;
}

type StepState = "done" | "now" | "todo";

const STATE_LABEL: Record<StepState, string> = {
  done: "Hecho",
  now: "En curso",
  todo: "Pendiente",
};

const LOGIN_COMMANDS = [
  { note: "Claude Code", cmd: "docker compose exec -it api claude auth login" },
  { note: "Codex CLI · device-code", cmd: "docker compose exec -it api codex login --device-auth" },
  { note: "Gemini CLI · URL + código", cmd: "docker compose exec -it -e NO_BROWSER=true api gemini" },
];

const NOTES = [
  {
    title: "Ejecutor cloud y privacidad (RGPD)",
    body: "Al elegir un ejecutor cloud los prompts incluyen contenido derivado de la evidencia — posibles datos personales reales — y salen a ese proveedor bajo tu propia suscripción. La alternativa 100 % local es Ollama, que nunca envía nada fuera del equipo.",
  },
  {
    title: "Coste y tiempo del análisis",
    body: "Iteraciones, tokens, tiempo y coste son orientativos, no un presupuesto: salen del histórico del caso o de una heurística. Agentopsy no inventa tarifas; con una suscripción de CLI el coste marginal puede ser 0.",
  },
  {
    title: "Principios forenses",
    body: "La evidencia nunca se toca directamente: todo acceso pasa por un handle hash-verificado y de solo lectura a nivel de bloque. Cada acción queda en un log de auditoría encadenado por hash.",
  },
  {
    title: "Alcance académico",
    body: "Agentopsy es post-mortem y de escritorio: no realiza forensia en vivo ni adquisición desde el equipo original. Sin validez legal certificada, pero con rigor forense real.",
  },
];

export function GuidePage({ onNavigate }: GuidePageProps) {
  const { activeCase } = useActiveCase();
  const facts = useCaseFacts();

  usePublishShellHeader(
    {
      title: "Guía de uso",
      meta: "de la ingesta al informe final",
      action: onNavigate ? (
        <button type="button" onClick={() => onNavigate("repository")}>
          {activeCase ? "Ir a Evidencia →" : "Empezar: crear caso →"}
        </button>
      ) : undefined,
    },
    [activeCase?.id, onNavigate],
  );

  // El estado de cada paso REFLEJA el caso activo. Sin caso o sin datos
  // cargados, todo queda pendiente: no se presume nada (RULE 2).
  const has = (n: number) => facts.loaded && n > 0;
  const steps: { n: string; title: string; desc: string; state: StepState; view?: ViewId }[] = [
    {
      n: "01",
      title: "Crear caso / repositorio",
      desc: "Registra un nuevo caso y define el examinador responsable antes de tocar evidencia.",
      state: activeCase ? "done" : "now",
      view: "repository",
    },
    {
      n: "02",
      title: "Registrar evidencia",
      desc: "Sube la imagen forense o el volcado; Agentopsy calcula el hash baseline y la deja en solo lectura.",
      state: has(facts.evidenceTotal) ? "done" : activeCase ? "now" : "todo",
      view: "repository",
    },
    {
      n: "03",
      title: "Investigar con el agente",
      desc: "Conversa con el agente, que ejecuta el maletín de herramientas forenses sobre la evidencia verificada.",
      state: has(facts.findings) ? "done" : has(facts.evidenceTotal) ? "now" : "todo",
      view: "investigation",
    },
    {
      n: "04",
      title: "Correlacionar con ATT&CK",
      desc: "Vincula los hallazgos con tácticas y técnicas conocidas para dar contexto al informe final.",
      state: has(facts.findings) ? "now" : "todo",
      view: "mitre",
    },
    {
      n: "05",
      title: "Revisar el timeline",
      desc: "Reconstruye la secuencia de eventos detectados por las distintas herramientas, ordenados cronológicamente.",
      state: has(facts.findings) ? "now" : "todo",
      view: "timeline",
    },
    {
      n: "06",
      title: "Redactar y firmar el informe",
      desc: "Genera el informe pericial desde los hallazgos reales, verifica su integridad y fírmalo como versión final.",
      state: has(facts.documents) ? "done" : has(facts.findings) ? "now" : "todo",
      view: "document-viewer",
    },
  ];

  return (
    <div className="view-scroll">
      <div className="view-stack view-stack--820">
        <div className="section-stack">
          <div className="rule-label">
            <span className="eyebrow eyebrow--section">Flujo de trabajo</span>
            <span className="rule" />
            <span className="rule-count">
              {activeCase ? "refleja el caso activo" : "sin caso activo"}
            </span>
          </div>
          <div className="guide-steps">
            {steps.map((s) => (
              <div className="guide-step" key={s.n}>
                <div className={`guide-step-num is-${s.state}`}>{s.n}</div>
                {onNavigate && s.view ? (
                  <button
                    type="button"
                    className="guide-step-title is-link"
                    onClick={() => onNavigate(s.view!)}
                  >
                    {s.title}
                  </button>
                ) : (
                  <div className="guide-step-title">{s.title}</div>
                )}
                <div className={`tag guide-step-state is-${s.state}`}>{STATE_LABEL[s.state]}</div>
                <div className="guide-step-desc">{s.desc}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="section-stack">
          <div className="rule-label">
            <span className="eyebrow eyebrow--section">Iniciar sesión en un ejecutor</span>
            <span className="rule" />
          </div>
          <div className="guide-prose">
            Agentopsy no usa API keys. <strong>Ollama</strong> funciona sin nada más. Para un
            ejecutor cloud necesitas tu propia sesión: en el primer arranque el stack intenta
            reutilizar la del host y, si no la hay, inicias sesión una única vez dentro del
            contenedor. La sesión persiste en el volumen{" "}
            <span className="mono">forensia-cli-auth</span>.
          </div>
          {/* Bloque de comandos: oscuro en AMBOS temas — es una terminal. */}
          <div className="code-block">
            {LOGIN_COMMANDS.map((c) => (
              <div className="code-line" key={c.cmd}>
                <div className="code-note">{c.note}</div>
                <div className="code-cmd">{c.cmd}</div>
              </div>
            ))}
          </div>
          <div className="guide-prose guide-prose--sm">
            Comprueba el estado en <strong>Configuración → Motor de análisis</strong>. Para
            revocar la sesión: <span className="mono">docker compose down -v</span>.
          </div>
        </div>

        <div className="section-stack">
          <div className="rule-label">
            <span className="eyebrow eyebrow--section">Lo que debes saber</span>
            <span className="rule" />
          </div>
          <div className="guide-notes">
            {NOTES.map((n) => (
              <div className="guide-note" key={n.title}>
                <div className="guide-note-title">{n.title}</div>
                <div className="guide-note-body">{n.body}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
