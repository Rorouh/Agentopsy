import type { ViewId } from "../navigation/navItems";
import { usePublishShellHeader } from "../layout/shellHeader";
import { useActiveCase } from "../state/activeCase";
import { useCaseFacts } from "../state/caseFacts";
import { useLang, type MessageKey } from "../i18n";

interface GuidePageProps {
  onNavigate?: (view: ViewId) => void;
}

type StepState = "done" | "now" | "todo";

const STATE_KEY: Record<StepState, MessageKey> = {
  done: "guide.state.done",
  now: "guide.state.now",
  todo: "guide.state.todo",
};

// El COMANDO es literal y no se traduce nunca: es lo que hay que teclear. Lo que
// se traduce es la nota que lo nombra, y la de Claude Code es un nombre propio.
const LOGIN_COMMANDS: { noteKey: MessageKey | null; note?: string; cmd: string }[] = [
  { noteKey: null, note: "Claude Code", cmd: "docker compose exec -it api claude auth login" },
  { noteKey: "guide.cmd.codex", cmd: "docker compose exec -it api codex login --device-auth" },
  { noteKey: "guide.cmd.gemini", cmd: "docker compose exec -it -e NO_BROWSER=true api gemini" },
];

const NOTES: { titleKey: MessageKey; bodyKey: MessageKey }[] = [
  { titleKey: "guide.note1.title", bodyKey: "guide.note1.body" },
  { titleKey: "guide.note2.title", bodyKey: "guide.note2.body" },
  { titleKey: "guide.note3.title", bodyKey: "guide.note3.body" },
];

export function GuidePage({ onNavigate }: GuidePageProps) {
  const { activeCase } = useActiveCase();
  const facts = useCaseFacts();
  const { t } = useLang();

  usePublishShellHeader(
    {
      title: t("guide.title"),
      action: onNavigate ? (
        <button type="button" onClick={() => onNavigate("repository")}>
          {activeCase ? `${t("guide.goToEvidence")} →` : `${t("guide.start")} →`}
        </button>
      ) : undefined,
    },
    [activeCase?.id, onNavigate, t],
  );

  // El estado de cada paso REFLEJA el caso activo. Sin caso o sin datos
  // cargados, todo queda pendiente: no se presume nada (RULE 2).
  const has = (n: number) => facts.loaded && n > 0;
  const steps: { n: string; title: string; desc: string; state: StepState; view?: ViewId }[] = [
    {
      n: "01",
      title: t("guide.step1.title"),
      desc: t("guide.step1.desc"),
      state: activeCase ? "done" : "now",
      view: "repository",
    },
    {
      n: "02",
      title: t("guide.step2.title"),
      desc: t("guide.step2.desc"),
      state: has(facts.evidenceTotal) ? "done" : activeCase ? "now" : "todo",
      view: "repository",
    },
    {
      n: "03",
      title: t("guide.step3.title"),
      desc: t("guide.step3.desc"),
      state: has(facts.findings) ? "done" : has(facts.evidenceTotal) ? "now" : "todo",
      view: "investigation",
    },
    {
      n: "04",
      title: t("guide.step4.title"),
      desc: t("guide.step4.desc"),
      // Hecho cuando la matriz tiene al menos una técnica tocada (propuesta del
      // agente, dictamen del perito o ambas), que es la MISMA cifra que usa la
      // escalera del sidebar: los dos estados no pueden contradecirse.
      state: has(facts.mitreTechniques) ? "done" : has(facts.findings) ? "now" : "todo",
      view: "mitre",
    },
    {
      n: "05",
      title: t("guide.step5.title"),
      desc: t("guide.step5.desc"),
      // Hecho cuando la capa del incidente sitúa al menos un evento en el eje:
      // es la capa de entrada y la que se lleva al informe. Lo que no se puede
      // situar no cuenta, y por eso el sidebar lo enuncia contado.
      state: has(facts.incidentEvents) ? "done" : has(facts.findings) ? "now" : "todo",
      view: "timeline",
    },
    {
      n: "06",
      title: t("guide.step6.title"),
      desc: t("guide.step6.desc"),
      state: has(facts.graphs) ? "done" : has(facts.findings) ? "now" : "todo",
      view: "graphs",
    },
    {
      n: "07",
      title: t("guide.step7.title"),
      desc: t("guide.step7.desc"),
      state: has(facts.documents) ? "done" : has(facts.findings) ? "now" : "todo",
      view: "document-viewer",
    },
  ];

  return (
    <div className="view-scroll">
      <div className="view-stack view-stack--820">
        <div className="section-stack">
          <div className="rule-label">
            <span className="eyebrow eyebrow--section">{t("guide.workflow")}</span>
            <span className="rule" />
            <span className="rule-count">
              {t(activeCase ? "guide.reflectsCase" : "guide.noActiveCase")}
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
                <div className={`tag guide-step-state is-${s.state}`}>{t(STATE_KEY[s.state])}</div>
                <div className="guide-step-desc">{s.desc}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="section-stack">
          <div className="rule-label">
            <span className="eyebrow eyebrow--section">{t("guide.loginSection")}</span>
            <span className="rule" />
          </div>
          <div className="guide-prose">
            {t("guide.loginProseA")} <strong>Ollama</strong> {t("guide.loginProseB")}{" "}
            <span className="mono">forensia-cli-auth</span>.
          </div>
          {/* Bloque de comandos: oscuro en AMBOS temas, es una terminal. */}
          <div className="code-block">
            {LOGIN_COMMANDS.map((c) => (
              <div className="code-line" key={c.cmd}>
                <div className="code-note">{c.noteKey ? t(c.noteKey) : c.note}</div>
                <div className="code-cmd">{c.cmd}</div>
              </div>
            ))}
          </div>
          <div className="guide-prose guide-prose--sm">
            {t("guide.loginNoteA")} <strong>{t("guide.settingsPath")}</strong>.{" "}
            {t("guide.loginNoteB")} <span className="mono">docker compose down -v</span>.
          </div>
        </div>

        <div className="section-stack">
          <div className="rule-label">
            <span className="eyebrow eyebrow--section">{t("guide.notesSection")}</span>
            <span className="rule" />
          </div>
          <div className="guide-notes">
            {NOTES.map((n) => (
              <div className="guide-note" key={n.titleKey}>
                <div className="guide-note-title">{t(n.titleKey)}</div>
                <div className="guide-note-body">{t(n.bodyKey)}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
