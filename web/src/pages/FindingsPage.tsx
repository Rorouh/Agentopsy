import { useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import type { AgentFinding } from "../api/types";
import type { ViewId } from "../navigation/navItems";
import { useActiveCase } from "../state/activeCase";
import { useCaseStream } from "../state/casePulse";
import { usePublishShellHeader } from "../layout/shellHeader";
import { useLang, type MessageKey } from "../i18n";
import { useFormat } from "../utils/format";

interface FindingsPageProps {
  onNavigate?: (view: ViewId) => void;
}

type SeverityFilter = "all" | AgentFinding["severity"];

const SEVERITY_KEY: Record<AgentFinding["severity"], MessageKey> = {
  low: "severity.low",
  medium: "severity.medium",
  high: "severity.high",
  critical: "severity.critical",
};

const SEVERITY_ORDER: Record<AgentFinding["severity"], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

function isHot(sev: AgentFinding["severity"]): boolean {
  return sev === "high" || sev === "critical";
}

// FASE 5 · Hallazgos. La lectura de los HALLAZGOS que el agente persiste vía
// `record_finding`: cada uno una tarjeta; al abrirla, el detalle completo con su
// procedencia (run que lo sostiene, evidencia, hash del artefacto) y su
// correlación ATT&CK. Es una fase SEPARADA del «Informe pericial» (el
// entregable final firmable): aquí se consulta el material, allí se redacta.
export function FindingsPage({ onNavigate }: FindingsPageProps) {
  const { t } = useLang();
  const { activeCase, phase: casesPhase, error: casesError } = useActiveCase();
  // El agente persiste hallazgos mientras analiza: la lista se recarga sola
  // cuando el flujo cambia, sin que el perito tenga que recargar la página.
  const revFindings = useCaseStream("findings");
  const [findings, setFindings] = useState<AgentFinding[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<SeverityFilter>("all");

  // Dos efectos y no uno, y la diferencia importa: cambiar de CASO reinicia la
  // vista (esqueleto de carga y selección a cero, porque el hallazgo que estaba
  // abierto es de otro caso), mientras que un hallazgo nuevo en el caso que ya
  // estás mirando sólo repone la lista. Con un único efecto, cada hallazgo que
  // el agente persistiera haría parpadear la lista y movería el detalle bajo el
  // cursor del perito, que es peor que no refrescar.
  useEffect(() => {
    const caseId = activeCase?.id;
    if (!caseId) {
      setFindings([]);
      setLoaded(false);
      setSelectedId(null);
      return;
    }
    let cancelled = false;
    setLoaded(false);
    setSelectedId(null);
    (async () => {
      try {
        const list = await api.cases.listFindings(caseId);
        if (!cancelled) setFindings(list);
      } catch {
        // 404 = sin findings.jsonl aún. Estado vacío, no error.
        if (!cancelled) setFindings([]);
      } finally {
        if (!cancelled) setLoaded(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [activeCase?.id]);

  // Reposición EN SILENCIO: el agente acaba de persistir un hallazgo mientras el
  // perito lee otro. Sin esqueleto y sin tocar la selección.
  useEffect(() => {
    const caseId = activeCase?.id;
    if (!caseId || revFindings === 0) return;
    let cancelled = false;
    (async () => {
      try {
        const list = await api.cases.listFindings(caseId);
        if (!cancelled) setFindings(list);
      } catch {
        /* el estado de error lo gobierna la carga de arriba */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [activeCase?.id, revFindings]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return findings
      .filter((f) => (severity === "all" ? true : f.severity === severity))
      .filter((f) =>
        q === ""
          ? true
          : `${f.title} ${f.summary} ${f.tool_id ?? ""} ${f.mitre_hints.join(" ")}`
              .toLowerCase()
              .includes(q),
      )
      .slice()
      .sort(
        (a, b) =>
          SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
          b.created_at.localeCompare(a.created_at),
      );
  }, [findings, search, severity]);

  // Auto-selecciona el primero visible para que el detalle no arranque vacío;
  // si el filtro deja fuera el seleccionado, cae al primero de la lista.
  useEffect(() => {
    if (filtered.length === 0) {
      setSelectedId(null);
      return;
    }
    if (!selectedId || !filtered.some((f) => f.id === selectedId)) {
      setSelectedId(filtered[0].id);
    }
  }, [filtered, selectedId]);

  const selected = findings.find((f) => f.id === selectedId) ?? null;

  usePublishShellHeader(
    {
      title: t("nav.findings"),
      // Sin meta con caso abierto: el vacío ya lo dice la columna de la
      // izquierda, y el recuento vive en la escalera del sidebar.
      meta: activeCase ? undefined : t("common.noCase"),
      action:
        onNavigate && activeCase ? (
          // Apagado sin hallazgos, igual que «Pasar a ATT&CK» en Investigación:
          // redactar el informe cuesta dinero y sobre cero hallazgos no puede
          // producir nada.
          <button
            type="button"
            disabled={findings.length === 0}
            title={
              findings.length === 0 ? t("findings.nothingToReport") : undefined
            }
            onClick={() => onNavigate("document-viewer")}
          >
            {t("findings.goToReport")} →
          </button>
        ) : undefined,
    },
    [activeCase?.id, activeCase?.name, findings.length, t],
  );

  if (casesPhase === "loading") {
    return (
      <div className="view-scroll">
        <div className="loading-state">
          <span className="spinner" aria-hidden="true" />
          <span>{t("inv.loadingContext")}</span>
        </div>
      </div>
    );
  }

  if (casesPhase === "error") {
    return (
      <div className="view-scroll">
        <div className="error-state">
          <strong>{t("findings.loadCaseFailed")}</strong> {casesError}
        </div>
      </div>
    );
  }

  if (!activeCase) {
    return (
      <div className="view-scroll">
        <div className="empty-rail">
          <div className="empty-rail-title">{t("findings.noCase")}</div>
          <div className="empty-rail-body">{t("findings.noCaseBody")}</div>
        </div>
        {onNavigate && (
          <div className="cta-row">
            <button type="button" className="link-action" onClick={() => onNavigate("repository")}>
              {t("findings.goToEvidence")} →
            </button>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="report">
      <div className="report-list">
        <div className="eyebrow eyebrow--section">{t("findings.section")}</div>

        <label className="visually-hidden" htmlFor="hallazgos-search">
          {t("findings.searchLabel")}
        </label>
        <input
          id="hallazgos-search"
          className="field-input field-input--sm"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder={t("findings.searchPlaceholder")}
        />

        <div className="report-filters">
          {(["all", "critical", "high", "medium", "low"] as SeverityFilter[]).map((s) => (
            <button
              key={s}
              type="button"
              className={`toggle-link${severity === s ? " is-on" : ""}`}
              aria-pressed={severity === s}
              onClick={() => setSeverity(s)}
            >
              {t(s === "all" ? "severity.all" : SEVERITY_KEY[s])}
            </button>
          ))}
        </div>

        <div className="hallazgo-cards">
          {!loaded ? (
            <div className="inv-empty">{t("findings.loading")}</div>
          ) : findings.length === 0 ? (
            <div className="inv-empty">{t("findings.empty")}</div>
          ) : filtered.length === 0 ? (
            <div className="inv-empty">{t("findings.noMatch")}</div>
          ) : (
            filtered.map((f) => (
              <button
                key={f.id}
                type="button"
                className={`hallazgo-card${isHot(f.severity) ? " is-hot" : ""}${
                  selectedId === f.id ? " is-active" : ""
                }`}
                onClick={() => setSelectedId(f.id)}
              >
                <span className="hallazgo-card-title">{f.title}</span>
                <span className="hallazgo-card-summary">{f.summary}</span>
                <span className="hallazgo-card-meta">
                  {f.finding_kind === "descarte" ? `${t("findingKind.descarte")} · ` : ""}
                  {t(SEVERITY_KEY[f.severity])}
                  {f.tool_id ? ` · ${f.tool_id}` : ""}
                  {f.mitre_hints.length > 0 ? ` · ${f.mitre_hints.length} ATT&CK` : ""}
                </span>
              </button>
            ))
          )}
        </div>
      </div>

      <div className="report-viewer">
        {!selected ? (
          <div className="empty-rail">
            <div className="empty-rail-title">{t("findings.noneOpen")}</div>
            <div className="empty-rail-body">{t("findings.noneOpenBody")}</div>
          </div>
        ) : (
          <FindingDetail finding={selected} />
        )}
      </div>
    </div>
  );
}

function FindingDetail({ finding: f }: { finding: AgentFinding }) {
  const { t } = useLang();
  const { formatDate, na } = useFormat();
  // Una fecha que el store guardó sin formato reconocible se pinta TAL CUAL: es
  // dato del caso, y sustituirla por un blanco escondería lo que de verdad hay.
  const fecha = (iso: string | null | undefined): string => {
    if (!iso) return na;
    return Number.isNaN(new Date(iso).getTime()) ? iso : formatDate(iso);
  };
  const kv: Array<[string, string]> = [
    [t("finding.severity"), t(SEVERITY_KEY[f.severity])],
    [t("finding.kind"), t(f.finding_kind === "descarte" ? "findingKind.descarte" : "findingKind.afirmacion")],
    [t("finding.tool"), f.tool_id ?? na],
    [t("finding.run"), f.run_id ?? na],
    [t("finding.evidence"), f.evidence_id ?? na],
    [t("finding.observedAt"), fecha(f.observed_at)],
    [t("finding.recordedAt"), fecha(f.created_at)],
    [t("finding.confidence"), f.confidence != null ? `${Math.round(f.confidence * 100)}%` : na],
    [t("finding.artifactHash"), f.artifact_sha256 ?? na],
    [t("finding.quote"), f.quote ?? na],
  ];

  return (
    <div className="report-doc-body">
      <div className="report-metarow">
        <span className={`sev-badge sev-badge--${f.severity}`}>{t(SEVERITY_KEY[f.severity])}</span>
        <span className="report-doc-meta">
          {t(f.finding_kind === "descarte" ? "findingKind.descarte" : "findingKind.afirmacion")} ·{" "}
          {t("finding.recordedOn", { date: fecha(f.created_at) })}
        </span>
      </div>

      <div>
        {/* Título y resumen son texto del CASO, escrito por el agente: se pintan
            tal cual, jamás traducidos. */}
        <h1 className="report-title">{f.title}</h1>
        <p className="report-summary">{f.summary}</p>
      </div>

      <section className="report-section">
        <div className="report-section-head">
          <span className="report-section-num">01</span>
          <span className="eyebrow">{t("finding.provenance")}</span>
        </div>
        <div className="report-kv">
          {kv.map(([k, v]) => (
            <div className="report-kv-row" key={k}>
              <span className="report-kv-k">{k}</span>
              <span className="report-kv-v">{v}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="report-section">
        <div className="report-section-head">
          <span className="report-section-num">02</span>
          <span className="eyebrow">{t("finding.attackCorrelation")}</span>
        </div>
        {f.mitre_hints.length === 0 ? (
          <p className="report-p report-p--muted">{t("finding.noTechniques")}</p>
        ) : (
          <div className="hallazgo-mitre">
            {f.mitre_hints.map((t) => (
              <span className="hallazgo-mitre-tag" key={t}>
                {t}
              </span>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
