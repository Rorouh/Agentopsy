import { useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import type { AgentFinding } from "../api/types";
import type { ViewId } from "../navigation/navItems";
import { useActiveCase } from "../state/activeCase";
import { usePublishShellHeader } from "../layout/shellHeader";

interface FindingsPageProps {
  onNavigate?: (view: ViewId) => void;
}

type SeverityFilter = "all" | AgentFinding["severity"];

const SEVERITY_LABEL: Record<AgentFinding["severity"], string> = {
  low: "baja",
  medium: "media",
  high: "alta",
  critical: "crítica",
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

function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "n/d";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("es-ES", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// FASE 5 · Documentos. La lectura de los HALLAZGOS que el agente persiste vía
// `record_finding`: cada uno una tarjeta; al abrirla, el detalle completo con su
// procedencia (run que lo sostiene, evidencia, hash del artefacto) y su
// correlación ATT&CK. Es una fase SEPARADA del «Informe pericial» (el
// entregable final firmable): aquí se consulta el material, allí se redacta.
export function FindingsPage({ onNavigate }: FindingsPageProps) {
  const { activeCase, phase: casesPhase, error: casesError } = useActiveCase();
  const [findings, setFindings] = useState<AgentFinding[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<SeverityFilter>("all");

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
      title: "Documentos",
      meta: activeCase
        ? findings.length === 0
          ? "sin hallazgos todavía"
          : `${findings.length} ${findings.length === 1 ? "hallazgo" : "hallazgos"} · del caso ${activeCase.name}`
        : "sin caso seleccionado",
      action:
        onNavigate && activeCase ? (
          <button type="button" onClick={() => onNavigate("document-viewer")}>
            Ir al informe pericial →
          </button>
        ) : undefined,
    },
    [activeCase?.id, activeCase?.name, findings.length],
  );

  if (casesPhase === "loading") {
    return (
      <div className="view-scroll">
        <div className="loading-state">
          <span className="spinner" aria-hidden="true" />
          <span>Cargando contexto del caso…</span>
        </div>
      </div>
    );
  }

  if (casesPhase === "error") {
    return (
      <div className="view-scroll">
        <div className="error-state">
          <strong>No se pudo cargar el caso activo:</strong> {casesError}
        </div>
      </div>
    );
  }

  if (!activeCase) {
    return (
      <div className="view-scroll">
        <div className="empty-rail">
          <div className="empty-rail-title">Sin caso abierto</div>
          <div className="empty-rail-body">
            Abre un caso en el lateral. Los hallazgos aparecen aquí a medida que el agente los
            registra durante la investigación.
          </div>
        </div>
        {onNavigate && (
          <div className="cta-row">
            <button type="button" className="link-action" onClick={() => onNavigate("repository")}>
              Ir a Evidencia →
            </button>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="report">
      <div className="report-list">
        <div className="eyebrow eyebrow--section">Hallazgos del caso</div>

        <label className="visually-hidden" htmlFor="hallazgos-search">
          Buscar hallazgo
        </label>
        <input
          id="hallazgos-search"
          className="field-input field-input--sm"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Buscar por título, herramienta o técnica…"
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
              {s === "all" ? "Todas" : SEVERITY_LABEL[s]}
            </button>
          ))}
        </div>

        <div className="hallazgo-cards">
          {!loaded ? (
            <div className="inv-empty">Cargando hallazgos…</div>
          ) : findings.length === 0 ? (
            <div className="inv-empty">
              Aún no hay hallazgos. El agente los registra en caliente durante la Investigación;
              en cuanto concluya algo (aunque sea un descarte), aparecerá aquí como tarjeta.
            </div>
          ) : filtered.length === 0 ? (
            <div className="inv-empty">Ningún hallazgo coincide con la búsqueda o el filtro.</div>
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
                  {f.finding_kind === "descarte" ? "descarte · " : ""}
                  {SEVERITY_LABEL[f.severity]}
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
            <div className="empty-rail-title">Ningún hallazgo abierto</div>
            <div className="empty-rail-body">
              Elige un hallazgo de la lista para leerlo completo, con su procedencia y su
              correlación ATT&CK.
            </div>
          </div>
        ) : (
          <FindingDetail finding={selected} />
        )}
      </div>
    </div>
  );
}

function FindingDetail({ finding: f }: { finding: AgentFinding }) {
  const kv: Array<[string, string]> = [
    ["Severidad", SEVERITY_LABEL[f.severity]],
    ["Tipo", f.finding_kind === "descarte" ? "descarte" : "afirmación"],
    ["Herramienta", f.tool_id ?? "n/d"],
    ["Run que lo sostiene", f.run_id ?? "n/d"],
    ["Evidencia", f.evidence_id ?? "n/d"],
    ["Observado en la evidencia", fmtDate(f.observed_at)],
    ["Registrado", fmtDate(f.created_at)],
    [
      "Confianza",
      f.confidence != null ? `${Math.round(f.confidence * 100)}%` : "n/d",
    ],
    ["SHA-256 del artefacto", f.artifact_sha256 ?? "n/d"],
  ];

  return (
    <div className="report-doc-body">
      <div className="report-metarow">
        <span className={`sev-badge sev-badge--${f.severity}`}>{SEVERITY_LABEL[f.severity]}</span>
        <span className="report-doc-meta">
          {f.finding_kind === "descarte" ? "descarte" : "afirmación"} · registrado {fmtDate(f.created_at)}
        </span>
      </div>

      <div>
        <h1 className="report-title">{f.title}</h1>
        <p className="report-summary">{f.summary}</p>
      </div>

      <section className="report-section">
        <div className="report-section-head">
          <span className="report-section-num">01</span>
          <span className="eyebrow">Procedencia y custodia</span>
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
          <span className="eyebrow">Correlación ATT&amp;CK</span>
        </div>
        {f.mitre_hints.length === 0 ? (
          <p className="report-p report-p--muted">
            El agente no asoció ninguna técnica a este hallazgo. Puede anclarlas desde el chat
            («dame la correlación MITRE») o el perito adjudicarlas en la fase ATT&amp;CK.
          </p>
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
