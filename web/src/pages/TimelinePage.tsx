import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import type { AgentFinding, Case } from "../api/types";
import { EmptyState } from "../ui/EmptyState";
import { PageHeader } from "../ui/PageHeader";

// Timeline de eventos del caso. Vista REAL: cada evento es un hallazgo que el
// agente registró (record_finding) sobre la evidencia, en orden cronológico por
// su created_at. Fuente = tool_id, severidad = severity, técnicas = mitre_hints.
// Sin datos inventados: un caso sin hallazgos sale vacío (RULE 2).

type Phase = "loading" | "ready" | "no-case" | "error";
type Severity = "low" | "medium" | "high" | "critical";
type SevFilter = Severity | "all";

const SEV_LABEL: Record<Severity, string> = {
  low: "Baja",
  medium: "Media",
  high: "Alta",
  critical: "Crítica",
};
const SEV_ORDER: SevFilter[] = ["all", "low", "medium", "high", "critical"];

interface TlEvent {
  id: string;
  dateLabel: string;
  timeLabel: string;
  sortKey: string;
  source: string;
  severity: Severity;
  evidenceId: string;
  description: string;
  techniques: string[];
}

function toEvent(f: AgentFinding): TlEvent {
  const d = new Date(f.created_at);
  const valid = !isNaN(d.getTime());
  return {
    id: f.id,
    dateLabel: valid ? d.toLocaleDateString("es-ES") : f.created_at.slice(0, 10),
    timeLabel: valid ? d.toLocaleTimeString("es-ES") : "",
    sortKey: f.created_at,
    source: f.tool_id ?? "agente",
    severity: f.severity,
    evidenceId: f.evidence_id ?? "—",
    description: f.summary || f.title,
    techniques: f.mitre_hints,
  };
}

export function TimelinePage() {
  const [cases, setCases] = useState<Case[]>([]);
  const [findings, setFindings] = useState<AgentFinding[]>([]);
  const [phase, setPhase] = useState<Phase>("loading");
  const [error, setError] = useState("");

  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState<SevFilter>("all");
  const [sourceFilter, setSourceFilter] = useState<string>("all");

  const activeCase = cases[0] ?? null;

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const list = await api.cases.list();
        if (cancelled) return;
        setCases(list);
        if (list.length === 0) {
          setPhase("no-case");
          return;
        }
        const finds = await api.cases
          .listFindings(list[0].id)
          .catch(() => [] as AgentFinding[]);
        if (cancelled) return;
        setFindings(finds);
        setPhase("ready");
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : String(err));
          setPhase("error");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const events = useMemo(
    () => findings.map(toEvent).sort((a, b) => a.sortKey.localeCompare(b.sortKey)),
    [findings],
  );

  const sources = useMemo(
    () => Array.from(new Set(events.map((e) => e.source))).sort(),
    [events],
  );

  const matches = useCallback(
    (e: TlEvent) => {
      if (sevFilter !== "all" && e.severity !== sevFilter) return false;
      if (sourceFilter !== "all" && e.source !== sourceFilter) return false;
      const q = search.trim().toLowerCase();
      if (!q) return true;
      return `${e.source} ${e.description} ${e.evidenceId} ${e.techniques.join(" ")}`
        .toLowerCase()
        .includes(q);
    },
    [sevFilter, sourceFilter, search],
  );

  const filtered = useMemo(() => events.filter(matches), [events, matches]);

  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    events.forEach((e) => (c[e.severity] += 1));
    return c;
  }, [events]);

  const days = useMemo(() => {
    const map = new Map<string, TlEvent[]>();
    filtered.forEach((e) => {
      if (!map.has(e.dateLabel)) map.set(e.dateLabel, []);
      map.get(e.dateLabel)!.push(e);
    });
    return Array.from(map.entries()).map(([label, evs]) => ({ label, events: evs }));
  }, [filtered]);

  if (phase === "loading") {
    return <PageHeader title="Timeline de eventos" subtitle="Cargando la línea de tiempo…" />;
  }
  if (phase === "error") {
    return (
      <div>
        <PageHeader title="Timeline de eventos" subtitle="No se pudo cargar la línea de tiempo." />
        <EmptyState title="Error" description={error} />
      </div>
    );
  }
  if (phase === "no-case" || !activeCase) {
    return (
      <div>
        <PageHeader
          title="Timeline de eventos"
          subtitle="Secuencia cronológica de hallazgos extraídos por las herramientas forenses."
        />
        <EmptyState
          title="Sin caso abierto"
          description="Abre un caso: la línea de tiempo se construye con los hallazgos que el agente registra sobre la evidencia."
        />
      </div>
    );
  }

  const metrics: { label: string; count: number; sev: Severity }[] = [
    { label: "Críticos", count: counts.critical, sev: "critical" },
    { label: "Altos", count: counts.high, sev: "high" },
    { label: "Medios", count: counts.medium, sev: "medium" },
    { label: "Bajos", count: counts.low, sev: "low" },
  ];

  return (
    <div className="tl-page">
      <PageHeader
        title="Timeline de eventos"
        subtitle="Secuencia cronológica de hallazgos extraídos por las herramientas forenses sobre la evidencia analizada."
      />

      <div className="mitre-context">
        <span>
          Caso activo: <strong>{activeCase.name}</strong> · {activeCase.examiner}
          {activeCase.os_profile ? ` · perfil ${activeCase.os_profile}` : ""}
        </span>
        <span className={`docs-badge ${activeCase.status === "active" ? "open" : "closed"}`}>
          {activeCase.status === "active" ? "Abierto" : "Cerrado"}
        </span>
      </div>

      {events.length === 0 && (
        <div className="docs-note">
          Aún no hay hallazgos en este caso. La línea de tiempo se construye con los
          hallazgos que el agente registra al analizar la evidencia desde el chat.
        </div>
      )}

      {/* Métricas por severidad */}
      <div className="tl-metrics">
        {metrics.map((m) => (
          <div key={m.sev} className={`tl-metric tl-metric--${m.sev}`}>
            <div className="tl-metric-label">{m.label}</div>
            <div className={`tl-metric-value tl-metric-value--${m.sev}`}>{m.count}</div>
          </div>
        ))}
      </div>

      {/* Toolbar */}
      <div className="tl-toolbar">
        <input
          className="tl-search"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Buscar en eventos, fuente o descripción…"
        />
        <div className="tl-filters">
          {SEV_ORDER.map((f) => (
            <button
              key={f}
              className={`tl-chip${sevFilter === f ? " is-active" : ""}`}
              onClick={() => setSevFilter(f)}
            >
              {f === "all" ? "Todas" : SEV_LABEL[f]}
            </button>
          ))}
        </div>
        <select
          className="tl-source"
          value={sourceFilter}
          onChange={(e) => setSourceFilter(e.target.value)}
        >
          <option value="all">Todas las fuentes</option>
          {sources.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>

      {/* Timeline */}
      <div className="tl-scroll">
        {filtered.length === 0 ? (
          <div className="tl-empty">
            No hay eventos con ese filtro de severidad, fuente o búsqueda.
          </div>
        ) : (
          days.map((day) => (
            <div className="tl-day" key={day.label}>
              <div className="tl-day-head">
                <span className="tl-day-label">{day.label}</span>
                <span className="tl-day-rule" />
                <span className="tl-day-count">{day.events.length} eventos</span>
              </div>
              <div className="tl-rail">
                {day.events.map((ev) => (
                  <div className="tl-event" key={ev.id}>
                    <span className={`tl-dot tl-dot--${ev.severity}`} />
                    <div className="tl-event-meta">
                      <span className="tl-time">{ev.timeLabel}</span>
                      <span className="tl-src">{ev.source}</span>
                      <span className={`tl-sev tl-sev--${ev.severity}`}>
                        {SEV_LABEL[ev.severity]}
                      </span>
                      <span className="tl-evid">{ev.evidenceId}</span>
                    </div>
                    <p className="tl-desc">{ev.description}</p>
                    {ev.techniques.length > 0 && (
                      <div className="tl-techs">
                        {ev.techniques.map((t) => (
                          <span className="tl-tech" key={t}>
                            {t}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
