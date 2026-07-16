import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError } from "../api/client";
import type {
  Case,
  EvidenceHandle,
  FsTimelineEvent,
  FsTimelineJob,
  TimelineEvent,
} from "../api/types";
import { EmptyState } from "../ui/EmptyState";
import { PageHeader } from "../ui/PageHeader";
import { useActiveCase, useActiveCaseFrom } from "../state/activeCase";

// Timeline forense del caso — DOS capas REALES (sin datos inventados, RULE 2):
//   1) Investigación: cada ejecución de herramienta del audit log + cada hallazgo,
//      en orden cronológico. Determinista, siempre disponible.
//   2) Sistema de ficheros: la super-timeline MACB (tsk_fls -m) sobre la evidencia
//      seleccionada, bajo demanda y asíncrona (job).
// Todas las marcas de tiempo son UTC y se muestran con la zona explícita
// (hallazgo F): NUNCA se convierten a la hora local del navegador.

type Phase = "loading" | "ready" | "no-case" | "error";
type Layer = "investigation" | "filesystem";

const SEV_LABEL: Record<string, string> = {
  low: "Baja",
  medium: "Media",
  high: "Alta",
  critical: "Crítica",
};

function fmtUtc(ts: string | null): { date: string; time: string } {
  if (!ts) return { date: "sin fecha", time: "—" };
  const d = new Date(ts);
  if (isNaN(d.getTime())) return { date: ts.slice(0, 10) || "sin fecha", time: ts.slice(11, 19) };
  const p = (n: number) => String(n).padStart(2, "0");
  return {
    date: `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}`,
    time: `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`,
  };
}

function groupByDay<T>(rows: T[], ts: (row: T) => string | null): { label: string; rows: T[] }[] {
  const map = new Map<string, T[]>();
  for (const row of rows) {
    const label = fmtUtc(ts(row)).date;
    if (!map.has(label)) map.set(label, []);
    map.get(label)!.push(row);
  }
  return Array.from(map.entries()).map(([label, r]) => ({ label, rows: r }));
}

function evidenceName(e: EvidenceHandle): string {
  const parts = e.original_path.split(/[\\/]/);
  return parts[parts.length - 1] || e.evidence_id;
}

export function TimelinePage() {
  const [cases, setCases] = useState<Case[]>([]);
  const [phase, setPhase] = useState<Phase>("loading");
  const [error, setError] = useState("");
  const [layer, setLayer] = useState<Layer>("investigation");
  const [search, setSearch] = useState("");
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState("");

  // Capa 1
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  // Capa 2
  const [evidences, setEvidences] = useState<EvidenceHandle[]>([]);
  const [selectedEvidence, setSelectedEvidence] = useState("");
  const [fsJob, setFsJob] = useState<FsTimelineJob | null>(null);
  const [fsError, setFsError] = useState("");
  const [starting, setStarting] = useState(false);
  const pollRef = useRef<number | null>(null);

  // Caso activo GLOBAL (compartido con las demás vistas). El selector de abajo
  // lo cambia y todas convergen.
  const { setActiveCaseId } = useActiveCase();
  const activeCase = useActiveCaseFrom(cases);

  // Carga la LISTA de casos una vez. La timeline/evidencias del caso activo las
  // gobierna el efecto de abajo (keyed en activeCase.id) para que cambiar de
  // caso — aquí o en otra vista — refetchee uniformemente.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const list = await api.cases.list();
        if (cancelled) return;
        setCases(list);
        setPhase(list.length === 0 ? "no-case" : "ready");
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

  // Timeline + evidencias del caso activo. Se recarga al cambiar de caso (desde
  // aquí o desde cualquier otra vista), limpiando el estado de la capa 2.
  useEffect(() => {
    const caseId = activeCase?.id;
    if (!caseId) {
      setEvents([]);
      setEvidences([]);
      setSelectedEvidence("");
      return;
    }
    let cancelled = false;
    setFsJob(null);
    setFsError("");
    if (pollRef.current !== null) window.clearTimeout(pollRef.current);
    (async () => {
      try {
        const [tl, evs] = await Promise.all([
          api.cases.timeline(caseId),
          api.cases.listEvidence(caseId).catch(() => [] as EvidenceHandle[]),
        ]);
        if (cancelled) return;
        setEvents(tl.events);
        setEvidences(evs);
        setSelectedEvidence(evs.length > 0 ? evs[0].evidence_id : "");
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
  }, [activeCase?.id]);

  // Limpia el sondeo al desmontar.
  useEffect(() => {
    return () => {
      if (pollRef.current !== null) window.clearTimeout(pollRef.current);
    };
  }, []);

  const poll = useCallback((caseId: string, jobId: string) => {
    const tick = async () => {
      try {
        const snap = await api.cases.getFsTimelineJob(caseId, jobId);
        setFsJob(snap);
        if (snap.status === "running") {
          pollRef.current = window.setTimeout(tick, 1200);
        }
      } catch (err) {
        setFsError(err instanceof ApiError ? err.detail : String(err));
      }
    };
    void tick();
  }, []);

  const startFsTimeline = useCallback(async () => {
    if (!activeCase || !selectedEvidence) return;
    setFsError("");
    setFsJob(null);
    setStarting(true);
    if (pollRef.current !== null) window.clearTimeout(pollRef.current);
    try {
      const job = await api.cases.startFsTimeline(activeCase.id, selectedEvidence);
      setFsJob(job);
      poll(activeCase.id, job.job_id);
    } catch (err) {
      setFsError(err instanceof ApiError ? err.detail : String(err));
    } finally {
      setStarting(false);
    }
  }, [activeCase, selectedEvidence, poll]);

  // Export CSV del timeline de investigación (tool runs + hallazgos). Se descarga con
  // el token mismo-origen; un caso sin actividad exporta igual (cabecera honesta).
  const exportInvestigationCsv = useCallback(async () => {
    if (!activeCase) return;
    setExporting(true);
    setExportError("");
    try {
      await api.cases.exportTimelineCsv(activeCase.id);
    } catch (err) {
      setExportError(err instanceof ApiError ? err.detail : String(err));
    } finally {
      setExporting(false);
    }
  }, [activeCase]);

  const invMatches = useCallback(
    (e: TimelineEvent) => {
      const q = search.trim().toLowerCase();
      if (!q) return true;
      const hay =
        e.kind === "finding"
          ? `${e.tool_id ?? ""} ${e.title} ${e.summary} ${e.mitre_hints.join(" ")}`
          : `${e.tool_id ?? ""} ${e.argv.join(" ")} ${e.status}`;
      return hay.toLowerCase().includes(q);
    },
    [search],
  );

  const invFiltered = useMemo(() => events.filter(invMatches), [events, invMatches]);
  const invDays = useMemo(() => groupByDay(invFiltered, (e) => e.ts), [invFiltered]);

  const counts = useMemo(() => {
    let toolRuns = 0;
    let findings = 0;
    for (const e of events) {
      if (e.kind === "tool_run") toolRuns += 1;
      else findings += 1;
    }
    return { toolRuns, findings, total: events.length };
  }, [events]);

  const fsResult = fsJob?.status === "done" ? fsJob.result : null;
  const fsFiltered = useMemo(() => {
    if (!fsResult) return [] as FsTimelineEvent[];
    const q = search.trim().toLowerCase();
    if (!q) return fsResult.events;
    return fsResult.events.filter((e) =>
      `${e.path} ${e.macb} ${e.inode}`.toLowerCase().includes(q),
    );
  }, [fsResult, search]);
  const fsDays = useMemo(() => groupByDay(fsFiltered, (e) => e.ts), [fsFiltered]);
  const fsProgress = fsJob?.events ?? [];
  const lastProgress = fsProgress[fsProgress.length - 1]?.message ?? "";

  if (phase === "loading") {
    return <PageHeader title="Timeline forense" subtitle="Cargando la línea de tiempo…" />;
  }
  if (phase === "error") {
    return (
      <div>
        <PageHeader title="Timeline forense" subtitle="No se pudo cargar la línea de tiempo." />
        <EmptyState title="Error" description={error} />
      </div>
    );
  }
  if (phase === "no-case" || !activeCase) {
    return (
      <div>
        <PageHeader
          title="Timeline forense"
          subtitle="Línea temporal del caso: acciones de investigación y super-timeline del sistema de ficheros."
        />
        <EmptyState
          title="Sin caso abierto"
          description="Abre un caso: la línea de tiempo se construye con la actividad auditada y la evidencia del caso."
        />
      </div>
    );
  }

  return (
    <div className="tl-page">
      <PageHeader
        title="Timeline forense"
        subtitle="Línea temporal del caso. Todas las marcas de tiempo se muestran en UTC."
      />

      <div className="mitre-context">
        <span className="case-picker-row">
          <span className="case-picker-label">Caso activo</span>
          <select
            className="case-picker"
            aria-label="Caso activo"
            value={activeCase.id}
            onChange={(e) => setActiveCaseId(e.target.value)}
          >
            {cases.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
                {c.os_profile ? ` · ${c.os_profile}` : ""}
              </option>
            ))}
          </select>
          <span>· {activeCase.examiner}</span>
        </span>
        <span className="tl-tz">Zona horaria: UTC</span>
      </div>

      {/* Selector de capa */}
      <div className="tl-layers">
        <button
          className={`tl-layer${layer === "investigation" ? " is-active" : ""}`}
          onClick={() => setLayer("investigation")}
        >
          Investigación
          <span className="tl-layer-count">{counts.total}</span>
        </button>
        <button
          className={`tl-layer${layer === "filesystem" ? " is-active" : ""}`}
          onClick={() => setLayer("filesystem")}
        >
          Sistema de ficheros (MACB)
          {fsResult && <span className="tl-layer-count">{fsResult.total_events}</span>}
        </button>
      </div>

      {/* Buscador (común a ambas capas) */}
      <div className="tl-toolbar">
        <input
          className="tl-search"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder={
            layer === "investigation"
              ? "Buscar por herramienta, argv, hallazgo o técnica…"
              : "Buscar por ruta, MACB o inode…"
          }
        />
        {layer === "investigation" && (
          <div className="tl-summary">
            <span>{counts.toolRuns} ejecuciones</span>
            <span>{counts.findings} hallazgos</span>
          </div>
        )}
        {layer === "investigation" && (
          <button
            className="tl-run-btn"
            onClick={exportInvestigationCsv}
            disabled={exporting}
            title="Descargar el timeline de investigación como CSV"
          >
            {exporting ? "Exportando…" : "Exportar CSV"}
          </button>
        )}
      </div>

      {exportError && layer === "investigation" && (
        <div className="tl-fserror">No se pudo exportar: {exportError}</div>
      )}

      {layer === "investigation" ? (
        <div className="tl-scroll">
          {events.length === 0 ? (
            <div className="tl-empty">
              Aún no hay actividad en este caso. La línea de tiempo se llena con cada
              herramienta que se ejecuta y cada hallazgo que el agente registra.
            </div>
          ) : invFiltered.length === 0 ? (
            <div className="tl-empty">No hay eventos que coincidan con la búsqueda.</div>
          ) : (
            invDays.map((day) => (
              <div className="tl-day" key={day.label}>
                <div className="tl-day-head">
                  <span className="tl-day-label">{day.label} · UTC</span>
                  <span className="tl-day-rule" />
                  <span className="tl-day-count">{day.rows.length} eventos</span>
                </div>
                <div className="tl-rail">
                  {day.rows.map((ev) =>
                    ev.kind === "finding" ? (
                      <div className="tl-event" key={ev.finding_id}>
                        <span className={`tl-dot tl-dot--${ev.severity}`} />
                        <div className="tl-event-meta">
                          <span className="tl-time">{fmtUtc(ev.ts).time} UTC</span>
                          <span className="tl-kind tl-kind--finding">Hallazgo</span>
                          <span className="tl-src">{ev.tool_id ?? "agente"}</span>
                          <span className={`tl-sev tl-sev--${ev.severity}`}>
                            {SEV_LABEL[ev.severity] ?? ev.severity}
                          </span>
                        </div>
                        <p className="tl-desc">{ev.summary || ev.title}</p>
                        {ev.mitre_hints.length > 0 && (
                          <div className="tl-techs">
                            {ev.mitre_hints.map((t) => (
                              <span className="tl-tech" key={t}>
                                {t}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="tl-event" key={ev.run_id ?? `${ev.ts}-${ev.tool_id}`}>
                        <span
                          className={`tl-dot ${
                            ev.exit === 0 ? "tl-dot--ok" : ev.exit === null ? "tl-dot--run" : "tl-dot--fail"
                          }`}
                        />
                        <div className="tl-event-meta">
                          <span className="tl-time">{fmtUtc(ev.ts).time} UTC</span>
                          <span className="tl-kind tl-kind--tool">Ejecución</span>
                          <span className="tl-src">{ev.tool_id ?? "tool"}</span>
                          <span
                            className={`tl-exit ${
                              ev.exit === 0
                                ? "tl-exit--ok"
                                : ev.exit === null
                                  ? "tl-exit--run"
                                  : "tl-exit--fail"
                            }`}
                          >
                            {ev.exit === null ? ev.status : `exit ${ev.exit}`}
                          </span>
                        </div>
                        <code className="tl-argv">{ev.argv.join(" ") || "(sin argv)"}</code>
                        {ev.output_files_count !== null && ev.output_files_count > 0 && (
                          <div className="tl-techs">
                            <span className="tl-tech">
                              {ev.output_files_count} artefacto
                              {ev.output_files_count === 1 ? "" : "s"}
                            </span>
                          </div>
                        )}
                      </div>
                    ),
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      ) : (
        <>
          <div className="tl-fsbar">
            <select
              className="tl-source"
              value={selectedEvidence}
              onChange={(e) => setSelectedEvidence(e.target.value)}
              disabled={evidences.length === 0 || fsJob?.status === "running"}
            >
              {evidences.length === 0 && <option value="">Sin evidencia registrada</option>}
              {evidences.map((e) => (
                <option key={e.evidence_id} value={e.evidence_id}>
                  {evidenceName(e)}
                </option>
              ))}
            </select>
            <button
              className="tl-run-btn"
              onClick={startFsTimeline}
              disabled={
                !selectedEvidence || starting || fsJob?.status === "running" || evidences.length === 0
              }
            >
              {fsJob?.status === "running" || starting
                ? "Generando…"
                : "Generar super-timeline (tsk_fls -m)"}
            </button>
          </div>

          {evidences.length === 0 && (
            <div className="docs-note">
              Registra una evidencia en el caso para construir la super-timeline del sistema
              de ficheros.
            </div>
          )}

          {fsError && <div className="tl-fserror">{fsError}</div>}

          {fsJob?.status === "running" && (
            <div className="tl-fsstatus">
              <span className="tl-spinner" />
              {lastProgress || "Ejecutando tsk_fls -m sobre la evidencia…"}
            </div>
          )}
          {fsJob?.status === "error" && (
            <div className="tl-fserror">{fsJob.error ?? "El análisis falló."}</div>
          )}

          {fsResult && (
            <div className="tl-scroll">
              {fsResult.truncated && (
                <div className="tl-truncated">
                  Mostrando {fsResult.returned} de {fsResult.total_events} eventos (recortado
                  para acotar el tamaño). Afina con la búsqueda.
                </div>
              )}
              {fsFiltered.length === 0 ? (
                <div className="tl-empty">
                  {fsResult.total_events === 0
                    ? "La evidencia no produjo eventos de sistema de ficheros."
                    : "No hay eventos que coincidan con la búsqueda."}
                </div>
              ) : (
                fsDays.map((day) => (
                  <div className="tl-day" key={day.label}>
                    <div className="tl-day-head">
                      <span className="tl-day-label">{day.label} · UTC</span>
                      <span className="tl-day-rule" />
                      <span className="tl-day-count">{day.rows.length} eventos</span>
                    </div>
                    <table className="tl-fstable">
                      <thead>
                        <tr>
                          <th>Hora (UTC)</th>
                          <th>MACB</th>
                          <th>Tamaño</th>
                          <th>Inodo</th>
                          <th>Ruta</th>
                        </tr>
                      </thead>
                      <tbody>
                        {day.rows.map((ev, i) => (
                          <tr key={`${ev.inode}-${ev.ts}-${i}`}>
                            <td className="tl-fs-time">{fmtUtc(ev.ts).time}</td>
                            <td>
                              <code className="tl-macb">{ev.macb}</code>
                            </td>
                            <td className="tl-fs-size">{ev.size.toLocaleString("es-ES")}</td>
                            <td className="tl-fs-inode">{ev.inode}</td>
                            <td className="tl-fs-path">{ev.path}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ))
              )}
            </div>
          )}

          {!fsJob && !fsError && evidences.length > 0 && (
            <div className="tl-empty">
              Pulsa «Generar super-timeline» para construir la línea temporal MACB del sistema
              de ficheros a partir de la evidencia seleccionada.
            </div>
          )}
        </>
      )}
    </div>
  );
}
