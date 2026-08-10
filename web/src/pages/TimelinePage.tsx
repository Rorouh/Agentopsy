import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError } from "../api/client";
import type {
  EvidenceHandle,
  FsRelevantEvent,
  FsTimelineEvent,
  FsTimelineJob,
  FsTimelineResult,
  TimelineEvent,
} from "../api/types";
import { usePublishShellHeader } from "../layout/shellHeader";
import { useActiveCase } from "../state/activeCase";
import { useCaseEvidence } from "../state/caseEvidence";

// FASE 4 · Timeline forense del caso, TRES capas REALES (sin datos inventados,
// RULE 2):
//   1) Investigación: cada ejecución de herramienta del audit log + cada
//      hallazgo, en orden cronológico. Determinista, siempre disponible.
//   2) Sistema de ficheros: la super-timeline MACB (tsk_fls -m) sobre la
//      evidencia seleccionada, bajo demanda y asíncrona (job).
//   3) Eventos relevantes: el triage forense determinista sobre (2).
// Todas las marcas de tiempo son UTC y se muestran con la zona explícita:
// NUNCA se convierten a la hora local del navegador.

type Layer = "investigation" | "filesystem" | "relevant";

const SEV_LABEL: Record<string, string> = {
  low: "Baja",
  medium: "Media",
  high: "Alta",
  critical: "Crítica",
};

// Filas por página en las tablas del sistema de ficheros (paginación client-side).
const FS_PAGE_SIZE = 200;

// Etiqueta legible de cada categoría de relevancia (clasificador determinista del
// backend, forensia.timeline.relevance). Fuente única de las etiquetas de la UI.
const CATEGORY_LABEL: Record<string, string> = {
  credenciales: "Credenciales",
  ssh: "SSH",
  historial: "Historial de shell",
  persistencia: "Persistencia",
  ejecutable_temporal: "Ejecutable en temporal",
  web: "Artefacto web",
  logs: "Logs",
  binario_sistema: "Binario de sistema",
};

function fmtUtc(ts: string | null): { date: string; time: string } {
  if (!ts) return { date: "sin fecha", time: "n/d" };
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

// Controles de paginación de las tablas del sistema de ficheros. `page` es 0-based.
function Pager({
  page,
  pageCount,
  total,
  noun,
  onPage,
}: {
  page: number;
  pageCount: number;
  total: number;
  noun: string;
  onPage: (p: number) => void;
}) {
  if (total === 0) return null;
  return (
    <div className="pager">
      <button type="button" className="pager-btn" onClick={() => onPage(0)} disabled={page <= 0}>
        «
      </button>
      <button
        type="button"
        className="pager-btn"
        onClick={() => onPage(page - 1)}
        disabled={page <= 0}
      >
        ‹
      </button>
      <span className="pager-info">
        Página {page + 1} de {pageCount} · {total.toLocaleString("es-ES")} {noun}
      </span>
      <button
        type="button"
        className="pager-btn"
        onClick={() => onPage(page + 1)}
        disabled={page >= pageCount - 1}
      >
        ›
      </button>
      <button
        type="button"
        className="pager-btn"
        onClick={() => onPage(pageCount - 1)}
        disabled={page >= pageCount - 1}
      >
        »
      </button>
    </div>
  );
}

export function TimelinePage() {
  const { activeCase, phase: casesPhase, error: casesError } = useActiveCase();
  // Capa 2: la evidencia elegible sale del store compartido, así una imagen
  // registrada mientras el perito está en esta vista aparece en el selector sin
  // recargar la página.
  const { evidence: evidences } = useCaseEvidence();
  const [layer, setLayer] = useState<Layer>("investigation");
  const [search, setSearch] = useState("");
  // Página actual de las tablas del sistema de ficheros (capas 2 y 3).
  const [fsPage, setFsPage] = useState(0);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState("");
  const [loadError, setLoadError] = useState("");

  // Capa 1
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  // RULE 2: NO se preselecciona «la primera» evidencia. La super-timeline se
  // construye sobre la que el perito elija; adivinarla es exactamente el
  // «coge el único / el más reciente» que la regla prohíbe.
  const [selectedEvidence, setSelectedEvidence] = useState("");
  const [fsJob, setFsJob] = useState<FsTimelineJob | null>(null);
  // Super-timeline PERSISTIDA de la evidencia seleccionada (rehidrata la vista
  // tras recargar/cambiar de caso sin re-ejecutar fls). null = nunca generada.
  const [loadedFsResult, setLoadedFsResult] = useState<FsTimelineResult | null>(null);
  const [fsError, setFsError] = useState("");
  const [starting, setStarting] = useState(false);
  const pollRef = useRef<number | null>(null);

  // Timeline del caso activo. Se recarga al cambiar de caso (desde el sidebar o
  // cualquier otra vista), limpiando el estado de la capa 2. La lista de
  // evidencias no se pide aquí, la sirve el store.
  useEffect(() => {
    const caseId = activeCase?.id;
    if (!caseId) {
      setEvents([]);
      setSelectedEvidence("");
      return;
    }
    let cancelled = false;
    setLoadError("");
    (async () => {
      try {
        const tl = await api.cases.timeline(caseId);
        if (cancelled) return;
        setEvents(tl.events);
        setSelectedEvidence("");
      } catch (err) {
        if (!cancelled) setLoadError(err instanceof Error ? err.message : String(err));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [activeCase?.id]);

  // Rehidrata la capa 2 al cambiar de caso o de evidencia seleccionada: cancela
  // cualquier job/sondeo en curso y carga la super-timeline PERSISTIDA de esa
  // evidencia (si nunca se generó, queda null → vacío explicativo).
  useEffect(() => {
    const caseId = activeCase?.id;
    const evidenceId = selectedEvidence;
    if (pollRef.current !== null) window.clearTimeout(pollRef.current);
    setFsJob(null);
    setFsError("");
    setLoadedFsResult(null);
    if (!caseId || !evidenceId) return;
    let cancelled = false;
    (async () => {
      try {
        const { result } = await api.cases.getPersistedFsTimeline(caseId, evidenceId);
        if (!cancelled) setLoadedFsResult(result);
      } catch {
        // Silencioso: sin persistido (o fallo puntual) se muestra el vacío.
        if (!cancelled) setLoadedFsResult(null);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [activeCase?.id, selectedEvidence]);

  // Vuelve a la primera página cuando cambia el conjunto mostrado.
  useEffect(() => {
    setFsPage(0);
  }, [layer, search, selectedEvidence, activeCase?.id, fsJob?.status]);

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

  // Export CSV del timeline de investigación (tool runs + hallazgos). Se descarga
  // con el token mismo-origen; un caso sin actividad exporta igual.
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

  // Un job activo gobierna la vista; sin job, la super-timeline persistida.
  const fsResult = fsJob ? (fsJob.status === "done" ? fsJob.result : null) : loadedFsResult;
  const fsFiltered = useMemo(() => {
    if (!fsResult) return [] as FsTimelineEvent[];
    const q = search.trim().toLowerCase();
    if (!q) return fsResult.events;
    return fsResult.events.filter((e) => `${e.path} ${e.macb} ${e.inode}`.toLowerCase().includes(q));
  }, [fsResult, search]);

  const relevantFiltered = useMemo(() => {
    const all = fsResult?.relevant_events ?? [];
    const q = search.trim().toLowerCase();
    if (!q) return all;
    return all.filter((e) =>
      `${e.path} ${e.macb} ${e.inode} ${e.reason} ${CATEGORY_LABEL[e.category] ?? e.category}`
        .toLowerCase()
        .includes(q),
    );
  }, [fsResult, search]);

  const activeFsRows = layer === "relevant" ? relevantFiltered : fsFiltered;
  const fsPageCount = Math.max(1, Math.ceil(activeFsRows.length / FS_PAGE_SIZE));
  const safeFsPage = Math.min(fsPage, fsPageCount - 1);
  const fsPageRows = useMemo(
    () => activeFsRows.slice(safeFsPage * FS_PAGE_SIZE, safeFsPage * FS_PAGE_SIZE + FS_PAGE_SIZE),
    [activeFsRows, safeFsPage],
  );
  const fsDays = useMemo(
    () => groupByDay(fsPageRows as FsTimelineEvent[], (e) => e.ts),
    [fsPageRows],
  );

  const fsProgress = fsJob?.events ?? [];
  const lastProgress = fsProgress[fsProgress.length - 1]?.message ?? "";
  const isInvestigation = layer === "investigation";
  const canGenerate =
    !!selectedEvidence && !starting && fsJob?.status !== "running" && evidences.length > 0;

  // Exportar CSV pertenece SOLO a la capa de investigación; generar la
  // super-timeline (tsk_fls -m), solo a las de sistema de ficheros. La cabecera
  // transporta la acción YA RESUELTA por la página, no la regla (RULE 3).
  usePublishShellHeader(
    {
      title: "Timeline forense",
      meta: !activeCase
        ? "sin caso seleccionado"
        : isInvestigation
          ? `UTC · ${counts.toolRuns} ejecuciones · ${counts.findings} hallazgos`
          : fsResult
            ? `UTC · ${fsResult.total_events} eventos MACB`
            : "UTC · super-timeline sin generar",
      action: !activeCase ? undefined : isInvestigation ? (
        <button type="button" disabled={exporting} onClick={() => void exportInvestigationCsv()}>
          {exporting ? "Exportando…" : "Exportar CSV"}
        </button>
      ) : (
        <button
          type="button"
          disabled={!canGenerate}
          title={selectedEvidence ? undefined : "Elige primero la evidencia."}
          onClick={() => void startFsTimeline()}
        >
          {fsJob?.status === "running" || starting ? "Generando…" : "Generar super-timeline"}
        </button>
      ),
    },
    [
      activeCase?.id,
      isInvestigation,
      counts.toolRuns,
      counts.findings,
      fsResult?.total_events,
      exporting,
      canGenerate,
      starting,
      fsJob?.status,
    ],
  );

  if (casesPhase === "loading") {
    return (
      <div className="view-scroll">
        <div className="loading-state">
          <span className="spinner" aria-hidden="true" />
          <span>Cargando la línea de tiempo…</span>
        </div>
      </div>
    );
  }

  if (casesPhase === "error" || loadError) {
    return (
      <div className="view-scroll">
        <div className="error-state">
          <strong>No se pudo cargar la línea de tiempo:</strong> {loadError || casesError}
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
            La línea de tiempo se construye con la actividad auditada y la evidencia del caso.
            Abre uno desde el lateral.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="timeline">
      <div className="tl-bar">
        <div className="tab-row">
          <button
            type="button"
            className={`tab${layer === "investigation" ? " is-active" : ""}`}
            onClick={() => setLayer("investigation")}
          >
            Investigación
            <span className="tab-count">{counts.total}</span>
          </button>
          <button
            type="button"
            className={`tab${layer === "filesystem" ? " is-active" : ""}`}
            onClick={() => setLayer("filesystem")}
          >
            Sistema de ficheros (MACB)
            <span className="tab-count">{fsResult ? fsResult.total_events : "n/d"}</span>
          </button>
          <button
            type="button"
            className={`tab${layer === "relevant" ? " is-active" : ""}`}
            onClick={() => setLayer("relevant")}
            title="Eventos del sistema de ficheros forensemente relevantes (credenciales, persistencia, historial, logs, ejecutables en temporales…)"
          >
            Eventos relevantes
            <span className="tab-count">
              {fsResult?.total_relevant !== undefined ? fsResult.total_relevant : "n/d"}
            </span>
          </button>
        </div>
        <span className="bar-note">Todas las horas en UTC</span>
      </div>

      <div className="tl-toolbar">
        <label className="visually-hidden" htmlFor="tl-search">
          Buscar en la línea de tiempo
        </label>
        <input
          id="tl-search"
          className="field-input tl-search"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder={
            isInvestigation
              ? "Buscar por herramienta, argv, hallazgo o técnica…"
              : layer === "relevant"
                ? "Buscar por ruta, motivo, categoría, MACB o inode…"
                : "Buscar por ruta, MACB o inode…"
          }
        />
        {isInvestigation ? (
          <div className="tl-meta">
            {counts.toolRuns} ejecuciones · {counts.findings} hallazgos
          </div>
        ) : (
          <div className="tl-evidence">
            <span className="eyebrow">Evidencia</span>
            <label className="visually-hidden" htmlFor="tl-evidence-select">
              Evidencia de la super-timeline
            </label>
            <select
              id="tl-evidence-select"
              className="field-select"
              value={selectedEvidence}
              onChange={(e) => setSelectedEvidence(e.target.value)}
              disabled={evidences.length === 0 || fsJob?.status === "running"}
            >
              <option value="">
                {evidences.length === 0 ? "Sin evidencia registrada" : "Elige la evidencia…"}
              </option>
              {evidences.map((e) => (
                <option key={e.evidence_id} value={e.evidence_id}>
                  {evidenceName(e)}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      <div className="tl-scroll">
        <div className="view-stack view-stack--1000 tl-stack">
          {exportError && isInvestigation && (
            <div className="error-state">No se pudo exportar: {exportError}</div>
          )}

          {isInvestigation ? (
            events.length === 0 ? (
              <div className="empty-rail">
                <div className="empty-rail-title">Sin actividad todavía</div>
                <div className="empty-rail-body">
                  La línea de tiempo se llena con cada herramienta que se ejecuta y cada hallazgo
                  que el agente registra, tomados del log de auditoría encadenado.
                </div>
              </div>
            ) : invFiltered.length === 0 ? (
              <div className="inline-note">Ningún evento coincide con la búsqueda.</div>
            ) : (
              invDays.map((day) => (
                <div className="tl-day" key={day.label}>
                  <div className="tl-day-head">
                    <span className="tl-day-label">{day.label} · UTC</span>
                    <span className="rule" />
                    <span className="rule-count">
                      {day.rows.length} evento{day.rows.length === 1 ? "" : "s"}
                    </span>
                  </div>
                  {day.rows.map((ev) =>
                    ev.kind === "finding" ? (
                      <div className="tl-row" key={ev.finding_id}>
                        <div className="tl-time">{fmtUtc(ev.ts).time}</div>
                        <div className="tl-kindcol">
                          <span className="tl-kind tl-kind--finding">Hallazgo</span>
                          <span className="tl-src">
                            {ev.tool_id ?? "agente"} · {SEV_LABEL[ev.severity] ?? ev.severity}
                          </span>
                        </div>
                        <div className="tl-body">
                          <div className="tl-desc">{ev.summary || ev.title}</div>
                          {ev.mitre_hints.length > 0 && (
                            <div className="tl-techs">
                              {ev.mitre_hints.map((t) => (
                                <span key={t}>{t}</span>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    ) : (
                      <div className="tl-row" key={ev.run_id ?? `${ev.ts}-${ev.tool_id}`}>
                        <div className="tl-time">{fmtUtc(ev.ts).time}</div>
                        <div className="tl-kindcol">
                          <span className="tl-kind">Ejecución</span>
                          <span className="tl-src">
                            {ev.tool_id ?? "tool"}
                            {ev.exit === null ? ` · ${ev.status}` : ` · exit ${ev.exit}`}
                          </span>
                        </div>
                        <div className="tl-body">
                          {/* El argv LITERAL que se ejecutó (FORENSIC INVARIANT 4). */}
                          <div className="tl-argv">{ev.argv.join(" ") || "(sin argv)"}</div>
                          {ev.output_files_count !== null && ev.output_files_count > 0 && (
                            <div className="tl-techs">
                              <span>
                                {ev.output_files_count} artefacto
                                {ev.output_files_count === 1 ? "" : "s"}
                              </span>
                            </div>
                          )}
                        </div>
                      </div>
                    ),
                  )}
                </div>
              ))
            )
          ) : (
            <>
              {evidences.length === 0 ? (
                <div className="empty-rail">
                  <div className="empty-rail-title">Sin evidencia registrada</div>
                  <div className="empty-rail-body">
                    Registra una evidencia en el caso para construir la super-timeline del
                    sistema de ficheros.
                  </div>
                </div>
              ) : !selectedEvidence ? (
                <div className="empty-rail">
                  <div className="empty-rail-title">Elige la evidencia</div>
                  <div className="empty-rail-body">
                    La super-timeline se construye sobre una evidencia concreta. Agentopsy no
                    elige por ti cuál analizar.
                  </div>
                </div>
              ) : null}

              {fsError && <div className="error-state">{fsError}</div>}

              {fsJob?.status === "running" && (
                <div className="progress-block" aria-live="polite">
                  <div className="progress-head">
                    <span>{lastProgress || "Ejecutando tsk_fls -m sobre la evidencia…"}</span>
                  </div>
                  <div className="progress-track">
                    <div className="progress-fill progress-fill--indeterminate" />
                  </div>
                  <div className="progress-note">
                    Es un trabajo asíncrono: puedes seguir investigando mientras corre.
                  </div>
                </div>
              )}
              {fsJob?.status === "error" && (
                <div className="error-state">{fsJob.error ?? "El análisis falló."}</div>
              )}

              {selectedEvidence && !fsJob && !fsResult && !fsError && (
                <div className="empty-rail">
                  <div className="empty-rail-title">Super-timeline sin generar</div>
                  <div className="empty-rail-body">
                    La línea temporal MACB se construye ejecutando <span className="mono">
                      tsk_fls -m
                    </span>{" "}
                    sobre la evidencia seleccionada. Es un trabajo asíncrono: puedes seguir
                    investigando mientras corre.
                  </div>
                </div>
              )}

              {fsResult && fsResult.generated_at && !fsJob && (
                <div className="inline-note">
                  Super-timeline generada el {fmtUtc(fsResult.generated_at).date} a las{" "}
                  {fmtUtc(fsResult.generated_at).time} UTC · {fsResult.total_events} eventos.
                  Vuelve a pulsar «Generar super-timeline» para recalcularla.
                </div>
              )}

              {fsResult && layer === "filesystem" && (
                <>
                  {fsResult.truncated && (
                    <div className="inline-note">
                      Mostrando {fsResult.returned} de {fsResult.total_events} eventos (recortado
                      para acotar el tamaño). Afina con la búsqueda.
                    </div>
                  )}
                  {fsFiltered.length === 0 ? (
                    <div className="inline-note">
                      {fsResult.total_events === 0
                        ? "La evidencia no produjo eventos de sistema de ficheros."
                        : "Ningún evento coincide con la búsqueda."}
                    </div>
                  ) : (
                    <>
                      {fsDays.map((day) => (
                        <div className="tl-day" key={day.label}>
                          <div className="tl-day-head">
                            <span className="tl-day-label">{day.label} · UTC</span>
                            <span className="rule" />
                            <span className="rule-count">{day.rows.length} eventos</span>
                          </div>
                          <div className="table-scroll">
                            <table className="data-table">
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
                                    <td className="cell-dim">{fmtUtc(ev.ts).time}</td>
                                    <td className="cell-mono">{ev.macb}</td>
                                    <td className="cell-dim">{ev.size.toLocaleString("es-ES")}</td>
                                    <td className="cell-dim">{ev.inode}</td>
                                    <td className="cell-path">{ev.path}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      ))}
                      <Pager
                        page={safeFsPage}
                        pageCount={fsPageCount}
                        total={fsFiltered.length}
                        noun="eventos"
                        onPage={setFsPage}
                      />
                    </>
                  )}
                </>
              )}

              {fsResult && layer === "relevant" && (
                <>
                  {fsResult.relevant_events === undefined ? (
                    <div className="inline-note">
                      Esta super-timeline se generó con una versión anterior sin triage de
                      relevancia. Vuelve a pulsar «Generar super-timeline» para calcular los
                      eventos relevantes.
                    </div>
                  ) : (
                    <>
                      {fsResult.relevant_truncated && (
                        <div className="inline-note">
                          Mostrando {fsResult.relevant_returned} de {fsResult.total_relevant}{" "}
                          eventos relevantes (recortado). Afina con la búsqueda.
                        </div>
                      )}
                      {relevantFiltered.length === 0 ? (
                        <div className="inline-note">
                          {(fsResult.total_relevant ?? 0) === 0
                            ? "El triage no marcó ningún evento del sistema de ficheros como relevante."
                            : "Ningún evento relevante coincide con la búsqueda."}
                        </div>
                      ) : (
                        <>
                          <div className="table-scroll">
                            <table className="data-table">
                              <thead>
                                <tr>
                                  <th>Fecha (UTC)</th>
                                  <th>Hora</th>
                                  <th>Categoría</th>
                                  <th>Motivo</th>
                                  <th>MACB</th>
                                  <th>Ruta</th>
                                </tr>
                              </thead>
                              <tbody>
                                {(fsPageRows as FsRelevantEvent[]).map((ev, i) => (
                                  <tr key={`${ev.inode}-${ev.ts}-${ev.category}-${i}`}>
                                    <td className="cell-dim">{fmtUtc(ev.ts).date}</td>
                                    <td className="cell-dim">{fmtUtc(ev.ts).time}</td>
                                    <td>
                                      <span className="tag tag--accent">
                                        {CATEGORY_LABEL[ev.category] ?? ev.category}
                                      </span>
                                    </td>
                                    <td className="cell-text">{ev.reason}</td>
                                    <td className="cell-mono">{ev.macb}</td>
                                    <td className="cell-path">{ev.path}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                          <Pager
                            page={safeFsPage}
                            pageCount={fsPageCount}
                            total={relevantFiltered.length}
                            noun="eventos relevantes"
                            onPage={setFsPage}
                          />
                        </>
                      )}
                    </>
                  )}
                </>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
