import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError } from "../api/client";
import type {
  EvidenceHandle,
  FsRelevantEvent,
  FsTimelineEvent,
  FsTimelineJob,
  FsTimelineResult,
  IncidentTimeline,
  TimelineEvent,
} from "../api/types";
import { usePublishShellHeader } from "../layout/shellHeader";
import { useLang, type MessageKey } from "../i18n";
import { useActiveCase } from "../state/activeCase";
import { useCaseStream } from "../state/casePulse";
import { useCaseEvidence } from "../state/caseEvidence";
import { IncidentRail, exportRailPng } from "./timeline/IncidentRail";
import { useThemePalette } from "./timeline/themePalette";

// FASE 4 · Timeline forense del caso, CUATRO capas REALES (sin datos inventados,
// RULE 2):
//   0) Hallazgos: la línea de tiempo del INCIDENTE, lo que pasó en el
//      dispositivo investigado, un evento por hallazgo con `observed_at`. Es la
//      capa de entrada porque es la que se lleva al informe y la primera que
//      lee un tercero, y se lee como FIGURA, no como tabla.
//   1) Investigación: cada ejecución de herramienta del audit log + cada
//      hallazgo, en orden cronológico. Determinista, siempre disponible. Es la
//      cronología del TRABAJO DEL AGENTE, otro objeto que la capa 0.
//   2) Sistema de ficheros: la super-timeline MACB (tsk_fls -m) sobre la
//      evidencia seleccionada, bajo demanda y asíncrona (job).
//   3) Eventos relevantes: el triage forense determinista sobre (2).
// Todas las marcas de tiempo son UTC y se muestran con la zona explícita:
// NUNCA se convierten a la hora local del navegador.

type Layer = "findings" | "investigation" | "filesystem" | "relevant";

const SEV_KEY: Record<string, MessageKey> = {
  low: "tl.sev.low",
  medium: "tl.sev.medium",
  high: "tl.sev.high",
  critical: "tl.sev.critical",
};

// Filas por página en las tablas del sistema de ficheros (paginación client-side).
const FS_PAGE_SIZE = 200;

// Etiqueta legible de cada categoría de relevancia (clasificador determinista del
// backend, agentopsy.timeline.relevance). Fuente única de las etiquetas de la UI.
// La CATEGORÍA la determina el clasificador del backend
// (`agentopsy.timeline.relevance`) y su valor es dato: una que esta tabla no
// declare se pinta tal cual (RULE 2), nunca traducida a lo que se le parezca.
const CATEGORY_KEY: Record<string, MessageKey> = {
  credenciales: "tl.cat.credenciales",
  ssh: "tl.cat.ssh",
  historial: "tl.cat.historial",
  persistencia: "tl.cat.persistencia",
  ejecutable_temporal: "tl.cat.ejecutable_temporal",
  web: "tl.cat.web",
  logs: "tl.cat.logs",
  binario_sistema: "tl.cat.binario_sistema",
};

function fmtUtc(
  ts: string | null,
  blancoFecha = "no date",
  blancoHora = "n/a",
): { date: string; time: string } {
  if (!ts) return { date: blancoFecha, time: blancoHora };
  const d = new Date(ts);
  if (isNaN(d.getTime())) return { date: ts.slice(0, 10) || blancoFecha, time: ts.slice(11, 19) };
  const p = (n: number) => String(n).padStart(2, "0");
  return {
    date: `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}`,
    time: `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`,
  };
}

function groupByDay<T>(
  rows: T[],
  ts: (row: T) => string | null,
  blancoFecha: string,
): { label: string; rows: T[] }[] {
  const map = new Map<string, T[]>();
  for (const row of rows) {
    const label = fmtUtc(ts(row), blancoFecha).date;
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
  const { t, locale } = useLang();
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
        {t("tl.pager", {
          page: page + 1,
          total: pageCount,
          count: total.toLocaleString(locale),
          noun,
        })}
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
  const { t, tn, locale } = useLang();
  // `fmtUtc` es puro; aquí se le atan los blancos del idioma para no
  // repetirlos en las quince llamadas de la vista.
  const fecha = (ts: string | null) => fmtUtc(ts, t("tl.noDate"), t("common.na"));
  const { activeCase, phase: casesPhase, error: casesError } = useActiveCase();
  // Las dos capas de la vista: la de investigación se agrega del log encadenado
  // (cada herramienta que corre añade eventos) y la del incidente, de los
  // hallazgos. Una y otra crecen mientras el análisis trabaja.
  const revTimeline = useCaseStream("audit", "findings");
  // Capa 2: la evidencia elegible sale del store compartido, así una imagen
  // registrada mientras el perito está en esta vista aparece en el selector sin
  // recargar la página.
  const { evidence: evidences } = useCaseEvidence();
  // La capa del INCIDENTE es la de entrada: es lo que se lleva al informe.
  const [layer, setLayer] = useState<Layer>("findings");
  const [search, setSearch] = useState("");
  // Página actual de las tablas del sistema de ficheros (capas 2 y 3).
  const [fsPage, setFsPage] = useState(0);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState("");
  const [loadError, setLoadError] = useState("");

  // Capa 0, la línea de tiempo del incidente (figura + su procedencia).
  const [incident, setIncident] = useState<IncidentTimeline | null>(null);
  const railRef = useRef<SVGSVGElement | null>(null);
  const palette = useThemePalette();
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
      setIncident(null);
      setSelectedEvidence("");
      return;
    }
    let cancelled = false;
    setLoadError("");
    (async () => {
      try {
        const [tl, inc] = await Promise.all([
          api.cases.timeline(caseId),
          api.cases.incidentTimeline(caseId),
        ]);
        if (cancelled) return;
        setEvents(tl.events);
        setIncident(inc);
        setSelectedEvidence("");
      } catch (err) {
        if (!cancelled) setLoadError(err instanceof Error ? err.message : String(err));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [activeCase?.id]);

  // Reposición EN SILENCIO mientras el análisis corre: la línea crece sola. No
  // toca `selectedEvidence`, que es una elección del perito para la capa 2 y no
  // puede reiniciarse cada vez que una herramienta termina.
  useEffect(() => {
    const caseId = activeCase?.id;
    if (!caseId || revTimeline === 0) return;
    let cancelled = false;
    (async () => {
      const [tl, inc] = await Promise.all([
        api.cases.timeline(caseId).catch(() => null),
        api.cases.incidentTimeline(caseId).catch(() => null),
      ]);
      if (cancelled) return;
      if (tl) setEvents(tl.events);
      if (inc) setIncident(inc);
    })();
    return () => {
      cancelled = true;
    };
  }, [activeCase?.id, revTimeline]);

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

  // Hoja de cálculo del timeline de investigación (tool runs + hallazgos). Se descarga
  // con el token mismo-origen; un caso sin actividad exporta igual.
  const exportInvestigationCsv = useCallback(async () => {
    if (!activeCase) return;
    setExporting(true);
    setExportError("");
    try {
      await api.cases.exportTimelineHoja(activeCase.id);
    } catch (err) {
      setExportError(err instanceof ApiError ? err.detail : String(err));
    } finally {
      setExporting(false);
    }
  }, [activeCase]);

  // Export PNG de la figura del incidente. Se vuelve a pedir la capa ANTES de dibujar:
  // la imagen lleva dentro su instante de exportación y su nombre de fichero, los dos
  // resueltos por el backend, y una figura que dice cuándo se exportó tiene que decir
  // la verdad, no la hora en que se abrió la vista.
  const exportIncidentPng = useCallback(async () => {
    if (!activeCase) return;
    setExporting(true);
    setExportError("");
    try {
      const fresh = await api.cases.incidentTimeline(activeCase.id);
      setIncident(fresh);
      // Un ciclo de pintado para que el SVG del ref sea ya el de los datos frescos.
      await new Promise((r) => requestAnimationFrame(() => r(null)));
      const svg = railRef.current;
      if (!svg) throw new Error(t("tl.figureNotDrawn"));
      await exportRailPng(svg, `${fresh.export_basename}.png`, palette["--surface"]);
    } catch (err) {
      setExportError(err instanceof ApiError ? err.detail : String(err));
    } finally {
      setExporting(false);
    }
  }, [activeCase, palette]);

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
  const invDays = useMemo(
    () => groupByDay(invFiltered, (e) => e.ts, t("tl.noDate")),
    [invFiltered, t],
  );

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
  }, [fsResult, search, t]);

  const relevantFiltered = useMemo(() => {
    const all = fsResult?.relevant_events ?? [];
    const q = search.trim().toLowerCase();
    if (!q) return all;
    return all.filter((e) =>
      `${e.path} ${e.macb} ${e.inode} ${e.reason} ${
        CATEGORY_KEY[e.category] ? t(CATEGORY_KEY[e.category]) : e.category
      }`
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
    () => groupByDay(fsPageRows as FsTimelineEvent[], (e) => e.ts, t("tl.noDate")),
    [fsPageRows, t],
  );

  const fsProgress = fsJob?.events ?? [];
  const lastProgress = fsProgress[fsProgress.length - 1]?.message ?? "";
  const isIncident = layer === "findings";
  const isInvestigation = layer === "investigation";
  // Sin ningún evento situable no se ofrece exportar: una imagen vacía no es un anexo.
  const canExportIncident = !!incident && incident.eventos.length > 0;
  const canGenerate =
    !!selectedEvidence && !starting && fsJob?.status !== "running" && evidences.length > 0;

  // Exportar la hoja pertenece SOLO a la capa de investigación; generar la
  // super-timeline (tsk_fls -m), solo a las de sistema de ficheros. La cabecera
  // transporta la acción YA RESUELTA por la página, no la regla (RULE 3).
  usePublishShellHeader(
    {
      title: t("tl.title"),
      // Sin meta con caso abierto: lo decía todo dos veces. El «UTC» lo enuncia
      // «todas las horas en UTC» junto a las pestañas, que es donde tiene peso
      // pericial porque va pegado al contenido que fecha; y los recuentos los
      // llevan las propias pestañas, las cuatro a la vez, en vez de una sola
      // cifra que cambia de significado según cuál esté abierta.
      meta: activeCase ? undefined : t("common.noCase"),
      action: !activeCase ? undefined : isIncident ? (
        canExportIncident ? (
          <button type="button" disabled={exporting} onClick={() => void exportIncidentPng()}>
            {t(exporting ? "mitre.exporting" : "graph.exportPng")}
          </button>
        ) : undefined
      ) : isInvestigation ? (
        <button type="button" disabled={exporting} onClick={() => void exportInvestigationCsv()}>
          {t(exporting ? "mitre.exporting" : "tl.exportSheet")}
        </button>
      ) : (
        <button
          type="button"
          disabled={!canGenerate}
          title={selectedEvidence ? undefined : t("tl.pickEvidenceFirst")}
          onClick={() => void startFsTimeline()}
        >
          {t(fsJob?.status === "running" || starting ? "tl.generating" : "tl.generate")}
        </button>
      ),
    },
    // Sin los recuentos: alimentaban la meta que se ha retirado, y como
    // disparadores del hook solo provocaban republicar la cabecera cada vez que
    // cambiaba una cifra que ya no se pinta.
    [
      activeCase?.id,
      isIncident,
      isInvestigation,
      canExportIncident,
      exporting,
      canGenerate,
      starting,
      fsJob?.status,
      t,
    ],
  );

  if (casesPhase === "loading") {
    return (
      <div className="view-scroll">
        <div className="loading-state">
          <span className="spinner" aria-hidden="true" />
          <span>{t("tl.loading")}</span>
        </div>
      </div>
    );
  }

  if (casesPhase === "error" || loadError) {
    return (
      <div className="view-scroll">
        <div className="error-state">
          <strong>{t("tl.loadFailed")}</strong> {loadError || casesError}
        </div>
      </div>
    );
  }

  if (!activeCase) {
    return (
      <div className="view-scroll">
        <div className="empty-rail">
          <div className="empty-rail-title">{t("findings.noCase")}</div>
          <div className="empty-rail-body">{t("tl.noCaseBody")}</div>
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
            className={`tab${layer === "findings" ? " is-active" : ""}`}
            onClick={() => setLayer("findings")}
            title={t("tl.tabFindingsTitle")}
          >
            {t("nav.findings")}
            <span className="tab-count">
              {incident ? incident.eventos.length : t("common.na")}
            </span>
          </button>
          <button
            type="button"
            className={`tab${layer === "investigation" ? " is-active" : ""}`}
            onClick={() => setLayer("investigation")}
          >
            {t("nav.investigation")}
            <span className="tab-count">{counts.total}</span>
          </button>
          <button
            type="button"
            className={`tab${layer === "filesystem" ? " is-active" : ""}`}
            onClick={() => setLayer("filesystem")}
          >
            {t("tl.tabFs")}
            <span className="tab-count">
              {fsResult ? fsResult.total_events : t("common.na")}
            </span>
          </button>
          <button
            type="button"
            className={`tab${layer === "relevant" ? " is-active" : ""}`}
            onClick={() => setLayer("relevant")}
            title={t("tl.tabRelevantTitle")}
          >
            {t("tl.tabRelevant")}
            <span className="tab-count">
              {fsResult?.total_relevant !== undefined ? fsResult.total_relevant : t("common.na")}
            </span>
          </button>
        </div>
        <span className="bar-note">{t("tl.allUtc")}</span>
      </div>

      {/* La capa del incidente es una FIGURA: no lleva barra de herramientas. Un
          buscador que no filtra la imagen sería un control que promete lo que no hace. */}
      {!isIncident && (
        <div className="tl-toolbar">
          <label className="visually-hidden" htmlFor="tl-search">
            {t("tl.searchLabel")}
          </label>
          <input
            id="tl-search"
            className="field-input tl-search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={
              isInvestigation
                ? t("tl.searchInv")
                : layer === "relevant"
                  ? t("tl.searchRelevant")
                  : t("tl.searchFs")
            }
          />
          {isInvestigation ? (
            <div className="tl-meta">
              {t("tl.metaCounts", { runs: counts.toolRuns, findings: counts.findings })}
            </div>
          ) : (
            <div className="tl-evidence">
              <span className="eyebrow">{t("inv.evidence")}</span>
              <label className="visually-hidden" htmlFor="tl-evidence-select">
                {t("tl.evidenceSelect")}
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
      )}

      {/* Sin barra de herramientas (la capa del incidente es una figura, no una
          lista), el contenido quedaba pegado a las pestañas: en las otras capas
          ese hueco lo crea el buscador. Se repone aquí para que las cuatro
          arranquen a la misma altura. */}
      <div className={`tl-scroll${isIncident ? " tl-scroll--bare" : ""}`}>
        <div className="view-stack view-stack--1000 tl-stack">
          {exportError && (isInvestigation || isIncident) && (
            <div className="error-state">{t("mitre.exportFailed", { detail: exportError })}</div>
          )}

          {isIncident ? (
            !incident ? (
              <div className="loading-state">
                <span className="spinner" aria-hidden="true" />
                <span>{t("tl.loadingIncident")}</span>
              </div>
            ) : incident.eventos.length === 0 ? (
              <div className="empty-rail">
                <div className="empty-rail-title">{t("tl.noPlaceable")}</div>
                {/* El backend dice POR QUÉ: no hay hallazgos, o los hay y ninguno
                    tiene marca temporal del artefacto. Son dos cosas distintas. */}
                <div className="empty-rail-body">{incident.message}</div>
              </div>
            ) : (
              <div className="tl-figure">
                <IncidentRail ref={railRef} timeline={incident} />
              </div>
            )
          ) : isInvestigation ? (
            events.length === 0 ? (
              <div className="empty-rail">
                <div className="empty-rail-title">{t("tl.noActivity")}</div>
                <div className="empty-rail-body">
                  {t("tl.noActivityBody")}
                </div>
              </div>
            ) : invFiltered.length === 0 ? (
              <div className="inline-note">{t("tl.noEventMatch")}</div>
            ) : (
              invDays.map((day) => (
                <div className="tl-day" key={day.label}>
                  <div className="tl-day-head">
                    <span className="tl-day-label">{day.label} · UTC</span>
                    <span className="rule" />
                    <span className="rule-count">
                      {tn("count.events", day.rows.length)}
                    </span>
                  </div>
                  {day.rows.map((ev) =>
                    ev.kind === "finding" ? (
                      <div className="tl-row" key={ev.finding_id}>
                        <div className="tl-time">{fecha(ev.ts).time}</div>
                        <div className="tl-kindcol">
                          <span className="tl-kind tl-kind--finding">{t("tl.kindFinding")}</span>
                          <span className="tl-src">
                            {ev.tool_id ?? t("tl.agent")} ·{" "}
                            {SEV_KEY[ev.severity] ? t(SEV_KEY[ev.severity]) : ev.severity}
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
                        <div className="tl-time">{fecha(ev.ts).time}</div>
                        <div className="tl-kindcol">
                          <span className="tl-kind">{t("tl.kindRun")}</span>
                          <span className="tl-src">
                            {ev.tool_id ?? "tool"}
                            {ev.exit === null ? ` · ${ev.status}` : ` · exit ${ev.exit}`}
                          </span>
                        </div>
                        <div className="tl-body">
                          {/* El argv LITERAL que se ejecutó (FORENSIC INVARIANT 4). */}
                          <div className="tl-argv">{ev.argv.join(" ") || t("tl.noArgv")}</div>
                          {ev.output_files_count !== null && ev.output_files_count > 0 && (
                            <div className="tl-techs">
                              <span>{tn("count.artifacts", ev.output_files_count)}</span>
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
                  <div className="empty-rail-title">{t("tl.noEvidence")}</div>
                  <div className="empty-rail-body">
                    {t("tl.noEvidenceBody")}
                  </div>
                </div>
              ) : !selectedEvidence ? (
                <div className="empty-rail">
                  <div className="empty-rail-title">{t("tl.pickEvidence")}</div>
                  <div className="empty-rail-body">
                    {t("tl.pickEvidenceBody")}
                  </div>
                </div>
              ) : null}

              {fsError && <div className="error-state">{fsError}</div>}

              {fsJob?.status === "running" && (
                <div className="progress-block" aria-live="polite">
                  <div className="progress-head">
                    <span>{lastProgress || t("tl.runningFls")}</span>
                  </div>
                  <div className="progress-track">
                    <div className="progress-fill progress-fill--indeterminate" />
                  </div>
                  <div className="progress-note">
                    {t("tl.asyncNote")}
                  </div>
                </div>
              )}
              {fsJob?.status === "error" && (
                <div className="error-state">{fsJob.error ?? t("tl.analysisFailed")}</div>
              )}

              {selectedEvidence && !fsJob && !fsResult && !fsError && (
                <div className="empty-rail">
                  <div className="empty-rail-title">{t("tl.notGenerated")}</div>
                  <div className="empty-rail-body">
                    {t("tl.notGeneratedA")} <span className="mono">tsk_fls -m</span>{" "}
                    {t("tl.notGeneratedB")}
                  </div>
                </div>
              )}

              {fsResult && fsResult.generated_at && !fsJob && (
                <div className="inline-note">
                  {t("tl.generatedAt", {
                    date: fecha(fsResult.generated_at).date,
                    time: fecha(fsResult.generated_at).time,
                    count: fsResult.total_events,
                  })}
                </div>
              )}

              {fsResult && layer === "filesystem" && (
                <>
                  {fsResult.truncated && (
                    <div className="inline-note">
                      {t("tl.truncated", {
                        shown: fsResult.returned,
                        total: fsResult.total_events,
                      })}
                    </div>
                  )}
                  {fsFiltered.length === 0 ? (
                    <div className="inline-note">
                      {t(fsResult.total_events === 0 ? "tl.noFsEvents" : "tl.noEventMatch")}
                    </div>
                  ) : (
                    <>
                      {fsDays.map((day) => (
                        <div className="tl-day" key={day.label}>
                          <div className="tl-day-head">
                            <span className="tl-day-label">{day.label} · UTC</span>
                            <span className="rule" />
                            <span className="rule-count">{tn("count.events", day.rows.length)}</span>
                          </div>
                          <div className="table-scroll">
                            <table className="data-table">
                              <thead>
                                <tr>
                                  <th>{t("tl.colTime")}</th>
                                  <th>{t("tl.colMacb")}</th>
                                  <th>{t("tl.colSize")}</th>
                                  <th>{t("tl.colInode")}</th>
                                  <th>{t("tl.colPath")}</th>
                                </tr>
                              </thead>
                              <tbody>
                                {day.rows.map((ev, i) => (
                                  <tr key={`${ev.inode}-${ev.ts}-${i}`}>
                                    <td className="cell-dim">{fecha(ev.ts).time}</td>
                                    <td className="cell-mono">{ev.macb}</td>
                                    <td className="cell-dim">{ev.size.toLocaleString(locale)}</td>
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
                        noun={t("tl.nounEvents")}
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
                      {t("tl.oldSuperTimeline")}
                    </div>
                  ) : (
                    <>
                      {fsResult.relevant_truncated && (
                        <div className="inline-note">
                          {t("tl.relevantTruncated", {
                            shown: fsResult.relevant_returned ?? 0,
                            total: fsResult.total_relevant ?? 0,
                          })}
                        </div>
                      )}
                      {relevantFiltered.length === 0 ? (
                        <div className="inline-note">
                          {t(
                            (fsResult.total_relevant ?? 0) === 0
                              ? "tl.noRelevantMarked"
                              : "tl.noRelevantMatch",
                          )}
                        </div>
                      ) : (
                        <>
                          <div className="table-scroll">
                            <table className="data-table">
                              <thead>
                                <tr>
                                  <th>{t("tl.colDate")}</th>
                                  <th>{t("tl.colHour")}</th>
                                  <th>{t("tl.colCategory")}</th>
                                  <th>{t("tl.colReason")}</th>
                                  <th>{t("tl.colMacb")}</th>
                                  <th>{t("tl.colPath")}</th>
                                </tr>
                              </thead>
                              <tbody>
                                {(fsPageRows as FsRelevantEvent[]).map((ev, i) => (
                                  <tr key={`${ev.inode}-${ev.ts}-${ev.category}-${i}`}>
                                    <td className="cell-dim">{fecha(ev.ts).date}</td>
                                    <td className="cell-dim">{fecha(ev.ts).time}</td>
                                    <td>
                                      <span className="tag tag--accent">
                                        {CATEGORY_KEY[ev.category]
                                          ? t(CATEGORY_KEY[ev.category])
                                          : ev.category}
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
                            noun={t("tl.nounRelevant")}
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
