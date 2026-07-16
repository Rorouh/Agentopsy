import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import type {
  AgentFinding,
  Case,
  MitreCatalog,
  MitreCoverageEntry,
  MitreStatus,
  MitreTechnique,
} from "../api/types";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { EmptyState } from "../ui/EmptyState";
import { PageHeader } from "../ui/PageHeader";
import { useActiveCase, useActiveCaseFrom } from "../state/activeCase";

// Matriz ATT&CK del caso. Dos ejes que NUNCA se funden:
//
//   · lo que el AGENTE propone  → `proposed_by`, derivado de los `mitre_hints`
//     de hallazgos reales. Es una sugerencia con procedencia, no un veredicto.
//   · lo que el OPERADOR dictamina → `status`, persistido y auditado. Sólo esto
//     es veredicto pericial, y exige un motivo.
//
// Una celda gris significa **no evaluada**, nunca «ausente»: el catálogo es la
// semilla del orquestador (enum cerrada), así que el denominador es honesto.
//
// El layout replica el diseño de Claude Design (barra superior única + selector
// de caso + ribbon con métricas), en el tema CLARO del proyecto.

type Phase = "loading" | "ready" | "no-catalog" | "error";

const STATUS_LABEL: Record<MitreStatus, string> = {
  confirmada: "Confirmada",
  sospechosa: "Sospechosa",
  descartada: "Descartada",
};

const STATUS_ORDER: MitreStatus[] = ["confirmada", "sospechosa", "descartada"];

interface Selection {
  tacticId: string;
  technique: MitreTechnique;
}

export function MitreAttackPage() {
  const [catalog, setCatalog] = useState<MitreCatalog | null>(null);
  const [cases, setCases] = useState<Case[]>([]);
  // Caso activo GLOBAL, más un modo local "Sin caso" (exploración de la matriz)
  // que NO toca el caso global — así explorar aquí no deja sin caso a las demás
  // vistas.
  const { setActiveCaseId } = useActiveCase();
  const [explore, setExplore] = useState(false);
  const [coverage, setCoverage] = useState<MitreCoverageEntry[]>([]);
  const [findings, setFindings] = useState<AgentFinding[]>([]);
  const [phase, setPhase] = useState<Phase>("loading");
  const [error, setError] = useState<string>("");

  const [search, setSearch] = useState("");
  const [subsOn, setSubsOn] = useState(true);
  const [onlyCovered, setOnlyCovered] = useState(false);
  const [view, setView] = useState<"matrix" | "timeline">("matrix");
  const [sel, setSel] = useState<Selection | null>(null);
  const [rationale, setRationale] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState("");
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState("");

  // Caso activo global resuelto (reconcilia el guardado contra la lista; cae al
  // más reciente si ya no existe). En modo exploración lo ignoramos.
  const globalCase = useActiveCaseFrom(cases);
  const activeCase = explore ? null : globalCase;
  const activeCaseId = activeCase?.id ?? null;
  const caseMode = activeCase !== null;

  const refreshCoverage = useCallback(async (caseId: string) => {
    setCoverage(await api.cases.listMitreCoverage(caseId));
  }, []);

  // Carga inicial: catálogo + lista de casos. El caso activo lo resuelve el
  // estado GLOBAL (useActiveCaseFrom); "Sin caso" = modo exploración local.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const cat = await api.mitre.catalog();
        if (cancelled) return;
        setCatalog(cat);
        if (!cat.available) {
          setPhase("no-catalog");
          return;
        }
        const list = await api.cases.list();
        if (cancelled) return;
        setCases(list);
        setPhase("ready");
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : String(err));
        setPhase("error");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Al cambiar de caso: carga su cobertura + hallazgos (o limpia en exploración).
  useEffect(() => {
    setSel(null);
    if (!activeCaseId) {
      setCoverage([]);
      setFindings([]);
      return;
    }
    let cancelled = false;
    (async () => {
      const [cov, finds] = await Promise.all([
        api.cases.listMitreCoverage(activeCaseId),
        api.cases.listFindings(activeCaseId).catch(() => [] as AgentFinding[]),
      ]);
      if (cancelled) return;
      setCoverage(cov);
      setFindings(finds);
    })();
    return () => {
      cancelled = true;
    };
  }, [activeCaseId]);

  // technique_id → entrada de cobertura
  const byTechnique = useMemo(() => {
    const map = new Map<string, MitreCoverageEntry>();
    coverage.forEach((c) => map.set(c.technique_id, c));
    return map;
  }, [coverage]);

  const findingById = useMemo(() => {
    const map = new Map<string, AgentFinding>();
    findings.forEach((f) => map.set(f.id, f));
    return map;
  }, [findings]);

  const matches = useCallback(
    (t: MitreTechnique) => {
      const q = search.trim().toLowerCase();
      if (!q) return true;
      return t.name.toLowerCase().includes(q) || t.id.toLowerCase().includes(q);
    },
    [search],
  );

  const onAdjudicate = useCallback(
    async (status: MitreStatus | "none") => {
      if (!activeCase || !sel) return;
      setSaving(true);
      setSaveError("");
      try {
        const entry = byTechnique.get(sel.technique.id);
        await api.cases.adjudicateMitre(activeCase.id, {
          technique_id: sel.technique.id,
          status,
          rationale: status === "none" ? "" : rationale.trim(),
          // Ancla el veredicto a los hallazgos que lo sostenían en este momento.
          related_finding_ids: entry?.proposed_by ?? [],
        });
        await refreshCoverage(activeCase.id);
        setRationale("");
      } catch (err) {
        setSaveError(err instanceof Error ? err.message : String(err));
      } finally {
        setSaving(false);
      }
    },
    [activeCase, sel, rationale, byTechnique, refreshCoverage],
  );

  // Export de la cobertura del caso (CSV o layer del Navigator). Se descarga con el
  // token mismo-origen; un caso con 0 propuestas exporta igual (cabecera honesta).
  const onExport = useCallback(
    async (kind: "csv" | "navigator") => {
      if (!activeCase) return;
      setExporting(true);
      setExportError("");
      try {
        if (kind === "csv") await api.cases.exportMitreCsv(activeCase.id);
        else await api.cases.exportMitreNavigator(activeCase.id);
      } catch (err) {
        setExportError(err instanceof Error ? err.message : String(err));
      } finally {
        setExporting(false);
      }
    },
    [activeCase],
  );

  const openTechnique = useCallback(
    (tacticId: string, technique: MitreTechnique) => {
      setSel({ tacticId, technique });
      setSaveError("");
      setRationale(byTechnique.get(technique.id)?.rationale ?? "");
    },
    [byTechnique],
  );

  // ── estados degradados ────────────────────────────────────────────────────

  if (phase === "loading") {
    return <PageHeader title="MITRE ATT&CK" subtitle="Cargando la matriz…" />;
  }

  if (phase === "error") {
    return (
      <div>
        <PageHeader title="MITRE ATT&CK" subtitle="No se pudo cargar la matriz." />
        <EmptyState title="Error" description={error} />
      </div>
    );
  }

  if (phase === "no-catalog" || !catalog) {
    return (
      <div>
        <PageHeader
          title="MITRE ATT&CK"
          subtitle="El catálogo de técnicas no está disponible."
        />
        <EmptyState
          title="Falta la semilla ATT&CK"
          description={
            catalog?.reason ??
            "El catálogo se deriva de la semilla del orquestador y no se ha podido cargar."
          }
        />
      </div>
    );
  }

  // ── métricas reales (sólo en modo caso) ───────────────────────────────────

  const confirmed = coverage.filter((c) => c.status === "confirmada").length;
  const suspected = coverage.filter((c) => c.status === "sospechosa").length;

  const tacticsTouched = catalog.tactics.filter((t) =>
    t.techniques.some((te) => {
      const c = byTechnique.get(te.id);
      return c && (c.status === "confirmada" || c.status === "sospechosa");
    }),
  ).length;

  const phaseStats = catalog.phases.map((ph) => {
    const tactics = catalog.tactics.filter((t) => t.phase === ph.key);
    const touched = tactics.filter((t) =>
      t.techniques.some((te) => {
        const c = byTechnique.get(te.id);
        return c && (c.status === "confirmada" || c.status === "sospechosa");
      }),
    ).length;
    return { ...ph, total: tactics.length, touched };
  });

  const searching = search.trim().length > 0;

  const columns = catalog.tactics
    .map((tactic) => {
      // Enterprise enumera técnicas padre; el toggle «Sub-técnicas» solo muestra
      // el conteo de sub por técnica, no filas aparte.
      const techniques = tactic.techniques;
      let conf = 0;
      let susp = 0;
      let disc = 0;
      techniques.forEach((te) => {
        const s = byTechnique.get(te.id)?.status;
        if (s === "confirmada") conf++;
        else if (s === "sospechosa") susp++;
        else if (s === "descartada") disc++;
      });
      const covered = conf + susp;
      const visible = techniques.filter((te) => {
        if (!matches(te)) return false;
        if (!caseMode || !onlyCovered) return true;
        const c = byTechnique.get(te.id);
        return !!c && (c.status !== null || c.proposed_by.length > 0);
      });
      return { tactic, techniques, visible, conf, susp, disc, covered };
    })
    .filter((col) => {
      if (col.visible.length === 0) return false;
      // "Solo cubiertas": oculta tácticas sin cobertura ni descartes.
      if (caseMode && onlyCovered && col.covered === 0 && col.disc === 0)
        return false;
      return true;
    });

  // Timeline: hallazgos reales que citan al menos una técnica, en orden.
  const timeline = findings
    .filter((f) => f.mitre_hints.length > 0)
    .slice()
    .sort((a, b) => a.created_at.localeCompare(b.created_at));

  const selEntry = sel ? byTechnique.get(sel.technique.id) : undefined;
  const selTactic = sel
    ? catalog.tactics.find((t) => t.id === sel.tacticId)
    : undefined;

  return (
    <div className="mitre-page">
      {/* ===================== BARRA SUPERIOR ===================== */}
      <div className="mitre-topbar">
        <div className="mitre-brand">
          <span className="mitre-brand-mark" aria-hidden />
          <span className="mitre-brand-text">
            <span className="mitre-brand-title">MITRE ATT&amp;CK</span>
            <span className="mitre-brand-sub">MATRIZ · ENTERPRISE</span>
          </span>
        </div>

        {/* Selector: "Sin caso" (exploración local) + un selector del CASO
            ACTIVO GLOBAL sobre todos los casos. Elegir un caso aquí lo fija como
            activo en TODAS las vistas (Investigación / Timeline / Documentos). */}
        <div className="mitre-seg" role="group" aria-label="Caso activo">
          <button
            className={`mitre-seg-btn${!caseMode ? " is-active" : ""}`}
            onClick={() => setExplore(true)}
            title="Explorar la matriz sin caso"
          >
            <span className="mitre-seg-label">Sin caso</span>
            <span className="mitre-seg-sub">exploración</span>
          </button>
          {cases.length > 0 && (
            <select
              className="case-picker"
              aria-label="Caso activo"
              value={caseMode && activeCase ? activeCase.id : ""}
              onChange={(e) => {
                const id = e.target.value;
                if (!id) {
                  setExplore(true);
                  return;
                }
                setExplore(false);
                setActiveCaseId(id);
              }}
            >
              {!caseMode && <option value="">Selecciona un caso…</option>}
              {cases.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                  {c.os_profile ? ` · ${c.os_profile}` : ""}
                </option>
              ))}
            </select>
          )}
        </div>

        {/* Conmutador de vista (sólo en modo caso). */}
        {caseMode && (
          <div className="mitre-seg" role="group" aria-label="Vista">
            <button
              className={`mitre-seg-btn mitre-seg-btn--view${view === "matrix" ? " is-active" : ""}`}
              onClick={() => setView("matrix")}
            >
              Matriz
            </button>
            <button
              className={`mitre-seg-btn mitre-seg-btn--view${view === "timeline" ? " is-active" : ""}`}
              onClick={() => setView("timeline")}
            >
              Línea temporal
            </button>
          </div>
        )}

        <div className="mitre-topbar-spacer" />

        <div className="mitre-searchbox">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="7" />
            <path d="M21 21l-4.3-4.3" />
          </svg>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Buscar técnica o ID (T1055)…"
            aria-label="Buscar técnica o identificador ATT&CK"
          />
          {search && (
            <button className="mitre-searchbox-clear" onClick={() => setSearch("")} aria-label="Limpiar búsqueda">
              ×
            </button>
          )}
        </div>

        <button
          className={`mitre-toggle${subsOn ? " is-active" : ""}`}
          onClick={() => setSubsOn((v) => !v)}
          aria-pressed={subsOn}
        >
          Sub-técnicas
        </button>
        {caseMode && view === "matrix" && (
          <button
            className={`mitre-toggle${onlyCovered ? " is-active" : ""}`}
            onClick={() => setOnlyCovered((v) => !v)}
            aria-pressed={onlyCovered}
          >
            Solo cubiertas
          </button>
        )}
        {caseMode && (
          <>
            <button
              className="mitre-toggle"
              onClick={() => onExport("csv")}
              disabled={exporting}
              title="Descargar la cobertura ATT&CK del caso como CSV"
            >
              Exportar CSV
            </button>
            <button
              className="mitre-toggle"
              onClick={() => onExport("navigator")}
              disabled={exporting}
              title="Descargar un layer del ATT&CK Navigator (formato 4.5)"
            >
              Exportar Navigator layer
            </button>
          </>
        )}
      </div>

      {exportError && (
        <div className="mitre-context mitre-context--error">
          No se pudo exportar: {exportError}
        </div>
      )}

      {/* ===================== RIBBON DE FASES + RESUMEN ===================== */}
      <div className="mitre-ribbon-row">
        <div className="mitre-ribbon">
          {phaseStats.map((ph, i) => (
            <div className="mitre-phase-wrap" key={ph.key}>
              <div className="mitre-phase">
                <div className="mitre-phase-head">
                  <span className={`mitre-phase-dot mitre-phase-dot--${ph.key}`} />
                  <span className="mitre-phase-label">{ph.label}</span>
                  <span className="mitre-phase-stat">
                    {caseMode ? `${ph.touched}/${ph.total}` : `${ph.total} tácticas`}
                  </span>
                </div>
                <div className="mitre-phase-track">
                  <div
                    className={`mitre-phase-fill mitre-phase-fill--${ph.key}`}
                    style={{
                      width: caseMode
                        ? ph.total
                          ? `${(ph.touched / ph.total) * 100}%`
                          : "0%"
                        : "100%",
                      opacity: caseMode ? 1 : 0.4,
                    }}
                  />
                </div>
              </div>
              {i < phaseStats.length - 1 && <span className="mitre-phase-arrow">›</span>}
            </div>
          ))}
        </div>

        {caseMode && (
          <div className="mitre-summary">
            <div className="mitre-chip mitre-chip--confirmada">
              <span className="mitre-chip-value">{confirmed}</span>
              <span className="mitre-chip-label">Confirmadas</span>
            </div>
            <div className="mitre-chip mitre-chip--sospechosa">
              <span className="mitre-chip-value">{suspected}</span>
              <span className="mitre-chip-label">Sospechosas</span>
            </div>
            <div className="mitre-chip mitre-chip--tacticas">
              <span className="mitre-chip-value">
                {tacticsTouched}/{catalog.tactics.length}
              </span>
              <span className="mitre-chip-label">Tácticas</span>
            </div>
          </div>
        )}
      </div>

      {/* ===================== MATRIZ ===================== */}
      {view === "matrix" && (
        <>
          {columns.length === 0 ? (
            <EmptyState
              title={searching ? "Sin coincidencias" : "Nada que mostrar"}
              description={
                searching
                  ? `Ninguna técnica coincide con «${search}».`
                  : "Ninguna táctica tiene cobertura todavía. Desactiva «Solo cubiertas» para ver la matriz completa."
              }
            />
          ) : (
            <div className="mitre-matrix-scroll">
              <div className="mitre-matrix">
                {columns.map(({ tactic, techniques, visible, conf, susp, disc, covered }) => (
                  <div className="mitre-col" key={tactic.id}>
                    <div className="mitre-col-head">
                      <div className={`mitre-col-accent mitre-phase-fill--${tactic.phase}`} />
                      <div className="mitre-col-body">
                        <div className="mitre-col-title">{tactic.name_es}</div>
                        <div className="mitre-col-meta">
                          <span className="mitre-col-en">{tactic.name}</span>
                          <span className="mitre-col-count">{techniques.length}</span>
                        </div>
                        {caseMode && (
                          <>
                            <div className="mitre-col-track">
                              <div
                                className="mitre-col-fill mitre-col-fill--confirmada"
                                style={{
                                  width: techniques.length
                                    ? `${(conf / techniques.length) * 100}%`
                                    : "0%",
                                }}
                              />
                              <div
                                className="mitre-col-fill mitre-col-fill--sospechosa"
                                style={{
                                  width: techniques.length
                                    ? `${(susp / techniques.length) * 100}%`
                                    : "0%",
                                }}
                              />
                            </div>
                            <div className="mitre-col-cov">
                              {covered}/{techniques.length} cubiertas
                              {disc > 0 ? ` · ${disc} descart.` : ""}
                            </div>
                          </>
                        )}
                      </div>
                    </div>

                    <div className="mitre-cells">
                      {visible.map((te) => {
                        const c = byTechnique.get(te.id);
                        const status = c?.status ?? null;
                        const isProposed = !!c && c.proposed_by.length > 0;
                        const dim = searching && !matches(te);
                        const cls = [
                          "mitre-cell",
                          status ? `mitre-cell--${status}` : "",
                          !status && isProposed ? "mitre-cell--propuesta" : "",
                          dim ? "is-dim" : "",
                          sel?.technique.id === te.id ? "is-selected" : "",
                        ]
                          .filter(Boolean)
                          .join(" ");
                        return (
                          <button
                            className={cls}
                            key={te.id}
                            onClick={() => openTechnique(tactic.id, te)}
                            title={`${te.id} · ${te.name}`}
                          >
                            <span className="mitre-cell-dot" />
                            <span className="mitre-cell-name">{te.name}</span>
                            {isProposed && (
                              <span
                                className="mitre-cell-badge"
                                title={`${c!.proposed_by.length} hallazgo(s) del agente citan esta técnica`}
                              >
                                {c!.proposed_by.length}
                              </span>
                            )}
                            {subsOn && te.sub > 0 && (
                              <span className="mitre-cell-sub" title={`${te.sub} sub-técnicas`}>
                                {te.sub} sub
                              </span>
                            )}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          <p className="mitre-legend">
            <span className="mitre-legend-item">
              <span className="mitre-swatch mitre-swatch--propuesta" /> Propuesta por
              el agente (sin dictaminar)
            </span>
            <span className="mitre-legend-item">
              <span className="mitre-swatch mitre-swatch--confirmada" /> Confirmada
            </span>
            <span className="mitre-legend-item">
              <span className="mitre-swatch mitre-swatch--sospechosa" /> Sospechosa
            </span>
            <span className="mitre-legend-item">
              <span className="mitre-swatch mitre-swatch--descartada" /> Descartada
            </span>
            <span className="mitre-legend-item">
              <span className="mitre-swatch" /> Sin evaluar
            </span>
          </p>
        </>
      )}

      {/* ===================== LÍNEA TEMPORAL ===================== */}
      {caseMode && view === "timeline" && (
        <div className="mitre-timeline">
          {timeline.length === 0 ? (
            <EmptyState
              title="Sin hallazgos correlacionados"
              description="Ningún hallazgo del caso cita todavía una técnica ATT&CK. La línea temporal se construye con los hallazgos reales que el agente asocia a una técnica."
            />
          ) : (
            timeline.map((f) => (
              <div className="mitre-tl-row" key={f.id}>
                <div className="mitre-tl-time">
                  {new Date(f.created_at).toLocaleString("es-ES")}
                </div>
                <div className="mitre-tl-rail">
                  <span className="mitre-tl-dot" />
                </div>
                <div className="mitre-tl-card">
                  <div className="mitre-tl-head">
                    <span className="mitre-tl-title">{f.title}</span>
                    <Badge variant={f.severity}>{f.severity}</Badge>
                  </div>
                  <div className="mitre-tl-summary">{f.summary}</div>
                  <div className="mitre-tl-foot">
                    {f.tool_id && <span className="mitre-tl-tool">{f.tool_id}</span>}
                    {f.mitre_hints.map((id) => {
                      const c = byTechnique.get(id);
                      return (
                        <span
                          key={id}
                          className={`mitre-tl-tech${c?.status ? ` mitre-tl-tech--${c.status}` : ""}`}
                        >
                          {id}
                        </span>
                      );
                    })}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* ===================== PANEL DE DETALLE ===================== */}
      {sel && selTactic && (
        <>
          <div className="mitre-scrim" onClick={() => setSel(null)} />
          <aside className="mitre-detail" aria-label={`Detalle de ${sel.technique.id}`}>
            <div className="mitre-detail-head">
              <div className="mitre-detail-tactic">
                <span className={`mitre-phase-dot mitre-phase-dot--${selTactic.phase}`} />
                {selTactic.name_es}
              </div>
              <button
                className="mitre-detail-close"
                onClick={() => setSel(null)}
                aria-label="Cerrar"
              >
                ×
              </button>
            </div>

            <div className="mitre-detail-title">{sel.technique.name}</div>
            <div className="mitre-detail-idrow">
              <span className="mitre-detail-id">{sel.technique.id}</span>
              {sel.technique.sub > 0 && (
                <span className="mitre-detail-subnote">
                  {sel.technique.sub} sub-técnicas
                </span>
              )}
            </div>

            <div className="mitre-detail-body">
              <section>
                <h4>Se sostiene con</h4>
                <p className="mitre-detail-supports">{sel.technique.supported_by}</p>
              </section>

              {!caseMode ? (
                <section>
                  <div className="mitre-detail-explore">
                    Abre un caso para registrar si esta técnica se ha{" "}
                    <span className="is-confirmada">confirmado</span>, está{" "}
                    <span className="is-sospechosa">en sospecha</span> o se ha{" "}
                    <span className="is-descartada">descartado</span> en la
                    investigación.
                  </div>
                </section>
              ) : (
                <>
                  <section>
                    <h4>Propuesta del agente</h4>
                    {selEntry && selEntry.proposed_by.length > 0 ? (
                      <ul className="mitre-detail-findings">
                        {selEntry.proposed_by.map((fid) => {
                          const f = findingById.get(fid);
                          return (
                            <li key={fid}>
                              {f ? f.title : fid}
                              {f?.tool_id && (
                                <span className="mitre-detail-tool">{f.tool_id}</span>
                              )}
                            </li>
                          );
                        })}
                      </ul>
                    ) : (
                      <p className="mitre-detail-empty">
                        Ningún hallazgo del agente cita esta técnica. Puedes
                        dictaminarla igualmente si la evidencia que has revisado lo
                        sostiene.
                      </p>
                    )}
                  </section>

                  <section>
                    <h4>Dictamen del perito</h4>
                    {selEntry?.status && (
                      <p className="mitre-detail-current">
                        Actualmente: <strong>{STATUS_LABEL[selEntry.status]}</strong>
                        {selEntry.adjudicated_at &&
                          ` · ${new Date(selEntry.adjudicated_at).toLocaleString("es-ES")}`}
                      </p>
                    )}
                    <label className="mitre-detail-label" htmlFor="mitre-rationale">
                      Motivo (obligatorio — queda en el log de auditoría)
                    </label>
                    <textarea
                      id="mitre-rationale"
                      className="mitre-detail-rationale"
                      value={rationale}
                      onChange={(e) => setRationale(e.target.value)}
                      rows={3}
                      placeholder="Qué evidencia sostiene este veredicto…"
                    />
                    <div className="mitre-detail-actions">
                      {STATUS_ORDER.map((s) => (
                        <button
                          key={s}
                          className={`mitre-status-btn mitre-status-btn--${s}${
                            selEntry?.status === s ? " is-active" : ""
                          }`}
                          disabled={saving || rationale.trim().length === 0}
                          onClick={() => onAdjudicate(s)}
                        >
                          {STATUS_LABEL[s]}
                        </button>
                      ))}
                    </div>
                    {selEntry?.status && (
                      <Button
                        variant="chip"
                        disabled={saving}
                        onClick={() => onAdjudicate("none")}
                      >
                        Retirar dictamen
                      </Button>
                    )}
                    {rationale.trim().length === 0 && (
                      <p className="mitre-detail-hint">
                        Un veredicto sin motivo no vale nada en un informe pericial:
                        el backend lo rechaza.
                      </p>
                    )}
                    {saveError && <p className="mitre-detail-error">{saveError}</p>}
                  </section>
                </>
              )}
            </div>
          </aside>
        </>
      )}
    </div>
  );
}
