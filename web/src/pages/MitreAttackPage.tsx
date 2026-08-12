import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import type {
  AgentFinding,
  MitreCatalog,
  MitreCoverageEntry,
  MitreStatus,
  MitreTechnique,
} from "../api/types";
import { usePublishShellHeader } from "../layout/shellHeader";
import { useActiveCase } from "../state/activeCase";
import { useCaseStream } from "../state/casePulse";

// FASE 3 · Matriz ATT&CK del caso. Dos ejes que NUNCA se funden:
//
//   · lo que el AGENTE propone  → `proposed_by`, derivado de los `mitre_hints`
//     de hallazgos reales. Es una sugerencia con procedencia, no un veredicto.
//   · lo que el PERITO dictamina → `status`, persistido y auditado. Sólo esto
//     es veredicto pericial, y exige un motivo.
//
// Una celda gris significa **no evaluada**, nunca «ausente»: el catálogo es la
// semilla del orquestador (enum cerrada), así que el denominador es honesto.

type Phase = "loading" | "ready" | "no-catalog" | "error";

const STATUS_LABEL: Record<MitreStatus, string> = {
  confirmada: "Confirmada",
  sospechosa: "Sospechosa",
  descartada: "Descartada",
};

const STATUS_ORDER: MitreStatus[] = ["confirmada", "sospechosa", "descartada"];

// Colores de fase: agrupación editorial de Agentopsy, categóricos, IGUALES en
// ambos temas, son taxonomía, no decoración.
const PHASE_COLOR: Record<string, string> = {
  prep: "#64748b",
  access: "#d97706",
  root: "#ea580c",
  act: "#db2777",
  goal: "#dc2626",
};

interface Selection {
  tacticId: string;
  technique: MitreTechnique;
}

export function MitreAttackPage() {
  const [catalog, setCatalog] = useState<MitreCatalog | null>(null);
  const { activeCase: globalCase } = useActiveCase();
  // Modo exploración: recorrer el catálogo sin dictaminar. No toca el caso
  // global, explorar aquí no deja sin caso a las demás vistas.
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

  const activeCase = explore ? null : globalCase;
  const activeCaseId = activeCase?.id ?? null;
  // Los dos ejes de la matriz y los hallazgos que los sostienen. Un análisis en
  // curso va anclando técnicas, y la matriz tiene que pintarlas al llegar.
  const revMitre = useCaseStream("mitre_proposals", "mitre_verdicts", "findings");
  const caseMode = activeCase !== null;

  const refreshCoverage = useCallback(async (caseId: string) => {
    setCoverage(await api.cases.listMitreCoverage(caseId));
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const cat = await api.mitre.catalog();
        if (cancelled) return;
        setCatalog(cat);
        setPhase(cat.available ? "ready" : "no-catalog");
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
  // Cierra la técnica abierta, que es del caso anterior.
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

  // Reposición EN SILENCIO cuando el análisis ancla técnicas nuevas: la matriz
  // se repinta sin cerrar la técnica que el perito tenga abierta dictaminando.
  useEffect(() => {
    if (!activeCaseId || revMitre === 0) return;
    let cancelled = false;
    (async () => {
      const [cov, finds] = await Promise.all([
        api.cases.listMitreCoverage(activeCaseId).catch(() => null),
        api.cases.listFindings(activeCaseId).catch(() => null),
      ]);
      if (cancelled) return;
      if (cov) setCoverage(cov);
      if (finds) setFindings(finds);
    })();
    return () => {
      cancelled = true;
    };
  }, [activeCaseId, revMitre]);

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
          // Ancla el veredicto a los hallazgos que lo sostenían en ese momento.
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

  // Export de la cobertura del caso (hoja de cálculo o layer del Navigator). Se descarga con
  // el token mismo-origen; un caso con 0 propuestas exporta igual (cabecera honesta).
  const onExport = useCallback(
    async (kind: "hoja" | "navigator") => {
      if (!activeCase) return;
      setExporting(true);
      setExportError("");
      try {
        if (kind === "hoja") await api.cases.exportMitreHoja(activeCase.id);
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

  usePublishShellHeader(
    {
      title: "Correlación ATT&CK",
      meta: caseMode ? "dictamen del perito · auditado" : "exploración del catálogo · sin caso",
      action: caseMode ? (
        <button type="button" disabled={exporting} onClick={() => void onExport("navigator")}>
          {exporting ? "Exportando…" : "Exportar layer"}
        </button>
      ) : undefined,
    },
    [caseMode, exporting],
  );

  // ── estados degradados ────────────────────────────────────────────────────

  if (phase === "loading") {
    return (
      <div className="view-scroll">
        <div className="loading-state">
          <span className="spinner" aria-hidden="true" />
          <span>Cargando la matriz…</span>
        </div>
      </div>
    );
  }

  if (phase === "error") {
    return (
      <div className="view-scroll">
        <div className="error-state">
          <strong>No se pudo cargar la matriz:</strong> {error}
        </div>
      </div>
    );
  }

  if (phase === "no-catalog" || !catalog) {
    return (
      <div className="view-scroll">
        <div className="empty-rail">
          <div className="empty-rail-title">Falta la semilla ATT&CK</div>
          <div className="empty-rail-body">
            {catalog?.reason ??
              "El catálogo se deriva de la semilla del orquestador y no se ha podido cargar."}
          </div>
        </div>
      </div>
    );
  }

  // ── métricas reales (sólo en modo caso) ───────────────────────────────────

  const confirmed = coverage.filter((c) => c.status === "confirmada").length;
  const suspected = coverage.filter((c) => c.status === "sospechosa").length;
  const touchedBy = (te: MitreTechnique) => {
    const c = byTechnique.get(te.id);
    return !!c && (c.status === "confirmada" || c.status === "sospechosa");
  };
  const tacticsTouched = catalog.tactics.filter((t) => t.techniques.some(touchedBy)).length;

  const phaseStats = catalog.phases.map((ph) => {
    const tactics = catalog.tactics.filter((t) => t.phase === ph.key);
    const touched = tactics.filter((t) => t.techniques.some(touchedBy)).length;
    return { ...ph, total: tactics.length, touched };
  });

  const searching = search.trim().length > 0;

  const columns = catalog.tactics
    .map((tactic) => {
      // Enterprise enumera técnicas padre; el conmutador «Sub-técnicas» sólo
      // muestra el conteo de sub por técnica, no filas aparte.
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
      // «Solo cubiertas»: oculta tácticas sin cobertura ni descartes.
      if (caseMode && onlyCovered && col.covered === 0 && col.disc === 0) return false;
      return true;
    });

  // Línea temporal: hallazgos reales que citan al menos una técnica, en orden.
  const timeline = findings
    .filter((f) => f.mitre_hints.length > 0)
    .slice()
    .sort((a, b) => a.created_at.localeCompare(b.created_at));

  const selEntry = sel ? byTechnique.get(sel.technique.id) : undefined;
  const selTactic = sel ? catalog.tactics.find((t) => t.id === sel.tacticId) : undefined;

  return (
    <div className="mitre">
      <div className="mitre-bar">
        <div className="tab-row">
          <button
            type="button"
            className={`tab${view === "matrix" ? " is-active" : ""}`}
            onClick={() => setView("matrix")}
          >
            Matriz
          </button>
          <button
            type="button"
            className={`tab${view === "timeline" ? " is-active" : ""}`}
            onClick={() => setView("timeline")}
          >
            Línea temporal
          </button>
        </div>

        <div className="mitre-bar-right">
          <label className="visually-hidden" htmlFor="mitre-search">
            Buscar técnica o identificador ATT&CK
          </label>
          <input
            id="mitre-search"
            className="field-input mitre-search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Buscar técnica o ID (T1055)…"
          />
          <button
            type="button"
            className={`toggle-link${subsOn ? " is-on" : ""}`}
            aria-pressed={subsOn}
            onClick={() => setSubsOn((v) => !v)}
          >
            Sub-técnicas
          </button>
          {caseMode && view === "matrix" && (
            <button
              type="button"
              className={`toggle-link${onlyCovered ? " is-on" : ""}`}
              aria-pressed={onlyCovered}
              onClick={() => setOnlyCovered((v) => !v)}
            >
              Solo cubiertas
            </button>
          )}
          {/* Explorar el catálogo sin dictaminar. Sin caso activo el modo es el
              único posible: no hay nada que adjudicar. */}
          {globalCase && (
            <button
              type="button"
              className={`toggle-link${explore ? " is-on" : ""}`}
              aria-pressed={explore}
              onClick={() => setExplore((v) => !v)}
            >
              Sin caso
            </button>
          )}
          {caseMode && (
            <>
              <button
                type="button"
                className="action-outline"
                disabled={exporting}
                onClick={() => void onExport("hoja")}
              >
                Exportar hoja
              </button>
              <button
                type="button"
                className="action-outline"
                disabled={exporting}
                onClick={() => void onExport("navigator")}
              >
                Exportar Navigator layer
              </button>
            </>
          )}
        </div>
      </div>

      {exportError && (
        <div className="mitre-inline-error">No se pudo exportar: {exportError}</div>
      )}

      <div className="mitre-ribbon-row">
        <div className="mitre-ribbon">
          {phaseStats.map((ph, i) => (
            <div className="mitre-phase-wrap" key={ph.key}>
              <div className="mitre-phase">
                <div className="mitre-phase-head">
                  <span
                    className="mitre-phase-dot"
                    style={{ background: PHASE_COLOR[ph.key] ?? "var(--ink-4)" }}
                  />
                  <span className="mitre-phase-label">{ph.label}</span>
                  <span className="mitre-phase-stat">
                    {caseMode ? `${ph.touched}/${ph.total}` : `${ph.total} tácticas`}
                  </span>
                </div>
                <div className="progress-track">
                  <div
                    className="mitre-phase-fill"
                    style={{
                      background: PHASE_COLOR[ph.key] ?? "var(--ink-4)",
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
            <div className="stat">
              <div className="mitre-summary-value mitre-summary-value--accent">{confirmed}</div>
              <div className="eyebrow">Confirmadas</div>
            </div>
            <div className="stat">
              <div className="mitre-summary-value">{suspected}</div>
              <div className="eyebrow">Sospechosas</div>
            </div>
            <div className="stat">
              <div className="mitre-summary-value">
                {tacticsTouched}
                <span className="mitre-summary-of">/{catalog.tactics.length}</span>
              </div>
              <div className="eyebrow">Tácticas</div>
            </div>
          </div>
        )}
      </div>

      {view === "matrix" && (
        <>
          <div className="mitre-scroll">
            {columns.length === 0 ? (
              <div className="empty-rail">
                <div className="empty-rail-title">
                  {searching ? "Sin coincidencias" : "Nada que mostrar"}
                </div>
                <div className="empty-rail-body">
                  {searching
                    ? `Ninguna técnica coincide con «${search}».`
                    : "Ninguna táctica tiene cobertura todavía. Desactiva «Solo cubiertas» para ver la matriz completa."}
                </div>
              </div>
            ) : (
              <div className="mitre-matrix">
                {columns.map(({ tactic, techniques, visible, conf, susp, disc, covered }) => (
                  <div className="mitre-col" key={tactic.id}>
                    <div className="mitre-col-head">
                      <div
                        className="mitre-col-accent"
                        style={{ background: PHASE_COLOR[tactic.phase] ?? "var(--ink-4)" }}
                      />
                      <div className="mitre-col-title">{tactic.name_es}</div>
                      <div className="mitre-col-meta">
                        <span className="mitre-col-en">{tactic.name}</span>
                        <span>{techniques.length}</span>
                      </div>
                      <div className="mitre-col-cov">
                        {caseMode
                          ? `${covered}/${techniques.length} cubiertas${
                              disc > 0 ? ` · ${disc} descart.` : ""
                            }`
                          : `${techniques.length} técnicas`}
                      </div>
                    </div>

                    <div className="mitre-cells">
                      {visible.map((te) => {
                        const c = byTechnique.get(te.id);
                        const status = c?.status ?? null;
                        const isProposed = !!c && c.proposed_by.length > 0;
                        const state = status ?? (isProposed ? "propuesta" : "none");
                        return (
                          <button
                            type="button"
                            className={`mitre-cell mitre-cell--${state}${
                              sel?.technique.id === te.id ? " is-selected" : ""
                            }`}
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
                              <span className="mitre-cell-sub">{te.sub} sub</span>
                            )}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Cuatro estados del mock + «descartada», que el mock omite y es
              justo el que distingue «el perito lo evaluó y lo negó» de «nadie
              lo miró». */}
          <div className="mitre-legend">
            <span className="mitre-legend-item">
              <span className="mitre-swatch mitre-swatch--confirmada" />
              confirmada por el perito
            </span>
            <span className="mitre-legend-item">
              <span className="mitre-swatch mitre-swatch--sospechosa" />
              sospechosa
            </span>
            <span className="mitre-legend-item">
              <span className="mitre-swatch mitre-swatch--descartada" />
              descartada por el perito
            </span>
            <span className="mitre-legend-item">
              <span className="mitre-swatch mitre-swatch--propuesta" />
              propuesta del agente, sin dictaminar
            </span>
            <span className="mitre-legend-item">
              <span className="mitre-swatch mitre-swatch--none" />
              no evaluada
            </span>
            <span className="mitre-legend-note">gris = no evaluada, nunca «ausente»</span>
          </div>
        </>
      )}

      {view === "timeline" && (
        <div className="mitre-scroll">
          {!caseMode ? (
            <div className="empty-rail">
              <div className="empty-rail-title">Sin caso</div>
              <div className="empty-rail-body">
                La línea temporal se construye con los hallazgos reales del caso. Desactiva «Sin
                caso» para volver al caso activo.
              </div>
            </div>
          ) : timeline.length === 0 ? (
            <div className="empty-rail">
              <div className="empty-rail-title">Sin hallazgos correlacionados</div>
              <div className="empty-rail-body">
                Ningún hallazgo del caso cita todavía una técnica ATT&CK. La línea temporal se
                construye con los hallazgos reales que el agente asocia a una técnica.
              </div>
            </div>
          ) : (
            <div className="mitre-tl">
              {timeline.map((f) => (
                <div className="mitre-tl-row" key={f.id}>
                  <div className="mitre-tl-time">
                    {new Date(f.created_at).toLocaleString("es-ES")}
                  </div>
                  <div className="mitre-tl-body">
                    <div className="mitre-tl-head">
                      <span className="mitre-tl-title">{f.title}</span>
                      <span className="tag tag--accent">{f.severity}</span>
                    </div>
                    <div className="mitre-tl-summary">{f.summary}</div>
                    <div className="mitre-tl-foot">
                      {f.tool_id && <span>{f.tool_id}</span>}
                      {f.mitre_hints.map((id) => {
                        const c = byTechnique.get(id);
                        return (
                          <span
                            key={id}
                            className={`mitre-tl-tech${c?.status ? ` is-${c.status}` : ""}`}
                          >
                            {id}
                          </span>
                        );
                      })}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {sel && selTactic && (
        <>
          <div className="mitre-scrim" onClick={() => setSel(null)} />
          <aside className="mitre-detail" aria-label={`Detalle de ${sel.technique.id}`}>
            <div className="mitre-detail-head">
              <div className="mitre-detail-tactic">
                <span
                  className="mitre-phase-dot"
                  style={{ background: PHASE_COLOR[selTactic.phase] ?? "var(--ink-4)" }}
                />
                {selTactic.name_es}
              </div>
              <button
                type="button"
                className="modal-close"
                onClick={() => setSel(null)}
                aria-label="Cerrar"
              >
                ×
              </button>
            </div>

            <div className="mitre-detail-title">{sel.technique.name}</div>
            <div className="mitre-detail-idrow">
              <span>{sel.technique.id}</span>
              {sel.technique.sub > 0 && <span>{sel.technique.sub} sub-técnicas</span>}
            </div>

            <div className="mitre-detail-body">
              <section className="section-stack">
                <div className="rule-label">
                  <span className="eyebrow">Se sostiene con</span>
                  <span className="rule" />
                </div>
                <div className="prose">{sel.technique.supported_by}</div>
              </section>

              {!caseMode ? (
                <div className="note-rail">
                  Vuelve al caso activo para registrar si esta técnica se ha confirmado, está en
                  sospecha o se ha descartado en la investigación.
                </div>
              ) : (
                <>
                  <section className="section-stack">
                    <div className="rule-label">
                      <span className="eyebrow">Propuesta del agente</span>
                      <span className="rule" />
                    </div>
                    {selEntry && selEntry.proposed_by.length > 0 ? (
                      <div className="mitre-detail-findings">
                        {selEntry.proposed_by.map((fid) => {
                          const f = findingById.get(fid);
                          return (
                            <div className="finding-rail" key={fid}>
                              <div className="finding-rail-title">{f ? f.title : fid}</div>
                              {f?.tool_id && (
                                <div className="finding-rail-meta">{f.tool_id}</div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    ) : (
                      <div className="inv-empty">
                        Ningún hallazgo del agente cita esta técnica. Puedes dictaminarla
                        igualmente si la evidencia que has revisado lo sostiene.
                      </div>
                    )}
                  </section>

                  <section className="section-stack">
                    <div className="rule-label">
                      <span className="eyebrow">Dictamen del perito</span>
                      <span className="rule" />
                    </div>
                    {selEntry?.status && (
                      <div className="inline-note">
                        Actualmente: <strong>{STATUS_LABEL[selEntry.status]}</strong>
                        {selEntry.adjudicated_at &&
                          ` · ${new Date(selEntry.adjudicated_at).toLocaleString("es-ES")}`}
                      </div>
                    )}
                    <div className="field">
                      <label className="eyebrow" htmlFor="mitre-rationale">
                        Motivo · obligatorio, queda en el log de auditoría
                      </label>
                      <textarea
                        id="mitre-rationale"
                        className="field-textarea"
                        value={rationale}
                        onChange={(e) => setRationale(e.target.value)}
                        rows={3}
                        placeholder="Qué evidencia sostiene este veredicto…"
                      />
                    </div>
                    <div className="cta-row">
                      {STATUS_ORDER.map((s) => (
                        <button
                          key={s}
                          type="button"
                          className={`chip-option${selEntry?.status === s ? " is-on" : ""}`}
                          disabled={saving || rationale.trim().length === 0}
                          onClick={() => void onAdjudicate(s)}
                        >
                          {STATUS_LABEL[s]}
                        </button>
                      ))}
                      {selEntry?.status && (
                        <button
                          type="button"
                          className="link-action"
                          disabled={saving}
                          onClick={() => void onAdjudicate("none")}
                        >
                          Retirar dictamen
                        </button>
                      )}
                    </div>
                    {rationale.trim().length === 0 && (
                      <div className="inline-note">
                        Un veredicto sin motivo no vale nada en un informe pericial: el backend
                        lo rechaza.
                      </div>
                    )}
                    {saveError && <div className="error-state">{saveError}</div>}
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
