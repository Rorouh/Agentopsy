import { useCallback, useEffect, useRef, useState } from "react";

import { ApiError, api } from "../../api/client";
import { useCaseStream } from "../../state/casePulse";
import type {
  ExecutorId,
  GraphCaseView,
  GraphFindingView,
  GraphIndex,
  GraphJob,
} from "../../api/types";
import { exportRailPng } from "../timeline/IncidentRail";
import { useThemePalette } from "../timeline/themePalette";
import { RelationGraph } from "./RelationGraph";
import { claveNodo, claveRelacion } from "./vocabulario";
import { useLang } from "../../i18n";

// GRAFOS DE RELACIONES: la figura, su ficha lateral y la extracción.
//
// La pinta GraphsPage, que es la fase propia de los grafos. Esto es la vista
// del grafo, no la página: recibe el caso y el ejecutor ya elegido y devuelve
// por `onResumen` lo que la cabecera necesita contar.
//
// Donde la línea de tiempo del incidente responde «cuándo pasó», el grafo
// responde «qué se conecta con qué»: qué equipo, qué cuenta, qué fichero, qué
// dominio y qué IP intervienen, y con qué relación.
//
// Dos figuras, y la del CASO es la que se lleva a un informe. Un hallazgo suelto
// es una observación, no una historia: medido sobre un caso real de 19
// hallazgos, la mayoría no llega a tres aristas. Al fundir por entidad, el mismo
// `IEUser` de siete hallazgos es UN nodo y ata el ejecutable con los documentos,
// la papelera y la cuenta de correo. Esa fusión no gasta ninguna llamada al
// modelo: la hace el servidor con lo ya extraído.

const JOB_POLL_MS = 1500;

function fmt(iso: string | null | undefined): string {
  if (!iso) return "n/d";
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString("es-ES");
}

function elapsed(desde: string, ahora: number): string {
  const t0 = new Date(desde).getTime();
  if (isNaN(t0)) return "";
  const s = Math.max(0, Math.round((ahora - t0) / 1000));
  return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
}


type Vista = { tipo: "caso" } | { tipo: "hallazgo"; findingId: string };

// Lo que la cabecera de la página necesita contar. Sale de aquí porque es esta
// vista la que ya pide el índice: pedirlo dos veces para pintar un número sería
// una llamada de más al api.
export type GraphResumen = { hallazgos: number; conGrafo: number };

type Props = {
  caseId: string;
  caseName: string;
  // El ejecutor que el perito ya eligió en esta página. Vacío = sin selección:
  // el botón no se pulsa y el motivo se dice (RULE 2).
  executor: ExecutorId | "";
  onResumen?: (r: GraphResumen) => void;
};

export function GraphSection({ caseId, caseName, executor, onResumen }: Props) {
  const { t, tn } = useLang();
  // Un tipo que el vocabulario no declara sale TAL CUAL (RULE 2): feo y
  // verdadero, en vez de una etiqueta inventada.
  const rotuloNodo = (tipo: string) => {
    const k = claveNodo(tipo);
    return k ? t(k) : tipo;
  };
  const rotuloRelacion = (tipo: string) => {
    const k = claveRelacion(tipo);
    return k ? t(k) : tipo;
  };
  const palette = useThemePalette();
  const svgRef = useRef<SVGSVGElement | null>(null);

  const [index, setIndex] = useState<GraphIndex | null>(null);
  const [vista, setVista] = useState<Vista>({ tipo: "caso" });
  const [caso, setCaso] = useState<GraphCaseView | null>(null);
  const [detalle, setDetalle] = useState<GraphFindingView | null>(null);
  const [nodo, setNodo] = useState<string | null>(null);

  const [job, setJob] = useState<GraphJob | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const pollRef = useRef<number | null>(null);

  const running = job?.status === "running";
  // Un lote de grafos va hallazgo a hallazgo y persiste cada uno según sale, y
  // los hallazgos que lo alimentan pueden aparecer mientras tanto.
  const revGrafos = useCaseStream("graphs", "findings");

  const recargar = useCallback(async () => {
    const idx = await api.cases.listGraphs(caseId);
    setIndex(idx);
    const grafo = await api.cases.caseGraph(caseId);
    setCaso(grafo);
  }, [caseId]);

  // Al montar: el estado del caso y, si hay una extracción viva, se retoma su
  // sondeo. Cerrar la pestaña o cambiar de sección no aborta nada.
  useEffect(() => {
    let cancelado = false;
    void (async () => {
      try {
        await recargar();
        const { jobs } = await api.cases.listGraphJobs(caseId);
        if (cancelado) return;
        const vivo = jobs.find((j) => j.status === "running") ?? jobs[0] ?? null;
        if (vivo) setJob(vivo);
      } catch (e) {
        if (!cancelado) setError(e instanceof ApiError ? e.message : String(e));
      }
    })();
    return () => {
      cancelado = true;
    };
  }, [caseId, recargar]);

  // Reposición EN SILENCIO: el grafo de un hallazgo termina y aparece sin que
  // haya que recargar la página. No toca la vista ni la selección del perito.
  useEffect(() => {
    if (revGrafos === 0) return;
    let cancelado = false;
    void (async () => {
      try {
        await recargar();
      } catch {
        /* el estado de error lo gobierna la carga de arriba */
      }
      if (cancelado) return;
    })();
    return () => {
      cancelado = true;
    };
  }, [revGrafos, recargar]);

  // Lo que la cabecera cuenta sale del índice ya cargado, no de otra petición.
  useEffect(() => {
    if (!index || !onResumen) return;
    onResumen({ hallazgos: index.hallazgos.length, conGrafo: index.grafos.length });
  }, [index, onResumen]);

  // Sondeo del job en curso.
  useEffect(() => {
    if (!running || !job) return;
    const tick = window.setInterval(() => {
      void (async () => {
        try {
          const snap = await api.cases.graphJob(caseId, job.job_id);
          setJob(snap);
          if (snap.status !== "running") await recargar();
        } catch (e) {
          setError(e instanceof ApiError ? e.message : String(e));
        }
      })();
    }, JOB_POLL_MS);
    pollRef.current = tick;
    return () => window.clearInterval(tick);
  }, [running, job, caseId, recargar]);

  // El cronómetro se ancla al `created_at` del SERVIDOR, así que cambiar de
  // sección o recargar no lo reinicia desde cero.
  useEffect(() => {
    if (!running) return;
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, [running]);

  // El grafo de un hallazgo se pide al cambiar de vista.
  useEffect(() => {
    if (vista.tipo !== "hallazgo") {
      setDetalle(null);
      return;
    }
    let cancelado = false;
    void (async () => {
      try {
        const d = await api.cases.graph(caseId, vista.findingId);
        if (!cancelado) {
          setDetalle(d);
          setError(null);
        }
      } catch (e) {
        if (cancelado) return;
        setDetalle(null);
        // Que un hallazgo no tenga grafo TODAVÍA no es un error de la vista: es
        // el estado normal antes de extraerlo, y se dice como tal.
        const sinGrafo = e instanceof ApiError && e.status === 404;
        setError(sinGrafo ? null : e instanceof ApiError ? e.message : String(e));
      }
    })();
    return () => {
      cancelado = true;
    };
  }, [vista, caseId]);

  const extraer = useCallback(
    async (findingIds: string[]) => {
      if (!executor) return;
      setBusy(true);
      setError(null);
      try {
        setJob(await api.cases.extractGraphs(caseId, findingIds, executor));
      } catch (e) {
        setError(e instanceof ApiError ? e.message : String(e));
      } finally {
        setBusy(false);
      }
    },
    [caseId, executor],
  );

  const exportar = useCallback(async () => {
    const svg = svgRef.current;
    if (!svg) return;
    try {
      // Se vuelve a pedir la capa para que la marca de exportación que va
      // DENTRO de la imagen sea la de este momento y no la de hace media hora.
      const fresco =
        vista.tipo === "caso"
          ? await api.cases.caseGraph(caseId)
          : await api.cases.graph(caseId, vista.findingId);
      if (vista.tipo === "caso") setCaso(fresco as GraphCaseView);
      else setDetalle(fresco as GraphFindingView);
      // Un frame para que el SVG se repinte con la marca nueva antes de
      // serializarlo: si no, se exportaría la anterior.
      await new Promise((r) => window.requestAnimationFrame(() => r(null)));
      await exportRailPng(
        svgRef.current ?? svg,
        `${fresco.export_basename}.png`,
        palette["--surface"],
      );
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    }
  }, [caseId, vista, palette]);

  if (!index) {
    return (
      <section className="graph-section">
        <div className="eyebrow eyebrow--section">{t("graph.figure")}</div>
        <div className="inline-note">{error ?? t("graphs.loading")}</div>
      </section>
    );
  }

  const activo = vista.tipo === "caso" ? caso : detalle;
  const nodos = activo?.nodos ?? [];
  const relaciones = activo?.relaciones ?? [];
  const pendientes = index.pendientes;
  const sinEjecutor = !executor;

  const seleccionado = nodos.find((n) => n.valor === nodo) ?? null;
  const susRelaciones = seleccionado
    ? relaciones.filter(
        (r) => r.origen === seleccionado.valor || r.destino === seleccionado.valor,
      )
    : [];
  const titulos = new Map(index.hallazgos.map((h) => [h.id, h.title]));

  return (
    <section className="graph-section">
      <div className="eyebrow eyebrow--section">{t("graph.figure")}</div>

      <div className="graph-toolbar">
        <label className="visually-hidden" htmlFor="graph-vista">
          {t("graph.selectLabel")}
        </label>
        <select
          id="graph-vista"
          className="field-input field-input--sm graph-select"
          value={vista.tipo === "caso" ? "caso" : vista.findingId}
          onChange={(e) => {
            setNodo(null);
            setVista(
              e.target.value === "caso"
                ? { tipo: "caso" }
                : { tipo: "hallazgo", findingId: e.target.value },
            );
          }}
        >
          <option value="caso">{t("graph.caseOption")}</option>
          {index.hallazgos.map((h) => {
            const g = index.grafos.find((x) => x.finding_id === h.id);
            return (
              <option key={h.id} value={h.id}>
                {h.title}
                {g
                  ? ` · ${t("graph.optionCounts", { nodes: g.n_nodos, edges: g.n_relaciones })}`
                  : ` · ${t("graph.optionNoGraph")}`}
              </option>
            );
          })}
        </select>

        {pendientes.length > 0 && (
          <button
            type="button"
            className="action-accent"
            disabled={busy || running || sinEjecutor}
            onClick={() => void extraer(pendientes)}
          >
            {running
              ? t("graph.extracting")
              : t("graph.extractMissing", { count: pendientes.length })}
          </button>
        )}
        {vista.tipo === "hallazgo" && (
          <button
            type="button"
            className={detalle ? "action" : "action-accent"}
            disabled={busy || running || sinEjecutor}
            onClick={() => void extraer([vista.findingId])}
          >
            {t(detalle ? "graph.reextractThis" : "graph.extractThis")}
          </button>
        )}
        <button
          type="button"
          className="action"
          disabled={nodos.length === 0}
          onClick={() => void exportar()}
        >
          {t("graph.exportPng")}
        </button>
      </div>

      {sinEjecutor && pendientes.length > 0 && (
        <div className="inline-note">
          {t("graph.needExecutor")}
        </div>
      )}

      {running && job && (
        <div className="progress-block">
          <div className="progress-head">
            <span>
              {(() => {
                const ultimo = [...(job.events ?? [])]
                  .reverse()
                  .find((e) => e.type === "graph_finding_start");
                return ultimo
                  ? t("graph.extractingNth", {
                      n: (ultimo.index ?? 0) + 1,
                      total: ultimo.total ?? "?",
                      title: ultimo.title ?? "",
                    })
                  : t("graph.extractingAll");
              })()}
            </span>
            <span className="mono">{elapsed(job.created_at, now)}</span>
          </div>
          <div className="progress-track">
            <div className="progress-fill progress-fill--indeterminate" />
          </div>
          <div className="progress-note">
            {t("graph.backgroundNote")}
          </div>
        </div>
      )}

      {/* El parte del lote: cuántos salieron, cuáles no y por qué. Un lote que
          aborta y no dice dónde es indistinguible de uno que no se lanzó. */}
      {job?.status === "done" && job.result && (
        <div className="graph-parte">
          <strong>
            {t("graph.batchResult", {
              done: job.result.con_grafo,
              asked: job.result.solicitados,
            })}
          </strong>
          <span className="mono">
            {t("graph.extractedWith", { executor: job.result.executor })}
          </span>
          {job.result.resultados
            .filter((r) => !r.ok)
            .map((r) => (
              <div className="graph-parte-fallo" key={r.finding_id}>
                <span>{r.title}</span>
                <span className="graph-parte-motivo">{r.error}</span>
              </div>
            ))}
        </div>
      )}

      {job?.status === "error" && (
        <div className="danger-notice">
          <strong>{t("graph.didNotFinish")}</strong>
          <div className="report-failure-reason">{job.error}</div>
        </div>
      )}

      {error && <div className="inline-note">{error}</div>}

      {activo ? (
        <div className="graph-figure">
          <RelationGraph
            ref={svgRef}
            titulo={t(vista.tipo === "caso" ? "graph.caseTitle" : "graph.findingTitle")}
            subtitulo={
              vista.tipo === "caso"
                ? t("graph.caseSubtitle", {
                    nodes: nodos.length,
                    edges: relaciones.length,
                    findings: caso?.hallazgos.length ?? 0,
                  })
                : t("graph.findingSubtitle", {
                    nodes: nodos.length,
                    edges: relaciones.length,
                  })
            }
            nodos={nodos}
            relaciones={relaciones}
            lienzo={activo.lienzo}
            aviso={activo.aviso}
            vacio={t(vista.tipo === "caso" ? "graph.emptyCase" : "graph.emptyFinding")}
            caseName={caseName}
            exportadoEn={activo.exported_at}
            seleccionado={nodo}
            onSeleccionar={setNodo}
          />

          {/* La ficha del nodo. Su mitad de arriba es PROPUESTA del modelo y su
              mitad de abajo es dato VERIFICADO del hallazgo: van separadas
              porque no valen lo mismo en un informe. */}
          {seleccionado && (
            <aside className="graph-card">
              <div className="graph-card-head">
                <span className="mono graph-card-type">{seleccionado.tipo}</span>
                <span className="graph-card-value">{seleccionado.valor}</span>
              </div>
              <div className="eyebrow">{t("graph.proposedByModel")}</div>
              <dl className="graph-card-list">
                <dt>{t("graph.cardType")}</dt>
                <dd>{rotuloNodo(seleccionado.tipo)}</dd>
                <dt>{t("graph.cardRelations")}</dt>
                <dd>
                  {susRelaciones.length === 0
                    ? t("common.na")
                    : susRelaciones.map((r, i) => (
                        <div key={i} className="graph-card-rel">
                          {r.origen === seleccionado.valor
                            ? t("graph.relTowards", {
                                relation: rotuloRelacion(r.tipo),
                                target: r.destino,
                              })
                            : t("graph.relFrom", {
                                relation: rotuloRelacion(r.tipo),
                                source: r.origen,
                              })}
                          {r.nota ? ` (${r.nota})` : ""}
                        </div>
                      ))}
                </dd>
              </dl>

              <div className="eyebrow">{t("graph.verifiedFromCase")}</div>
              {vista.tipo === "caso" ? (
                <dl className="graph-card-list">
                  <dt>{t("graph.cardFindings")}</dt>
                  <dd>
                    {(seleccionado.hallazgos ?? []).map((fid) => (
                      <button
                        type="button"
                        key={fid}
                        className="graph-card-link"
                        onClick={() => {
                          setNodo(null);
                          setVista({ tipo: "hallazgo", findingId: fid });
                        }}
                      >
                        {titulos.get(fid) ?? fid}
                      </button>
                    ))}
                  </dd>
                </dl>
              ) : (
                <dl className="graph-card-list">
                  <dt>{t("graph.cardFinding")}</dt>
                  <dd>{detalle?.hallazgo?.title ?? t("common.na")}</dd>
                  <dt>run_id</dt>
                  <dd className="mono">{detalle?.procedencia?.run_id ?? t("common.na")}</dd>
                  <dt>{t("graph.cardTool")}</dt>
                  <dd className="mono">{detalle?.procedencia?.tool_id ?? t("common.na")}</dd>
                  <dt>{t("graph.cardArtifactHash")}</dt>
                  <dd className="mono graph-card-hash">
                    {detalle?.procedencia?.artifact_sha256 ?? t("common.na")}
                  </dd>
                  <dt>{t("graph.cardObserved")}</dt>
                  <dd className="mono">{fmt(detalle?.procedencia?.observed_at)}</dd>
                </dl>
              )}
            </aside>
          )}
        </div>
      ) : (
        <div className="empty-rail">
          <div className="empty-rail-title">
            {t(vista.tipo === "hallazgo" ? "graph.noGraphFinding" : "graph.noGraphYet")}
          </div>
          <div className="empty-rail-body">
            {t(index.hallazgos.length === 0 ? "graph.noFindingsBody" : "graph.pressExtract")}
          </div>
        </div>
      )}

      {vista.tipo === "hallazgo" && detalle && (
        <div className="graph-meta mono">
          {t("graph.revisionMeta", {
            rev: detalle.revision,
            total: detalle.revisiones.length,
          })}{" "}
          · SHA-256 {detalle.sha256.slice(0, 12)} · {fmt(detalle.created_at)} ·{" "}
          {detalle.extraction.executor ?? t("common.na")}
          {detalle.extraction.attempts && detalle.extraction.attempts > 1
            ? ` · ${tn("count.attempts", detalle.extraction.attempts)}`
            : ""}
        </div>
      )}
    </section>
  );
}
