import { useCallback, useEffect, useRef, useState } from "react";

import { ApiError, api } from "../../api/client";
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
import { etiquetaNodo, etiquetaRelacion } from "./vocabulario";

// GRAFOS DE RELACIONES, dentro de Documentos.
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

const usd = (n: number) => `${n.toFixed(4)} USD`;

type Vista = { tipo: "caso" } | { tipo: "hallazgo"; findingId: string };

type Props = {
  caseId: string;
  caseName: string;
  // El ejecutor que el perito ya eligió en esta página. Vacío = sin selección:
  // el botón no se pulsa y el motivo se dice (RULE 2).
  executor: ExecutorId | "";
};

export function GraphSection({ caseId, caseName, executor }: Props) {
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
        <div className="eyebrow eyebrow--section">Grafos de relaciones</div>
        <div className="inline-note">{error ?? "Cargando los grafos del caso…"}</div>
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
      <div className="eyebrow eyebrow--section">Grafos de relaciones</div>

      <div className="graph-toolbar">
        <label className="visually-hidden" htmlFor="graph-vista">
          Figura
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
          <option value="caso">Grafo del caso (todos los hallazgos, fundidos)</option>
          {index.hallazgos.map((h) => {
            const g = index.grafos.find((x) => x.finding_id === h.id);
            return (
              <option key={h.id} value={h.id}>
                {h.title}
                {g
                  ? ` · ${g.n_nodos} nodos, ${g.n_relaciones} aristas`
                  : " · sin grafo"}
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
              ? "Extrayendo…"
              : `Extraer los ${pendientes.length} que faltan`}
          </button>
        )}
        {vista.tipo === "hallazgo" && (
          <button
            type="button"
            className={detalle ? "action" : "action-accent"}
            disabled={busy || running || sinEjecutor}
            onClick={() => void extraer([vista.findingId])}
          >
            {detalle ? "Volver a extraer este" : "Extraer este hallazgo"}
          </button>
        )}
        <button
          type="button"
          className="action"
          disabled={nodos.length === 0}
          onClick={() => void exportar()}
        >
          Exportar PNG
        </button>
      </div>

      {/* La previsión, con su base declarada, ANTES de gastar. Nunca comparte
          campo con el coste real del lote ya ejecutado. */}
      {pendientes.length > 0 && !running && (
        <div className="graph-cost">
          <span className="mono">
            Coste estimado: {usd(index.estimacion.coste_estimado_usd)} por{" "}
            {index.estimacion.hallazgos} hallazgos
          </span>
          <span className="graph-cost-base">
            Previsión, {index.estimacion.base_del_estimado}
          </span>
        </div>
      )}

      {sinEjecutor && pendientes.length > 0 && (
        <div className="inline-note">
          El grafo lo extrae el modelo que selecciones. Elige un ejecutor en el panel
          de la izquierda: Agentopsy no elige uno por ti.
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
                  ? `Extrayendo ${(ultimo.index ?? 0) + 1} de ${ultimo.total ?? "?"}: ${ultimo.title ?? ""}`
                  : "Extrayendo los grafos…";
              })()}
            </span>
            <span className="mono">{elapsed(job.created_at, now)}</span>
          </div>
          <div className="progress-track">
            <div className="progress-fill progress-fill--indeterminate" />
          </div>
          <div className="progress-note">
            Puedes cambiar de sección o cerrar la pestaña: la extracción corre en el
            servidor y al volver aquí se retoma su progreso.
          </div>
        </div>
      )}

      {/* El parte del lote: cuántos salieron, cuáles no y por qué. Un lote que
          aborta y no dice dónde es indistinguible de uno que no se lanzó. */}
      {job?.status === "done" && job.result && (
        <div className="graph-parte">
          <strong>
            {job.result.con_grafo} de {job.result.solicitados} hallazgos con grafo
          </strong>
          <span className="mono">
            {job.result.coste_usd === null
              ? `Coste real: no informado por ${job.result.executor}`
              : `Coste real: ${usd(job.result.coste_usd)}`}
            {" · "}
            {job.result.input_tokens} tok entrada, {job.result.output_tokens} tok salida
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
          <strong>La extracción no llegó a terminar</strong>
          <div className="report-failure-reason">{job.error}</div>
        </div>
      )}

      {error && <div className="inline-note">{error}</div>}

      {activo ? (
        <div className="graph-figure">
          <RelationGraph
            ref={svgRef}
            titulo={
              vista.tipo === "caso"
                ? "Grafo de relaciones del caso"
                : "Grafo de relaciones del hallazgo"
            }
            subtitulo={
              vista.tipo === "caso"
                ? `${nodos.length} activos y ${relaciones.length} conexiones, de ${caso?.hallazgos.length ?? 0} hallazgos`
                : `${nodos.length} activos y ${relaciones.length} conexiones`
            }
            nodos={nodos}
            relaciones={relaciones}
            lienzo={activo.lienzo}
            aviso={activo.aviso}
            vacio={
              vista.tipo === "caso"
                ? "Todavía no se ha extraído ningún grafo en este caso. El grafo del caso funde los de los hallazgos, así que aparece en cuanto haya uno."
                : "Este hallazgo no nombra ninguna entidad de los cinco tipos. Grafo vacío, que es un resultado legítimo."
            }
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
              <div className="eyebrow">Propuesto por el modelo</div>
              <dl className="graph-card-list">
                <dt>Tipo</dt>
                <dd>{etiquetaNodo(seleccionado.tipo)}</dd>
                <dt>Relaciones</dt>
                <dd>
                  {susRelaciones.length === 0
                    ? "n/d"
                    : susRelaciones.map((r, i) => (
                        <div key={i} className="graph-card-rel">
                          {r.origen === seleccionado.valor
                            ? `${etiquetaRelacion(r.tipo)} hacia ${r.destino}`
                            : `${etiquetaRelacion(r.tipo)} desde ${r.origen}`}
                          {r.nota ? ` (${r.nota})` : ""}
                        </div>
                      ))}
                </dd>
              </dl>

              <div className="eyebrow">Verificado, del caso</div>
              {vista.tipo === "caso" ? (
                <dl className="graph-card-list">
                  <dt>Hallazgos</dt>
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
                  <dt>Hallazgo</dt>
                  <dd>{detalle?.hallazgo?.title ?? "n/d"}</dd>
                  <dt>run_id</dt>
                  <dd className="mono">{detalle?.procedencia?.run_id ?? "n/d"}</dd>
                  <dt>Herramienta</dt>
                  <dd className="mono">{detalle?.procedencia?.tool_id ?? "n/d"}</dd>
                  <dt>SHA-256 del artefacto</dt>
                  <dd className="mono graph-card-hash">
                    {detalle?.procedencia?.artifact_sha256 ?? "n/d"}
                  </dd>
                  <dt>Observado</dt>
                  <dd className="mono">{fmt(detalle?.procedencia?.observed_at)}</dd>
                </dl>
              )}
            </aside>
          )}
        </div>
      ) : (
        <div className="empty-rail">
          <div className="empty-rail-title">
            {vista.tipo === "hallazgo" ? "Este hallazgo no tiene grafo" : "Sin grafo todavía"}
          </div>
          <div className="empty-rail-body">
            {index.hallazgos.length === 0
              ? "El grafo se extrae del texto de los hallazgos, y este caso no tiene ninguno todavía."
              : "Pulsa «Extraer» y el modelo seleccionado leerá el texto del hallazgo para proponer qué entidades intervienen y con qué relación."}
          </div>
        </div>
      )}

      {vista.tipo === "hallazgo" && detalle && (
        <div className="graph-meta mono">
          Revisión v{detalle.revision} de {detalle.revisiones.length} · SHA-256{" "}
          {detalle.sha256.slice(0, 12)} · {fmt(detalle.created_at)} ·{" "}
          {detalle.extraction.executor ?? "n/d"}
          {detalle.extraction.attempts && detalle.extraction.attempts > 1
            ? ` · ${detalle.extraction.attempts} intentos`
            : ""}
        </div>
      )}
    </section>
  );
}
