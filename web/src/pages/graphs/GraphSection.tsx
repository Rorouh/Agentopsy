import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";

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
import { GraphViewport } from "./GraphViewport";
import {
  RelationGraph,
  relacionesPresentes,
  tiposPresentes,
} from "./RelationGraph";
import { claveNodo, claveRelacion, colorNodo, colorRelacion } from "./vocabulario";
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

// FUNCIÓN «VISTAS»: el orden en que se agrupan los cortes en el desplegable. Es
// el mismo de `forensia.graph.vistas.EJES`, para que la lista se lea igual que
// la calcula el servidor. Un eje que el backend gane y esta tabla no conozca no
// se pinta, que es preferible a inventarle un rótulo (RULE 2).
const EJES_VISTA = ["tecnica", "tactica", "evidencia", "severidad"] as const;

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
  //: El selector de modelo, que construye la PÁGINA (es suya la selección y su
  //: persistencia) y se pinta aquí, en la barra, junto al botón que lo gasta.
  controlModelo?: ReactNode;
  //: Por qué el ejecutor elegido no se puede usar, si es el caso.
  avisoModelo?: string | null;
};

export function GraphSection({
  caseId,
  caseName,
  executor,
  onResumen,
  controlModelo,
  avisoModelo,
}: Props) {
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
  // El SVG que se serializa es el de la figura ENTERA, que solo se monta durante
  // la exportación: en pantalla se pinta el dibujo a secas, y componer las dos
  // versiones a la vez sería dibujar cada nodo dos veces sin que nadie lo vea.
  const svgExportRef = useRef<SVGSVGElement | null>(null);
  const [exportando, setExportando] = useState(false);

  const [index, setIndex] = useState<GraphIndex | null>(null);
  const [vista, setVista] = useState<Vista>({ tipo: "caso" });
  const [caso, setCaso] = useState<GraphCaseView | null>(null);
  const [detalle, setDetalle] = useState<GraphFindingView | null>(null);
  const [nodo, setNodo] = useState<string | null>(null);

  // FUNCIÓN «VISTAS»: el corte aplicado al grafo del caso. Vacío = caso entero.
  const [vistaCorte, setVistaCorte] = useState("");
  const vistaCorteRef = useRef("");
  vistaCorteRef.current = vistaCorte;
  // FUNCIÓN «LOCALIZADOR»: la búsqueda y el encuadre que produce.
  const [busqueda, setBusqueda] = useState("");
  const [centrarEn, setCentrarEn] = useState<{ x: number; y: number; sello: number } | null>(
    null,
  );
  const [profundidadFoco, setProfundidadFoco] = useState(1);

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
    // El corte va por REF y no por dependencia: `recargar` la usan tres efectos
    // y rehacerla al cambiar de vista los dispararía todos, incluido el que
    // vuelve a pedir la lista de jobs.
    const grafo = await api.cases.caseGraph(caseId, vistaCorteRef.current || undefined);
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

  // FUNCIÓN «VISTAS»: cambiar de corte vuelve a pedir el grafo del caso, y solo
  // eso. La selección del perito (nodo enfocado, búsqueda) se descarta porque es
  // de la figura anterior.
  useEffect(() => {
    let cancelado = false;
    void (async () => {
      try {
        const grafo = await api.cases.caseGraph(caseId, vistaCorte || undefined);
        if (cancelado) return;
        setCaso(grafo);
        setNodo(null);
        setBusqueda("");
        setError(null);
      } catch (e) {
        if (!cancelado) setError(e instanceof ApiError ? e.message : String(e));
      }
    })();
    return () => {
      cancelado = true;
    };
  }, [vistaCorte, caseId]);

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
    setExportando(true);
    try {
      // Se vuelve a pedir la capa para que la marca de exportación que va
      // DENTRO de la imagen sea la de este momento y no la de hace media hora.
      const fresco =
        vista.tipo === "caso"
          ? await api.cases.caseGraph(caseId, vistaCorte || undefined)
          : await api.cases.graph(caseId, vista.findingId);
      if (vista.tipo === "caso") setCaso(fresco as GraphCaseView);
      else setDetalle(fresco as GraphFindingView);
      // DOS frames: uno para que React monte la figura de exportación y otro
      // para que se repinte con la marca nueva. Con uno solo se serializaría un
      // SVG que todavía no existe, o el de la marca anterior.
      await new Promise((r) => window.requestAnimationFrame(() => r(null)));
      await new Promise((r) => window.requestAnimationFrame(() => r(null)));
      const svg = svgExportRef.current;
      if (!svg) throw new Error(t("graph.exportNotReady"));
      await exportRailPng(svg, `${fresco.export_basename}.png`, palette["--surface"]);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setExportando(false);
    }
  }, [caseId, vista, vistaCorte, palette, t]);

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

  // La identidad de la figura y su leyenda. Se calculan UNA vez y las usan las
  // dos versiones (la de pantalla, que las pinta fijas alrededor del dibujo, y
  // la de exportación, que las compone dentro del SVG), para que no puedan decir
  // cosas distintas de la misma figura.
  const figuraTitulo = t(vista.tipo === "caso" ? "graph.caseTitle" : "graph.findingTitle");
  // Las entidades de la figura son las de la red MÁS las de la banda: la
  // exportación dibuja las dos, así que contar aquí solo la red haría que la
  // misma figura dijera 36 en pantalla y 82 en el PNG.
  const inventarioActivo = vista.tipo === "caso" ? caso?.inventario ?? null : null;
  const totalEntidades = nodos.length + (inventarioActivo?.total ?? 0);
  const figuraSubtitulo =
    vista.tipo === "caso"
      ? t("graph.caseSubtitle", {
          nodes: totalEntidades,
          edges: relaciones.length,
          findings: caso?.hallazgos.length ?? 0,
        })
      : t("graph.findingSubtitle", { nodes: totalEntidades, edges: relaciones.length });
  // El tema se lee del ATRIBUTO del documento y no del contexto, por la misma
  // razón que lo hace `useThemePalette`, de quien esta vista ya depende: al
  // cambiar de tema la paleta se relee y este render vuelve a pasar por aquí.
  const oscuro = document.documentElement.getAttribute("data-theme") === "dark";
  const tiposLeyenda = tiposPresentes(nodos);
  const relacionesLeyenda = relacionesPresentes(relaciones);

  // FUNCIÓN «VISTAS»: cómo se lee el corte aplicado, y los cortes que ofrece el
  // caso agrupados por eje. El texto declarado viaja DENTRO del PNG.
  const cortes = caso?.vistas ?? [];
  const cortesPorEje = EJES_VISTA.map((eje) => ({
    eje,
    opciones: cortes.filter((c) => c.eje === eje),
  })).filter((g) => g.opciones.length > 0);
  const corteAplicado = caso?.vista ?? null;
  const vistaDeclarada = corteAplicado
    ? t("graph.viewDeclared", {
        label: corteAplicado.etiqueta,
        count: corteAplicado.hallazgos,
      })
    : null;

  // FUNCIÓN «LOCALIZADOR»: qué entidades de ESTA figura contienen lo buscado.
  // La comparación es la misma que usa la extracción para comprobar que una
  // entidad está escrita en el hallazgo: subcadena, insensible a mayúsculas.
  //
  // Se busca en la red Y en el inventario. Buscar solo en la red haría que
  // preguntar por `gmail.com` respondiera «ninguna entidad contiene gmail.com»
  // teniéndola el caso en la lista de abajo, que es peor que no buscar: una
  // negación falsa sobre el contenido de un expediente.
  const consulta = busqueda.trim().toLowerCase();
  const coincidencias = consulta
    ? nodos.filter((n) => n.valor.toLowerCase().includes(consulta))
    : [];
  const enInventario =
    consulta && coincidencias.length === 0
      ? (inventarioActivo?.nodos ?? []).find((n) =>
          n.valor.toLowerCase().includes(consulta),
        )
      : undefined;

  const localizar = (texto: string) => {
    setBusqueda(texto);
    const q = texto.trim().toLowerCase();
    // Vaciar la caja suelta el foco: dejarlo puesto apagaría media figura sin
    // que quede en pantalla el motivo.
    if (!q) {
      setNodo(null);
      return;
    }
    const encontrado = nodos.find((n) => n.valor.toLowerCase().includes(q));
    // Sin coincidencia no se toca la vista: el aviso ya dice que no hay ninguna,
    // y saltar a otro sitio al escribir una letra de más desorienta.
    if (!encontrado || encontrado.valor === nodo) return;
    setNodo(encontrado.valor);
    setCentrarEn({ x: encontrado.x, y: encontrado.y, sello: Date.now() });
  };

  // El rótulo de la figura, FIJO sobre el visor. Va aquí y no dentro del SVG de
  // pantalla porque es el marco de lectura, no el dato: moverlo con el dibujo lo
  // sacaba de la ventana en cuanto el perito arrastraba un poco.
  const cabeceraFigura = (
    <>
      <div className="graph-caption">
        <div className="graph-caption-text">
          <span className="graph-caption-title">{figuraTitulo}</span>
          <span className="graph-caption-sub">{figuraSubtitulo}</span>
        </div>
        <span className="mono graph-caption-counts">
          {t("graph.svgCounts", { nodes: totalEntidades, edges: relaciones.length })}
        </span>
      </div>

      {/* FUNCIÓN «LOCALIZADOR». En una figura de decenas de nodos, la pregunta
          que más se hace un perito es «dónde está esta IP», y hasta ahora la
          respuesta era recorrerla con la vista. */}
      <div className="graph-explore">
        <label className="graph-explore-field">
          <span className="eyebrow">{t("graph.searchLabel")}</span>
          <input
            type="search"
            className="field-input field-input--sm"
            value={busqueda}
            placeholder={t("graph.searchPlaceholder")}
            onChange={(e) => localizar(e.target.value)}
          />
        </label>
        <div className="graph-explore-depth">
          <span className="eyebrow">{t("graph.focusDepth")}</span>
          {([1, 2] as const).map((saltos) => (
            <button
              key={saltos}
              type="button"
              className={profundidadFoco === saltos ? "action-accent" : "action-outline"}
              onClick={() => setProfundidadFoco(saltos)}
            >
              {t(saltos === 1 ? "graph.focusDepth1" : "graph.focusDepth2")}
            </button>
          ))}
        </div>
      </div>
      {enInventario && (
        <div className="inline-note">
          {t("graph.searchInInventory", { value: enInventario.valor })}
        </div>
      )}
      {consulta && coincidencias.length === 0 && !enInventario && (
        <div className="inline-note">
          {t("graph.searchNoMatch", { query: busqueda.trim() })}
        </div>
      )}
      {coincidencias.length > 1 && (
        <div className="inline-note">
          {t("graph.searchMatches", { count: coincidencias.length })}
        </div>
      )}
    </>
  );

  // La leyenda, FIJA bajo el visor. Enumera lo que la figura pinta de verdad, no
  // las dieciocho entradas de las dos enums.
  const leyendaFigura = (
    <div className="graph-legend">
      <div className="graph-legend-row">
        <span className="eyebrow graph-legend-label">{t("graph.legendNodes")}</span>
        {tiposLeyenda.length === 0 ? (
          <span className="graph-legend-empty">{t("common.na")}</span>
        ) : (
          tiposLeyenda.map((tipo) => (
            <span className="graph-legend-item" key={`ln-${tipo}`}>
              <span
                className="graph-legend-swatch"
                style={{ background: colorNodo(tipo, oscuro) }}
                aria-hidden="true"
              />
              {rotuloNodo(tipo)}
            </span>
          ))
        )}
      </div>
      <div className="graph-legend-row">
        <span className="eyebrow graph-legend-label">{t("graph.legendEdges")}</span>
        {relacionesLeyenda.length === 0 ? (
          <span className="graph-legend-empty">{t("common.na")}</span>
        ) : (
          relacionesLeyenda.map((tipo) => (
            <span className="graph-legend-item" key={`lr-${tipo}`}>
              <span
                className="graph-legend-rule"
                style={{ background: colorRelacion(tipo, oscuro) }}
                aria-hidden="true"
              />
              {rotuloRelacion(tipo)}
            </span>
          ))
        )}
      </div>
    </div>
  );

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
            setBusqueda("");
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

        {/* FUNCIÓN «VISTAS». Solo tiene sentido sobre el grafo del CASO: el de
            un hallazgo ya ES un corte, el de ese hallazgo. Los ejes salen de lo
            que el caso tiene persistido, así que un caso sin correlación ATT&CK
            solo ofrece evidencia y severidad, y uno sin nada no ofrece el
            desplegable. */}
        {vista.tipo === "caso" && cortesPorEje.length > 0 && (
          <>
            <label className="visually-hidden" htmlFor="graph-corte">
              {t("graph.viewLabel")}
            </label>
            <select
              id="graph-corte"
              className="field-input field-input--sm graph-select-corte"
              value={vistaCorte}
              onChange={(e) => setVistaCorte(e.target.value)}
            >
              <option value="">{t("graph.viewWhole")}</option>
              {cortesPorEje.map(({ eje, opciones }) => (
                <optgroup key={eje} label={t(`graph.viewAxis.${eje}` as const)}>
                  {opciones.map((c) => (
                    <option key={c.id} value={c.id}>
                      {t("graph.viewOption", { label: c.etiqueta, count: c.hallazgos })}
                    </option>
                  ))}
                </optgroup>
              ))}
            </select>
          </>
        )}

        {controlModelo}

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
          disabled={nodos.length === 0 || exportando}
          onClick={() => void exportar()}
        >
          {t(exportando ? "graph.exporting" : "graph.exportPng")}
        </button>
      </div>

      {avisoModelo && <div className="inline-note">{avisoModelo}</div>}

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

      {/* FUNCIÓN «VISTAS»: qué corte se está mirando. Se dice en la vista y se
          escribe DENTRO del PNG, porque una figura recortada que no lo anuncia
          engaña a quien la lee en un informe. */}
      {vista.tipo === "caso" && vistaDeclarada && (
        <div className="inline-note">{vistaDeclarada}</div>
      )}
      {vista.tipo === "caso" && corteAplicado && corteAplicado.hallazgos === 0 && (
        <div className="inline-note">{t("graph.viewEmptyNote")}</div>
      )}

      {/* Lo que el layout tuvo que hacer para que la figura cupiera. Una figura
          ampliada o con solapes corregidos no es lo mismo que una que salió a la
          primera, y quien la lleva a un informe tiene derecho a saberlo
          (RULE 2: nada se comprime en silencio). */}
      {(activo?.notas_layout ?? []).map((n, i) => (
        <div className="inline-note" key={`nota-${i}`}>
          {n.codigo === "lienzo_ampliado"
            ? t("graph.layoutEnlarged", { width: n.ancho ?? 0, height: n.alto ?? 0 })
            : t("graph.layoutRelaxed", { count: n.pares ?? 0 })}
        </div>
      ))}

      {activo ? (
        <div className="graph-figure">
          <GraphViewport
            encuadreDe={vista.tipo === "caso" ? "caso" : vista.findingId}
            ancho={activo.lienzo.ancho}
            alto={activo.lienzo.alto}
            cabecera={cabeceraFigura}
            leyenda={leyendaFigura}
            centrarEn={centrarEn}
          >
            <RelationGraph
              modo="pantalla"
              titulo={figuraTitulo}
              subtitulo={figuraSubtitulo}
              nodos={nodos}
              relaciones={relaciones}
              lienzo={activo.lienzo}
              aviso={activo.aviso}
              vacio={t(vista.tipo === "caso" ? "graph.emptyCase" : "graph.emptyFinding")}
              caseName={caseName}
              exportadoEn={activo.exported_at}
              seleccionado={nodo}
              onSeleccionar={setNodo}
              profundidadFoco={profundidadFoco}
            />
          </GraphViewport>

          {/* La figura ENTERA, la que se serializa al PNG. Se monta fuera de la
              vista y solo mientras se exporta: es la misma geometría que se está
              explorando, con su cabecera, su leyenda y su procedencia dentro del
              dibujo, que es lo que un PNG suelto necesita para sostenerse en un
              informe. */}
          {exportando && (
            <div className="graph-export-offscreen" aria-hidden="true">
              <RelationGraph
                modo="exportacion"
                ref={svgExportRef}
                titulo={figuraTitulo}
                subtitulo={figuraSubtitulo}
                nodos={nodos}
                relaciones={relaciones}
                lienzo={activo.lienzo}
                aviso={activo.aviso}
                vacio={t(vista.tipo === "caso" ? "graph.emptyCase" : "graph.emptyFinding")}
                caseName={caseName}
                exportadoEn={activo.exported_at}
                seleccionado={nodo}
                profundidadFoco={profundidadFoco}
                inventario={inventarioActivo}
                vistaDeclarada={vista.tipo === "caso" ? vistaDeclarada : null}
              />
            </div>
          )}

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

      {/* FUNCIÓN «INVENTARIO»: las entidades que ningún hallazgo relaciona. En
          pantalla son una LISTA y no una banda de discos: se leen mejor como
          texto, y meterlas en el lienzo lo alargaba hasta devolver los rótulos
          de la red a cuatro píxeles, que es de lo que se venía. Dentro del PNG
          sí van como banda, porque una imagen suelta tiene que llevarlo todo. */}
      {inventarioActivo && (
        <div className="graph-inventory">
          <div className="graph-inventory-head">
            <span className="eyebrow">{t("graph.inventoryTitle")}</span>
            <span className="mono graph-inventory-count">
              {t("graph.inventoryCount", {
                loose: inventarioActivo.total,
                total: inventarioActivo.total + inventarioActivo.en_la_red,
              })}
            </span>
          </div>
          <p className="graph-inventory-note">{t("graph.inventoryNote")}</p>
          <ul className="graph-inventory-list">
            {inventarioActivo.nodos.map((n) => (
              <li className="graph-inventory-item" key={`${n.tipo}:${n.valor}`}>
                <span
                  className="graph-legend-swatch"
                  style={{ background: colorNodo(n.tipo, oscuro) }}
                  aria-hidden="true"
                />
                <span className="mono graph-inventory-value">{n.valor}</span>
                <span className="graph-inventory-type">{rotuloNodo(n.tipo)}</span>
              </li>
            ))}
          </ul>
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
