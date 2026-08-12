import { useCallback, useEffect, useState } from "react";

import { api } from "../api/client";
import type { Capabilities, ExecutorId, ExecutorStatus } from "../api/types";
import { usePublishShellHeader } from "../layout/shellHeader";
import { useActiveCase } from "../state/activeCase";
import { GraphSection, type GraphResumen } from "./graphs/GraphSection";

// FASE 6 · Grafos de relaciones.
//
// Vivía dentro del Informe pericial, y ahí estaba mal puesta: extraer los grafos
// es un acto propio, con su modelo y su parte de resultados, no un
// paso de la redacción. Al compartir pantalla con «Finalizar investigación»,
// dos acciones que llaman al modelo y cuestan dinero competían por la misma
// mirada. Aquí es la fase que separa leer los hallazgos de
// redactar el informe, que es justo el orden en que se usa.
//
// El ejecutor se elige aquí, y se guarda en la MISMA clave que el chat y el
// informe (`DEFAULT_EXECUTOR`): es la selección explícita del operador, una
// sola, no tres que puedan contradecirse. Sin selección no se llama a ningún
// modelo y el motivo se dice (RULE 2).

const EXECUTOR_CONFIG_KEY = "DEFAULT_EXECUTOR";

export function GraphsPage() {
  const { activeCase, phase: casesPhase, error: casesError } = useActiveCase();

  const [caps, setCaps] = useState<Capabilities | null>(null);
  const [executor, setExecutor] = useState<ExecutorId | "">("");
  const [resumen, setResumen] = useState<GraphResumen | null>(null);

  useEffect(() => {
    let cancelado = false;
    api
      .capabilities()
      .then((c) => {
        if (!cancelado) setCaps(c);
      })
      .catch(() => {
        if (!cancelado) setCaps(null);
      });
    api.config
      .get()
      .then((snap) => {
        const def = snap.keys[EXECUTOR_CONFIG_KEY];
        if (!cancelado && def?.set && def.preview) {
          setExecutor((prev) => prev || (def.preview as ExecutorId));
        }
      })
      .catch(() => {
        /* sin config aún: el perito elige a mano */
      });
    return () => {
      cancelado = true;
    };
  }, []);

  // El resumen es de UN caso: al cambiar de caso se descarta, para que la
  // cabecera no siga contando los grafos del anterior.
  useEffect(() => {
    setResumen(null);
  }, [activeCase?.id]);

  const seleccionar = (id: ExecutorId | "") => {
    setExecutor(id);
    if (id) {
      api.config.set(EXECUTOR_CONFIG_KEY, id).catch(() => {
        /* persistencia best-effort: la sesión ya lleva la selección */
      });
    }
  };

  const onResumen = useCallback((r: GraphResumen) => setResumen(r), []);

  const executorStatus: ExecutorStatus | null =
    executor && caps ? caps.executors[executor] ?? null : null;
  const executorEntries: [ExecutorId, ExecutorStatus][] = caps
    ? (Object.entries(caps.executors) as [ExecutorId, ExecutorStatus][])
    : [];

  usePublishShellHeader(
    {
      title: "Grafos de relaciones",
      meta: !activeCase
        ? "sin caso seleccionado"
        : resumen
          ? resumen.hallazgos === 0
            ? "sin hallazgos que analizar"
            : `${resumen.conGrafo} de ${resumen.hallazgos} hallazgos con grafo`
          : "cargando",
    },
    [activeCase?.id, resumen?.conGrafo, resumen?.hallazgos],
  );

  if (casesPhase === "loading") {
    return (
      <div className="view-scroll">
        <div className="loading-state">
          <span className="spinner" aria-hidden="true" />
          <span>Cargando los grafos del caso…</span>
        </div>
      </div>
    );
  }

  if (casesPhase === "error") {
    return (
      <div className="view-scroll">
        <div className="error-state">
          <strong>No se pudieron cargar los grafos:</strong> {casesError}
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
            El grafo se extrae del texto de los hallazgos de un caso. Abre uno desde el
            lateral.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="view-scroll">
      <div className="graphs-page">
        <div className="graphs-intro">
          <div className="graphs-intro-text">
            Donde la línea de tiempo responde cuándo pasó, el grafo responde qué se conecta
            con qué: qué cuentas, ficheros, equipos, dominios e IP intervienen en cada
            hallazgo y con qué relación. El grafo del caso funde los de todos los hallazgos
            por entidad, y esa fusión no gasta ninguna llamada al modelo. Es una propuesta
            del modelo, no un hecho verificado, y así viaja etiquetada también dentro de la
            imagen exportada.
          </div>
          <div className="field graphs-intro-field">
            <label className="eyebrow" htmlFor="graphs-executor">
              Modelo que extrae
            </label>
            {/* Selección EXPLÍCITA del operador. Un ejecutor no disponible se
                lista deshabilitado con su nombre, nunca se sustituye por otro
                (RULE 2). Es la misma clave que usan el chat y el informe. */}
            <select
              id="graphs-executor"
              className="field-input field-input--sm"
              value={executor}
              onChange={(e) => seleccionar(e.target.value as ExecutorId | "")}
            >
              <option value="">Elige un ejecutor…</option>
              {executorEntries.map(([id, st]) => (
                <option key={id} value={id} disabled={!st.available}>
                  {st.available ? st.name : `${st.name} (no disponible)`}
                  {st.local ? " · local" : ""}
                </option>
              ))}
            </select>
            {executorStatus && !executorStatus.available && (
              <div className="inline-note">
                {executorStatus.reason ?? `${executorStatus.name} no está disponible.`}
              </div>
            )}
          </div>
        </div>

        <GraphSection
          caseId={activeCase.id}
          caseName={activeCase.name}
          executor={executor}
          onResumen={onResumen}
        />
      </div>
    </div>
  );
}
