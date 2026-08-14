import { useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import { useActiveCase } from "./activeCase";
import { useCaseEvidence } from "./caseEvidence";
import { useCaseStream } from "./casePulse";

// Cifras del caso que alimentan el estado de las fases: la escalera del sidebar
// y los pasos de la Guía leen LAS MISMAS, para que no puedan contradecirse.
//
// RULE 2: mientras `loaded` sea false no se pinta ninguna meta ni ningún estado
// avanzado. Un contador inventado para que la escalera «se vea llena» es
// exactamente lo que la regla prohíbe.
export interface CaseFacts {
  evidenceTotal: number;
  evidenceVerified: number;
  findings: number;
  // Técnicas ATT&CK que el caso ha TOCADO: propuestas por el agente, dictaminadas
  // por el perito, o ambas (una entrada de cobertura por técnica). Es lo que la
  // matriz pinta, así que la fase está hecha cuando hay al menos una.
  mitreTechniques: number;
  // De esas, cuántas llevan dictamen del perito. Es el OTRO eje y nunca se funde
  // con el primero (ver forensia.mitre.coverage): se cuenta aparte para que la
  // escalera pueda decir «propuestas, aún sin dictaminar» en vez de callarlo.
  mitreAdjudicated: number;
  // Eventos de la línea de tiempo del INCIDENTE: un hallazgo con `observed_at`
  // situable en el eje. Es la capa de entrada del Timeline y la que se lleva al
  // informe, así que es la que dice si esa fase tiene contenido.
  incidentEvents: number;
  // Hallazgos que NO se pudieron situar en el eje (sin `observed_at` o con una
  // marca no parseable). Viaja contado porque un hueco declarado es un dato del
  // caso, no un residuo: explica una fase que aún no está hecha.
  incidentUndated: number;
  // Hallazgos que YA tienen grafo extraído, no grafos posibles: la fase de
  // Grafos está hecha cuando hay al menos uno, porque el del caso funde los que
  // haya.
  graphs: number;
  documents: number;
  loaded: boolean;
}

export const EMPTY_FACTS: CaseFacts = {
  evidenceTotal: 0,
  evidenceVerified: 0,
  findings: 0,
  mitreTechniques: 0,
  mitreAdjudicated: 0,
  incidentEvents: 0,
  incidentUndated: 0,
  graphs: 0,
  documents: 0,
  loaded: false,
};

// Las cifras que NO salen del store de evidencia, en un solo objeto: cambian a la
// vez (una sola vuelta de lecturas) y así no se pintan mezcladas dos vueltas.
type Counts = Pick<
  CaseFacts,
  | "findings"
  | "graphs"
  | "documents"
  | "mitreTechniques"
  | "mitreAdjudicated"
  | "incidentEvents"
  | "incidentUndated"
>;

const ZERO_COUNTS: Counts = {
  findings: 0,
  graphs: 0,
  documents: 0,
  mitreTechniques: 0,
  mitreAdjudicated: 0,
  incidentEvents: 0,
  incidentUndated: 0,
};

export function useCaseFacts(): CaseFacts {
  const { activeCaseId } = useActiveCase();
  // La evidencia sale del store COMPARTIDO, no de una lectura propia: es lo que
  // hace que registrar una imagen actualice la escalera del sidebar en el momento
  // en que el registro termina, sin recargar la página. El sidebar nunca se
  // desmonta, así que su lectura propia se quedaba vieja para siempre.
  const { evidence, phase: evidencePhase } = useCaseEvidence();
  // La escalera del sidebar vive fuera de las vistas y NUNCA se desmonta, así que
  // sin esto se quedaba con las cifras del momento en que se cargó el caso: el
  // perito veía «sin hallazgos» con veinte ya persistidos. Se observan todos los
  // flujos que alimentan estas cifras: la cobertura ATT&CK depende de los TRES
  // que la componen (los `mitre_hints` viajan dentro del hallazgo, las
  // anotaciones del agente en `mitre_proposals` y los dictámenes del perito en
  // `mitre_verdicts`), y la capa del incidente, de los hallazgos.
  const revFacts = useCaseStream(
    "findings",
    "graphs",
    "documents",
    "mitre_proposals",
    "mitre_verdicts",
  );
  const [counts, setCounts] = useState<Counts>(ZERO_COUNTS);

  useEffect(() => {
    let cancelled = false;
    if (!activeCaseId) {
      setCounts(ZERO_COUNTS);
      return;
    }
    (async () => {
      // Un fallo de cualquiera de estas lecturas deja su cifra a cero: `loaded`
      // lo gobierna la evidencia, que es la lectura que decide si hay caso que
      // enseñar.
      const [findings, graphs, documents, mitre, incident] = await Promise.all([
        api.cases.listFindings(activeCaseId).catch(() => null),
        api.cases.listGraphs(activeCaseId).catch(() => null),
        api.cases.listDocuments(activeCaseId).catch(() => null),
        api.cases.listMitreCoverage(activeCaseId).catch(() => null),
        api.cases.incidentTimeline(activeCaseId).catch(() => null),
      ]);
      if (cancelled) return;
      setCounts({
        findings: findings?.length ?? 0,
        graphs: graphs?.grafos.length ?? 0,
        documents: documents?.length ?? 0,
        mitreTechniques: mitre?.length ?? 0,
        mitreAdjudicated: mitre?.filter((c) => c.status !== null).length ?? 0,
        incidentEvents: incident?.eventos.length ?? 0,
        incidentUndated: incident ? incident.sin_observed_at + incident.no_parseable : 0,
      });
    })();
    return () => {
      cancelled = true;
    };
  }, [activeCaseId, revFacts]);

  return useMemo(() => {
    if (!activeCaseId) return EMPTY_FACTS;
    return {
      evidenceTotal: evidence.length,
      evidenceVerified: evidence.filter((e) => e.last_verification !== null).length,
      ...counts,
      loaded: evidencePhase === "ready",
    };
  }, [activeCaseId, evidence, evidencePhase, counts]);
}
