import { useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import { useActiveCase } from "./activeCase";
import { useCaseEvidence } from "./caseEvidence";

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
  documents: number;
  loaded: boolean;
}

export const EMPTY_FACTS: CaseFacts = {
  evidenceTotal: 0,
  evidenceVerified: 0,
  findings: 0,
  documents: 0,
  loaded: false,
};

export function useCaseFacts(): CaseFacts {
  const { activeCaseId } = useActiveCase();
  // La evidencia sale del store COMPARTIDO, no de una lectura propia: es lo que
  // hace que registrar una imagen actualice la escalera del sidebar en el momento
  // en que el registro termina, sin recargar la página. El sidebar nunca se
  // desmonta, así que su lectura propia se quedaba vieja para siempre.
  const { evidence, phase: evidencePhase } = useCaseEvidence();
  const [counts, setCounts] = useState<{ findings: number; documents: number }>({
    findings: 0,
    documents: 0,
  });

  useEffect(() => {
    let cancelled = false;
    if (!activeCaseId) {
      setCounts({ findings: 0, documents: 0 });
      return;
    }
    (async () => {
      // Un fallo de estas dos deja su cifra a cero: `loaded` lo gobierna la
      // evidencia, que es la lectura que decide si hay caso que enseñar.
      const [findings, documents] = await Promise.all([
        api.cases.listFindings(activeCaseId).catch(() => null),
        api.cases.listDocuments(activeCaseId).catch(() => null),
      ]);
      if (cancelled) return;
      setCounts({
        findings: findings?.length ?? 0,
        documents: documents?.length ?? 0,
      });
    })();
    return () => {
      cancelled = true;
    };
  }, [activeCaseId]);

  return useMemo(() => {
    if (!activeCaseId) return EMPTY_FACTS;
    return {
      evidenceTotal: evidence.length,
      evidenceVerified: evidence.filter((e) => e.last_verification !== null).length,
      findings: counts.findings,
      documents: counts.documents,
      loaded: evidencePhase === "ready",
    };
  }, [activeCaseId, evidence, evidencePhase, counts]);
}
