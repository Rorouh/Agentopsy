import { useEffect, useState } from "react";
import { api } from "../api/client";
import { useActiveCase } from "./activeCase";

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
  const [facts, setFacts] = useState<CaseFacts>(EMPTY_FACTS);

  useEffect(() => {
    let cancelled = false;
    if (!activeCaseId) {
      setFacts(EMPTY_FACTS);
      return;
    }
    (async () => {
      // Cualquier fallo deja la cifra a cero y `loaded` en true solo si las tres
      // lecturas respondieron: media verdad es peor que ninguna.
      const [evidence, findings, documents] = await Promise.all([
        api.cases.listEvidence(activeCaseId).catch(() => null),
        api.cases.listFindings(activeCaseId).catch(() => null),
        api.cases.listDocuments(activeCaseId).catch(() => null),
      ]);
      if (cancelled) return;
      setFacts({
        evidenceTotal: evidence?.length ?? 0,
        evidenceVerified: evidence?.filter((e) => e.last_verification !== null).length ?? 0,
        findings: findings?.length ?? 0,
        documents: documents?.length ?? 0,
        loaded: evidence !== null,
      });
    })();
    return () => {
      cancelled = true;
    };
  }, [activeCaseId]);

  return facts;
}
