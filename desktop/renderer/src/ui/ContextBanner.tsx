import type { CaseSummary, EvidenceFile } from "../types/domain";
import { Badge } from "./Badge";
import { shortHash } from "../utils/format";

interface ContextBannerProps {
  activeCase: CaseSummary;
  activeEvidence?: EvidenceFile;
}

const CASE_STATUS_LABEL: Record<CaseSummary["status"], string> = {
  open: "Abierto",
  closed: "Cerrado",
  archived: "Archivado",
};

// Banner compartido que deja explícito que Investigación/Timeline/Documentos/
// MITRE dependen de un caso y una evidencia activos. Hoy viene de
// frontendPreviewData.ts; cuando exista selección real de caso/evidencia,
// este componente recibe esas props desde el estado real en lugar del mock.
export function ContextBanner({ activeCase, activeEvidence }: ContextBannerProps) {
  return (
    <div className="context-banner">
      <div className="context-banner-main">
        <span>
          Caso activo: <strong>{activeCase.name}</strong>
        </span>
        {activeEvidence && (
          <span className="context-banner-evidence">
            · Evidencia: <strong>{activeEvidence.name}</strong>
            {activeEvidence.sha256 && <> · SHA-256 {shortHash(activeEvidence.sha256, 8)}</>}
            {activeEvidence.osProfile && <> · {activeEvidence.osProfile}</>}
          </span>
        )}
      </div>
      <Badge variant={activeCase.status === "open" ? "success" : "neutral"}>
        {CASE_STATUS_LABEL[activeCase.status]}
      </Badge>
    </div>
  );
}
