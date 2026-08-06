import { useEffect, useMemo, useState } from "react";
import type { EvidenceHandle } from "../api/types";
import { formatBytes, shortHash } from "../utils/format";
import { DETECTED_KIND_LABEL } from "../utils/evidence";
import { Pagination } from "./Pagination";

const EVIDENCE_PAGE_SIZE = 10;
// El buscador solo aparece con listas donde de verdad ayuda.
const SEARCH_THRESHOLD = 5;

// Columnas del mock. La fecha de registro no está: vive en el acta de
// adquisición, que es su sitio de custodia.
const COLUMNS = ["Fichero", "Tipo", "Tamaño", "SHA-256", "Integridad", ""];

function evidenceFileName(ev: EvidenceHandle): string {
  return ev.original_path.split("/").pop() ?? ev.original_path;
}

// Cuántos ficheros respaldan la evidencia, cuando es más de uno. Un EWF partido se
// registra como UNA evidencia a partir del .E01, así que sin esto la tabla enseñaba
// el nombre y el tamaño del primer segmento y no había forma de comprobar que el
// conjunto entero entró.
function segmentNote(ev: EvidenceHandle): string | null {
  if (ev.segment_count <= 1) return null;
  return `${ev.segment_count} segmentos`;
}

interface EvidenceTableProps {
  evidence: EvidenceHandle[];
  verifyingIds: Set<string>;
  onVerify: (evidenceId: string) => void;
  // Mensaje del último fallo de verificación (kind "verify"), o null.
  verifyError: string | null;
}

// Tabla de evidencias registradas, con búsqueda y paginación client-side. La
// verificación (re-hash) es por fila y asíncrona.
export function EvidenceTable({
  evidence,
  verifyingIds,
  onVerify,
  verifyError,
}: EvidenceTableProps) {
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    setPage(1);
  }, [query]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return evidence;
    return evidence.filter((ev) => evidenceFileName(ev).toLowerCase().includes(q));
  }, [evidence, query]);

  const pageCount = Math.max(1, Math.ceil(visible.length / EVIDENCE_PAGE_SIZE));
  const safePage = Math.min(page, pageCount);
  const pageItems = visible.slice(
    (safePage - 1) * EVIDENCE_PAGE_SIZE,
    safePage * EVIDENCE_PAGE_SIZE,
  );

  const copyHash = async (evidenceId: string, sha256: string) => {
    try {
      await navigator.clipboard.writeText(sha256);
      setCopiedId(evidenceId);
      window.setTimeout(() => {
        setCopiedId((prev) => (prev === evidenceId ? null : prev));
      }, 1500);
    } catch {
      /* clipboard no disponible: el title de la celda ya expone el hash completo */
    }
  };

  if (evidence.length === 0) {
    return (
      <div className="empty-rail">
        <div className="empty-rail-title">Sin evidencia registrada</div>
        <div className="empty-rail-body">
          Arrastra la imagen forense a la zona de arriba o elígela de la bandeja. Nada llega a
          una herramienta antes de que exista su hash baseline.
        </div>
      </div>
    );
  }

  return (
    <>
      {verifyError && (
        <div className="error-state" aria-live="polite">
          <strong>No se pudo verificar la evidencia:</strong> {verifyError}
        </div>
      )}

      {evidence.length > SEARCH_THRESHOLD && (
        <div className="field">
          <label className="visually-hidden" htmlFor="evidence-search">
            Buscar evidencia
          </label>
          <input
            id="evidence-search"
            className="field-input field-input--sm"
            type="search"
            placeholder="Buscar por nombre de fichero…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
      )}

      {visible.length === 0 ? (
        <div className="inline-note">Ningún fichero coincide con «{query.trim()}».</div>
      ) : (
        <div className="table-scroll">
          <table className="data-table data-table--evidence">
            <thead>
              <tr>
                {COLUMNS.map((c, i) => (
                  <th key={c || `col-${i}`}>{c}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {pageItems.map((ev) => {
                const fileName = evidenceFileName(ev);
                const segments = segmentNote(ev);
                const verifying = verifyingIds.has(ev.evidence_id);
                const lv = ev.last_verification;
                return (
                  <tr key={ev.evidence_id}>
                    <td className="cell-mono" title={fileName}>
                      {fileName}
                      {segments && <span className="cell-note">{segments}</span>}
                    </td>
                    <td className="cell-text">{DETECTED_KIND_LABEL[ev.detected_kind]}</td>
                    {/* El tamaño del CONJUNTO. En un set EWF, `size` es solo el
                        primer segmento (es lo que cubre el hash baseline). */}
                    <td className="cell-mono">
                      {formatBytes(ev.total_size)}
                      {segments && (
                        <span className="cell-note">
                          {formatBytes(ev.size)} el primer segmento
                        </span>
                      )}
                    </td>
                    <td className="cell-dim">
                      <button
                        type="button"
                        className={`hash-copy${copiedId === ev.evidence_id ? " is-copied" : ""}`}
                        onClick={() => copyHash(ev.evidence_id, ev.sha256)}
                        title={`${ev.sha256}\n\nClic para copiar el SHA-256 completo`}
                        aria-label="Copiar el SHA-256 completo"
                      >
                        <span>{shortHash(ev.sha256)}</span>
                        <span className="hash-copy-icon" aria-hidden="true">
                          {copiedId === ev.evidence_id ? "✓" : "⧉"}
                        </span>
                      </button>
                    </td>
                    <td>
                      {verifying ? (
                        <span className="tag tag--muted">verificando…</span>
                      ) : lv === null ? (
                        <span className="tag tag--accent">sin verificar</span>
                      ) : lv.verified ? (
                        <span className="tag tag--ok">✓ verificada</span>
                      ) : (
                        <span className="tag tag--danger">⚠ hash mismatch</span>
                      )}
                    </td>
                    <td>
                      <button
                        type="button"
                        className="link-action"
                        disabled={verifying}
                        onClick={() => onVerify(ev.evidence_id)}
                      >
                        {verifying ? "Verificando…" : lv ? "Re-verificar" : "Verificar ahora"}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {visible.length > EVIDENCE_PAGE_SIZE && (
        <Pagination page={safePage} pageCount={pageCount} onPage={setPage} />
      )}
    </>
  );
}
