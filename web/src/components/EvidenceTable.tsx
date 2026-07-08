import { useEffect, useMemo, useState } from "react";
import type { EvidenceHandle } from "../api/types";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { EmptyState } from "../ui/EmptyState";
import { formatBytes, formatDate, shortHash } from "../utils/format";
import { DETECTED_KIND_LABEL } from "../utils/evidence";
import { Pagination } from "./Pagination";

const EVIDENCE_PAGE_SIZE = 10;
// El buscador solo aparece con listas donde de verdad ayuda.
const SEARCH_THRESHOLD = 5;

function evidenceFileName(ev: EvidenceHandle): string {
  return ev.original_path.split("/").pop() ?? ev.original_path;
}

interface EvidenceTableProps {
  evidence: EvidenceHandle[];
  verifyingIds: Set<string>;
  onVerify: (evidenceId: string) => void;
  // Mensaje del último fallo de verificación (kind "verify"), o null.
  verifyError: string | null;
}

// Tabla semántica de evidencias registradas, con búsqueda y paginación
// client-side. La verificación (re-hash) es por fila y asíncrona.
export function EvidenceTable({ evidence, verifyingIds, onVerify, verifyError }: EvidenceTableProps) {
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
      <EmptyState
        title="Aún no hay evidencia registrada en este caso."
        description="Arrastra un archivo a la zona de arriba o selecciona desde la bandeja."
      />
    );
  }

  return (
    <div>
      {verifyError && (
        <div className="error-state" aria-live="polite" style={{ marginBottom: 10 }}>
          <strong>No se pudo verificar la evidencia:</strong> {verifyError}
        </div>
      )}

      {evidence.length > SEARCH_THRESHOLD && (
        <div className="form-field" style={{ marginBottom: 10 }}>
          <label className="form-label" htmlFor="evidence-search">
            Buscar evidencia
          </label>
          <input
            id="evidence-search"
            className="form-input"
            type="search"
            placeholder="Buscar evidencia…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
      )}

      {visible.length === 0 ? (
        <div className="empty-state">Sin resultados para «{query.trim()}».</div>
      ) : (
        <div className="evidence-table-wrap">
          <table className="evidence-table">
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Tipo</th>
                <th>Tamaño</th>
                <th>SHA-256</th>
                <th>Estado</th>
                <th>Fecha</th>
                <th>Acciones</th>
              </tr>
            </thead>
            <tbody>
              {pageItems.map((ev) => {
                const fileName = evidenceFileName(ev);
                const verifying = verifyingIds.has(ev.evidence_id);
                const lv = ev.last_verification;
                return (
                  <tr key={ev.evidence_id}>
                    <td>
                      <span className="evidence-table-name" title={fileName}>
                        {fileName}
                      </span>
                    </td>
                    <td>{DETECTED_KIND_LABEL[ev.detected_kind]}</td>
                    <td>{formatBytes(ev.size)}</td>
                    <td>
                      <span className="evidence-table-hash" title={ev.sha256}>
                        {shortHash(ev.sha256)}
                      </span>{" "}
                      <Button
                        variant="chip"
                        onClick={() => copyHash(ev.evidence_id, ev.sha256)}
                        title="Copiar el SHA-256 completo"
                      >
                        {copiedId === ev.evidence_id ? "Copiado" : "Copiar"}
                      </Button>
                    </td>
                    <td>
                      {verifying ? (
                        <Badge variant="medium">Verificando…</Badge>
                      ) : lv === null ? (
                        <Badge variant="neutral">Sin verificar</Badge>
                      ) : lv.verified ? (
                        <Badge variant="success">✓ Verificada</Badge>
                      ) : (
                        <Badge variant="critical">⚠ Hash MISMATCH</Badge>
                      )}
                    </td>
                    <td>{formatDate(ev.registered_at)}</td>
                    <td>
                      <Button
                        variant="chip"
                        disabled={verifying}
                        onClick={() => onVerify(ev.evidence_id)}
                      >
                        {verifying
                          ? "Verificando…"
                          : lv
                            ? "Re-verificar"
                            : "Verificar ahora"}
                      </Button>
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
    </div>
  );
}
