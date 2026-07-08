import { useEffect, useMemo, useRef, useState } from "react";
import type { Case } from "../api/types";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { ErrorState } from "../ui/ErrorState";
import { Modal } from "../ui/Modal";
import { formatDate } from "../utils/format";
import { Pagination } from "./Pagination";

const CASE_PAGE_SIZE = 8;

type CaseFilter = "all" | "active" | "closed";
type CaseSort = "recent" | "oldest" | "name-asc" | "name-desc";

const FILTER_LABEL: Record<CaseFilter, string> = {
  all: "Todos",
  active: "Abiertos",
  closed: "Cerrados",
};

// Fila de resultado — mismo tratamiento que las filas de evidencia
// (.file-row clickable/active), con Enter/Space para abrir.
function CaseRow({
  c,
  active,
  onSelect,
}: {
  c: Case;
  active: boolean;
  onSelect: () => void;
}) {
  return (
    <div
      className={`file-row file-row--clickable${active ? " file-row--active" : ""}`}
      role="button"
      tabIndex={0}
      aria-selected={active}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSelect();
        }
      }}
    >
      <div className="file-row-main">
        <div style={{ minWidth: 0 }}>
          <div className="file-row-name" title={c.name}>
            {c.name}
          </div>
          <div className="file-row-meta">
            {c.examiner} · {formatDate(c.created_at)}
          </div>
        </div>
      </div>
      <div className="file-row-side">
        <Badge variant={c.status === "active" ? "low" : "neutral"}>
          {c.status === "active" ? "Abierto" : "Cerrado"}
        </Badge>
      </div>
    </div>
  );
}

interface CaseSearchModalProps {
  open: boolean;
  onClose: () => void;
  cases: Case[];
  activeCaseId: string | null;
  onSelect: (caseId: string) => void;
  // Error del listado de casos (phase "error" en la página) + su retry.
  error: string | null;
  onRetry: () => void;
}

// Buscador de casos estilo command-palette: búsqueda + filtros + orden +
// paginación, todo client-side sobre el array ya cargado (no existe
// search/filter/paginate en el backend). Sustituye al antiguo panel lateral.
export function CaseSearchModal({
  open,
  onClose,
  cases,
  activeCaseId,
  onSelect,
  error,
  onRetry,
}: CaseSearchModalProps) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<CaseFilter>("all");
  const [sort, setSort] = useState<CaseSort>("recent");
  const [page, setPage] = useState(1);
  const inputRef = useRef<HTMLInputElement>(null);

  // Foco directo al input al abrir — es un buscador, se llega tecleando.
  useEffect(() => {
    if (open) inputRef.current?.focus();
  }, [open]);

  // Cambiar búsqueda o filtro invalida la página actual.
  useEffect(() => {
    setPage(1);
  }, [query, filter]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    const filtered = cases.filter((c) => {
      if (filter === "active" && c.status !== "active") return false;
      if (filter === "closed" && c.status !== "closed") return false;
      if (q && !c.name.toLowerCase().includes(q) && !c.examiner.toLowerCase().includes(q)) {
        return false;
      }
      return true;
    });
    const sorted = [...filtered];
    switch (sort) {
      case "recent":
        sorted.sort((a, b) => b.created_at.localeCompare(a.created_at));
        break;
      case "oldest":
        sorted.sort((a, b) => a.created_at.localeCompare(b.created_at));
        break;
      case "name-asc":
        sorted.sort((a, b) => a.name.localeCompare(b.name));
        break;
      case "name-desc":
        sorted.sort((a, b) => b.name.localeCompare(a.name));
        break;
    }
    return sorted;
  }, [cases, query, filter, sort]);

  const pageCount = Math.max(1, Math.ceil(visible.length / CASE_PAGE_SIZE));
  const safePage = Math.min(page, pageCount);
  const pageItems = visible.slice((safePage - 1) * CASE_PAGE_SIZE, safePage * CASE_PAGE_SIZE);

  const pick = (caseId: string) => {
    onSelect(caseId);
    onClose();
  };

  return (
    <Modal open={open} title="Buscar casos" onClose={onClose} panelClassName="case-search-modal">
      <div className="case-search-modal-search">
        <span aria-hidden="true">🔍</span>
        <label className="visually-hidden" htmlFor="case-search-input">
          Buscar casos
        </label>
        <input
          id="case-search-input"
          ref={inputRef}
          type="search"
          placeholder="Buscar casos…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>

      <div className="case-search-modal-filters">
        <div className="case-filter-row" role="group" aria-label="Filtrar casos por estado">
          {(Object.keys(FILTER_LABEL) as CaseFilter[]).map((f) => (
            <Button
              key={f}
              variant="chip"
              className={f === filter ? "active" : undefined}
              aria-pressed={f === filter}
              onClick={() => setFilter(f)}
            >
              {FILTER_LABEL[f]}
            </Button>
          ))}
        </div>
        <label className="visually-hidden" htmlFor="case-search-sort">
          Ordenar por
        </label>
        <select
          id="case-search-sort"
          className="form-select"
          value={sort}
          onChange={(e) => setSort(e.target.value as CaseSort)}
        >
          <option value="recent">Más reciente</option>
          <option value="oldest">Más antiguo</option>
          <option value="name-asc">Nombre A-Z</option>
          <option value="name-desc">Nombre Z-A</option>
        </select>
      </div>

      <div className="case-search-modal-results">
        {error ? (
          <>
            <ErrorState message={error} />
            <div className="cta-row" style={{ justifyContent: "center" }}>
              <Button variant="chip" onClick={onRetry}>
                Reintentar
              </Button>
            </div>
          </>
        ) : cases.length === 0 ? (
          <div className="empty-state">
            Aún no hay casos. Pulsa «Abrir caso nuevo» para empezar.
          </div>
        ) : visible.length === 0 ? (
          <div className="empty-state">
            {query.trim() ? <>Sin resultados para «{query.trim()}».</> : "Sin resultados."}
          </div>
        ) : (
          <div className="file-list">
            {pageItems.map((c) => (
              <CaseRow
                key={c.id}
                c={c}
                active={c.id === activeCaseId}
                onSelect={() => pick(c.id)}
              />
            ))}
          </div>
        )}
        {!error && <Pagination page={safePage} pageCount={pageCount} onPage={setPage} />}
      </div>

      <div className="case-search-modal-footer">
        <span>
          {visible.length} caso{visible.length === 1 ? "" : "s"}
        </span>
        <span>ESC cerrar · ↵ abrir</span>
      </div>
    </Modal>
  );
}
