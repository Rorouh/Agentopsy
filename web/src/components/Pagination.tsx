import { Button } from "../ui/Button";

interface PaginationProps {
  page: number; // 1-based
  pageCount: number;
  onPage: (page: number) => void;
}

// Paginador client-side compartido (casos y evidencias). Se oculta solo
// cuando no hay nada que paginar.
export function Pagination({ page, pageCount, onPage }: PaginationProps) {
  if (pageCount <= 1) return null;
  return (
    <div className="pagination-row">
      <Button variant="chip" disabled={page <= 1} onClick={() => onPage(page - 1)}>
        ‹ Anterior
      </Button>
      <span className="pagination-label">
        {page} / {pageCount}
      </span>
      <Button variant="chip" disabled={page >= pageCount} onClick={() => onPage(page + 1)}>
        Siguiente ›
      </Button>
    </div>
  );
}
