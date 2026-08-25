import { useT } from "../i18n";

interface PaginationProps {
  page: number; // 1-based
  pageCount: number;
  onPage: (page: number) => void;
}

// Paginador client-side compartido (casos y evidencias). El mock no la dibuja
// sus listas son de tres filas, pero los volúmenes reales la necesitan; se
// oculta sola cuando no hay nada que paginar.
export function Pagination({ page, pageCount, onPage }: PaginationProps) {
  const t = useT();
  if (pageCount <= 1) return null;
  return (
    <div className="pager">
      <button
        type="button"
        className="pager-btn"
        disabled={page <= 1}
        onClick={() => onPage(page - 1)}
        aria-label={t("ui.prevPage")}
      >
        ‹
      </button>
      <span className="pager-info">
        {page} / {pageCount}
      </span>
      <button
        type="button"
        className="pager-btn"
        disabled={page >= pageCount}
        onClick={() => onPage(page + 1)}
        aria-label={t("ui.nextPage")}
      >
        ›
      </button>
    </div>
  );
}
