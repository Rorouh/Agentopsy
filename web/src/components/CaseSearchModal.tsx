import { useEffect, useMemo, useRef, useState } from "react";
import type { KeyboardEvent } from "react";
import { api } from "../api/client";
import type { Case } from "../api/types";
import { Modal } from "../ui/Modal";
import { ErrorState } from "../ui/ErrorState";
import { useFormat } from "../utils/format";
import { useLang, type MessageKey } from "../i18n";
import { Pagination } from "./Pagination";

const CASE_PAGE_SIZE = 8;

type CaseFilter = "all" | "active" | "closed";
type CaseSort = "recent" | "oldest" | "name-asc" | "name-desc";
// El diálogo es a la vez buscador y administración del caso activo: el mock
// saca la gestión de casos del cuerpo de la vista y deja «cambiar caso» como
// único punto de entrada, así que editar / cerrar / eliminar viven aquí.
type Pane = "search" | "edit" | "delete";

const FILTER_KEY: Record<CaseFilter, MessageKey> = {
  all: "caseSearch.filter.all",
  active: "caseSearch.filter.active",
  closed: "caseSearch.filter.closed",
};

interface CaseSearchModalProps {
  open: boolean;
  onClose: () => void;
  cases: Case[];
  activeCaseId: string | null;
  onSelect: (caseId: string) => void;
  // Error del listado de casos (phase "error" del store) + su retry.
  error: string | null;
  onRetry: () => void;
  // Un caso modificado (editado, cerrado, reabierto) vuelve al store sin pagar
  // otra vuelta al api; un borrado obliga a recargar la lista entera.
  onCaseUpdated: (c: Case) => void;
  onCaseDeleted: () => void | Promise<void>;
}

// Buscador de casos estilo command-palette: búsqueda + filtros + orden +
// paginación, todo client-side sobre el array ya cargado (no existe
// search/filter/paginate en el backend).
export function CaseSearchModal({
  open,
  onClose,
  cases,
  activeCaseId,
  onSelect,
  error,
  onRetry,
  onCaseUpdated,
  onCaseDeleted,
}: CaseSearchModalProps) {
  const { t, tn } = useLang();
  const { formatDate } = useFormat();
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<CaseFilter>("all");
  const [sort, setSort] = useState<CaseSort>("recent");
  const [page, setPage] = useState(1);
  const [pane, setPane] = useState<Pane>("search");
  const inputRef = useRef<HTMLInputElement>(null);

  const [editForm, setEditForm] = useState({ name: "", examiner: "", notes: "" });
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  // Borrado PERMANENTE: el operador escribe el nombre exacto. El backend
  // re-valida `confirm_name` (RULE 2) y responde 409 si no cuadra, sin borrar.
  const [deleteConfirmName, setDeleteConfirmName] = useState("");

  const activeCase = useMemo(
    () => cases.find((c) => c.id === activeCaseId) ?? null,
    [cases, activeCaseId],
  );

  // Foco directo al input al abrir, es un buscador, se llega tecleando.
  // Cada apertura vuelve al panel de búsqueda: nadie espera reencontrarse con
  // el formulario de borrado a medio escribir.
  useEffect(() => {
    if (!open) return;
    setPane("search");
    setActionError(null);
    setDeleteConfirmName("");
    inputRef.current?.focus();
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

  // Pulsar una fila SELECCIONA y el diálogo SIGUE ABIERTO. Es a la vez buscador
  // y administración: si cerrase al primer clic, editar o cerrar el caso que
  // acabas de elegir obligaría a reabrirlo. Cerrar es explícito: Esc, la ×, o
  // Intro sobre la fila del cursor, que es lo que el pie viene anunciando.
  const pick = (caseId: string) => {
    onSelect(caseId);
  };

  const pickAndClose = (caseId: string) => {
    onSelect(caseId);
    onClose();
  };

  // Cursor de teclado. Vive sobre `visible` (la lista filtrada y ordenada), no
  // sobre la página, para que bajar más allá del último de la página avance de
  // página en vez de topar contra un muro.
  const [cursor, setCursor] = useState(0);
  // El cursor SÓLO se pinta si estás navegando con el teclado. Si no, la primera
  // fila aparecería resaltada nada más abrir, indistinguible de un hover pegado
  // o de una selección que nadie ha hecho.
  const [keyboardNav, setKeyboardNav] = useState(false);
  useEffect(() => {
    setCursor(0);
    setKeyboardNav(false);
  }, [query, filter, sort, open]);
  // Mantener el cursor dentro de la página que se está viendo.
  useEffect(() => {
    const target = Math.floor(cursor / CASE_PAGE_SIZE) + 1;
    setPage((p) => (p === target ? p : target));
  }, [cursor]);

  const onListKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (pane !== "search" || visible.length === 0) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setKeyboardNav(true);
      setCursor((i) => Math.min(i + 1, visible.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setKeyboardNav(true);
      setCursor((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const target = visible[cursor];
      if (target) pickAndClose(target.id);
    }
  };

  const startEdit = () => {
    if (!activeCase) return;
    setEditForm({
      name: activeCase.name,
      examiner: activeCase.examiner,
      notes: activeCase.notes,
    });
    setActionError(null);
    setPane("edit");
  };

  const editValid =
    editForm.name.trim().length > 0 &&
    editForm.name.trim().length <= 200 &&
    editForm.examiner.trim().length > 0 &&
    editForm.examiner.trim().length <= 200;

  const saveEdit = async () => {
    if (!activeCase || !editValid) return;
    setBusy(true);
    setActionError(null);
    try {
      const updated = await api.cases.update(activeCase.id, {
        name: editForm.name.trim(),
        examiner: editForm.examiner.trim(),
        notes: editForm.notes.trim(),
      });
      onCaseUpdated(updated);
      setPane("search");
    } catch (err) {
      setActionError(String(err instanceof Error ? err.message : err));
    } finally {
      setBusy(false);
    }
  };

  const toggleClosed = async () => {
    if (!activeCase) return;
    setBusy(true);
    setActionError(null);
    try {
      const updated =
        activeCase.status === "active"
          ? await api.cases.close(activeCase.id)
          : await api.cases.reopen(activeCase.id);
      onCaseUpdated(updated);
    } catch (err) {
      setActionError(String(err instanceof Error ? err.message : err));
    } finally {
      setBusy(false);
    }
  };

  const deleteCase = async () => {
    if (!activeCase) return;
    setBusy(true);
    setActionError(null);
    try {
      await api.cases.delete(activeCase.id, deleteConfirmName);
      setDeleteConfirmName("");
      setPane("search");
      await onCaseDeleted();
    } catch (err) {
      setActionError(String(err instanceof Error ? err.message : err));
    } finally {
      setBusy(false);
    }
  };

  const eyebrow = t(
    pane === "edit"
      ? "caseSearch.eyebrow.edit"
      : pane === "delete"
        ? "caseSearch.eyebrow.delete"
        : "caseSearch.eyebrow.list",
  );
  const title = t(
    pane === "edit"
      ? "caseSearch.title.edit"
      : pane === "delete"
        ? "caseSearch.title.delete"
        : "caseSearch.title.list",
  );

  return (
    <Modal
      open={open}
      eyebrow={eyebrow}
      title={title}
      onClose={onClose}
      panelClassName="case-search-modal"
      footerHint={t(pane === "search" ? "caseSearch.hint.list" : "caseSearch.hint.other")}
      footer={
        pane === "edit" ? (
          <>
            <button
              type="button"
              className="modal-action"
              disabled={!editValid || busy}
              onClick={() => void saveEdit()}
            >
              {busy ? t("newCase.saving") : t("caseSearch.saveChanges")}
            </button>
            <button
              type="button"
              className="modal-action modal-action--quiet"
              disabled={busy}
              onClick={() => setPane("search")}
            >
              Cancelar
            </button>
          </>
        ) : pane === "delete" ? (
          <>
            <button
              type="button"
              className="modal-action modal-action--danger"
              // Habilitado solo con el nombre EXACTO; el backend lo re-valida.
              disabled={busy || deleteConfirmName !== (activeCase?.name ?? "")}
              onClick={() => void deleteCase()}
            >
              {busy ? t("caseSearch.deleting") : t("caseSearch.deleteForever")}
            </button>
            <button
              type="button"
              className="modal-action modal-action--quiet"
              disabled={busy}
              onClick={() => setPane("search")}
            >
              Cancelar
            </button>
          </>
        ) : (
          <span className="modal-footer-count">{tn("count.cases", visible.length)}</span>
        )
      }
    >
      {pane === "search" && (
        // El teclado se escucha en TODO el panel, no sólo en el input: bajar por
        // la lista tiene que seguir funcionando después de pulsar un filtro.
        <div onKeyDown={onListKeyDown}>
          <div className="case-search-field">
            <label className="visually-hidden" htmlFor="case-search-input">
              {t("caseSearch.label")}
            </label>
            <input
              id="case-search-input"
              ref={inputRef}
              type="search"
              className="field-input"
              placeholder={t("caseSearch.placeholder")}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>

          <div className="case-search-filters">
            <div className="tab-row tab-row--inline" role="group" aria-label={t("caseSearch.filterGroup")}>
              {(Object.keys(FILTER_KEY) as CaseFilter[]).map((f) => (
                <button
                  key={f}
                  type="button"
                  className={`toggle-link${f === filter ? " is-on" : ""}`}
                  aria-pressed={f === filter}
                  onClick={() => setFilter(f)}
                >
                  {t(FILTER_KEY[f])}
                </button>
              ))}
            </div>
            <label className="visually-hidden" htmlFor="case-search-sort">
              {t("caseSearch.sortLabel")}
            </label>
            <select
              id="case-search-sort"
              className="field-select"
              value={sort}
              onChange={(e) => setSort(e.target.value as CaseSort)}
            >
              <option value="recent">{t("caseSearch.sort.recent")}</option>
              <option value="oldest">{t("caseSearch.sort.oldest")}</option>
              <option value="name-asc">{t("caseSearch.sort.nameAsc")}</option>
              <option value="name-desc">{t("caseSearch.sort.nameDesc")}</option>
            </select>
          </div>

          <div className="case-search-results">
            {error ? (
              <>
                <ErrorState message={error} />
                <div className="cta-row">
                  <button type="button" className="link-action" onClick={onRetry}>
                    {t("common.retry")}
                  </button>
                </div>
              </>
            ) : cases.length === 0 ? (
              <div className="empty-rail">
                <div className="empty-rail-title">{t("caseSearch.emptyTitle")}</div>
                <div className="empty-rail-body">{t("caseSearch.emptyBody")}</div>
              </div>
            ) : visible.length === 0 ? (
              <div className="empty-rail">
                <div className="empty-rail-title">{t("caseSearch.noResults")}</div>
                <div className="empty-rail-body">
                  {query.trim()
                    ? t("caseSearch.noMatchQuery", { query: query.trim() })
                    : t("caseSearch.noMatchFilter")}
                </div>
              </div>
            ) : (
              <div className="case-rows">
                {pageItems.map((c, i) => {
                  const isActive = c.id === activeCaseId;
                  const isCursor = (safePage - 1) * CASE_PAGE_SIZE + i === cursor;
                  return (
                    // La fila NO es un <button>: la del caso activo contiene sus
                    // propias acciones, y anidar botones es HTML inválido.
                    <div
                      key={c.id}
                      role="option"
                      aria-selected={isActive}
                      tabIndex={-1}
                      className={`case-row${isActive ? " is-active" : ""}${
                        isCursor && keyboardNav ? " is-cursor" : ""
                      }${c.status === "closed" ? " is-closed" : ""}`}
                      // Tocar la lista con el ratón devuelve el mando al puntero:
                      // el hover pasa a ser la única marca de «dónde estoy».
                      onMouseEnter={() => keyboardNav && setKeyboardNav(false)}
                      onClick={() => pick(c.id)}
                    >
                      <span className="case-row-main">
                        <span className="case-row-name">{c.name}</span>
                        <span className="case-row-meta">
                          {c.examiner} · {formatDate(c.created_at)}
                        </span>
                      </span>

                      {isActive ? (
                        // Las acciones del caso viven EN su fila: actúan sobre lo
                        // que estás mirando, y no hay que bajar a un bloque al pie
                        // que repite el nombre.
                        <span
                          className="case-row-actions"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <button
                            type="button"
                            className="link-action"
                            disabled={busy}
                            onClick={startEdit}
                          >
                            {t("caseSearch.edit")}
                          </button>
                          <button
                            type="button"
                            className="link-action"
                            disabled={busy}
                            onClick={() => void toggleClosed()}
                          >
                            {t(c.status === "active" ? "caseSearch.close" : "caseSearch.reopen")}
                          </button>
                          <button
                            type="button"
                            className="link-action link-action--danger"
                            disabled={busy}
                            onClick={() => {
                              setDeleteConfirmName("");
                              setActionError(null);
                              setPane("delete");
                            }}
                          >
                            {t("common.delete")}
                          </button>
                        </span>
                      ) : (
                        <span
                          className={`tag${c.status === "active" ? " tag--ok" : " tag--muted"}`}
                        >
                          {t(c.status === "active" ? "case.status.active" : "case.status.closed")}
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
            {!error && <Pagination page={safePage} pageCount={pageCount} onPage={setPage} />}
          </div>

          {/* El bloque «Caso activo» que vivía aquí repetía el nombre y dejaba
              sus acciones bajo el pliegue. Ahora están en la propia fila; sólo
              queda el error, que no pertenece a ninguna fila concreta. */}
          {activeCase && actionError && (
            <div className="error-state">
              <strong>{t("caseSearch.actionFailed")}</strong> {actionError}
            </div>
          )}
        </div>
      )}

      {pane === "edit" && activeCase && (
        <div className="modal-form">
          <div className="field">
            <label className="eyebrow" htmlFor="edit-case-name">
              {t("newCase.name")}
            </label>
            <input
              id="edit-case-name"
              className="field-input"
              value={editForm.name}
              onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
              maxLength={200}
              autoFocus
            />
          </div>
          <div className="field">
            <label className="eyebrow" htmlFor="edit-case-examiner">
              {t("newCase.examiner")}
            </label>
            <input
              id="edit-case-examiner"
              className="field-input"
              value={editForm.examiner}
              onChange={(e) => setEditForm({ ...editForm, examiner: e.target.value })}
              maxLength={200}
            />
          </div>
          <div className="field">
            <label className="eyebrow" htmlFor="edit-case-notes">
              {t("newCase.notes")} <span className="field-optional">{t("newCase.optional")}</span>
            </label>
            <textarea
              id="edit-case-notes"
              className="field-textarea"
              rows={3}
              value={editForm.notes}
              onChange={(e) => setEditForm({ ...editForm, notes: e.target.value })}
            />
          </div>
          {/* El os_profile no se edita: lo deriva el triage de la evidencia. */}
          <div className="note-rail">{t("caseSearch.osNotEditable")}</div>
          {actionError && (
            <div className="error-state">
              <strong>{t("caseSearch.saveFailed")}</strong> {actionError}
            </div>
          )}
        </div>
      )}

      {pane === "delete" && activeCase && (
        <div className="modal-form">
          <div className="danger-notice">
            <strong>{t("caseSearch.dangerLead")}</strong>{" "}
            {t("caseSearch.dangerBody", { name: activeCase.name })}
          </div>
          <div className="field">
            <label className="eyebrow" htmlFor="delete-case-confirm">
              {t("caseSearch.typeToConfirm", { name: activeCase.name })}
            </label>
            <input
              id="delete-case-confirm"
              className="field-input"
              value={deleteConfirmName}
              onChange={(e) => setDeleteConfirmName(e.target.value)}
              placeholder={activeCase.name}
              autoComplete="off"
              autoFocus
            />
          </div>
          {actionError && (
            <div className="error-state">
              <strong>{t("caseSearch.deleteFailed")}</strong> {actionError}
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}
