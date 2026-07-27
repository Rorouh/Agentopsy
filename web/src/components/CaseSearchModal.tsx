import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api/client";
import type { Case } from "../api/types";
import { Modal } from "../ui/Modal";
import { ErrorState } from "../ui/ErrorState";
import { formatDate } from "../utils/format";
import { Pagination } from "./Pagination";

const CASE_PAGE_SIZE = 8;

type CaseFilter = "all" | "active" | "closed";
type CaseSort = "recent" | "oldest" | "name-asc" | "name-desc";
// El diálogo es a la vez buscador y administración del caso activo: el mock
// saca la gestión de casos del cuerpo de la vista y deja «cambiar caso» como
// único punto de entrada, así que editar / cerrar / eliminar viven aquí.
type Pane = "search" | "edit" | "delete";

const FILTER_LABEL: Record<CaseFilter, string> = {
  all: "Todos",
  active: "Abiertos",
  closed: "Cerrados",
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

  // Foco directo al input al abrir — es un buscador, se llega tecleando.
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

  const pick = (caseId: string) => {
    onSelect(caseId);
    onClose();
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

  const eyebrow =
    pane === "edit" ? "Caso activo" : pane === "delete" ? "Irreversible" : "Casos del servicio";
  const title =
    pane === "edit" ? "Editar caso" : pane === "delete" ? "Eliminar caso" : "Buscar casos";

  return (
    <Modal
      open={open}
      eyebrow={eyebrow}
      title={title}
      onClose={onClose}
      panelClassName="case-search-modal"
      footerHint={pane === "search" ? "esc cerrar · ↵ abrir" : "esc cerrar"}
      footer={
        pane === "edit" ? (
          <>
            <button
              type="button"
              className="modal-action"
              disabled={!editValid || busy}
              onClick={() => void saveEdit()}
            >
              {busy ? "Guardando…" : "Guardar cambios"}
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
              {busy ? "Eliminando…" : "Eliminar permanentemente"}
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
          <span className="modal-footer-count">
            {visible.length} caso{visible.length === 1 ? "" : "s"}
          </span>
        )
      }
    >
      {pane === "search" && (
        <>
          <div className="case-search-field">
            <label className="visually-hidden" htmlFor="case-search-input">
              Buscar casos
            </label>
            <input
              id="case-search-input"
              ref={inputRef}
              type="search"
              className="field-input"
              placeholder="Buscar por nombre o examinador…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>

          <div className="case-search-filters">
            <div className="tab-row tab-row--inline" role="group" aria-label="Filtrar casos por estado">
              {(Object.keys(FILTER_LABEL) as CaseFilter[]).map((f) => (
                <button
                  key={f}
                  type="button"
                  className={`toggle-link${f === filter ? " is-on" : ""}`}
                  aria-pressed={f === filter}
                  onClick={() => setFilter(f)}
                >
                  {FILTER_LABEL[f]}
                </button>
              ))}
            </div>
            <label className="visually-hidden" htmlFor="case-search-sort">
              Ordenar por
            </label>
            <select
              id="case-search-sort"
              className="field-select"
              value={sort}
              onChange={(e) => setSort(e.target.value as CaseSort)}
            >
              <option value="recent">Más reciente</option>
              <option value="oldest">Más antiguo</option>
              <option value="name-asc">Nombre A-Z</option>
              <option value="name-desc">Nombre Z-A</option>
            </select>
          </div>

          <div className="case-search-results">
            {error ? (
              <>
                <ErrorState message={error} />
                <div className="cta-row">
                  <button type="button" className="link-action" onClick={onRetry}>
                    Reintentar
                  </button>
                </div>
              </>
            ) : cases.length === 0 ? (
              <div className="empty-rail">
                <div className="empty-rail-title">Aún no hay casos</div>
                <div className="empty-rail-body">
                  Pulsa «Nuevo caso» en el lateral para abrir el primero. Sin caso no hay
                  dónde registrar evidencia.
                </div>
              </div>
            ) : visible.length === 0 ? (
              <div className="empty-rail">
                <div className="empty-rail-title">Sin resultados</div>
                <div className="empty-rail-body">
                  {query.trim()
                    ? `Ningún caso coincide con «${query.trim()}».`
                    : "Ningún caso coincide con el filtro."}
                </div>
              </div>
            ) : (
              <div className="case-rows">
                {pageItems.map((c) => (
                  <button
                    key={c.id}
                    type="button"
                    className={`case-row${c.id === activeCaseId ? " is-active" : ""}`}
                    aria-current={c.id === activeCaseId ? "true" : undefined}
                    onClick={() => pick(c.id)}
                  >
                    <span className="case-row-main">
                      <span className="case-row-name">{c.name}</span>
                      <span className="case-row-meta">
                        {c.examiner} · {formatDate(c.created_at)}
                      </span>
                    </span>
                    <span
                      className={`tag${c.status === "active" ? " tag--ok" : " tag--muted"}`}
                    >
                      {c.status === "active" ? "abierto" : "cerrado"}
                    </span>
                  </button>
                ))}
              </div>
            )}
            {!error && <Pagination page={safePage} pageCount={pageCount} onPage={setPage} />}
          </div>

          {activeCase && (
            <div className="case-admin">
              <div className="rule-label">
                <span className="eyebrow">Caso activo</span>
                <span className="rule" />
              </div>
              <div className="case-admin-name">{activeCase.name}</div>
              <div className="case-admin-actions">
                <button type="button" className="link-action" disabled={busy} onClick={startEdit}>
                  Editar
                </button>
                <button
                  type="button"
                  className="link-action"
                  disabled={busy}
                  onClick={() => void toggleClosed()}
                >
                  {activeCase.status === "active" ? "Cerrar caso" : "Reabrir caso"}
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
                  Eliminar
                </button>
              </div>
              {actionError && (
                <div className="error-state">
                  <strong>No se pudo completar la acción:</strong> {actionError}
                </div>
              )}
            </div>
          )}
        </>
      )}

      {pane === "edit" && activeCase && (
        <div className="modal-form">
          <div className="field">
            <label className="eyebrow" htmlFor="edit-case-name">
              Nombre del caso
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
              Examinador
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
              Descripción · notas <span className="field-optional">opcional</span>
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
          <div className="note-rail">
            El perfil de sistema operativo no se edita aquí: lo deriva el orquestador del
            contenido de la evidencia registrada.
          </div>
          {actionError && (
            <div className="error-state">
              <strong>No se pudo guardar:</strong> {actionError}
            </div>
          )}
        </div>
      )}

      {pane === "delete" && activeCase && (
        <div className="modal-form">
          <div className="danger-notice">
            <strong>Esta acción es irreversible.</strong> Se borrará de forma PERMANENTE todo
            el caso «{activeCase.name}» y con él su cadena de custodia completa: las copias de
            evidencia registradas, el log de auditoría hash-encadenado, los hallazgos, los
            artefactos, los chats y los informes. No hay papelera ni deshacer.
          </div>
          <div className="field">
            <label className="eyebrow" htmlFor="delete-case-confirm">
              Escribe «{activeCase.name}» para confirmar
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
              <strong>No se pudo eliminar el caso:</strong> {actionError}
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}
