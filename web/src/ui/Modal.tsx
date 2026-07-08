import { useEffect } from "react";
import type { ReactNode } from "react";

interface ModalProps {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
  // Clase extra sobre .modal-panel para variantes (p. ej. el buscador de
  // casos estilo command-palette: más ancho y con el body a sangre).
  panelClassName?: string;
}

// Diálogo mínimo: backdrop fijo + panel centrado. Cierra con click en el
// backdrop, Escape, o el botón ×. Sin createPortal — no hay ningún ancestro
// con `transform` en AppShell/index.css que rompa `position: fixed`.
export function Modal({ open, title, onClose, children, panelClassName }: ModalProps) {
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className={panelClassName ? `modal-panel ${panelClassName}` : "modal-panel"}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          <h3>{title}</h3>
          <button type="button" className="modal-close" aria-label="Cerrar" onClick={onClose}>
            ×
          </button>
        </div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}
