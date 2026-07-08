import { useEffect, useRef, useState } from "react";
import type { Case } from "../api/types";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { formatDate } from "../utils/format";

interface ActiveCaseHeaderProps {
  c: Case;
  busy: boolean;
  // Presente solo cuando la página recibió onNavigate (navegación por ViewId).
  onInvestigate?: () => void;
  onEdit: () => void;
  // Abre el Modal de confirmación de cierre (vive en la página, no aquí).
  onRequestClose: () => void;
  onReopen: () => void;
}

// Header compacto del caso activo: identidad en 2 líneas + acciones. La
// acción primaria es Investigar; cerrar queda detrás del menú «Más» porque
// es infrecuente y pide confirmación.
export function ActiveCaseHeader({
  c,
  busy,
  onInvestigate,
  onEdit,
  onRequestClose,
  onReopen,
}: ActiveCaseHeaderProps) {
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!menuOpen) return;
    const onDown = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [menuOpen]);

  const closed = c.status === "closed";

  return (
    <div className="active-case-header">
      <div className="active-case-title">
        <span className="active-case-name" title={c.name}>
          {c.name}
        </span>
        <Badge variant={closed ? "neutral" : "low"}>{closed ? "Cerrado" : "Abierto"}</Badge>
      </div>
      <div className="active-case-meta">
        {c.examiner} · perfil {c.os_profile ?? "sin determinar"} · creado{" "}
        {formatDate(c.created_at)}
      </div>

      {closed ? (
        <div className="active-case-actions">
          <span className="active-case-closed-note">Este caso está cerrado.</span>
          <Button variant="primary" disabled={busy} onClick={onReopen}>
            {busy ? "Reabriendo…" : "Reabrir caso"}
          </Button>
        </div>
      ) : (
        <div className="active-case-actions">
          {onInvestigate && (
            <Button variant="primary" onClick={onInvestigate}>
              Investigar caso →
            </Button>
          )}
          <Button variant="chip" onClick={onEdit}>
            Editar
          </Button>
          <div className="context-menu-wrap" ref={menuRef}>
            <Button
              variant="chip"
              aria-haspopup="menu"
              aria-expanded={menuOpen}
              onClick={() => setMenuOpen((v) => !v)}
            >
              Más ▾
            </Button>
            {menuOpen && (
              <div className="context-menu" role="menu">
                <button
                  type="button"
                  role="menuitem"
                  className="context-menu-item"
                  disabled={busy}
                  onClick={() => {
                    setMenuOpen(false);
                    onRequestClose();
                  }}
                >
                  Cerrar caso
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {c.notes && (
        <details className="active-case-notes">
          <summary>Notas del caso</summary>
          <div className="active-case-notes-body">{c.notes}</div>
        </details>
      )}
    </div>
  );
}
