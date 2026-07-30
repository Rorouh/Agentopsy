import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { Case } from "../api/types";
import { Modal } from "../ui/Modal";

interface NewCaseModalProps {
  open: boolean;
  onClose: () => void;
  // El caso creado sube al armazón, que lo activa y encadena con el paso
  // siguiente del flujo: registrar evidencia.
  onCreated: (c: Case) => void;
}

interface FormState {
  name: string;
  examiner: string;
  notes: string;
}

const EMPTY_FORM: FormState = { name: "", examiner: "", notes: "" };

// Alta de caso. El mock la saca del cuerpo de la vista y la convierte en el
// diálogo que abre el botón en píldora del sidebar, disponible desde cualquier
// pantalla.
export function NewCaseModal({ open, onClose, onCreated }: NewCaseModalProps) {
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Cada apertura empieza en limpio: un borrador heredado de la vez anterior
  // se guardaría sin que nadie lo hubiera revisado.
  useEffect(() => {
    if (open) {
      setForm(EMPTY_FORM);
      setError(null);
    }
  }, [open]);

  const valid =
    form.name.trim().length > 0 &&
    form.name.trim().length <= 200 &&
    form.examiner.trim().length > 0 &&
    form.examiner.trim().length <= 200;

  const submit = async () => {
    if (!valid || creating) return;
    setCreating(true);
    setError(null);
    try {
      // os_profile se omite a propósito, lo deriva el orquestador del
      // contenido de la evidencia al registrarla (RULE 2: no se adivina).
      const created = await api.cases.create({
        name: form.name.trim(),
        examiner: form.examiner.trim(),
        notes: form.notes.trim(),
      });
      onCreated(created);
      onClose();
    } catch (err) {
      setError(String(err instanceof Error ? err.message : err));
    } finally {
      setCreating(false);
    }
  };

  return (
    <Modal
      open={open}
      eyebrow="Fase 1 · antes de tocar evidencia"
      title="Abrir caso nuevo"
      onClose={onClose}
      footerHint="enter para guardar"
      footer={
        <>
          <button
            type="button"
            className="modal-action"
            disabled={!valid || creating}
            onClick={() => void submit()}
          >
            {creating ? "Guardando…" : "Guardar caso"}
          </button>
          <button
            type="button"
            className="modal-action modal-action--quiet"
            disabled={creating}
            onClick={onClose}
          >
            Cancelar
          </button>
        </>
      }
    >
      <div className="modal-form">
        <div className="field">
          <label className="eyebrow" htmlFor="nc-name">
            Nombre del caso
          </label>
          <input
            id="nc-name"
            className="field-input"
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            maxLength={200}
            placeholder="Nombre o referencia del caso"
            autoFocus
          />
        </div>

        <div className="field">
          <label className="eyebrow" htmlFor="nc-examiner">
            Examinador
          </label>
          <input
            id="nc-examiner"
            className="field-input"
            value={form.examiner}
            onChange={(e) => setForm({ ...form, examiner: e.target.value })}
            maxLength={200}
            placeholder="Nombre completo"
          />
          <div className="field-hint">
            Responsable del caso. Figura en el acta de adquisición y en el informe pericial.
          </div>
        </div>

        <div className="field">
          <label className="eyebrow" htmlFor="nc-notes">
            Descripción · notas <span className="field-optional">opcional</span>
          </label>
          <textarea
            id="nc-notes"
            className="field-textarea"
            rows={3}
            value={form.notes}
            onChange={(e) => setForm({ ...form, notes: e.target.value })}
            onKeyDown={(e) => {
              // Enter en el último campo = guardar (Shift+Enter para salto de
              // línea, mismo gesto que el compositor del chat).
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                void submit();
              }
            }}
            placeholder="Descripción breve del caso"
          />
        </div>

        {/* RULE 2 dicha al usuario: aquí no se elige el perfil de SO. */}
        <div className="note-rail">
          El perfil de sistema operativo no se elige aquí: el orquestador lo deriva del
          contenido de la evidencia al registrarla. Agentopsy no lo adivina por ti.
        </div>

        {error && (
          <div className="error-state">
            <strong>No se pudo crear el caso:</strong> {error}
          </div>
        )}
      </div>
    </Modal>
  );
}
