import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { Case } from "../api/types";
import { Modal } from "../ui/Modal";
import { useT } from "../i18n";

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
  const t = useT();
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
      eyebrow={t("newCase.eyebrow")}
      title={t("newCase.title")}
      onClose={onClose}
      footerHint={t("newCase.enterToSave")}
      footer={
        <>
          <button
            type="button"
            className="modal-action"
            disabled={!valid || creating}
            onClick={() => void submit()}
          >
            {creating ? t("newCase.saving") : t("newCase.save")}
          </button>
          <button
            type="button"
            className="modal-action modal-action--quiet"
            disabled={creating}
            onClick={onClose}
          >
            {t("common.cancel")}
          </button>
        </>
      }
    >
      <div className="modal-form">
        <div className="field">
          <label className="eyebrow" htmlFor="nc-name">
            {t("newCase.name")}
          </label>
          <input
            id="nc-name"
            className="field-input"
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            maxLength={200}
            placeholder={t("newCase.namePlaceholder")}
            autoFocus
          />
        </div>

        <div className="field">
          <label className="eyebrow" htmlFor="nc-examiner">
            {t("newCase.examiner")}
          </label>
          <input
            id="nc-examiner"
            className="field-input"
            value={form.examiner}
            onChange={(e) => setForm({ ...form, examiner: e.target.value })}
            maxLength={200}
            placeholder={t("newCase.examinerPlaceholder")}
          />
          <div className="field-hint">{t("newCase.examinerHint")}</div>
        </div>

        <div className="field">
          <label className="eyebrow" htmlFor="nc-notes">
            {t("newCase.notes")} <span className="field-optional">{t("newCase.optional")}</span>
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
            placeholder={t("newCase.notesPlaceholder")}
          />
        </div>

        {/* El aviso de que aquí no se elige el perfil de SO se retira: el
            formulario no ofrece ese campo, así que explicaba la ausencia de algo
            que nadie echa en falta. Donde el perfil SÍ es una pregunta abierta
            (triage no concluyente) se dice en Evidencia, junto a la huella que
            lo justifica. */}
        {error && (
          <div className="error-state">
            <strong>{t("newCase.failed")}</strong> {error}
          </div>
        )}
      </div>
    </Modal>
  );
}
