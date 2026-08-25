import { useEffect, useRef, useState } from "react";
import type { DragEvent, KeyboardEvent } from "react";
import type { EvidenceRegisterJob, EvidenceSource } from "../api/types";
import { useFormat } from "../utils/format";
import { useT, type MessageKey } from "../i18n";
import {
  FILE_INPUT_ACCEPT_EXTENSIONS,
  IMAGE_AND_DUMP_EXTENSIONS,
  fileExtension,
  isEwfContinuationSegment,
  isRegistrableEvidence,
  isUploadableEvidence,
} from "../utils/evidence";
import { Icon } from "../ui/Icon";

interface EvidenceInboxProps {
  caseClosed: boolean;
  // null = bandeja aún no consultada; [] = consultada y vacía.
  sources: EvidenceSource[] | null;
  loadingSources: boolean;
  selectedSourcePath: string;
  registering: boolean;
  // Último estado sondeado del job de registro (fase + bytes reales), o null
  // mientras no hay ninguno. Lo gobierna la página.
  registerJob: EvidenceRegisterJob | null;
  // Mensaje del último fallo de registro (kind "register"), o null.
  registerError: string | null;
  // Sin contacto con el api mientras se sondea el registro: AVISO, no fallo. El
  // hash-gate corre en el servidor y sigue su curso.
  registerStalled: string | null;
  // Aviso tras un registro correcto: el texto ya resuelto por la página (nombra
  // cuántos segmentos y cuánto pesa el conjunto), o null si no hay ninguno.
  registerSuccess: string | null;
  // Subida (drag-and-drop / examinar): la gobierna la página.
  uploading: boolean;
  uploadProgress: number; // 0..1
  uploadError: string | null;
  // Resumen INFORMATIVO de la última subida (p. ej. segmentos que ya estaban en
  // la bandeja): no es un fallo, no se pinta en rojo.
  uploadNotice: string | null;
  onSelectSource: (path: string) => void;
  onLoadSources: () => void;
  onRegister: () => void;
  onUploadFiles: (files: File[]) => void;
}

// La lista entera pasa de cien extensiones: enumerarlas aquí sería un muro
// ilegible. Se nombran las FAMILIAS, que es lo que el perito necesita saber para
// decidir si su fichero entra, y las imágenes y volcados se enumeran porque son
// pocas y porque acertar el formato ahí sí importa.
const IMAGE_FORMATS_HINT = IMAGE_AND_DUMP_EXTENSIONS.join(" · ");
const FILE_INPUT_ACCEPT = FILE_INPUT_ACCEPT_EXTENSIONS.join(",");
// Un EWF partido se sube ENTERO (todos sus segmentos); registrar sigue siendo
// cosa del .E01, que ingiere el set completo en el backend. La frase vive en el
// catálogo (`inbox.ewfHint`); aquí sólo queda la lista de extensiones, que es
// DATO y se escribe igual en los dos idiomas.

// Fases REALES del hash-gate (backend/forensia/evidence.py PROGRESS_PHASES). El
// progreso es observacional: describe las tres pasadas que ya se hacían, no
// añade ninguna (FORENSIC INVARIANT 2).
const PHASE_KEY: Record<NonNullable<EvidenceRegisterJob["phase"]>, MessageKey> = {
  hashing: "inbox.phase.hashing",
  copying: "inbox.phase.copying",
  verifying: "inbox.phase.verifying",
};

// Compone texto, así que recibe el traductor: la función sigue siendo pura y no
// arrastra un hook a un módulo que se llama desde el render.
function registerProgressLabel(
  job: EvidenceRegisterJob | null,
  t: (k: MessageKey, p?: Record<string, string | number>) => string,
): string {
  if (!job || job.bytes_total <= 0) {
    // Aún validando (caso, ruta, conjunto EWF): no hay bytes que medir todavía.
    return t("inbox.preparing");
  }
  const pct = Math.min(100, Math.round((job.bytes_done / job.bytes_total) * 100));
  const parts = [`${pct}%`];
  if (job.seg_count > 1) {
    parts.push(t("inbox.segmentOf", { index: job.seg_index, total: job.seg_count }));
  }
  if (job.phase) parts.push(t(PHASE_KEY[job.phase]));
  return parts.join(" · ");
}

// Zona de registro de evidencia. El perito puede DEPOSITAR evidencia en la
// bandeja de dos formas: copiándola a ./evidence en el host, o SUBIÉNDOLA desde
// aquí (drag-and-drop o «Examinar», uno o VARIOS ficheros a la vez). La subida
// escribe en la bandeja (el api la monta rw, cadena de custodia: el agente/
// maletines la ven ro y nunca mutan la imagen); subir NO registra: deja los
// ficheros listos para que el operador ELIJA el punto de entrada y pulse
// «Registrar», donde ocurre el hash-gate. El backend re-valida nombre y formato
// (RULE 2).
export function EvidenceInbox({
  caseClosed,
  sources,
  loadingSources,
  selectedSourcePath,
  registering,
  registerJob,
  registerError,
  registerStalled,
  registerSuccess,
  uploading,
  uploadProgress,
  uploadError,
  uploadNotice,
  onSelectSource,
  onLoadSources,
  onRegister,
  onUploadFiles,
}: EvidenceInboxProps) {
  const t = useT();
  const { formatBytes } = useFormat();
  const [dragActive, setDragActive] = useState(false);
  // Mensaje local si el usuario suelta/elige ficheros con formato no soportado
  // (feedback inmediato; el backend re-valida igualmente).
  const [rejectHint, setRejectHint] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  // dragenter/dragleave también disparan al cruzar los HIJOS de la zona. Con un
  // booleano el resaltado parpadea; contamos entradas/salidas para que sólo se
  // apague cuando el puntero abandona la zona de verdad.
  const dragDepth = useRef(0);

  // Guardia global: si el perito suelta la imagen FUERA de la zona, el
  // comportamiento por defecto del navegador es NAVEGAR al fichero (la app
  // desaparece y se abre el .E01 crudo). Cancelamos ese default en toda la
  // ventana; la zona detiene la propagación, así que sus propios drops no pasan
  // por aquí. Sólo intervenimos si el arrastre trae ficheros (no rompe el
  // drag-and-drop de texto o de la propia UI).
  useEffect(() => {
    const block = (e: globalThis.DragEvent) => {
      if (!e.dataTransfer || !Array.from(e.dataTransfer.types).includes("Files")) return;
      e.preventDefault();
      if (e.type === "dragover") e.dataTransfer.dropEffect = "none";
    };
    window.addEventListener("dragover", block);
    window.addEventListener("drop", block);
    return () => {
      window.removeEventListener("dragover", block);
      window.removeEventListener("drop", block);
    };
  }, []);

  const selectedSource = sources?.find((s) => s.path === selectedSourcePath) ?? null;
  // Todo lo que hay en la bandeja es punto de entrada registrable MENOS una
  // continuación EWF, que no puede ensamblar la imagen por sí sola: su set se
  // registra desde el .E01.
  const selectedRegistrable =
    selectedSource !== null && isRegistrableEvidence(selectedSource.name);
  const canRegister =
    !caseClosed && !registering && selectedSourcePath !== "" && selectedRegistrable;

  // Caso cerrado: zona deshabilitada, sin bandeja.
  if (caseClosed) {
    return (
      <div className="dashed-panel">
        <div className="dashed-panel-main">
          <div className="dashed-panel-title">{t("inbox.caseClosed")}</div>
          <div className="dashed-panel-body">{t("inbox.caseClosedBody")}</div>
        </div>
      </div>
    );
  }

  const handleFiles = (files: FileList | null, droppedFolder = false) => {
    setRejectHint(null);
    const picked = Array.from(files ?? []);
    if (picked.length === 0) {
      setRejectHint(
        droppedFolder ? t("inbox.droppedFolder") : t("inbox.noFiles"),
      );
      return;
    }
    const hints: string[] = [];
    if (droppedFolder) {
      hints.push(t("inbox.foldersIgnored"));
    }
    // Se suben TODOS los ficheros subibles de la tanda (un EWF partido son N);
    // los no soportados se nombran, no se cuelan en silencio.
    const uploadable = picked.filter((f) => isUploadableEvidence(f.name));
    const rejected = picked.filter((f) => !isUploadableEvidence(f.name));
    if (rejected.length > 0) {
      hints.push(
        t("inbox.rejected", {
          names: rejected.map((f) => `«${f.name}»`).join(", "),
          images: IMAGE_FORMATS_HINT,
          material: t("inbox.materialFormats"),
        }),
      );
    }
    setRejectHint(hints.length > 0 ? hints.join(" ") : null);
    if (uploadable.length > 0) onUploadFiles(uploadable);
  };

  const openFileDialog = () => fileInputRef.current?.click();

  // Un arrastre "de ficheros" (no de texto ni de la propia UI).
  const carriesFiles = (e: DragEvent<HTMLElement>) =>
    Array.from(e.dataTransfer?.types ?? []).includes("Files");
  const busy = uploading || registering;

  return (
    <>
      <div
        className={`dashed-panel dashed-panel--drop${dragActive ? " is-dragging" : ""}`}
        onDragEnter={(e) => {
          if (!carriesFiles(e)) return;
          e.preventDefault();
          e.stopPropagation();
          dragDepth.current += 1;
          if (!busy) setDragActive(true);
        }}
        onDragOver={(e) => {
          if (!carriesFiles(e)) return;
          // preventDefault en dragover es lo que marca el elemento como destino
          // válido; sin dropEffect el cursor puede mostrar "prohibido".
          e.preventDefault();
          e.stopPropagation();
          e.dataTransfer.dropEffect = busy ? "none" : "copy";
          if (!busy) setDragActive(true);
        }}
        onDragLeave={(e) => {
          if (!carriesFiles(e)) return;
          e.preventDefault();
          e.stopPropagation();
          dragDepth.current -= 1;
          if (dragDepth.current <= 0) {
            dragDepth.current = 0;
            setDragActive(false);
          }
        }}
        onDrop={(e) => {
          if (!carriesFiles(e)) return;
          e.preventDefault();
          e.stopPropagation();
          dragDepth.current = 0;
          setDragActive(false);
          if (busy) return;
          // webkitGetAsEntry SÓLO es válido de forma síncrona dentro del handler.
          const droppedFolder = Array.from(e.dataTransfer.items ?? []).some(
            (it) => it.kind === "file" && it.webkitGetAsEntry()?.isDirectory === true,
          );
          handleFiles(e.dataTransfer.files, droppedFolder);
        }}
      >
        <input
          ref={fileInputRef}
          type="file"
          multiple
          accept={FILE_INPUT_ACCEPT}
          style={{ display: "none" }}
          onChange={(e) => {
            handleFiles(e.target.files);
            // Permite volver a elegir el MISMO fichero (onChange no dispara si
            // el value no cambia).
            e.target.value = "";
          }}
        />

        {/* Zona de arrastre centrada. El icono ancla la acción; los botones van
            debajo, que es el orden de lectura real: primero qué se puede
            soltar, después las dos alternativas a arrastrar. */}
        <div className="dashed-panel-main">
          <Icon name="file-upload" size={26} className="dashed-panel-icon" />
          <div className="dashed-panel-title">{t("inbox.dropTitle")}</div>
          <div className="dashed-panel-body">{t("inbox.dropBody")}</div>
          <div className="dashed-panel-actions">
            {/* Los iconos separan dos cosas que el texto solo no distinguía:
                buscar en TU equipo frente a mirar lo que ya está depositado en
                la bandeja del host. */}
            <button
              type="button"
              className="action-outline"
              disabled={uploading}
              onClick={openFileDialog}
            >
              <Icon name="folder" size={14} />
              {t("inbox.browse")}
            </button>
            <button
              type="button"
              className="action-outline"
              disabled={loadingSources || uploading}
              onClick={onLoadSources}
            >
              <Icon name="inbox" size={14} />
              {loadingSources ? t("inbox.searching") : t("inbox.browseInbox")}
            </button>
          </div>
          {/* Los formatos salen del párrafo: son decenas de extensiones metidas
              en mitad de una frase, y ahí abajo siguen consultables sin partir
              en cuatro líneas el texto que sí se lee. Las dos familias van por
              separado porque no son lo mismo: una imagen de un sistema entero y
              un fichero que te entregan entran por el mismo hash-gate pero se
              analizan distinto. */}
          <div className="dashed-panel-formats">
            {t("inbox.imagesLabel")} {IMAGE_FORMATS_HINT}
          </div>
          <div className="dashed-panel-formats">
            {t("inbox.materialLabel")} {t("inbox.materialFormats")}
          </div>
          <div className="dashed-panel-formats">{t("inbox.ewfHint")}</div>
        </div>
      </div>

      {/* Subiendo a la bandeja: progreso real (XHR upload.onprogress), agregado
          sobre toda la tanda cuando son varios ficheros. */}
      {uploading && (
        <div className="progress-block" aria-live="polite">
          <div className="progress-head">
            <span>{t("inbox.uploading")}</span>
            <span className="mono">{Math.round(uploadProgress * 100)}%</span>
          </div>
          <div className="progress-track" aria-hidden="true">
            <div
              className="progress-fill"
              style={{ width: `${Math.round(uploadProgress * 100)}%` }}
            />
          </div>
          <div className="progress-note">{t("inbox.dontClose")}</div>
        </div>
      )}

      {/* Registrando: PROGRESO REAL del hash-gate (bytes de las tres pasadas),
          sondeado del job. No hay cancelación a propósito: el registro es
          atómico, se publica entero o no se publica. */}
      {registering && !uploading && (
        <div className="progress-block" aria-live="polite">
          <div className="progress-head">
            <span>
              {t("inbox.registeringName")}{" "}
              <span className="mono">
                {selectedSource?.name ??
                  registerJob?.source_path.split(/[\\/]/).pop() ??
                  t("inbox.evidenceWord")}
              </span>
            </span>
            <span className="mono">{registerProgressLabel(registerJob, t)}</span>
          </div>
          {registerJob && registerJob.bytes_total > 0 && (
            <div className="progress-track" aria-hidden="true">
              <div
                className="progress-fill"
                style={{
                  width: `${Math.min(
                    100,
                    Math.round((registerJob.bytes_done / registerJob.bytes_total) * 100),
                  )}%`,
                }}
              />
            </div>
          )}
          <div className="progress-note">
            El hash-gate recorre la imagen tres veces (SHA-256 del origen → copia inmutable →
            re-hash de la copia): puede tardar varios minutos. Puedes cerrar esta ventana, el
            registro sigue en el servidor y se retoma al volver.
          </div>
        </div>
      )}

      {/* Bandeja: filas seleccionables. Las continuaciones EWF se listan pero no
          se eligen, el punto de entrada del set es el .E01. */}
      {!busy && sources !== null && sources.length > 0 && (
        <div className="inbox-list">
          <div className="rule-label">
            <span className="eyebrow">{t("inbox.title")}</span>
            <span className="rule" />
            <span className="rule-count">{sources.length}</span>
          </div>
          <div className="source-rows">
            {sources.map((s) => {
              const continuation = isEwfContinuationSegment(s.name);
              const registrable = isRegistrableEvidence(s.name);
              const selected = s.path === selectedSourcePath;
              const select = () => onSelectSource(selected ? "" : s.path);
              return (
                <div
                  key={s.path}
                  className={`source-row${registrable ? " is-selectable" : ""}${
                    selected && registrable ? " is-selected" : ""
                  }`}
                  role={registrable ? "button" : undefined}
                  tabIndex={registrable ? 0 : undefined}
                  aria-selected={registrable ? selected : undefined}
                  onClick={registrable ? select : undefined}
                  onKeyDown={
                    registrable
                      ? (e: KeyboardEvent<HTMLDivElement>) => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            select();
                          }
                        }
                      : undefined
                  }
                >
                  <span className="source-row-name">{s.name}</span>
                  <span className="source-row-meta">
                    {formatBytes(s.size)} · {fileExtension(s.name) || t("inbox.noExtension")}
                  </span>
                  <span className="source-row-side">
                    {continuation ? (
                      <span className="tag tag--muted">{t("inbox.ewfContinuation")}</span>
                    ) : selected ? (
                      <span className="tag tag--accent">{t("inbox.selected")}</span>
                    ) : null}
                  </span>
                </div>
              );
            })}
          </div>
          <div className="cta-row">
            {/* NOMBRA lo que va a registrar. Pegado a la fila elegida puede
                hacerlo, y en un EWF partido eso confirma que entra el .E01 y no
                un segmento suelto. */}
            <button
              type="button"
              className="action-invert"
              disabled={!canRegister}
              onClick={onRegister}
            >
              {registering
                ? t("inbox.registering")
                : selectedSource && selectedRegistrable
                  ? t("inbox.registerNamed", { name: selectedSource.name })
                  : t("inbox.register")}
            </button>
            <button
              type="button"
              className="link-action"
              disabled={loadingSources}
              onClick={onLoadSources}
            >
              {t("inbox.refresh")}
            </button>
          </div>
        </div>
      )}

      {!busy && sources !== null && sources.length === 0 && (
        <div className="inline-note" aria-live="polite">
          {t("inbox.emptyBefore")} <code>./evidence</code> {t("inbox.emptyAfter")}
        </div>
      )}

      {rejectHint && !uploading && (
        <div className="inline-note" aria-live="polite">
          {rejectHint}
        </div>
      )}

      {registerStalled && registering && (
        <div className="inline-note" aria-live="polite">
          {registerStalled}
        </div>
      )}

      {registerSuccess && (
        <div className="inline-note inline-note--ok" aria-live="polite">
          <Icon name="check" size={13} /> {registerSuccess}
        </div>
      )}

      {uploadNotice && !uploading && (
        // Informativo, no error: p. ej. segmentos que ya estaban en la bandeja
        // (el backend nunca sobrescribe evidencia).
        <div className="inline-note" aria-live="polite">
          {uploadNotice}
        </div>
      )}

      {uploadError && !uploading && (
        <div className="error-state" aria-live="polite">
          <strong>{t("inbox.uploadFailed")}</strong> {uploadError}
        </div>
      )}

      {registerError && !registering && (
        <div className="error-state" aria-live="polite">
          <strong>{t("inbox.registerFailed")}</strong> {registerError}
          {selectedSourcePath && (
            <div className="cta-row">
              <button type="button" className="link-action" onClick={onRegister}>
                {t("common.retry")}
              </button>
            </div>
          )}
        </div>
      )}
    </>
  );
}
