import { useEffect, useRef, useState } from "react";
import type { DragEvent, KeyboardEvent } from "react";
import type { EvidenceRegisterJob, EvidenceSource } from "../api/types";
import { formatBytes } from "../utils/format";
import {
  FILE_INPUT_ACCEPT_EXTENSIONS,
  SUPPORTED_EXTENSIONS,
  fileExtension,
  isEwfContinuationSegment,
  isRegistrableEvidence,
  isUploadableEvidence,
} from "../utils/evidence";

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
  // Flash de 2 s tras un registro exitoso (lo gobierna la página).
  registerSuccess: boolean;
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

const FORMATS_HINT = SUPPORTED_EXTENSIONS.join(" · ");
const FILE_INPUT_ACCEPT = FILE_INPUT_ACCEPT_EXTENSIONS.join(",");
// Un EWF partido se sube ENTERO (todos sus segmentos); registrar sigue siendo
// cosa del .E01, que ingiere el set completo en el backend.
const EWF_HINT =
  "Si la imagen es un EWF partido (.E01, .E02, …), suelta o selecciona TODOS " +
  "sus segmentos: se registran desde el .E01 como una sola evidencia.";

// Fases REALES del hash-gate (backend/forensia/evidence.py PROGRESS_PHASES). El
// progreso es observacional: describe las tres pasadas que ya se hacían, no
// añade ninguna (FORENSIC INVARIANT 2).
const PHASE_LABEL: Record<NonNullable<EvidenceRegisterJob["phase"]>, string> = {
  hashing: "SHA-256 del origen",
  copying: "copiando a la carpeta del caso",
  verifying: "re-hash de la copia",
};

function registerProgressLabel(job: EvidenceRegisterJob | null): string {
  if (!job || job.bytes_total <= 0) {
    // Aún validando (caso, ruta, conjunto EWF): no hay bytes que medir todavía.
    return "Preparando el registro…";
  }
  const pct = Math.min(100, Math.round((job.bytes_done / job.bytes_total) * 100));
  const parts = [`${pct}%`];
  if (job.seg_count > 1) parts.push(`segmento ${job.seg_index}/${job.seg_count}`);
  if (job.phase) parts.push(PHASE_LABEL[job.phase]);
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
  // Solo un formato single-file soportado o el PRIMER segmento EWF es un punto
  // de entrada registrable; una continuación .E02 no se registra por sí sola.
  const selectedRegistrable =
    selectedSource !== null && isRegistrableEvidence(selectedSource.name);
  const canRegister =
    !caseClosed && !registering && selectedSourcePath !== "" && selectedRegistrable;

  // Caso cerrado: zona deshabilitada, sin bandeja.
  if (caseClosed) {
    return (
      <div className="dashed-panel">
        <div className="dashed-panel-main">
          <div className="dashed-panel-title">Este caso está cerrado</div>
          <div className="dashed-panel-body">
            Reábrelo desde «cambiar caso» en el lateral para registrar más evidencia.
          </div>
        </div>
      </div>
    );
  }

  const handleFiles = (files: FileList | null, droppedFolder = false) => {
    setRejectHint(null);
    const picked = Array.from(files ?? []);
    if (picked.length === 0) {
      setRejectHint(
        droppedFolder
          ? "Has soltado una carpeta. Suelta los FICHEROS de imagen forense, no el " +
            "directorio que los contiene."
          : "No se ha recibido ningún fichero. Vuelve a intentarlo o usa «Examinar…».",
      );
      return;
    }
    const hints: string[] = [];
    if (droppedFolder) {
      hints.push(
        "Se han ignorado las carpetas del arrastre: suelta los ficheros de imagen " +
          "forense directamente.",
      );
    }
    // Se suben TODOS los ficheros subibles de la tanda (un EWF partido son N);
    // los no soportados se nombran, no se cuelan en silencio.
    const uploadable = picked.filter((f) => isUploadableEvidence(f.name));
    const rejected = picked.filter((f) => !isUploadableEvidence(f.name));
    if (rejected.length > 0) {
      hints.push(
        `${rejected.map((f) => `«${f.name}»`).join(", ")} no ${
          rejected.length === 1 ? "es un formato soportado" : "son formatos soportados"
        }. Formatos válidos: ${FORMATS_HINT} (y los segmentos de un EWF partido).`,
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
        className={`dashed-panel${dragActive ? " is-dragging" : ""}`}
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

        <div className="dashed-panel-main">
          <div className="dashed-panel-title">
            Arrastra la imagen forense o el volcado aquí
          </div>
          <div className="dashed-panel-body">
            Agentopsy calcula el SHA-256 baseline y la deja en solo lectura antes de que
            ninguna herramienta la toque. También puedes copiarla a <code>./evidence</code> en
            el host. Formatos: {FORMATS_HINT}. {EWF_HINT}
          </div>
        </div>
        <div className="cta-row">
          <button
            type="button"
            className="action-outline"
            disabled={uploading}
            onClick={openFileDialog}
          >
            Examinar…
          </button>
          <button
            type="button"
            className="action-outline"
            disabled={loadingSources || uploading}
            onClick={onLoadSources}
          >
            {loadingSources ? "Buscando…" : "Examinar bandeja"}
          </button>
        </div>
      </div>

      {/* Subiendo a la bandeja: progreso real (XHR upload.onprogress), agregado
          sobre toda la tanda cuando son varios ficheros. */}
      {uploading && (
        <div className="progress-block" aria-live="polite">
          <div className="progress-head">
            <span>Subiendo evidencia a la bandeja…</span>
            <span className="mono">{Math.round(uploadProgress * 100)}%</span>
          </div>
          <div className="progress-track" aria-hidden="true">
            <div
              className="progress-fill"
              style={{ width: `${Math.round(uploadProgress * 100)}%` }}
            />
          </div>
          <div className="progress-note">No cierres esta ventana hasta que termine.</div>
        </div>
      )}

      {/* Registrando: PROGRESO REAL del hash-gate (bytes de las tres pasadas),
          sondeado del job. No hay cancelación a propósito: el registro es
          atómico, se publica entero o no se publica. */}
      {registering && !uploading && (
        <div className="progress-block" aria-live="polite">
          <div className="progress-head">
            <span>
              Registrando{" "}
              <span className="mono">
                {selectedSource?.name ??
                  registerJob?.source_path.split(/[\\/]/).pop() ??
                  "evidencia"}
              </span>
            </span>
            <span className="mono">{registerProgressLabel(registerJob)}</span>
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
            <span className="eyebrow">Bandeja ./evidence</span>
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
                    {formatBytes(s.size)} · {fileExtension(s.name) || "sin extensión"}
                  </span>
                  <span className="source-row-side">
                    {continuation ? (
                      <span className="tag tag--muted">segmento EWF · se registra desde el .E01</span>
                    ) : !registrable ? (
                      <span className="tag tag--muted">formato no compatible</span>
                    ) : selected ? (
                      <span className="tag tag--accent">seleccionada</span>
                    ) : null}
                  </span>
                </div>
              );
            })}
          </div>
          <div className="cta-row">
            <button
              type="button"
              className="action-invert"
              disabled={!canRegister}
              onClick={onRegister}
            >
              Registrar evidencia
            </button>
            <button
              type="button"
              className="link-action"
              disabled={loadingSources}
              onClick={onLoadSources}
            >
              Actualizar bandeja
            </button>
          </div>
        </div>
      )}

      {!busy && sources !== null && sources.length === 0 && (
        <div className="inline-note" aria-live="polite">
          La bandeja está vacía. Arrastra la imagen forense arriba para subirla, o cópiala a{" "}
          <code>./evidence</code> en el host.
        </div>
      )}

      {rejectHint && !uploading && (
        <div className="inline-note" aria-live="polite">
          {rejectHint}
        </div>
      )}

      {registerSuccess && (
        <div className="inline-note inline-note--ok" aria-live="polite">
          ✓ Evidencia registrada
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
          <strong>No se pudo subir la evidencia:</strong> {uploadError}
        </div>
      )}

      {registerError && !registering && (
        <div className="error-state" aria-live="polite">
          <strong>No se pudo registrar la evidencia:</strong> {registerError}
          {selectedSourcePath && (
            <div className="cta-row">
              <button type="button" className="link-action" onClick={onRegister}>
                Reintentar
              </button>
            </div>
          )}
        </div>
      )}
    </>
  );
}
