import { useEffect, useRef, useState } from "react";
import type { DragEvent, KeyboardEvent } from "react";
import type { EvidenceRegisterJob, EvidenceSource } from "../api/types";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
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
// escribe en la bandeja (el api la monta rw — cadena de custodia: el agente/
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

  // Estado B — caso cerrado: zona deshabilitada, sin bandeja.
  if (caseClosed) {
    return (
      <div className="dropzone dropzone--disabled">
        <div className="dropzone-title">
          Este caso está cerrado. Reabre el caso para registrar más evidencia.
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

  const browseButton = (
    <Button variant="chip" disabled={uploading} onClick={openFileDialog}>
      Examinar…
    </Button>
  );

  return (
    <>
      <div
        className={`dropzone${dragActive ? " dropzone--active" : ""}`}
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

        {uploading ? (
          // Estado I — subiendo a la bandeja: progreso real (XHR upload.onprogress),
          // agregado sobre toda la tanda cuando son varios ficheros.
          <div className="loading-state" aria-live="polite">
            <span className="spinner" aria-hidden="true" />
            <div style={{ flex: 1, minWidth: 0, textAlign: "left" }}>
              <div>
                Subiendo evidencia a la bandeja… {Math.round(uploadProgress * 100)}%
              </div>
              <div className="upload-progress" aria-hidden="true">
                <div
                  className="upload-progress-bar"
                  style={{ width: `${Math.round(uploadProgress * 100)}%` }}
                />
              </div>
              <div className="dropzone-hint">
                No cierres esta ventana hasta que termine.
              </div>
            </div>
          </div>
        ) : registering ? (
          // Estado G — registrando: PROGRESO REAL del hash-gate (bytes de las
          // tres pasadas), sondeado del job. No hay cancelación a propósito: el
          // registro es atómico (se publica entero o no se publica).
          <>
            <div className="dropzone-title">
              {selectedSource?.name ??
                registerJob?.source_path.split(/[\\/]/).pop() ??
                "Registrando evidencia"}
            </div>
            <div className="loading-state" aria-live="polite">
              <span className="spinner" aria-hidden="true" />
              <div style={{ flex: 1, minWidth: 0, textAlign: "left" }}>
                <div>Registrando… {registerProgressLabel(registerJob)}</div>
                {registerJob && registerJob.bytes_total > 0 && (
                  <div className="upload-progress" aria-hidden="true">
                    <div
                      className="upload-progress-bar"
                      style={{
                        width: `${Math.min(
                          100,
                          Math.round((registerJob.bytes_done / registerJob.bytes_total) * 100),
                        )}%`,
                      }}
                    />
                  </div>
                )}
                <div className="dropzone-hint">
                  El hash-gate recorre la imagen tres veces (SHA-256 del origen →
                  copia inmutable → re-hash de la copia): puede tardar varios
                  minutos. Puedes cerrar esta ventana — el registro sigue en el
                  servidor y se retoma al volver.
                </div>
              </div>
            </div>
          </>
        ) : sources === null ? (
          // Estado C — bandeja no consultada todavía.
          <>
            <div className="dropzone-title">
              Arrastra aquí la imagen forense (.E01 · .raw · .vmdk · volcado de memoria)
              para subirla, o cópiala a la carpeta <code>./evidence</code> del host.
            </div>
            <div className="dropzone-hint">
              Formatos soportados: {FORMATS_HINT}
              <br />
              {EWF_HINT}
            </div>
            <div className="cta-row" style={{ justifyContent: "center" }}>
              {browseButton}
              <Button variant="chip" disabled={loadingSources} onClick={onLoadSources}>
                {loadingSources ? "Buscando…" : "Buscar en la bandeja"}
              </Button>
            </div>
          </>
        ) : loadingSources ? (
          // Estado D — recargando la bandeja.
          <div className="loading-state">
            <span className="spinner" aria-hidden="true" />
            <span>Buscando en la bandeja…</span>
          </div>
        ) : sources.length === 0 ? (
          // Estado E — bandeja vacía.
          <>
            <div className="dropzone-title">
              La bandeja está vacía. Arrastra la imagen forense aquí para subirla.
            </div>
            <div className="dropzone-hint">
              También puedes copiarla a <code>./evidence</code> en el host.
              <br />
              Formatos soportados: {FORMATS_HINT}
              <br />
              {EWF_HINT}
            </div>
            <div className="cta-row" style={{ justifyContent: "center" }}>
              {browseButton}
              <Button variant="chip" onClick={onLoadSources}>
                Actualizar bandeja
              </Button>
            </div>
          </>
        ) : (
          // Estado F — fuentes disponibles: filas seleccionables (solo las
          // registrables; las continuaciones EWF se listan pero no se eligen).
          <>
            <div className="dropzone-title">
              Elige la imagen forense desde la bandeja de evidencias
            </div>
            <div className="dropzone-hint">
              …o arrastra otra imagen aquí para subirla. {EWF_HINT}
            </div>
            <div className="file-list" style={{ marginTop: 10, textAlign: "left" }}>
              {sources.map((s) => {
                const continuation = isEwfContinuationSegment(s.name);
                const registrable = isRegistrableEvidence(s.name);
                const selected = s.path === selectedSourcePath;
                const select = () => onSelectSource(selected ? "" : s.path);
                return (
                  <div
                    key={s.path}
                    className={`file-row${
                      registrable ? " file-row--clickable" : ""
                    }${selected && registrable ? " file-row--active" : ""}`}
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
                    <div className="file-row-main">
                      <div style={{ minWidth: 0 }}>
                        <div className="file-row-name" title={s.name}>
                          {s.name}
                        </div>
                        <div className="file-row-meta">
                          {formatBytes(s.size)} · {fileExtension(s.name) || "sin extensión"}
                        </div>
                      </div>
                    </div>
                    <div className="file-row-side">
                      {continuation ? (
                        <Badge variant="neutral">
                          segmento EWF · se registra desde el .E01
                        </Badge>
                      ) : (
                        !registrable && <Badge variant="medium">Formato no compatible</Badge>
                      )}
                      {selected && registrable && <Badge variant="low">Seleccionada</Badge>}
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="cta-row" style={{ justifyContent: "center" }}>
              {browseButton}
              <Button variant="chip" disabled={loadingSources} onClick={onLoadSources}>
                Actualizar bandeja
              </Button>
              <Button variant="primary" disabled={!canRegister} onClick={onRegister}>
                Registrar evidencia
              </Button>
            </div>
          </>
        )}

        {rejectHint && !uploading && (
          <div className="dropzone-hint" aria-live="polite" style={{ marginTop: 10 }}>
            {rejectHint}
          </div>
        )}
      </div>

      {registerSuccess && (
        <div className="register-feedback register-feedback--success" aria-live="polite">
          ✓ Evidencia registrada
        </div>
      )}

      {uploadNotice && !uploading && (
        // Informativo, no error: p. ej. segmentos que ya estaban en la bandeja
        // (el backend nunca sobrescribe evidencia).
        <div className="dropzone-hint" aria-live="polite" style={{ marginTop: 8 }}>
          {uploadNotice}
        </div>
      )}

      {uploadError && !uploading && (
        // Estado J — error de subida, inline y accionable.
        <div className="error-state" aria-live="polite" style={{ marginTop: 8 }}>
          <strong>No se pudo subir la evidencia:</strong> {uploadError}
        </div>
      )}

      {registerError && !registering && (
        // Estado H — error de registro, inline y accionable.
        <div className="error-state" aria-live="polite" style={{ marginTop: 8 }}>
          <strong>No se pudo registrar la evidencia:</strong> {registerError}
          {selectedSourcePath && (
            <div style={{ marginTop: 8 }}>
              <Button variant="chip" onClick={onRegister}>
                Reintentar
              </Button>
            </div>
          )}
        </div>
      )}
    </>
  );
}
