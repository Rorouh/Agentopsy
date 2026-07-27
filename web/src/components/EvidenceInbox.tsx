import { useRef, useState } from "react";
import type { KeyboardEvent } from "react";
import type { EvidenceSource } from "../api/types";
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

  const handleFiles = (files: FileList | null) => {
    setRejectHint(null);
    const picked = Array.from(files ?? []);
    if (picked.length === 0) return;
    // Se suben TODOS los ficheros subibles de la tanda (un EWF partido son N);
    // los no soportados se nombran, no se cuelan en silencio.
    const uploadable = picked.filter((f) => isUploadableEvidence(f.name));
    const rejected = picked.filter((f) => !isUploadableEvidence(f.name));
    if (rejected.length > 0) {
      setRejectHint(
        `${rejected.map((f) => `«${f.name}»`).join(", ")} no ${
          rejected.length === 1 ? "es un formato soportado" : "son formatos soportados"
        }. Formatos válidos: ${FORMATS_HINT} (y los segmentos de un EWF partido).`,
      );
    }
    if (uploadable.length > 0) onUploadFiles(uploadable);
  };

  const openFileDialog = () => fileInputRef.current?.click();

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
          e.preventDefault();
          if (!uploading && !registering) setDragActive(true);
        }}
        onDragOver={(e) => {
          e.preventDefault();
          if (!uploading && !registering) setDragActive(true);
        }}
        onDragLeave={(e) => {
          e.preventDefault();
          setDragActive(false);
        }}
        onDrop={(e) => {
          e.preventDefault();
          setDragActive(false);
          if (uploading || registering) return;
          handleFiles(e.dataTransfer.files);
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
          // Estado G — registrando: indeterminado (no hay progreso ni
          // cancelación en el backend, a propósito — hash gate atómico).
          <>
            {selectedSource && (
              <div className="dropzone-title">{selectedSource.name}</div>
            )}
            <div className="loading-state" aria-live="polite">
              <span className="spinner" aria-hidden="true" />
              <span>
                Registrando y calculando SHA-256 baseline… Este proceso puede tardar
                varios minutos para imágenes grandes. No cierres esta ventana.
              </span>
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
