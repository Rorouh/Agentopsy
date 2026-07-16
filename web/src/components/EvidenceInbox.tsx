import { useRef, useState } from "react";
import type { EvidenceSource } from "../api/types";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { formatBytes } from "../utils/format";
import { SUPPORTED_EXTENSIONS, fileExtension, isSupportedEvidence } from "../utils/evidence";

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
  onSelectSource: (path: string) => void;
  onLoadSources: () => void;
  onRegister: () => void;
  onUploadFile: (file: File) => void;
}

const FORMATS_HINT = SUPPORTED_EXTENSIONS.join(" · ");
const FILE_INPUT_ACCEPT = SUPPORTED_EXTENSIONS.join(",");

// Zona de registro de evidencia. El perito puede DEPOSITAR evidencia en la
// bandeja de dos formas: copiándola a ./evidence en el host, o SUBIÉNDOLA desde
// aquí (drag-and-drop o «Examinar»). La subida escribe en la bandeja (el api la
// monta rw — cadena de custodia: el agente/maletines la ven ro y nunca mutan la
// imagen); subir NO registra: deja el fichero listo para que el operador lo
// ELIJA y pulse «Registrar», donde ocurre el hash-gate. El backend re-valida
// nombre y formato (RULE 2).
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
  onSelectSource,
  onLoadSources,
  onRegister,
  onUploadFile,
}: EvidenceInboxProps) {
  const [dragActive, setDragActive] = useState(false);
  // Mensaje local si el usuario suelta/elige un fichero con formato no soportado
  // (feedback inmediato; el backend re-valida igualmente).
  const [rejectHint, setRejectHint] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const selectedSource = sources?.find((s) => s.path === selectedSourcePath) ?? null;
  const selectedCompatible =
    selectedSource !== null && isSupportedEvidence(selectedSource.name);
  const canRegister =
    !caseClosed && !registering && selectedSourcePath !== "" && selectedCompatible;

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
    const file = files?.[0];
    if (!file) return;
    if (!isSupportedEvidence(file.name)) {
      setRejectHint(
        `«${file.name}» no es un formato soportado. Formatos válidos: ${FORMATS_HINT}.`,
      );
      return;
    }
    onUploadFile(file);
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
          // Estado I — subiendo a la bandeja: progreso real (XHR upload.onprogress).
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
            <div className="dropzone-hint">Formatos soportados: {FORMATS_HINT}</div>
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
            </div>
            <div className="cta-row" style={{ justifyContent: "center" }}>
              {browseButton}
              <Button variant="chip" onClick={onLoadSources}>
                Actualizar bandeja
              </Button>
            </div>
          </>
        ) : (
          // Estado F — fuentes disponibles: filas seleccionables.
          <>
            <div className="dropzone-title">
              Elige la imagen forense desde la bandeja de evidencias
            </div>
            <div className="dropzone-hint">
              …o arrastra otra imagen aquí para subirla.
            </div>
            <div className="file-list" style={{ marginTop: 10, textAlign: "left" }}>
              {sources.map((s) => {
                const compatible = isSupportedEvidence(s.name);
                const selected = s.path === selectedSourcePath;
                return (
                  <div
                    key={s.path}
                    className={`file-row file-row--clickable${selected ? " file-row--active" : ""}`}
                    role="button"
                    tabIndex={0}
                    aria-selected={selected}
                    onClick={() => onSelectSource(selected ? "" : s.path)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        onSelectSource(selected ? "" : s.path);
                      }
                    }}
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
                      {!compatible && <Badge variant="medium">Formato no compatible</Badge>}
                      {selected && compatible && <Badge variant="low">Seleccionada</Badge>}
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
