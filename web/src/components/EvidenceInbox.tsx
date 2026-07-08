import { useState } from "react";
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
  onSelectSource: (path: string) => void;
  onLoadSources: () => void;
  onRegister: () => void;
}

const FORMATS_HINT = SUPPORTED_EXTENSIONS.join(" · ");

// Zona de registro de evidencia. OJO: aquí NO hay upload HTTP ni File API —
// la evidencia llega por la bandeja server-side (./evidence en el host). El
// "drag-and-drop" es solo affordance visual: si el usuario suelta un fichero
// del SO, se le indica el camino real (copiar a ./evidence) sin leer el File.
export function EvidenceInbox({
  caseClosed,
  sources,
  loadingSources,
  selectedSourcePath,
  registering,
  registerError,
  registerSuccess,
  onSelectSource,
  onLoadSources,
  onRegister,
}: EvidenceInboxProps) {
  const [dndHint, setDndHint] = useState(false);

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

  return (
    <>
      <div
        className="dropzone"
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => {
          // Nunca leemos el File object: el flujo real es la bandeja.
          e.preventDefault();
          setDndHint(true);
        }}
      >
        {registering ? (
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
              Copia el archivo (.E01 · .raw · .vmdk · volcado de memoria) a la carpeta{" "}
              <code>./evidence</code> en el host y haz clic en «Buscar en la bandeja».
            </div>
            <div className="dropzone-hint">Formatos soportados: {FORMATS_HINT}</div>
            <div className="cta-row" style={{ justifyContent: "center" }}>
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
            <div className="dropzone-title">La bandeja está vacía.</div>
            <div className="dropzone-hint">
              Copia la imagen forense a <code>./evidence</code> en el host.
              <br />
              Formatos soportados: {FORMATS_HINT}
            </div>
            <div className="cta-row" style={{ justifyContent: "center" }}>
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
              <Button variant="chip" disabled={loadingSources} onClick={onLoadSources}>
                Actualizar bandeja
              </Button>
              <Button variant="primary" disabled={!canRegister} onClick={onRegister}>
                Registrar evidencia
              </Button>
            </div>
          </>
        )}

        {dndHint && (
          <div className="dropzone-hint" aria-live="polite" style={{ marginTop: 10 }}>
            Copia el archivo a <code>./evidence</code> y haz clic en «Actualizar bandeja»
            para verlo aquí.
          </div>
        )}
      </div>

      {registerSuccess && (
        <div className="register-feedback register-feedback--success" aria-live="polite">
          ✓ Evidencia registrada
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
