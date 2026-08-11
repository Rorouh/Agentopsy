import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ApiError, api } from "../api/client";
import type {
  CustodyAct,
  EvidenceHandle,
  EvidenceMetadata,
  EvidenceSource,
} from "../api/types";
import type { ViewId } from "../navigation/navItems";
import { useActiveCase } from "../state/activeCase";
import { useCaseEvidence } from "../state/caseEvidence";
import { EvidenceInbox } from "../components/EvidenceInbox";
import { EvidenceTable } from "../components/EvidenceTable";
import { ErrorState } from "../ui/ErrorState";
import { LoadingState } from "../ui/LoadingState";
import { Modal } from "../ui/Modal";
import { usePublishShellHeader } from "../layout/shellHeader";
import { formatBytes, formatDate, shortHash } from "../utils/format";
import { isEwfFirstSegment, isRegistrableEvidence } from "../utils/evidence";

function evidenceFileName(ev: EvidenceHandle): string {
  return ev.original_path.split("/").pop() ?? ev.original_path;
}

const KIND_LABEL: Record<EvidenceHandle["detected_kind"], string> = {
  disk: "imagen de disco",
  container_disk: "imagen contenedor",
  memory: "volcado de memoria",
  unknown: "formato no identificado",
};

interface RepositoryPageProps {
  onNavigate?: (view: ViewId) => void;
}

// FASE 1 · Evidencia. El rediseño saca la gestión del caso del cuerpo de la
// vista (vive en el sidebar y en sus diálogos) y deja aquí SOLO la evidencia,
// en los cuatro bloques del mock: cifras · alta · tabla · cadena de custodia.
export function RepositoryPage({ onNavigate }: RepositoryPageProps) {
  const {
    activeCaseId,
    activeCase,
    phase: casesPhase,
    error: casesError,
    reload: reloadCases,
    upsertCase,
  } = useActiveCase();
  // La evidencia del caso y el registro en SEGUNDO PLANO los gobierna el store
  // compartido (state/caseEvidence): esta vista se destruye al cambiar de vista,
  // así que ni la lista ni el sondeo del job pueden vivir aquí. Lo que queda en
  // la página es lo suyo: la bandeja, la selección, el acta y la verificación.
  const {
    evidence,
    error: evidenceListError,
    replaceEvidence,
    registering,
    registerJob,
    registerError,
    registerStalled,
    startRegister,
    registeredSeq,
    lastRegisteredId,
  } = useCaseEvidence();

  // Aviso de registro correcto: el TEXTO que se pinta (aria-live en
  // EvidenceInbox), null mientras no hay ninguno. Nombra lo que entró, que en un
  // EWF partido es lo único que confirma que el conjunto está completo.
  const [registerSuccess, setRegisterSuccess] = useState<string | null>(null);
  const successTimer = useRef<number | undefined>(undefined);
  // Bandeja de entrada de evidencias (/api/evidence/sources./evidence del
  // host): el operador copia el fichero a la bandeja y lo ELIGE aquí
  // (RULE 2: nunca "el único" ni "el más reciente").
  const [sources, setSources] = useState<EvidenceSource[] | null>(null);
  const [loadingSources, setLoadingSources] = useState(false);
  const [selectedSourcePath, setSelectedSourcePath] = useState("");
  const [verifyingIds, setVerifyingIds] = useState<Set<string>>(new Set());
  // Subida de evidencia a la bandeja (drag-and-drop / examinar). Deposita el
  // fichero; el registro (hash-gate) es un paso aparte.
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadError, setUploadError] = useState<string | null>(null);
  // Resumen informativo de la última tanda (p. ej. segmentos EWF que ya estaban
  // en la bandeja: 409 del backend, que NUNCA sobrescribe evidencia). No es un
  // error, el operador puede seguir adelante y registrar.
  const [uploadNotice, setUploadNotice] = useState<string | null>(null);

  // Acta de adquisición: modal por evidencia con la metadata de custodia + el
  // acta estructurada (cadena hash-encadenada), ambas del backend.
  const [actaEvidence, setActaEvidence] = useState<EvidenceHandle | null>(null);
  const [actaMeta, setActaMeta] = useState<EvidenceMetadata | null>(null);
  const [acta, setActa] = useState<CustodyAct | null>(null);
  const [actaLoading, setActaLoading] = useState(false);
  const [actaError, setActaError] = useState<string | null>(null);
  // Los tres fallos de esta vista van cada uno a su sitio, con su nombre: el de
  // REGISTRO y el de la LISTA los da el store, y el de VERIFICAR es local.
  // Mezclarlos en un slot único hacía que un 404 de verify apareciera como «No se
  // pudo registrar la evidencia: …», que era falso por los dos lados.
  const [verifyError, setVerifyError] = useState<string | null>(null);
  // Fallo al leer la BANDEJA (./evidence), que no es la lista de evidencias
  // registradas ni el registro.
  const [sourcesError, setSourcesError] = useState<string | null>(null);

  useEffect(() => {
    return () => window.clearTimeout(successTimer.current);
  }, []);

  // Un registro que TERMINA BIEN lo anuncia el store (registeredSeq), ya con la
  // lista recargada. Aquí solo queda lo presentacional: soltar la selección de la
  // bandeja y el aviso de 2 s. El ref arranca en el valor actual para que volver a
  // esta vista no reviva el aviso de un registro que ya pasó.
  const seenRegisteredSeq = useRef(registeredSeq);
  useEffect(() => {
    if (registeredSeq === seenRegisteredSeq.current) return;
    seenRegisteredSeq.current = registeredSeq;
    setSelectedSourcePath("");
    // El aviso NOMBRA lo que se registró. Un EWF partido entra como una sola
    // evidencia desde su .E01, así que sin decir cuántos segmentos y cuánto pesa
    // el conjunto no hay forma de ver desde aquí que entró completo.
    const done = evidence.find((ev) => ev.evidence_id === lastRegisteredId);
    setRegisterSuccess(
      done
        ? done.segment_count > 1
          ? `Evidencia registrada: ${done.segment_count} segmentos, ${formatBytes(done.total_size)} en total`
          : `Evidencia registrada: ${formatBytes(done.total_size)}`
        : "Evidencia registrada",
    );
    window.clearTimeout(successTimer.current);
    // Nombrar el conjunto es un dato que se lee, no un destello: 6 s, no 2.
    successTimer.current = window.setTimeout(() => setRegisterSuccess(null), 6000);
  }, [registeredSeq, evidence, lastRegisteredId]);

  // Devuelve la bandeja recién leída (además de fijarla en el estado) para que
  // quien la refresca pueda decidir sobre la lista NUEVA sin esperar al render.
  const loadSources = useCallback(async (): Promise<EvidenceSource[] | null> => {
    setLoadingSources(true);
    setSourcesError(null);
    try {
      const res = await api.evidence.listSources();
      setSources(res.sources);
      // Si el fichero seleccionado desapareció de la bandeja, deselecciona,
      // jamás se registra una ruta que ya no está (el backend la rechazaría).
      setSelectedSourcePath((prev) => (res.sources.some((s) => s.path === prev) ? prev : ""));
      return res.sources;
    } catch (err) {
      setSources(null);
      setSourcesError(String(err instanceof Error ? err.message : err));
      return null;
    } finally {
      setLoadingSources(false);
    }
  }, []);

  // Sube una TANDA de ficheros a la bandeja, en serie. Un EWF partido son N
  // ficheros (.E01 … .E0N) y la bandeja los necesita todos para que ewfmount
  // reensamble la imagen; por eso se sube el conjunto, no solo el primero.
  // Un 409 («ya está en la bandeja») NO es un fallo: el backend nunca
  // sobrescribe evidencia, así que re-soltar un set del que ya había parte es
  // el caso normal, se cuenta como informativo.
  const uploadSources = useCallback(
    async (files: File[]) => {
      if (files.length === 0) return;
      setUploading(true);
      setUploadProgress(0);
      setUploadError(null);
      setUploadNotice(null);

      const uploaded: EvidenceSource[] = [];
      const already: string[] = [];
      const failed: string[] = [];
      try {
        for (let i = 0; i < files.length; i += 1) {
          const file = files[i];
          try {
            const src = await api.evidence.uploadSource(file, (fraction) =>
              // Progreso agregado sobre la tanda completa.
              setUploadProgress((i + fraction) / files.length),
            );
            uploaded.push(src);
          } catch (err) {
            if (err instanceof ApiError && err.status === 409) {
              already.push(file.name);
            } else {
              failed.push(`${file.name}: ${String(err instanceof Error ? err.message : err)}`);
            }
          }
        }
      } finally {
        setUploading(false);
        setUploadProgress(1);
      }

      if (failed.length > 0) setUploadError(failed.join(" · "));
      const notes: string[] = [];
      if (uploaded.length > 0) {
        notes.push(
          `${uploaded.length} ${uploaded.length === 1 ? "fichero subido" : "ficheros subidos"} a la bandeja`,
        );
      }
      if (already.length > 0) {
        notes.push(
          `${already.length} ya ${already.length === 1 ? "estaba" : "estaban"} en la bandeja (${already.join(", ")}); no se sobrescribe evidencia`,
        );
      }
      setUploadNotice(notes.length > 0 ? `${notes.join(" · ")}.` : null);

      // Refresca SIEMPRE (incluso si todo eran duplicados: la bandeja ya los
      // tiene y el operador debe poder registrarlos).
      const refreshed = await loadSources();
      if (!refreshed) return;
      const batch = new Set(files.map((f) => f.name));
      const inBatch = refreshed.filter((s) => batch.has(s.name.split(/[\\/]/).pop() ?? s.name));
      // Punto de entrada del set: el primer segmento EWF de la tanda. Si no hay
      // ninguno y la tanda era un único fichero, se selecciona ese.
      const entry =
        inBatch.find((s) => isEwfFirstSegment(s.name)) ??
        (files.length === 1 ? inBatch[0] : undefined);
      if (entry) setSelectedSourcePath(entry.path);
    },
    [loadSources],
  );

  const verifyOne = useCallback(
    async (evidenceId: string) => {
      const intendedCaseId = activeCase?.id;
      if (!intendedCaseId) return;
      setVerifyError(null);
      setVerifyingIds((prev) => new Set(prev).add(evidenceId));
      try {
        const updated = await api.cases.verifyEvidence(intendedCaseId, evidenceId);
        // El router devuelve el handle completo con last_verification recién
        // persistida (verification.json + audit.jsonl). El store sustituye la
        // fila en sitio; si el caso ya cambió por debajo, ese id no está en su
        // lista y la actualización no hace nada.
        replaceEvidence(evidenceId, updated);
      } catch (err) {
        setVerifyError(String(err instanceof Error ? err.message : err));
      } finally {
        setVerifyingIds((prev) => {
          const next = new Set(prev);
          next.delete(evidenceId);
          return next;
        });
      }
    },
    [activeCase, replaceEvidence],
  );

  // ── Determinación del sistema operativo ───────────────────────────────────
  // El SO NO se le pregunta al perito: lo determina `forensia.triage` del
  // CONTENIDO de la evidencia y, si es una imagen contenedor, el pase profundo
  // que la abre por el maletín (solo lectura, a nivel de bloque). Aquí vive
  // todo lo que puede hacer falta cuando esa determinación no llegó a cerrar:
  // reintentarla (el maletín pudo estar arrancando al registrar) y, como último
  // recurso ante una imagen genuinamente ambigua, anclarla a mano (RULE 2,
  // nadie elige un perfil en silencio).
  const [redetecting, setRedetecting] = useState<string | null>(null);
  const [anchoring, setAnchoring] = useState<"unix" | "windows" | null>(null);
  const [osError, setOsError] = useState<string | null>(null);
  // Evidencias cuya re-determinación automática ya se intentó en esta sesión,
  // para no repetirla en bucle a cada render cuando sigue sin poder cerrarse.
  const autoRedetected = useRef<Set<string>>(new Set());

  const redetectOs = useCallback(
    async (evidenceId: string) => {
      const caseId = activeCaseId;
      if (!caseId || redetecting) return;
      setRedetecting(evidenceId);
      setOsError(null);
      try {
        const res = await api.cases.redetectEvidenceOs(caseId, evidenceId);
        replaceEvidence(evidenceId, res.evidence);
        upsertCase(res.case);
      } catch (err) {
        setOsError(
          err instanceof ApiError ? err.detail : String(err instanceof Error ? err.message : err),
        );
      } finally {
        setRedetecting(null);
      }
    },
    [activeCaseId, redetecting, replaceEvidence, upsertCase],
  );

  // Reintento AUTOMÁTICO, una vez por evidencia y sesión: si el caso no tiene
  // perfil y hay una evidencia con SO sin determinar, el sistema vuelve a
  // intentarlo por su cuenta antes de mostrarle nada al perito. Es lo que
  // convierte «el maletín aún no estaba listo» en un no-evento.
  useEffect(() => {
    if (!activeCaseId || !activeCase || activeCase.os_profile !== null) return;
    // De una en una: `redetectOs` abre la imagen dentro del maletín y eso no se
    // paraleliza gratis. Sin esta guarda, el re-render que provoca `setRedetecting`
    // volvería a entrar aquí, marcaría la SEGUNDA evidencia como ya intentada y
    // se toparía con la salida temprana de `redetectOs`, quedándose sin
    // reintentar de verdad. Al terminar la primera, el efecto vuelve por la
    // siguiente.
    if (redetecting !== null) return;
    const pending = evidence.find(
      (ev) => ev.detected_os === "unknown" && !autoRedetected.current.has(ev.evidence_id),
    );
    if (!pending) return;
    autoRedetected.current.add(pending.evidence_id);
    void redetectOs(pending.evidence_id);
  }, [activeCaseId, activeCase, evidence, redetecting, redetectOs]);

  // Cambiar de caso limpia el registro de intentos: otro caso, otras evidencias.
  useEffect(() => {
    autoRedetected.current = new Set();
    setOsError(null);
  }, [activeCaseId]);

  const anchorProfile = useCallback(
    async (profile: "unix" | "windows") => {
      const caseId = activeCaseId;
      if (!caseId || anchoring) return;
      setAnchoring(profile);
      setOsError(null);
      try {
        upsertCase(await api.cases.anchorProfile(caseId, profile));
      } catch (err) {
        setOsError(
          err instanceof ApiError ? err.detail : String(err instanceof Error ? err.message : err),
        );
      } finally {
        setAnchoring(null);
      }
    },
    [activeCaseId, anchoring, upsertCase],
  );

  const openActa = useCallback(
    async (ev: EvidenceHandle) => {
      const caseId = activeCase?.id;
      if (!caseId) return;
      setActaEvidence(ev);
      setActa(null);
      setActaMeta(null);
      setActaError(null);
      setActaLoading(true);
      try {
        // Metadata + acta en paralelo, ambas son lecturas puras del backend.
        const [meta, actaRes] = await Promise.all([
          api.cases.evidenceMetadata(caseId, ev.evidence_id),
          api.cases.custodyAct(caseId, ev.evidence_id),
        ]);
        setActaMeta(meta);
        setActa(actaRes);
      } catch (err) {
        setActaError(String(err instanceof Error ? err.message : err));
      } finally {
        setActaLoading(false);
      }
    },
    [activeCase],
  );

  const downloadActa = useCallback(() => {
    if (!acta) return;
    const blob = new Blob([JSON.stringify(acta, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `acta-adquisicion-${acta.evidence.evidence_id}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }, [acta]);

  const verifiedCount = useMemo(
    () => evidence.filter((e) => e.last_verification?.verified === true).length,
    [evidence],
  );
  const pendingCount = evidence.length - verifiedCount;
  const caseClosed = activeCase?.status === "closed";

  // La acción de la cabecera es la del mock, «Registrar evidencia», y solo
  // procede con un punto de entrada elegido: sin selección no se adivina cuál
  // registrar (RULE 2).
  const selectedSource = sources?.find((s) => s.path === selectedSourcePath) ?? null;
  const canRegister =
    !caseClosed &&
    !registering &&
    !uploading &&
    selectedSource !== null &&
    isRegistrableEvidence(selectedSource.name);

  // La cabecera se publica ANTES de cualquier return temprano: es un hook y
  // tiene que ejecutarse en todos los renders.
  usePublishShellHeader(
    {
      title: "Evidencia",
      meta: activeCase
        ? `bandeja ./evidence · solo lectura${caseClosed ? " · caso cerrado" : ""}`
        : "sin caso seleccionado",
      action: activeCase ? (
        <button
          type="button"
          disabled={!canRegister}
          title={
            canRegister
              ? undefined
              : "Elige primero el punto de entrada en la bandeja (un formato soportado o el .E01 del set)."
          }
          onClick={() => void startRegister(selectedSourcePath)}
        >
          {registering ? "Registrando…" : "Registrar evidencia"}
        </button>
      ) : undefined,
    },
    // `selectedSourcePath` va en los disparadores porque el nodo de la acción se
    // publica UNA vez por cambio de dependencias y se queda con el cierre de ese
    // render: cambiar de fichero elegido no movía `canRegister` (seguía habiendo
    // uno seleccionado), así que el botón de la cabecera conservaba la ruta
    // ANTERIOR y registraba la evidencia equivocada.
    [
      activeCase?.id,
      activeCase?.examiner,
      caseClosed,
      canRegister,
      registering,
      selectedSourcePath,
      startRegister,
    ],
  );

  if (casesPhase === "loading") {
    return (
      <div className="view-scroll">
        <LoadingState label="Cargando casos…" />
      </div>
    );
  }

  if (casesPhase === "error") {
    return (
      <div className="view-scroll">
        {/* RULE 2: el fallo del listado se muestra aquí mismo, no solo dentro
            del diálogo de casos que quizá nadie abra. */}
        <ErrorState message={casesError ?? "no se pudo listar los casos"} />
        <div className="cta-row">
          <button type="button" className="link-action" onClick={() => void reloadCases()}>
            Reintentar
          </button>
        </div>
      </div>
    );
  }

  if (!activeCase) {
    return (
      <div className="view-scroll">
        <div className="empty-rail">
          <div className="empty-rail-title">Sin caso activo</div>
          <div className="empty-rail-body">
            Abre uno con «Nuevo caso» o elige otro con «cambiar caso», en el lateral. La
            evidencia se registra siempre dentro de un caso: es lo que ancla la cadena de
            custodia.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="view-scroll">
      <div className="view-stack view-stack--1000">
        {/* 1 · Cifras del caso */}
        <div className="stat-row">
          <div className="stat">
            <div className="eyebrow">Registradas</div>
            <div className="stat-value">{evidence.length}</div>
          </div>
          <div className="stat">
            <div className="eyebrow">Hash verificado</div>
            <div className="stat-value stat-value--ok">{verifiedCount}</div>
          </div>
          <div className="stat">
            <div className="eyebrow">Pendientes</div>
            <div className={`stat-value${pendingCount > 0 ? " stat-value--accent" : ""}`}>
              {pendingCount}
            </div>
          </div>
          <div className="stat">
            <div className="eyebrow">Examinador</div>
            <div className="stat-text">{activeCase.examiner}</div>
          </div>
        </div>

        {/* 2 · Alta de evidencia */}
        <div className="section-stack">
          <div className="eyebrow eyebrow--section">Añadir evidencia</div>
          <EvidenceInbox
            caseClosed={caseClosed}
            sources={sources}
            loadingSources={loadingSources}
            selectedSourcePath={selectedSourcePath}
            registering={registering}
            registerJob={registerJob}
            registerError={registerError}
            registerStalled={registerStalled}
            registerSuccess={registerSuccess}
            uploading={uploading}
            uploadProgress={uploadProgress}
            uploadError={uploadError}
            uploadNotice={uploadNotice}
            onSelectSource={setSelectedSourcePath}
            onLoadSources={() => void loadSources()}
            onRegister={() => void startRegister(selectedSourcePath)}
            onUploadFiles={uploadSources}
          />
          {sourcesError && (
            <ErrorState message={`No se pudo leer la bandeja: ${sourcesError}`} />
          )}
        </div>

        {/* 3 · Evidencias del caso */}
        <div className="section-stack">
          <div className="rule-label">
            <span className="eyebrow eyebrow--section">Evidencias del caso</span>
            <span className="rule" />
            <span className="rule-count">{evidence.length}</span>
          </div>
          {/* El fallo de la LECTURA de la lista se nombra como lo que es: antes
              se pintaba como «No se pudo registrar la evidencia», que confundía
              un caso sin leer con un registro fallido. */}
          {evidenceListError && (
            <ErrorState
              message={`No se pudo listar la evidencia del caso: ${evidenceListError}`}
            />
          )}
          <EvidenceTable
            evidence={evidence}
            verifyingIds={verifyingIds}
            onVerify={verifyOne}
            verifyError={verifyError}
          />
        </div>

        {/* 3.bis · Sistema operativo determinado */}
        {evidence.length > 0 && (
          <div className="section-stack">
            <div className="rule-label">
              <span className="eyebrow eyebrow--section">Sistema operativo</span>
              <span className="rule" />
              <span className="rule-count">
                {activeCase.os_profile ?? "sin determinar"}
              </span>
            </div>
            <div className="os-rows">
              {evidence.map((ev) => (
                <div className="os-row" key={ev.evidence_id}>
                  <span className="os-name">{evidenceFileName(ev)}</span>
                  <span className="os-meta">{KIND_LABEL[ev.detected_kind]}</span>
                  <span
                    className={`os-verdict${ev.detected_os === "unknown" ? " is-open" : ""}`}
                  >
                    {ev.detected_os === "unknown" ? "SO sin determinar" : ev.detected_os}
                  </span>
                  {ev.detected_os === "unknown" && (
                    <button
                      type="button"
                      className="link-action os-action"
                      disabled={redetecting !== null}
                      title="Volver a abrir la imagen y determinar su sistema operativo"
                      onClick={() => void redetectOs(ev.evidence_id)}
                    >
                      {redetecting === ev.evidence_id ? "Determinando…" : "Reintentar"}
                    </button>
                  )}
                </div>
              ))}
            </div>

            {/* Último recurso, y sólo cuando la determinación automática no ha
                podido cerrar: una imagen dual-boot, señales en conflicto o un
                contenedor que el maletín no pudo abrir. RULE 2 prohíbe elegir
                un perfil en silencio, así que aquí lo ancla el operador, con
                la huella delante, no en mitad del chat. */}
            {activeCase.os_profile === null && redetecting === null && (
              <div className="note-rail">
                La determinación automática no ha podido cerrar el sistema operativo de este
                caso, o la imagen contiene señales de más de un SO, o el maletín que la abre
                no está disponible. El agente no se enruta hasta que haya un perfil, así que
                puedes anclarlo tú:
                <div className="anchor-actions">
                  <button
                    type="button"
                    className="chip-option"
                    disabled={anchoring !== null}
                    onClick={() => void anchorProfile("unix")}
                  >
                    {anchoring === "unix" ? "Anclando…" : "unix"}
                  </button>
                  <button
                    type="button"
                    className="chip-option"
                    disabled={anchoring !== null}
                    onClick={() => void anchorProfile("windows")}
                  >
                    {anchoring === "windows" ? "Anclando…" : "windows"}
                  </button>
                </div>
                El anclaje es final y queda en el log de auditoría del caso.
              </div>
            )}

            {osError && <ErrorState message={osError} />}
          </div>
        )}

        {/* 4 · Cadena de custodia */}
        {evidence.length > 0 && (
          <div className="section-stack">
            <div className="rule-label">
              <span className="eyebrow eyebrow--section">Cadena de custodia</span>
              <span className="rule" />
            </div>
            <div className="prose">
              El acta de adquisición recoge el hash baseline, el tamaño y el enlace de la
              cadena encadenada por hash.
            </div>
            <div className="custody-rows">
              {evidence.map((ev) => (
                <div className="custody-row" key={ev.evidence_id}>
                  <span className="custody-name">{evidenceFileName(ev)}</span>
                  {/* Tamaño del CONJUNTO y cuántos ficheros lo forman: en un EWF
                      partido, `size` es solo el primer segmento. */}
                  <span className="custody-meta">
                    {formatBytes(ev.total_size)}
                    {ev.segment_count > 1 && ` en ${ev.segment_count} segmentos`}
                  </span>
                  <span className="custody-meta" title={ev.sha256}>
                    sha256 {shortHash(ev.sha256)}
                  </span>
                  {/* Estado REAL del handle. La verificación de la cadena la
                      calcula el backend al emitir el acta: no se afirma aquí. */}
                  {ev.last_verification === null ? (
                    <span className="custody-meta">sin re-verificar</span>
                  ) : ev.last_verification.verified ? (
                    <span className="custody-meta custody-meta--ok">hash re-verificado</span>
                  ) : (
                    <span className="custody-meta custody-meta--danger">⚠ hash mismatch</span>
                  )}
                  <button type="button" className="link-action custody-action" onClick={() => void openActa(ev)}>
                    Acta de adquisición
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {onNavigate && evidence.length > 0 && (
          <div className="cta-row">
            <button type="button" className="link-action" onClick={() => onNavigate("investigation")}>
              Pasar a Investigación →
            </button>
          </div>
        )}
      </div>

      <Modal
        open={actaEvidence !== null}
        eyebrow="Cadena de custodia"
        title="Acta de adquisición"
        subtitle={actaEvidence ? evidenceFileName(actaEvidence) : undefined}
        onClose={() => setActaEvidence(null)}
        panelClassName="acta-modal"
        footerHint="esc para cerrar"
        footer={
          <>
            <button
              type="button"
              className="modal-action"
              disabled={!acta}
              onClick={downloadActa}
            >
              Descargar acta (JSON)
            </button>
            <button
              type="button"
              className="modal-action modal-action--quiet"
              onClick={() => setActaEvidence(null)}
            >
              Cerrar
            </button>
          </>
        }
      >
        {actaLoading ? (
          <LoadingState label="Generando acta…" />
        ) : actaError ? (
          <ErrorState message={actaError} />
        ) : acta && actaMeta ? (
          <div className="acta-rows">
            <div className="acta-row">
              <div className="eyebrow">Caso</div>
              <div className="acta-value">
                {acta.case.name} · {acta.case.examiner}
              </div>
            </div>
            <div className="acta-row">
              <div className="eyebrow">Origen</div>
              <div className="acta-value acta-value--mono">
                {acta.evidence.source_path ?? "n/d"}
              </div>
            </div>
            <div className="acta-row">
              <div className="eyebrow">SHA-256 (baseline)</div>
              <div className="acta-value acta-value--mono">
                {acta.evidence.sha256}
                {acta.evidence.segment_count > 1 && (
                  <span className="acta-note">
                    cubre el primer segmento; cada uno tiene el suyo, abajo
                  </span>
                )}
              </div>
            </div>
            <div className="acta-row">
              <div className="eyebrow">Tamaño</div>
              <div className="acta-value acta-value--mono">
                {acta.evidence.total_size_human} (
                {acta.evidence.total_size_bytes.toLocaleString("es-ES")} bytes)
                {acta.evidence.segment_count > 1 && (
                  <span className="acta-note">
                    {acta.evidence.segment_count} segmentos ingeridos como una sola
                    evidencia; el primero pesa {acta.evidence.size_human}
                  </span>
                )}
              </div>
            </div>
            {/* Un EWF partido se registra desde el .E01 y arrastra todo su conjunto.
                Enumerarlo aquí es lo que permite comprobar que entró COMPLETO: cada
                fichero con su propio hash baseline, en orden de segmento. */}
            {acta.evidence.segments.length > 1 && (
              <div className="acta-row">
                <div className="eyebrow">
                  Segmentos ({acta.evidence.segments.length})
                </div>
                <div className="acta-value">
                  <div className="segment-rows">
                    {acta.evidence.segments.map((s) => (
                      <div className="segment-row" key={s.name}>
                        <span className="segment-name">{s.name}</span>
                        <span className="segment-size">{s.size_human}</span>
                        <span className="segment-hash" title={s.sha256}>
                          sha256 {shortHash(s.sha256)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
            <div className="acta-row">
              <div className="eyebrow">Registrada</div>
              <div className="acta-value acta-value--mono">
                {formatDate(acta.evidence.registered_at)}
              </div>
            </div>
            <div className="acta-row">
              <div className="eyebrow">Nivel de solo-lectura</div>
              <div className="acta-value">{actaMeta.read_only_label}</div>
            </div>
            <div className="acta-row">
              <div className="eyebrow">Cadena de custodia</div>
              <div
                className={`acta-value acta-value--mono${
                  acta.chain_of_custody.hash_chain_verified ? " is-ok" : " is-bad"
                }`}
              >
                entry_hash {acta.chain_of_custody.register_entry_hash ?? "n/d"} ·{" "}
                {acta.chain_of_custody.hash_chain_verified
                  ? "cadena verificada"
                  : "⚠ la cadena NO verifica"}
              </div>
            </div>
            <div className="acta-row">
              <div className="eyebrow">Verificación</div>
              <div
                className={`acta-value acta-value--mono${
                  acta.verification?.verified ? " is-ok" : acta.verification ? " is-bad" : ""
                }`}
              >
                {acta.verification
                  ? acta.verification.verified
                    ? `Verificada ${formatDate(acta.verification.verified_at)}`
                    : "⚠ Hash MISMATCH"
                  : "Sin verificar"}
              </div>
            </div>
            <div className="acta-row">
              <div className="eyebrow">Herramienta</div>
              <div className="acta-value">
                {acta.tool.name} {acta.tool.version} · {acta.tool.method}
              </div>
            </div>
          </div>
        ) : null}
      </Modal>
    </div>
  );
}
