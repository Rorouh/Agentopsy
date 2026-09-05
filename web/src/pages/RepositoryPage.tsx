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
import { useCaseStream } from "../state/casePulse";
import { EvidenceInbox } from "../components/EvidenceInbox";
import { EvidenceTable } from "../components/EvidenceTable";
import { ErrorState } from "../ui/ErrorState";
import { LoadingState } from "../ui/LoadingState";
import { Modal } from "../ui/Modal";
import { usePublishShellHeader } from "../layout/shellHeader";
import { useFormat } from "../utils/format";
import { useLang, type MessageKey } from "../i18n";
import { isEwfFirstSegment } from "../utils/evidence";
import { Icon } from "../ui/Icon";

function evidenceFileName(ev: EvidenceHandle): string {
  return ev.original_path.split("/").pop() ?? ev.original_path;
}

const KIND_KEY: Record<EvidenceHandle["detected_kind"], MessageKey> = {
  disk: "evidence.kind.disk",
  container_disk: "evidence.kind.container_disk",
  memory: "evidence.kind.memory",
  document: "evidence.kind.document",
  unknown: "evidence.kind.unknown",
};

// Un fichero APORTADO (un PDF, una foto, un correo, un log) no es el sistema
// investigado: es material sobre él. No hay SO que determinarle, así que ni se
// reintenta la determinación ni se le pinta «SO sin determinar», que sería
// pedirle al perito que resuelva algo que no es una pregunta.
function hasOperatingSystem(ev: EvidenceHandle): boolean {
  return ev.detected_kind !== "document";
}

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
  // La ficha del caso cambia sola: el triage deriva el perfil de SO al registrar
  // una evidencia, y el caso puede cerrarse desde otra pestaña. La LISTA de
  // evidencias no se pide aquí, ya la repone el store con su propio flujo.
  const revCase = useCaseStream("case");
  useEffect(() => {
    if (revCase === 0) return;
    void reloadCases();
  }, [revCase, reloadCases]);

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
  const { t, locale } = useLang();
  const { formatBytes, formatDate, shortHash } = useFormat();

  // Evidencia cuya FICHA está abierta bajo la tabla. Sin selección explícita se
  // abre la primera. Con una sola evidencia (el caso normal), obligar a un clic
  // para ver su hash y su acta sería un paso de más.
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | null>(null);
  // Acuse de copia del SHA-256 de la ficha, 1,5 s.
  const [hashCopied, setHashCopied] = useState(false);

  const copySha = useCallback(async (sha256: string) => {
    try {
      await navigator.clipboard.writeText(sha256);
      setHashCopied(true);
      window.setTimeout(() => setHashCopied(false), 1500);
    } catch {
      /* portapapeles bloqueado: el hash está delante, se puede seleccionar */
    }
  }, []);

  const selectedEvidence = useMemo(
    () =>
      evidence.find((ev) => ev.evidence_id === selectedEvidenceId) ?? evidence[0] ?? null,
    [evidence, selectedEvidenceId],
  );

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
          ? t("evidence.registeredSet", {
              segments: done.segment_count,
              size: formatBytes(done.total_size),
            })
          : t("evidence.registeredSize", { size: formatBytes(done.total_size) })
        : t("evidence.registeredPlain"),
    );
    window.clearTimeout(successTimer.current);
    // Nombrar el conjunto es un dato que se lee, no un destello: 6 s, no 2.
    successTimer.current = window.setTimeout(() => setRegisterSuccess(null), 6000);
  }, [registeredSeq, evidence, lastRegisteredId, t, formatBytes]);

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
          t(uploaded.length === 1 ? "evidence.uploadedOne" : "evidence.uploadedMany", {
            count: uploaded.length,
          }),
        );
      }
      if (already.length > 0) {
        notes.push(
          t(already.length === 1 ? "evidence.alreadyOne" : "evidence.alreadyMany", {
            count: already.length,
            names: already.join(", "),
          }),
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
    [loadSources, t],
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
  // El SO NO se le pregunta al perito: lo determina `agentopsy.triage` del
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
      (ev) =>
        hasOperatingSystem(ev) &&
        ev.detected_os === "unknown" &&
        !autoRedetected.current.has(ev.evidence_id),
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
  // Un caso cuya evidencia es SÓLO material aportado no tiene un SO que
  // determinar, así que el aviso de abajo no puede hablarle de una imagen que no
  // ha podido abrirse. Sigue haciendo falta un perfil, pero por otro motivo: es
  // lo que elige el maletín donde corren las herramientas.
  const onlyMaterial = useMemo(
    () => evidence.length > 0 && evidence.every((ev) => !hasOperatingSystem(ev)),
    [evidence],
  );

  // Quién puede registrar y cuál lo decide EvidenceInbox, que es donde vive el
  // botón y la lista de la bandeja. La página ya no duplica ese cálculo.

  // La cabecera se publica ANTES de cualquier return temprano: es un hook y
  // tiene que ejecutarse en todos los renders.
  usePublishShellHeader(
    {
      title: t("nav.repository"),
      // Sin meta con un caso abierto o cerrado: «bandeja ./evidence · solo
      // lectura» describía el funcionamiento interno, y el caso cerrado ya lo
      // enuncia la zona de registro, que además dice qué hacer al respecto
      // («Reabre el caso para registrar más evidencia»).
      meta: activeCase ? undefined : t("common.noCase"),
      // La cabecera lleva el AVANCE DE FASE, como las otras seis. «Registrar
      // evidencia» estaba aquí duplicando el botón que ya vive al pie de la
      // bandeja, a unos 600px de la fila que lo activa: se elegía el fichero
      // abajo y había que subir a la esquina opuesta para registrarlo.
      action:
        onNavigate && activeCase ? (
          <button
            type="button"
            disabled={evidence.length === 0}
            title={
              evidence.length === 0
                ? t("evidence.needEvidenceFirst")
                : undefined
            }
            onClick={() => onNavigate("investigation")}
          >
            {t("evidence.goToInvestigation")} →
          </button>
        ) : undefined,
    },
    [
      activeCase?.id,
      activeCase?.examiner,
      caseClosed,
      evidence.length,
      onNavigate,
      t,
    ],
  );

  if (casesPhase === "loading") {
    return (
      <div className="view-scroll">
        <LoadingState label={t("evidence.loadingCases")} />
      </div>
    );
  }

  if (casesPhase === "error") {
    return (
      <div className="view-scroll">
        {/* RULE 2: el fallo del listado se muestra aquí mismo, no solo dentro
            del diálogo de casos que quizá nadie abra. */}
        <ErrorState message={casesError ?? t("evidence.casesFailed")} />
        <div className="cta-row">
          <button type="button" className="link-action" onClick={() => void reloadCases()}>
            {t("common.retry")}
          </button>
        </div>
      </div>
    );
  }

  if (!activeCase) {
    return (
      <div className="view-scroll">
        <div className="empty-rail">
          <div className="empty-rail-title">{t("evidence.noActiveCase")}</div>
          <div className="empty-rail-body">{t("evidence.noActiveCaseBody")}</div>
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
            <div className="eyebrow">{t("evidence.statRegistered")}</div>
            <div className="stat-value">{evidence.length}</div>
          </div>
          <div className="stat">
            <div className="eyebrow">{t("evidence.statVerified")}</div>
            <div className="stat-value stat-value--ok">{verifiedCount}</div>
          </div>
          <div className="stat">
            <div className="eyebrow">{t("evidence.statPending")}</div>
            <div className={`stat-value${pendingCount > 0 ? " stat-value--accent" : ""}`}>
              {pendingCount}
            </div>
          </div>
          <div className="stat">
            <div className="eyebrow">{t("evidence.statExaminer")}</div>
            <div className="stat-text">{activeCase.examiner}</div>
          </div>
        </div>

        {/* 2 · Alta de evidencia */}
        <div className="section-stack">
          <div className="eyebrow eyebrow--section">{t("evidence.addSection")}</div>
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
            <ErrorState message={t("evidence.inboxFailed", { detail: sourcesError })} />
          )}
        </div>

        {/* 3 · Evidencias del caso.
            La TABLA sirve para comparar y elegir, así que solo aparece cuando
            hay más de una. Con una sola no compara nada y repite campo por
            campo lo que la ficha de abajo dice mejor (allí el SHA-256 va
            entero). Con cero se pinta igualmente: su estado vacío es el que
            explica que no hay evidencia registrada. */}
        {evidence.length !== 1 && (
          <div className="section-stack">
            <div className="rule-label">
              <span className="eyebrow eyebrow--section">{t("evidence.listSection")}</span>
              <span className="rule" />
              <span className="rule-count">{evidence.length}</span>
            </div>
            {/* El fallo de la LECTURA de la lista se nombra como lo que es: antes
                se pintaba como «No se pudo registrar la evidencia», que confundía
                un caso sin leer con un registro fallido. */}
            {evidenceListError && (
              <ErrorState
                message={t("evidence.listFailed", { detail: evidenceListError })}
              />
            )}
            <EvidenceTable
              evidence={evidence}
              verifyingIds={verifyingIds}
              onVerify={verifyOne}
              verifyError={verifyError}
              selectedId={selectedEvidence?.evidence_id ?? null}
              onSelect={setSelectedEvidenceId}
            />
          </div>
        )}

        {/* Con una sola evidencia no hay tabla, así que sus dos fallos (leer la
            lista y verificar) se pintan aquí o se perderían. */}
        {evidence.length === 1 && evidenceListError && (
          <ErrorState message={t("evidence.listFailed", { detail: evidenceListError })} />
        )}
        {evidence.length === 1 && verifyError && (
          <ErrorState message={t("evidence.verifyFailed", { detail: verifyError })} />
        )}

        {/* 3.bis · FICHA de la evidencia elegida.
            «Sistema operativo» y «Cadena de custodia» eran dos secciones que
            listaban SIEMPRE todas las evidencias: con tres imágenes había nueve
            filas repartidas en tres tablas y había que cruzarlas a mano para
            saber qué le pasaba a cada una. Ahora son apartados de UNA ficha, la
            de la fila abierta. */}
        {selectedEvidence && (
          <div className="section-stack evidence-card">
            <div className="rule-label">
              {/* El nombre va LITERAL, no por `.eyebrow`: esa clase fuerza
                  mayúsculas y en forense un nombre de fichero las distingue:
                  pintar «ORIGINAL.RAW» donde el disco dice «original.raw» es
                  afirmar algo que no es. */}
              <span className="evidence-card-name">
                {evidenceFileName(selectedEvidence)}
              </span>
              <span className="rule" />
              <span className="rule-count">
                {t(KIND_KEY[selectedEvidence.detected_kind])}
              </span>
            </div>

            <div className="evidence-card-grid">
              <span className="evidence-card-k">sha-256</span>
              {/* El hash es lo que se cita en un informe y lo que se compara
                  contra el acta: tiene que poder copiarse. El control vivía en
                  la fila de la tabla, que ya no se pinta con una sola
                  evidencia. */}
              <button
                type="button"
                className={`hash-copy evidence-card-v is-mono${
                  hashCopied ? " is-copied" : ""
                }`}
                onClick={() => void copySha(selectedEvidence.sha256)}
                title={t("evidenceTable.copyHash")}
                aria-label={t("evidenceTable.copyHashLabel")}
              >
                <span>{selectedEvidence.sha256}</span>
                <span className="hash-copy-icon" aria-hidden="true">
                  <Icon name={hashCopied ? "check" : "copy"} size={13} />
                </span>
              </button>

              <span className="evidence-card-k">{t("evidence.kSize")}</span>
              <span className="evidence-card-v is-mono">
                {formatBytes(selectedEvidence.total_size)}
                {selectedEvidence.segment_count > 1 &&
                  ` ${t("evidence.inSegments", { count: selectedEvidence.segment_count })}`}
              </span>

              <span className="evidence-card-k">{t("evidence.kIntegrity")}</span>
              <span className="evidence-card-v is-mono">
                {selectedEvidence.last_verification === null ? (
                  t("evidence.notReverified")
                ) : selectedEvidence.last_verification.verified ? (
                  <span className="custody-meta--ok">{t("evidence.reverified")}</span>
                ) : (
                  <span className="custody-meta--danger">
                    <Icon name="alert" size={12} /> {t("evidenceTable.mismatch")}
                  </span>
                )}
              </span>

              <span className="evidence-card-k">{t("evidence.kOs")}</span>
              <span className="evidence-card-v is-mono">
                {!hasOperatingSystem(selectedEvidence) ? (
                  <>
                    {t("evidence.osNotApplicable")}
                    <span className="evidence-card-note">
                      {t("evidence.osNotApplicableNote")}
                    </span>
                  </>
                ) : selectedEvidence.detected_os === "unknown" ? (
                  <>
                    {t("evidence.osUndetermined")}
                    <button
                      type="button"
                      className="link-action os-action"
                      disabled={redetecting !== null}
                      title={t("evidence.osRedetectTitle")}
                      onClick={() => void redetectOs(selectedEvidence.evidence_id)}
                    >
                      {redetecting === selectedEvidence.evidence_id
                        ? t("evidence.osDetermining")
                        : t("common.retry")}
                    </button>
                  </>
                ) : (
                  <>
                    {selectedEvidence.detected_os}
                    <span className="evidence-card-note">{t("evidence.osFromContent")}</span>
                  </>
                )}
              </span>
            </div>

            <div className="evidence-card-actions">
              {/* Con una sola evidencia no hay tabla donde pulsar «Re-verificar»,
                  así que la acción vive aquí. Con varias también: actúa sobre la
                  ficha abierta, que es lo que estás mirando. */}
              <button
                type="button"
                className="link-action"
                disabled={verifyingIds.has(selectedEvidence.evidence_id)}
                onClick={() => verifyOne(selectedEvidence.evidence_id)}
              >
                {verifyingIds.has(selectedEvidence.evidence_id)
                  ? t("evidenceTable.verifyingBtn")
                  : selectedEvidence.last_verification
                    ? t("evidenceTable.reverify")
                    : t("evidenceTable.verifyNow")}
              </button>
              <button
                type="button"
                className="link-action"
                onClick={() => void openActa(selectedEvidence)}
              >
                {t("evidence.acquisitionRecord")}
              </button>
            </div>

            {/* Último recurso, y sólo cuando la determinación automática no ha
                podido cerrar: una imagen dual-boot, señales en conflicto o un
                contenedor que el maletín no pudo abrir. RULE 2 prohíbe elegir
                un perfil en silencio, así que aquí lo ancla el operador, con
                la huella delante, no en mitad del chat. */}
            {activeCase.os_profile === null && redetecting === null && (
              <div className="note-rail">
                {t(onlyMaterial ? "evidence.anchorOnlyMaterial" : "evidence.anchorUndetermined")}
                <div className="anchor-actions">
                  <button
                    type="button"
                    className="chip-option"
                    disabled={anchoring !== null}
                    onClick={() => void anchorProfile("unix")}
                  >
                    {anchoring === "unix" ? t("evidence.anchoring") : "unix"}
                  </button>
                  <button
                    type="button"
                    className="chip-option"
                    disabled={anchoring !== null}
                    onClick={() => void anchorProfile("windows")}
                  >
                    {anchoring === "windows" ? t("evidence.anchoring") : "windows"}
                  </button>
                </div>
                {t("evidence.anchorFinal")}
              </div>
            )}

            {osError && <ErrorState message={osError} />}
          </div>
        )}

        {/* «Pasar a Investigación» vive ahora en la cabecera, como en las otras
            seis fases. Aquí abajo era la única excepción del patrón. */}
      </div>

      <Modal
        open={actaEvidence !== null}
        eyebrow={t("evidence.custodyEyebrow")}
        title={t("evidence.acquisitionRecord")}
        subtitle={actaEvidence ? evidenceFileName(actaEvidence) : undefined}
        onClose={() => setActaEvidence(null)}
        panelClassName="acta-modal"
        footerHint={t("evidence.escToClose")}
        footer={
          <>
            <button
              type="button"
              className="modal-action"
              disabled={!acta}
              onClick={downloadActa}
            >
              {t("evidence.downloadRecord")}
            </button>
            <button
              type="button"
              className="modal-action modal-action--quiet"
              onClick={() => setActaEvidence(null)}
            >
              {t("common.close")}
            </button>
          </>
        }
      >
        {actaLoading ? (
          <LoadingState label={t("evidence.generatingRecord")} />
        ) : actaError ? (
          <ErrorState message={actaError} />
        ) : acta && actaMeta ? (
          <div className="acta-rows">
            <div className="acta-row">
              <div className="eyebrow">{t("acta.case")}</div>
              <div className="acta-value">
                {acta.case.name} · {acta.case.examiner}
              </div>
            </div>
            <div className="acta-row">
              <div className="eyebrow">{t("acta.source")}</div>
              <div className="acta-value acta-value--mono">
                {acta.evidence.source_path ?? t("common.na")}
              </div>
            </div>
            <div className="acta-row">
              <div className="eyebrow">{t("acta.baselineHash")}</div>
              <div className="acta-value acta-value--mono">
                {acta.evidence.sha256}
                {acta.evidence.segment_count > 1 && (
                  <span className="acta-note">{t("acta.baselineNote")}</span>
                )}
              </div>
            </div>
            <div className="acta-row">
              <div className="eyebrow">{t("acta.size")}</div>
              <div className="acta-value acta-value--mono">
                {acta.evidence.total_size_human} (
                {acta.evidence.total_size_bytes.toLocaleString(locale)} {t("acta.bytes")})
                {acta.evidence.segment_count > 1 && (
                  <span className="acta-note">
                    {t("acta.sizeNote", {
                      count: acta.evidence.segment_count,
                      size: acta.evidence.size_human,
                    })}
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
                  {t("acta.segments", { count: acta.evidence.segments.length })}
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
              <div className="eyebrow">{t("acta.registered")}</div>
              <div className="acta-value acta-value--mono">
                {formatDate(acta.evidence.registered_at)}
              </div>
            </div>
            <div className="acta-row">
              <div className="eyebrow">{t("acta.readOnlyLevel")}</div>
              <div className="acta-value">{actaMeta.read_only_label}</div>
            </div>
            <div className="acta-row">
              <div className="eyebrow">{t("evidence.custodyEyebrow")}</div>
              <div
                className={`acta-value acta-value--mono${
                  acta.chain_of_custody.hash_chain_verified ? " is-ok" : " is-bad"
                }`}
              >
                entry_hash {acta.chain_of_custody.register_entry_hash ?? t("common.na")} ·{" "}
                {t(
                  acta.chain_of_custody.hash_chain_verified
                    ? "acta.chainVerified"
                    : "acta.chainNotVerified",
                )}
              </div>
            </div>
            <div className="acta-row">
              <div className="eyebrow">{t("acta.verification")}</div>
              <div
                className={`acta-value acta-value--mono${
                  acta.verification?.verified ? " is-ok" : acta.verification ? " is-bad" : ""
                }`}
              >
                {acta.verification
                  ? acta.verification.verified
                    ? t("acta.verifiedAt", { date: formatDate(acta.verification.verified_at) })
                    : t("acta.hashMismatch")
                  : t("acta.unverified")}
              </div>
            </div>
            <div className="acta-row">
              <div className="eyebrow">{t("acta.tool")}</div>
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
