import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ApiError, api } from "../api/client";
import type {
  CustodyAct,
  EvidenceHandle,
  EvidenceMetadata,
  EvidenceRegisterJob,
  EvidenceSource,
} from "../api/types";
import type { ViewId } from "../navigation/navItems";
import { useActiveCase } from "../state/activeCase";
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
  const [evidence, setEvidence] = useState<EvidenceHandle[]>([]);

  const [registering, setRegistering] = useState(false);
  // Registro en SEGUNDO PLANO: el hash-gate de una imagen grande tarda minutos,
  // así que no vive dentro de la petición HTTP (504 del proxy + copia cortada a
  // medias). `registerJob` es el último estado sondeado (fase + bytes, para la
  // barra); `registerJobRef` ata el sondeo a SU caso, cambiar de caso no debe
  // sondear el job del anterior contra el nuevo (daría 404).
  const [registerJob, setRegisterJob] = useState<EvidenceRegisterJob | null>(null);
  const [registerJobRef, setRegisterJobRef] = useState<
    { caseId: string; jobId: string } | null
  >(null);
  // Flash de éxito de registro (2 s), aria-live en EvidenceInbox.
  const [registerSuccess, setRegisterSuccess] = useState(false);
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
  // Etiquetado para que el aviso nombre el fallo con honestidad: mezclar ambos
  // en un mismo slot hacía que un 404 de verify apareciera como «No se pudo
  // registrar la evidencia: …», que era falso por los dos lados.
  const [evidenceError, setEvidenceError] = useState<
    { kind: "register" | "verify"; message: string } | null
  >(null);

  // Espejo de activeCaseId en un ref. El registro es asíncrono (hashear una
  // imagen de varios GB tarda) y el operador puede cambiar de caso mientras
  // corre; el closure anclaría la evidencia a un case_id viejo.
  const activeCaseIdRef = useRef<string | null>(null);
  useEffect(() => {
    activeCaseIdRef.current = activeCaseId;
  }, [activeCaseId]);

  useEffect(() => {
    return () => window.clearTimeout(successTimer.current);
  }, []);

  // Única fuente de verdad de la lista de evidencias: sigue a activeCaseId. Se
  // limpia de inmediato para que la UI no pinte filas zombi del caso anterior.
  useEffect(() => {
    if (!activeCaseId) {
      setEvidence([]);
      return;
    }
    let cancelled = false;
    setEvidence([]);
    (async () => {
      try {
        const ev = await api.cases.listEvidence(activeCaseId);
        if (!cancelled) setEvidence(ev);
      } catch (err) {
        if (!cancelled) {
          setEvidenceError({
            kind: "register",
            message: String(err instanceof Error ? err.message : err),
          });
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [activeCaseId]);

  // Devuelve la bandeja recién leída (además de fijarla en el estado) para que
  // quien la refresca pueda decidir sobre la lista NUEVA sin esperar al render.
  const loadSources = useCallback(async (): Promise<EvidenceSource[] | null> => {
    setLoadingSources(true);
    setEvidenceError(null);
    try {
      const res = await api.evidence.listSources();
      setSources(res.sources);
      // Si el fichero seleccionado desapareció de la bandeja, deselecciona,
      // jamás se registra una ruta que ya no está (el backend la rechazaría).
      setSelectedSourcePath((prev) => (res.sources.some((s) => s.path === prev) ? prev : ""));
      return res.sources;
    } catch (err) {
      setSources(null);
      setEvidenceError({
        kind: "register",
        message: String(err instanceof Error ? err.message : err),
      });
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

  // Arranca el registro en SEGUNDO PLANO y devuelve al instante: el hash-gate
  // (hash del origen → copia inmutable → re-hash) recorre todos los bytes tres
  // veces y tarda minutos en una imagen grande. El avance llega por sondeo del
  // job; el registro sobrevive a cerrar la pestaña.
  const registerSelectedSource = useCallback(async () => {
    // Instantánea del caso en el momento del clic: el job queda anclado a él y
    // el operador puede cambiar de caso mientras corre.
    const intendedCaseId = activeCase?.id;
    if (!intendedCaseId || !selectedSourcePath) return;
    setEvidenceError(null);
    setRegistering(true);
    setRegisterJob(null);
    try {
      const job = await api.evidence.registerAsync(intendedCaseId, selectedSourcePath);
      setRegisterJob(job);
      setRegisterJobRef({ caseId: intendedCaseId, jobId: job.job_id });
    } catch (err) {
      setRegistering(false);
      setEvidenceError({
        kind: "register",
        message: String(err instanceof Error ? err.message : err),
      });
    }
  }, [activeCase, selectedSourcePath]);

  // Sondeo del job de registro (~1 s). Solo sondea el job de SU caso: si el
  // operador cambia de caso, el job sigue vivo en el servidor y se re-engancha
  // al volver (efecto siguiente).
  useEffect(() => {
    if (!registerJobRef || registerJobRef.caseId !== activeCaseId) return;
    const { caseId, jobId } = registerJobRef;
    let cancelled = false;
    let timer: number | undefined;

    const poll = async () => {
      let job: EvidenceRegisterJob;
      try {
        job = await api.evidence.registerJob(caseId, jobId);
      } catch (err) {
        if (cancelled) return;
        setRegisterJobRef(null);
        setRegistering(false);
        setEvidenceError({
          kind: "register",
          message: String(err instanceof Error ? err.message : err),
        });
        return;
      }
      if (cancelled) return;
      setRegisterJob(job);
      if (job.state === "pending" || job.state === "running") {
        timer = window.setTimeout(() => void poll(), 1000);
        return;
      }

      setRegisterJobRef(null);
      setRegistering(false);
      if (job.state === "error") {
        // RULE 2: el mensaje del backend nombra la dependencia/guarda que falló.
        setEvidenceError({
          kind: "register",
          message: job.error ?? "el registro terminó en error sin detalle",
        });
        return;
      }

      // done: la evidencia ya está publicada (registro atómico). Refresca la
      // lista y la ficha del caso (el triage puede haber derivado os_profile).
      setSelectedSourcePath("");
      try {
        const [list, refreshed] = await Promise.all([
          api.cases.listEvidence(caseId),
          api.cases.get(caseId),
        ]);
        if (cancelled) return;
        if (activeCaseIdRef.current === caseId) setEvidence(list);
        upsertCase(refreshed);
      } catch {
        /* refresco best-effort; la evidencia ya quedó registrada */
      }
      if (cancelled) return;
      setRegisterSuccess(true);
      window.clearTimeout(successTimer.current);
      successTimer.current = window.setTimeout(() => setRegisterSuccess(false), 2000);
    };

    void poll();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [activeCaseId, registerJobRef, upsertCase]);

  // Re-enganche: al montar (o al cambiar de caso) pregunta si ese caso tiene un
  // registro VIVO y retoma su sondeo. Cerrar/reabrir la ventana no aborta nada
  // el job corre en el api.
  useEffect(() => {
    setRegisterJob(null);
    setRegisterJobRef(null);
    setRegistering(false);
    if (!activeCaseId) return;
    let cancelled = false;
    (async () => {
      try {
        const jobs = await api.evidence.listRegisterJobs(activeCaseId);
        if (cancelled) return;
        const live = jobs.find((j) => j.state === "pending" || j.state === "running");
        if (!live) return;
        setRegisterJob(live);
        setRegisterJobRef({ caseId: activeCaseId, jobId: live.job_id });
        setRegistering(true);
      } catch {
        /* sin re-enganche: no es un fallo del caso, solo no hay job que retomar */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [activeCaseId]);

  const verifyOne = useCallback(
    async (evidenceId: string) => {
      const intendedCaseId = activeCase?.id;
      if (!intendedCaseId) return;
      setEvidenceError(null);
      setVerifyingIds((prev) => new Set(prev).add(evidenceId));
      try {
        const updated = await api.cases.verifyEvidence(intendedCaseId, evidenceId);
        // El router devuelve el handle completo con last_verification recién
        // persistida (verification.json + audit.jsonl). Sustituye la fila en
        // sitio, pero solo si el caso activo no ha cambiado por debajo.
        if (activeCaseIdRef.current === intendedCaseId) {
          setEvidence((prev) =>
            prev.map((ev) => (ev.evidence_id === evidenceId ? { ...ev, ...updated } : ev)),
          );
        }
      } catch (err) {
        setEvidenceError({
          kind: "verify",
          message: String(err instanceof Error ? err.message : err),
        });
      } finally {
        setVerifyingIds((prev) => {
          const next = new Set(prev);
          next.delete(evidenceId);
          return next;
        });
      }
    },
    [activeCase],
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
      const caseId = activeCaseIdRef.current;
      if (!caseId || redetecting) return;
      setRedetecting(evidenceId);
      setOsError(null);
      try {
        const res = await api.cases.redetectEvidenceOs(caseId, evidenceId);
        if (activeCaseIdRef.current !== caseId) return;
        setEvidence((prev) =>
          prev.map((ev) => (ev.evidence_id === evidenceId ? res.evidence : ev)),
        );
        upsertCase(res.case);
      } catch (err) {
        setOsError(
          err instanceof ApiError ? err.detail : String(err instanceof Error ? err.message : err),
        );
      } finally {
        setRedetecting(null);
      }
    },
    [redetecting, upsertCase],
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
      const caseId = activeCaseIdRef.current;
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
    [anchoring, upsertCase],
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
          onClick={() => void registerSelectedSource()}
        >
          {registering ? "Registrando…" : "Registrar evidencia"}
        </button>
      ) : undefined,
    },
    [activeCase?.id, activeCase?.examiner, caseClosed, canRegister, registering],
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
            registerError={evidenceError?.kind === "register" ? evidenceError.message : null}
            registerSuccess={registerSuccess}
            uploading={uploading}
            uploadProgress={uploadProgress}
            uploadError={uploadError}
            uploadNotice={uploadNotice}
            onSelectSource={setSelectedSourcePath}
            onLoadSources={() => void loadSources()}
            onRegister={() => void registerSelectedSource()}
            onUploadFiles={uploadSources}
          />
        </div>

        {/* 3 · Evidencias del caso */}
        <div className="section-stack">
          <div className="rule-label">
            <span className="eyebrow eyebrow--section">Evidencias del caso</span>
            <span className="rule" />
            <span className="rule-count">{evidence.length}</span>
          </div>
          <EvidenceTable
            evidence={evidence}
            verifyingIds={verifyingIds}
            onVerify={verifyOne}
            verifyError={evidenceError?.kind === "verify" ? evidenceError.message : null}
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
            <div className="prose">
              Agentopsy lo determina del CONTENIDO de la evidencia, nunca de la máquina en la
              que corre: cabeceras, sectores de arranque y, en una imagen contenedor, el
              directorio raíz de sus sistemas de ficheros leído a través del maletín (solo
              lectura a nivel de bloque: la imagen no se monta). El orquestador enruta con
              ese perfil al sub-agente que corresponde.
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
              Solo lectura a nivel de sistema de ficheros (<span className="mono">chmod 0444</span>
              ); el bloqueo a nivel de bloque llega en la Fase 2. El acta de adquisición recoge
              el hash baseline, el tamaño y el enlace de la cadena encadenada por hash.
            </div>
            <div className="custody-rows">
              {evidence.map((ev) => (
                <div className="custody-row" key={ev.evidence_id}>
                  <span className="custody-name">{evidenceFileName(ev)}</span>
                  <span className="custody-meta">{formatBytes(ev.size)}</span>
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
              <div className="acta-value acta-value--mono">{acta.evidence.sha256}</div>
            </div>
            <div className="acta-row">
              <div className="eyebrow">Tamaño</div>
              <div className="acta-value acta-value--mono">
                {acta.evidence.size_human} (
                {acta.evidence.size_bytes.toLocaleString("es-ES")} bytes)
              </div>
            </div>
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
