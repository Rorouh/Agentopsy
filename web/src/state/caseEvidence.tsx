import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { ApiError, GATEWAY_STATUS, api } from "../api/client";
import type { EvidenceHandle, EvidenceRegisterJob } from "../api/types";
import { useActiveCase } from "./activeCase";
import { useT } from "../i18n";
import { useCaseStream } from "./casePulse";

// Evidencia del caso activo, UNA sola fuente de verdad para toda la aplicación,
// mismo patrón que ActiveCaseProvider con la lista de casos.
//
// Antes cada vista pedía la lista por su cuenta y la guardaba en estado local:
// Evidencia, Investigación, Timeline y las cifras del sidebar (useCaseFacts).
// Cada una la leía UNA vez, al montar. Como App.tsx cambia de vista destruyendo
// la anterior, registrar una imagen solo actualizaba la lista de la vista de
// Evidencia: el sidebar seguía diciendo «sin evidencia», Investigación seguía
// creyendo que el caso no tenía ninguna (y el chat mandaba `evidence_id` vacío)
// y solo un F5 los ponía de acuerdo. Ahora el registro actualiza el store y
// todas las vistas se enteran a la vez.
//
// El JOB de registro también vive aquí, no en la página: el hash-gate de una
// imagen grande tarda minutos y el perito se va a Investigación mientras corre.
// Si el sondeo viviera en la vista, cambiar de vista lo mataría y nadie sabría
// que el registro terminó.

export type EvidencePhase = "loading" | "ready" | "error";

// Cadencia del sondeo del job de registro.
const POLL_MS = 1000;
// Cadencia cuando NO hay contacto con el api: sondear cada segundo contra un
// servicio que está reiniciándose no informa de nada.
const POLL_RETRY_MS = 3000;
// Fallos de transporte seguidos antes de DECIRLO. El primero es normalmente el
// reinicio de un contenedor y se recupera solo; avisar del primero convertiría un
// no-evento en una alarma.
const STALL_AFTER_FAILURES = 2;
// Cuánto se insiste sin contacto antes de dejar de sondear. Pasado ese punto la
// verdad es que no sabemos en qué quedó el registro, y decirlo es lo correcto:
// al volver a la vista, el re-enganche pregunta al api si el job sigue vivo.
const STALL_GIVE_UP_MS = 120_000;

interface CaseEvidenceContextValue {
  // Evidencia del caso activo. Vacía mientras no hay caso o no ha respondido la
  // lectura: nunca se rellena con filas del caso anterior.
  evidence: EvidenceHandle[];
  phase: EvidencePhase;
  // Fallo de la LECTURA de la lista (no del registro), con su mensaje real.
  error: string | null;
  // Sustituye en sitio los campos de una evidencia ya listada (verificar hash,
  // re-determinar el SO). Si no está en la lista del caso activo, no hace nada.
  replaceEvidence: (evidenceId: string, patch: Partial<EvidenceHandle>) => void;

  // Registro en segundo plano.
  registering: boolean;
  // Último estado sondeado del job (fase + bytes, para la barra de progreso).
  registerJob: EvidenceRegisterJob | null;
  registerError: string | null;
  // Sin contacto con el api mientras se sondea un registro. NO es un fallo del
  // registro: el hash-gate corre en el api y sigue su curso. Se pinta como aviso,
  // nunca como error, y desaparece en cuanto el sondeo vuelve a responder.
  registerStalled: string | null;
  startRegister: (sourcePath: string) => Promise<void>;
  // Sube en uno cada vez que un registro TERMINA BIEN y la lista ya se ha
  // recargado. Una vista lo observa para reaccionar (limpiar la selección de la
  // bandeja, avisar de que la evidencia ya está registrada) sin tener que
  // sondear ella el job.
  registeredSeq: number;
  // La evidencia que acaba de registrarse, para que el aviso pueda nombrar lo que
  // entró (cuántos segmentos, cuánto pesa el conjunto) en vez de un «hecho» seco.
  lastRegisteredId: string | null;
}

const CaseEvidenceContext = createContext<CaseEvidenceContextValue | null>(null);

export function CaseEvidenceProvider({ children }: { children: ReactNode }) {
  const t = useT();
  const { activeCaseId, upsertCase } = useActiveCase();

  const [evidence, setEvidence] = useState<EvidenceHandle[]>([]);
  const [phase, setPhase] = useState<EvidencePhase>("loading");
  const [error, setError] = useState<string | null>(null);
  const revEvidence = useCaseStream("evidence");

  const [registering, setRegistering] = useState(false);
  const [registerJob, setRegisterJob] = useState<EvidenceRegisterJob | null>(null);
  // Ata el sondeo a SU caso: cambiar de caso no debe sondear el job del anterior
  // contra el nuevo (daría 404). El job sigue vivo en el api y se retoma al
  // volver a ese caso.
  const [registerJobRef, setRegisterJobRef] = useState<
    { caseId: string; jobId: string } | null
  >(null);
  const [registerError, setRegisterError] = useState<string | null>(null);
  const [registerStalled, setRegisterStalled] = useState<string | null>(null);
  const [registeredSeq, setRegisteredSeq] = useState(0);
  const [lastRegisteredId, setLastRegisteredId] = useState<string | null>(null);

  // Espejo de activeCaseId en un ref: las lecturas son asíncronas y el perito
  // puede cambiar de caso mientras una está en vuelo. Se declara ANTES que los
  // demás efectos para que ya esté actualizado cuando estos corran.
  const activeCaseIdRef = useRef<string | null>(activeCaseId);
  useEffect(() => {
    activeCaseIdRef.current = activeCaseId;
  }, [activeCaseId]);

  // `announceLoading` distingue las dos lecturas: la de estrenar un caso (la
  // vista aún no tiene nada que pintar, procede el estado de carga) y el refresco
  // de una lista ya pintada (registro terminado), que no debe hacer parpadear ni
  // la tabla ni las cifras del sidebar.
  const load = useCallback(async (caseId: string, announceLoading: boolean) => {
    if (announceLoading) setPhase("loading");
    try {
      const list = await api.cases.listEvidence(caseId);
      // Respuesta de un caso que ya no es el activo: se descarta.
      if (activeCaseIdRef.current !== caseId) return;
      setEvidence(list);
      setError(null);
      setPhase("ready");
    } catch (err) {
      if (activeCaseIdRef.current !== caseId) return;
      setEvidence([]);
      setError(String(err instanceof Error ? err.message : err));
      setPhase("error");
    }
  }, []);

  // Sigue al caso activo. Limpia de inmediato para que ninguna vista pinte filas
  // zombi del caso anterior.
  useEffect(() => {
    setEvidence([]);
    setError(null);
    if (!activeCaseId) {
      setPhase("ready");
      return;
    }
    void load(activeCaseId, true);
  }, [activeCaseId, load]);

  // Reposición EN SILENCIO cuando el directorio de evidencias del caso cambia.
  // Cubre lo que el sondeo del registro no ve: una evidencia registrada desde
  // otra pestaña, o un registro que terminó mientras esta pestaña estaba en
  // segundo plano. `announceLoading` en false: la tabla no debe parpadear.
  useEffect(() => {
    if (!activeCaseId || revEvidence === 0) return;
    void load(activeCaseId, false);
  }, [activeCaseId, revEvidence, load]);

  const replaceEvidence = useCallback(
    (evidenceId: string, patch: Partial<EvidenceHandle>) => {
      setEvidence((prev) =>
        prev.map((ev) => (ev.evidence_id === evidenceId ? { ...ev, ...patch } : ev)),
      );
    },
    [],
  );

  // Arranca el registro y vuelve al instante: el hash-gate (hash del origen →
  // copia inmutable → re-hash) recorre todos los bytes tres veces y tarda
  // minutos en una imagen grande. El avance llega por sondeo del job.
  const startRegister = useCallback(async (sourcePath: string) => {
    // Instantánea del caso en el momento del clic: el job queda anclado a él.
    const caseId = activeCaseIdRef.current;
    if (!caseId || !sourcePath) return;
    setRegisterError(null);
    setRegisterStalled(null);
    setRegistering(true);
    setRegisterJob(null);
    try {
      const job = await api.evidence.registerAsync(caseId, sourcePath);
      setRegisterJob(job);
      setRegisterJobRef({ caseId, jobId: job.job_id });
    } catch (err) {
      setRegistering(false);
      setRegisterError(String(err instanceof Error ? err.message : err));
    }
  }, []);

  // Sondeo del job de registro (~1 s). Vive en el provider, así que sobrevive a
  // cambiar de vista: el perito puede irse a Investigación y la evidencia
  // aparecerá allí en cuanto el registro termine.
  useEffect(() => {
    if (!registerJobRef || registerJobRef.caseId !== activeCaseId) return;
    const { caseId, jobId } = registerJobRef;
    let cancelled = false;
    let timer: number | undefined;

    // Fallos de transporte SEGUIDOS y cuándo empezó la racha: sondear es hablar con
    // el api por un proxy, y eso puede fallar sin que el registro tenga nada que ver.
    let failures = 0;
    let firstFailureAt = 0;

    const poll = async () => {
      let job: EvidenceRegisterJob;
      try {
        job = await api.evidence.registerJob(caseId, jobId);
      } catch (err) {
        if (cancelled) return;
        // Un 502/503/504 (o un fetch que no sale) es el PROXY diciendo que no
        // alcanzó al api, no el api diciendo que el registro falló. El hash-gate
        // corre dentro del api y sobrevive a que el navegador pierda contacto, así
        // que darlo por fallado era MENTIR sobre la cadena de custodia: el perito
        // leía «No se pudo registrar la evidencia» con el registro corriendo, y con
        // la página de error de nginx en crudo como explicación.
        const transporte =
          !(err instanceof ApiError) || GATEWAY_STATUS.has(err.status);
        if (transporte) {
          failures += 1;
          if (failures === 1) firstFailureAt = Date.now();
          const sinContacto = Date.now() - firstFailureAt;
          if (sinContacto < STALL_GIVE_UP_MS) {
            if (failures > STALL_AFTER_FAILURES) {
              setRegisterStalled(
                t("register.stalled", { seconds: Math.round(sinContacto / 1000) }),
              );
            }
            timer = window.setTimeout(() => void poll(), POLL_RETRY_MS);
            return;
          }
          // Se agotó la insistencia. Lo honesto no es «falló», es «no sabemos»:
          // al volver a esta vista el re-enganche pregunta al api si sigue vivo.
          setRegistering(false);
          setRegisterStalled(null);
          setRegisterError(
            t("register.gaveUp", {
              seconds: Math.round(sinContacto / 1000),
              detail: err instanceof Error ? err.message : String(err),
            }),
          );
          setRegisterJobRef(null);
          return;
        }
        // 404: el api responde pero no conoce este job, o sea que se reinició
        // mientras corría. El registro es ATÓMICO, así que no publicó nada a medias;
        // se recarga la lista por si llegó a terminar antes del reinicio y se dice
        // exactamente eso, en vez de un fallo genérico.
        if (err instanceof ApiError && err.status === 404) {
          await load(caseId, false);
          setRegistering(false);
          setRegisterStalled(null);
          setRegisterError(t("register.jobLost"));
          setRegisterJobRef(null);
          return;
        }
        setRegistering(false);
        setRegisterStalled(null);
        setRegisterError(String(err instanceof Error ? err.message : err));
        setRegisterJobRef(null);
        return;
      }
      if (cancelled) return;
      // Contacto recuperado: la racha se olvida y el aviso se retira.
      failures = 0;
      setRegisterStalled(null);
      setRegisterJob(job);
      if (job.state === "pending" || job.state === "running") {
        timer = window.setTimeout(() => void poll(), POLL_MS);
        return;
      }

      if (job.state === "error") {
        // RULE 2: el mensaje del backend nombra la dependencia/guarda que falló.
        setRegistering(false);
        setRegisterError(job.error ?? t("register.errorNoDetail"));
        setRegisterJobRef(null);
        return;
      }

      // done: la evidencia ya está publicada (registro atómico). Se recarga la
      // lista y la ficha del caso (el triage puede haber derivado os_profile)
      // ANTES de soltar el job, y ese orden es el arreglo de fondo: soltarlo
      // cambia las dependencias de este efecto, React ejecuta su limpieza, y esa
      // limpieza marca la corrida como cancelada. Con el `setRegisterJobRef(null)`
      // delante, el `await` de la recarga daba tiempo a que la limpieza corriera y
      // TODO lo que venía después se descartaba: la evidencia recién registrada no
      // entraba en la lista, la ficha del caso no se refrescaba y el aviso de
      // éxito no llegaba a pintarse. De ahí el F5.
      await load(caseId, false);
      try {
        upsertCase(await api.cases.get(caseId));
      } catch {
        /* la evidencia ya quedó registrada; la ficha se refresca al volver */
      }
      setRegistering(false);
      // El anuncio va SIEMPRE detrás de la recarga, y solo si el perito sigue en
      // ese caso: quien lo observe ve la evidencia ya en la lista, nunca un aviso
      // que se adelanta ni el de un caso que ya no tiene delante.
      if (activeCaseIdRef.current === caseId) {
        setLastRegisteredId(job.evidence_id);
        setRegisteredSeq((n) => n + 1);
      }
      setRegisterJobRef(null);
    };

    void poll();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [activeCaseId, registerJobRef, load, upsertCase, t]);

  // Re-enganche: al arrancar (o al cambiar de caso) pregunta si ese caso tiene un
  // registro VIVO y retoma su sondeo. Cerrar la pestaña no aborta nada, el job
  // corre en el api.
  useEffect(() => {
    setRegisterJob(null);
    setRegisterJobRef(null);
    setRegistering(false);
    setRegisterError(null);
    setRegisterStalled(null);
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

  const value = useMemo(
    () => ({
      evidence,
      phase,
      error,
      replaceEvidence,
      registering,
      registerJob,
      registerError,
      registerStalled,
      startRegister,
      registeredSeq,
      lastRegisteredId,
    }),
    [
      evidence,
      phase,
      error,
      replaceEvidence,
      registering,
      registerJob,
      registerError,
      registerStalled,
      startRegister,
      registeredSeq,
      lastRegisteredId,
    ],
  );

  return <CaseEvidenceContext.Provider value={value}>{children}</CaseEvidenceContext.Provider>;
}

export function useCaseEvidence(): CaseEvidenceContextValue {
  const ctx = useContext(CaseEvidenceContext);
  if (!ctx) {
    throw new Error("useCaseEvidence debe usarse dentro de <CaseEvidenceProvider>");
  }
  return ctx;
}
