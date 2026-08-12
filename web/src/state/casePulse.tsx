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
import { api } from "../api/client";
import type { CaseStream } from "../api/types";
import { useActiveCase } from "./activeCase";

// El SONDEO COMPARTIDO que hace que la interfaz se refresque sola.
//
// El problema: Agentopsy trabaja en segundo plano (un análisis persiste hallazgos
// según los concluye, un registro de evidencia recorre gigabytes, una redacción
// tarda minutos, un lote de grafos va hallazgo a hallazgo), pero cada vista leía
// sus datos UNA vez al montarse, y `App` DESTRUYE la vista anterior al cambiar de
// sección. Resultado: había que pulsar F5, y no había forma de distinguir «aún no
// ha terminado» de «terminó hace diez minutos y nadie te lo dijo».
//
// La forma: UNA petición barata (`GET /api/cases/{id}/pulse`, que es un `stat` por
// flujo, sin leer contenido) devuelve una FIRMA por flujo. Cuando la firma de un
// flujo cambia, este store incrementa la REVISIÓN de ese flujo, y la vista que lo
// pinta recarga SUS datos por su endpoint de siempre poniendo esa revisión en las
// dependencias de su efecto. Así el coste no crece con el número de vistas
// abiertas ni con el tamaño del caso, y cada vista sigue siendo dueña de sus
// datos (RULE 3: aquí no hay lógica de negocio, sólo la señal).
//
// Vive por ENCIMA de las vistas, en `App`, por el mismo motivo que
// `CaseEvidenceProvider`: cambiar de sección no puede desmontar el sondeo.

// Cada cuánto se pregunta. Dos cadencias porque son dos situaciones distintas: con
// algo corriendo, el perito está MIRANDO y espera ver avanzar; sin nada corriendo,
// el sondeo sólo cubre lo que pueda haber cambiado desde otra pestaña, y ahí gastar
// una petición cada dos segundos no compra nada.
const CADENCIA_ACTIVA_MS = 2000;
const CADENCIA_REPOSO_MS = 10000;

// Tras un fallo de transporte (el api reiniciándose, un 502 del proxy) se espera
// más: el pulso es una señal de fondo y no debe convertirse en un martilleo
// mientras el backend levanta.
const CADENCIA_FALLO_MS = 15000;

export interface CasePulseValue {
  // Revisión por flujo: un número que sólo sirve para compararlo consigo mismo.
  // Cambia cuando el flujo cambió; una vista lo pone en las dependencias de su
  // efecto de recarga.
  revisions: Record<CaseStream, number>;
  // Trabajos de fondo en curso, por tipo. Lo usa el propio store para decidir la
  // cadencia, y las vistas para saber que hay algo vivo sin pedirlo aparte.
  runningJobs: number;
  jobsByKind: Record<string, number>;
  // Fuerza una comprobación inmediata: se llama al terminar una acción del
  // perito, para no esperar a la siguiente vuelta.
  refresh: () => void;
}

const VACIO: Record<CaseStream, number> = {
  case: 0,
  evidence: 0,
  findings: 0,
  audit: 0,
  documents: 0,
  graphs: 0,
  mitre_proposals: 0,
  mitre_verdicts: 0,
  timeline: 0,
  knowledge: 0,
  chats: 0,
};

const CasePulseContext = createContext<CasePulseValue | null>(null);

export function CasePulseProvider({ children }: { children: ReactNode }) {
  const { activeCaseId } = useActiveCase();
  const [revisions, setRevisions] = useState<Record<CaseStream, number>>(VACIO);
  const [runningJobs, setRunningJobs] = useState(0);
  const [jobsByKind, setJobsByKind] = useState<Record<string, number>>({});
  // Las firmas de la última vuelta. En una ref y no en estado: cambiarlas no debe
  // renderizar por sí mismo, sólo alimentar la comparación de la siguiente.
  const firmasRef = useRef<Record<string, string>>({});
  // Se incrementa para pedir una comprobación fuera de turno.
  const [tick, setTick] = useState(0);

  const refresh = useCallback(() => setTick((t) => t + 1), []);

  // Al cambiar de caso se olvida todo: las firmas de un caso no dicen nada de
  // otro, y compararlas haría que la primera vuelta del caso nuevo pareciera un
  // cambio en todos los flujos a la vez.
  useEffect(() => {
    firmasRef.current = {};
    setRevisions(VACIO);
    setRunningJobs(0);
    setJobsByKind({});
  }, [activeCaseId]);

  useEffect(() => {
    if (!activeCaseId) return;
    let cancelado = false;
    let temporizador: number | undefined;

    const vuelta = async () => {
      let siguiente = CADENCIA_REPOSO_MS;
      try {
        const pulso = await api.cases.pulse(activeCaseId);
        if (cancelado) return;

        const previas = firmasRef.current;
        const actuales: Record<string, string> = pulso.streams;
        // La primera vuelta de un caso no cuenta como cambio: no había nada con
        // qué comparar, y contarla haría recargar todas las vistas a la vez justo
        // después de que ya se hubieran cargado solas.
        const cambiados = Object.keys(actuales).filter(
          (k) => previas[k] !== undefined && previas[k] !== actuales[k],
        );
        firmasRef.current = actuales;

        if (cambiados.length > 0) {
          setRevisions((prev) => {
            const next = { ...prev };
            for (const k of cambiados) {
              if (k in next) next[k as CaseStream] = next[k as CaseStream] + 1;
            }
            return next;
          });
        }

        const corriendo = pulso.jobs.running;
        setRunningJobs((prev) => (prev === corriendo ? prev : corriendo));
        setJobsByKind((prev) => {
          const igual =
            Object.keys(prev).length === Object.keys(pulso.jobs.by_kind).length &&
            Object.entries(pulso.jobs.by_kind).every(([k, v]) => prev[k] === v);
          return igual ? prev : pulso.jobs.by_kind;
        });
        siguiente = corriendo > 0 ? CADENCIA_ACTIVA_MS : CADENCIA_REPOSO_MS;
      } catch {
        // Un pulso que falla no se le cuenta al perito: es una señal de fondo, y
        // el fallo que SÍ importa lo reporta la vista cuando pide sus datos. Se
        // espera más y se vuelve a intentar; las firmas se conservan, así que al
        // recuperar el contacto se compara contra lo último que se supo.
        if (cancelado) return;
        siguiente = CADENCIA_FALLO_MS;
      }
      if (!cancelado) temporizador = window.setTimeout(() => void vuelta(), siguiente);
    };

    void vuelta();
    return () => {
      cancelado = true;
      if (temporizador !== undefined) window.clearTimeout(temporizador);
    };
  }, [activeCaseId, tick]);

  // Con la pestaña oculta el navegador ya frena los temporizadores, pero al
  // volver el perito espera ver lo de AHORA, no lo de la última vuelta que
  // llegase a correr. Volver a la pestaña comprueba de inmediato.
  useEffect(() => {
    const alVolver = () => {
      if (document.visibilityState === "visible") refresh();
    };
    document.addEventListener("visibilitychange", alVolver);
    window.addEventListener("focus", alVolver);
    return () => {
      document.removeEventListener("visibilitychange", alVolver);
      window.removeEventListener("focus", alVolver);
    };
  }, [refresh]);

  const value = useMemo(
    () => ({ revisions, runningJobs, jobsByKind, refresh }),
    [revisions, runningJobs, jobsByKind, refresh],
  );

  return <CasePulseContext.Provider value={value}>{children}</CasePulseContext.Provider>;
}

export function useCasePulse(): CasePulseValue {
  const ctx = useContext(CasePulseContext);
  if (!ctx) throw new Error("useCasePulse debe usarse dentro de <CasePulseProvider>");
  return ctx;
}

/**
 * La revisión de uno o varios flujos del caso. Se pone en las dependencias del
 * efecto que recarga los datos de la vista:
 *
 *     const rev = useCaseStream("findings");
 *     useEffect(() => { void recargar(); }, [caseId, rev]);
 *
 * Con varios flujos devuelve su suma, que cambia cuando cambia cualquiera de
 * ellos. El valor es opaco: sólo sirve para compararlo consigo mismo.
 */
export function useCaseStream(...streams: CaseStream[]): number {
  const { revisions } = useCasePulse();
  return streams.reduce((n, s) => n + (revisions[s] ?? 0), 0);
}
