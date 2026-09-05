import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type Dispatch,
  type ReactNode,
  type SetStateAction,
} from "react";
import { api } from "../api/client";
import type { Case } from "../api/types";

// Caso activo GLOBAL, compartido por todas las vistas (Evidencia, Investigación,
// Timeline, Informe, ATT&CK) y persistido en localStorage, mismo patrón que
// la vista activa en App.tsx (VIEW_STORAGE_KEY). Antes cada vista resolvía su
// propio "caso más reciente" y no se sincronizaban: cambiar el caso en una vista
// no tocaba a las demás. Ahora hay una sola fuente de verdad.
//
// Rediseño 2026-07: el bloque de caso vive en el SIDEBAR, siempre visible, y
// «cambiar caso» / «Nuevo caso» se disparan desde el armazón. Por eso la LISTA
// de casos también vive aquí: si cada vista la cargase por su cuenta, el
// sidebar tendría que cargarla una sexta vez en cada render.
const ACTIVE_CASE_STORAGE_KEY = "agentopsy-active-case";

function initialActiveCaseId(): string | null {
  try {
    return localStorage.getItem(ACTIVE_CASE_STORAGE_KEY);
  } catch {
    // localStorage no disponible: sin caso recordado, se cae al más reciente
    // al cargar la lista.
    return null;
  }
}

export type CasesPhase = "loading" | "ready" | "error";

interface ActiveCaseContextValue {
  activeCaseId: string | null;
  // Dispatch completo para admitir tanto un id directo como un updater
  // funcional (p. ej. "conserva el actual si sigue existiendo, si no el más
  // reciente"), igual que un useState normal.
  setActiveCaseId: Dispatch<SetStateAction<string | null>>;
  cases: Case[];
  activeCase: Case | null;
  phase: CasesPhase;
  error: string | null;
  // Recarga la lista desde el api y reconcilia el caso activo.
  reload: () => Promise<void>;
  // Refleja en la lista un caso que acaba de crearse o modificarse, sin pagar
  // otra vuelta al api.
  upsertCase: (c: Case) => void;
}

const ActiveCaseContext = createContext<ActiveCaseContextValue | null>(null);

export function ActiveCaseProvider({ children }: { children: ReactNode }) {
  const [activeCaseId, setActiveCaseId] = useState<string | null>(initialActiveCaseId);
  const [cases, setCases] = useState<Case[]>([]);
  const [phase, setPhase] = useState<CasesPhase>("loading");
  const [error, setError] = useState<string | null>(null);

  // Persiste cada cambio para que una recarga (o abrir otra vista) recupere el
  // mismo caso activo.
  useEffect(() => {
    try {
      if (activeCaseId) localStorage.setItem(ACTIVE_CASE_STORAGE_KEY, activeCaseId);
      else localStorage.removeItem(ACTIVE_CASE_STORAGE_KEY);
    } catch {
      /* ignora si localStorage no está disponible */
    }
  }, [activeCaseId]);

  const reload = useCallback(async () => {
    setPhase("loading");
    setError(null);
    try {
      const list = await api.cases.list();
      setCases(list);
      // Conserva el caso activo si sigue existiendo; si el guardado ya no está
      // (caso borrado) o no hay ninguno, cae al más reciente, el backend lista
      // con el más reciente primero.
      setActiveCaseId((prev) =>
        prev && list.some((c) => c.id === prev) ? prev : list[0]?.id ?? null,
      );
      setPhase("ready");
    } catch (err) {
      setError(String(err instanceof Error ? err.message : err));
      setPhase("error");
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  const upsertCase = useCallback((c: Case) => {
    setCases((prev) =>
      prev.some((x) => x.id === c.id) ? prev.map((x) => (x.id === c.id ? c : x)) : [c, ...prev],
    );
  }, []);

  const activeCase = useMemo(
    () => cases.find((c) => c.id === activeCaseId) ?? null,
    [cases, activeCaseId],
  );

  const value = useMemo(
    () => ({
      activeCaseId,
      setActiveCaseId,
      cases,
      activeCase,
      phase,
      error,
      reload,
      upsertCase,
    }),
    [activeCaseId, cases, activeCase, phase, error, reload, upsertCase],
  );

  return <ActiveCaseContext.Provider value={value}>{children}</ActiveCaseContext.Provider>;
}

export function useActiveCase(): ActiveCaseContextValue {
  const ctx = useContext(ActiveCaseContext);
  if (!ctx) {
    throw new Error("useActiveCase debe usarse dentro de <ActiveCaseProvider>");
  }
  return ctx;
}
