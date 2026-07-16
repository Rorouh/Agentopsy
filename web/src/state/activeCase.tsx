import {
  createContext,
  useContext,
  useEffect,
  useState,
  type Dispatch,
  type ReactNode,
  type SetStateAction,
} from "react";
import type { Case } from "../api/types";

// Caso activo GLOBAL, compartido por todas las vistas (Casos, Investigación,
// Timeline, Documentos, MITRE) y persistido en localStorage — mismo patrón que
// la vista activa en App.tsx (VIEW_STORAGE_KEY). Antes cada vista resolvía su
// propio "caso más reciente" y no se sincronizaban: cambiar el caso en una vista
// no tocaba a las demás. Ahora hay una sola fuente de verdad.
const ACTIVE_CASE_STORAGE_KEY = "forensia-active-case";

function initialActiveCaseId(): string | null {
  try {
    return localStorage.getItem(ACTIVE_CASE_STORAGE_KEY);
  } catch {
    // localStorage no disponible: sin caso recordado, cada vista caerá al más
    // reciente al cargar su lista.
    return null;
  }
}

interface ActiveCaseContextValue {
  activeCaseId: string | null;
  // Dispatch completo para admitir tanto un id directo como un updater
  // funcional (p. ej. "conserva el actual si sigue existiendo, si no el más
  // reciente"), igual que un useState normal.
  setActiveCaseId: Dispatch<SetStateAction<string | null>>;
}

const ActiveCaseContext = createContext<ActiveCaseContextValue | null>(null);

export function ActiveCaseProvider({ children }: { children: ReactNode }) {
  const [activeCaseId, setActiveCaseId] = useState<string | null>(initialActiveCaseId);

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

  return (
    <ActiveCaseContext.Provider value={{ activeCaseId, setActiveCaseId }}>
      {children}
    </ActiveCaseContext.Provider>
  );
}

export function useActiveCase(): ActiveCaseContextValue {
  const ctx = useContext(ActiveCaseContext);
  if (!ctx) {
    throw new Error("useActiveCase debe usarse dentro de <ActiveCaseProvider>");
  }
  return ctx;
}

// Reconcilia el caso activo global contra la lista que la vista acaba de cargar
// y devuelve el `Case` resuelto. Si el id guardado ya no existe (caso borrado)
// o no hay ninguno, cae al más reciente (el backend lista los casos con el más
// reciente primero) y lo persiste — para que TODAS las vistas converjan al
// mismo caso. Devuelve la caída al más reciente de inmediato (sin esperar al
// efecto) para que no haya un parpadeo con "sin caso".
export function useActiveCaseFrom(cases: Case[]): Case | null {
  const { activeCaseId, setActiveCaseId } = useActiveCase();

  useEffect(() => {
    if (cases.length === 0) return;
    if (!activeCaseId || !cases.some((c) => c.id === activeCaseId)) {
      setActiveCaseId(cases[0].id);
    }
  }, [cases, activeCaseId, setActiveCaseId]);

  return cases.find((c) => c.id === activeCaseId) ?? cases[0] ?? null;
}
