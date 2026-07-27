import { createContext, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

// Cabecera contextual del rediseño 2026-07: el armazón pinta UNA cabecera
// (eyebrow · título · meta · acción) y las páginas le publican su contenido en
// vez de dibujar la suya. Transporta DATOS YA RESUELTOS por la página, nunca
// reglas: el armazón no sabe cuándo una acción procede, solo la pinta (RULE 3).
export interface ShellHeaderPayload {
  title: string;
  meta?: string;
  action?: ReactNode;
}

interface ShellHeaderCtx {
  payload: ShellHeaderPayload | null;
  publish: (p: ShellHeaderPayload | null) => void;
}

const Ctx = createContext<ShellHeaderCtx | null>(null);

export function ShellHeaderProvider({ children }: { children: ReactNode }) {
  const [payload, setPayload] = useState<ShellHeaderPayload | null>(null);
  const value = useMemo(() => ({ payload, publish: setPayload }), [payload]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useShellHeader(): ShellHeaderCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useShellHeader debe usarse dentro de <ShellHeaderProvider>");
  return ctx;
}

// Publica la cabecera desde una página y la retira al desmontar, para que una
// vista no herede el título de la anterior.
export function usePublishShellHeader(p: ShellHeaderPayload | null, deps: unknown[]) {
  const { publish } = useShellHeader();
  useEffect(() => {
    publish(p);
    return () => publish(null);
    // El payload lleva ReactNode (identidad nueva en cada render): se declara
    // el disparador explícito en vez de comparar el objeto.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
}
