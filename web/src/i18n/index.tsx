// El eje de idioma en React: provider, hooks y el `t()` que pinta cada cadena.
//
// Calcado de `ThemeProvider` a propósito (mismo patrón de contexto, mismo
// localStorage, mismo efecto que publica el valor en el documento): son dos
// preferencias del mismo rango y quien lea una entiende la otra sin esfuerzo.

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { type MessageKey } from "./en";
import {
  CATALOGOS,
  DEFAULT_LANG,
  LANGS,
  LOCALES,
  type Lang,
  type Params,
  interpolar,
  publishLang,
  readStoredLang,
} from "./state";

export { LANGS, LOCALES, DEFAULT_LANG, tr, type Lang, type Params } from "./state";
export type { MessageKey } from "./en";

// Un plural declara DOS claves, `base.one` y `base.other`. `PluralKey` es la
// intersección de las bases que tienen las dos, así que pedir `tn()` sobre una
// clave a la que le falte una de las formas no compila.
type OtherBase<K> = K extends `${infer B}.other` ? B : never;
type OneBase<K> = K extends `${infer B}.one` ? B : never;
export type PluralKey = OtherBase<MessageKey> & OneBase<MessageKey>;

interface LangCtx {
  lang: Lang;
  setLang: (l: Lang) => void;
  // Locale de `Intl` derivado del idioma: fechas y números del caso se leen en
  // la convención del idioma elegido, no en una fijada en el código.
  locale: string;
  t: (key: MessageKey, params?: Params) => string;
  tn: (base: PluralKey, count: number, params?: Params) => string;
}

const LanguageContext = createContext<LangCtx | null>(null);

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [lang, setLang] = useState<Lang>(readStoredLang);

  // Publica el idioma fuera de React: el espejo que lee `api/client.ts` para la
  // cabecera, el `localStorage` y el atributo `lang` del documento.
  useEffect(() => {
    publishLang(lang);
  }, [lang]);

  const t = useCallback(
    (key: MessageKey, params?: Params) => interpolar(CATALOGOS[lang][key], params),
    [lang],
  );

  const tn = useCallback(
    (base: PluralKey, count: number, params?: Params) => {
      const key = (count === 1 ? `${base}.one` : `${base}.other`) as MessageKey;
      return interpolar(CATALOGOS[lang][key], { count, ...params });
    },
    [lang],
  );

  const value = useMemo<LangCtx>(
    () => ({ lang, setLang, locale: LOCALES[lang], t, tn }),
    [lang, t, tn],
  );

  return <LanguageContext.Provider value={value}>{children}</LanguageContext.Provider>;
}

// Sin default silencioso: usar `t()` fuera del provider es un fallo de montaje,
// y devolver un catálogo de repuesto lo dejaría corriendo con el idioma
// equivocado sin que nadie se entere (RULE 2).
export function useLang(): LangCtx {
  const ctx = useContext(LanguageContext);
  if (!ctx) throw new Error("useLang: falta <LanguageProvider> por encima");
  return ctx;
}

// Azúcar para el caso normal, que es pintar texto.
export function useT(): LangCtx["t"] {
  return useLang().t;
}
