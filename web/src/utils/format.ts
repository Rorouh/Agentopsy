// Helpers de formateo puros, sin dependencias de UI. Compartidos por las
// páginas para no duplicar lógica de presentación.
//
// Dos de los tres dependen del IDIOMA, así que existen en dos formas: la
// función pura, que recibe lo que necesita por parámetro y se puede llamar
// desde cualquier sitio, y el hook `useFormat()`, que las devuelve ya atadas al
// idioma en curso para el caso normal, que es pintar dentro de un componente.
//
// `formatBytes` NO depende del idioma: sus unidades son símbolos del SI y se
// escriben igual en las dos lenguas.

import { useMemo } from "react";

import { useLang } from "../i18n";

export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const exp = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** exp).toFixed(exp === 0 ? 0 : 1)} ${units[exp]}`;
}

// El locale sale del idioma elegido y no está fijado en el código. Los dos que
// servimos (`es-ES` y `en-GB`) dan dd/mm/aaaa: en un informe pericial una fecha
// que se puede leer del revés según quién la mire es una trampa, y por eso el
// inglés va a la convención británica y no a la estadounidense.
export function formatDate(iso: string, locale: string): string {
  const d = new Date(iso);
  return d.toLocaleString(locale, {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// `blank` es el texto de «sin dato», que es `n/a` en inglés y `n/d` en
// castellano (RULE 7: nunca una raya).
export function shortHash(hash: string | null, blank: string, visible = 10): string {
  if (!hash) return blank;
  return `${hash.slice(0, visible)}…`;
}

export interface Formatters {
  formatBytes: (bytes: number) => string;
  formatDate: (iso: string) => string;
  shortHash: (hash: string | null, visible?: number) => string;
  // El blanco de «sin dato», para quien lo necesite suelto.
  na: string;
}

export function useFormat(): Formatters {
  const { locale, t } = useLang();
  return useMemo(() => {
    const na = t("common.na");
    return {
      formatBytes,
      formatDate: (iso: string) => formatDate(iso, locale),
      shortHash: (hash: string | null, visible?: number) => shortHash(hash, na, visible),
      na,
    };
  }, [locale, t]);
}
