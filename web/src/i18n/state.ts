// El eje de IDIOMA de la interfaz, SIN React.
//
// Vive aparte del provider por una razón concreta: `api/client.ts` tiene que
// poner el idioma en la cabecera de cada llamada y no es un componente, así que
// si el estado viviera dentro del contexto habría que elegir entre un import
// circular o pasar el idioma a mano por las cuarenta funciones del cliente.
// Aquí el valor es un módulo: el provider lo escribe, el cliente lo lee.
//
// Mismo estatuto que el tema y la paleta (ver ThemeProvider): es una
// preferencia de PRESENTACIÓN, se guarda en ESTE navegador y no toca un solo
// dato del caso. Lo que sí decide es en qué idioma se REDACTA un informe nuevo,
// porque el informe sigue al selector; una revisión ya firmada conserva el suyo.

import { en, type MessageKey } from "./en";
import { es } from "./es";

export type Lang = "en" | "es";

export const LANGS: readonly Lang[] = ["en", "es"];

// Idioma de partida. Decisión de producto, no una adivinanza de configuración:
// siempre hay que pintar en alguno, equivocarse no falsea nada del expediente y
// el selector lo cambia en un clic. Mismo estatuto que la paleta «papel».
export const DEFAULT_LANG: Lang = "en";

export const LANG_STORAGE_KEY = "forensia-lang";

// La cabecera con la que cada llamada declara su idioma, gemela del token.
// El api la tiene declarada en su allowlist de CORS (forensia/i18n.py).
export const LANG_HEADER = "X-Forensia-Lang";

// Locale con el que se formatean fechas y números. `en-GB` y no `en-US` a
// propósito: mantiene el orden día/mes del formato actual, y en un informe
// pericial una fecha que se puede leer del revés según quién la mire es una
// trampa. Los dos locales dan dd/mm/aaaa.
export const LOCALES: Record<Lang, string> = {
  en: "en-GB",
  es: "es-ES",
};

function isLang(value: unknown): value is Lang {
  return typeof value === "string" && (LANGS as readonly string[]).includes(value);
}

export function readStoredLang(): Lang {
  try {
    const stored = localStorage.getItem(LANG_STORAGE_KEY);
    if (isLang(stored)) return stored;
  } catch {
    /* localStorage no disponible: cae al idioma de partida */
  }
  return DEFAULT_LANG;
}

// Espejo del estado de React, para los consumidores que no son componentes.
let actual: Lang = readStoredLang();

export function getLang(): Lang {
  return actual;
}

// La escribe SOLO el provider, en su efecto, para que no haya dos fuentes de
// verdad discutiendo cuál es el idioma.
export function publishLang(lang: Lang): void {
  actual = lang;
  try {
    localStorage.setItem(LANG_STORAGE_KEY, lang);
  } catch {
    /* la preferencia no se persiste; la sesión sigue en el idioma elegido */
  }
  // `lang` del documento: lo leen el corrector del navegador, un lector de
  // pantalla y la partición silábica del CSS. Sin esto, un lector de pantalla
  // recita la interfaz inglesa con fonética castellana.
  document.documentElement.setAttribute("lang", lang);
}

// ── el traductor, sin React ──────────────────────────────────────────────────
//
// `useLang().t` es el camino normal, dentro de un componente. Esto es para los
// consumidores que NO lo son: hoy `api/client.ts`, que traduce un fallo de
// transporte antes de que ninguna vista lo vea. Los dos comparten catálogo e
// interpolación, así que no pueden dar textos distintos para la misma clave.

const CATALOGOS: Record<Lang, Record<MessageKey, string>> = { en, es };

export type Params = Record<string, string | number>;

// Sustituye `{nombre}`. Un hueco sin parámetro se queda VISIBLE con sus llaves:
// es feo y evidente, que es lo que hace que se arregle. Lanzar tumbaría la vista
// de un caso abierto por un fallo de texto, y un blanco lo escondería.
export function interpolar(texto: string, params?: Params): string {
  if (!params) return texto;
  return texto.replace(/\{(\w+)\}/g, (crudo, nombre: string) =>
    nombre in params ? String(params[nombre]) : crudo,
  );
}

export function tr(key: MessageKey, params?: Params): string {
  return interpolar(CATALOGOS[getLang()][key], params);
}

export { CATALOGOS };
