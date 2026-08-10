import { useEffect, useState } from "react";

// Resuelve los tokens de color de `index.css` a LITERALES.
//
// Existe por una sola razón: la figura del incidente se exporta a PNG serializando su
// SVG y rasterizándolo en un canvas, y ahí el SVG viaja SOLO, fuera del documento. No
// lleva consigo las variables CSS de la aplicación, así que un `fill="var(--accent)"`
// se rasteriza como nada. Los colores tienen que estar puestos como `#8c3a2b` ya en el
// SVG que se dibuja en pantalla, para que el que se serializa sea exactamente ese.
//
// La señal de relectura es el ATRIBUTO `data-theme` del documento, observado, y no el
// `theme` de `useTheme()`, que es lo que parece obvio y no funciona: `ThemeProvider` es
// un ANTECESOR de esta vista y escribe el atributo en su propio efecto, pero React
// ejecuta los efectos de los HIJOS antes que los del padre. Suscribiéndose al `theme`
// se lee la paleta ANTES de que el atributo cambie y la figura se queda con los colores
// del tema anterior: medido, la interfaz pasaba a claro y el dibujo seguía oscuro.
// Observar el atributo no depende del orden de los efectos, porque observa la cosa de
// la que la paleta de verdad depende.

//: Los tokens que la figura necesita. Solo estos: leer la paleta entera invitaría a
//: usarla como atajo desde cualquier sitio, y para la interfaz el CSS ya sirve.
const TOKENS = [
  "--surface",
  "--ink",
  "--ink-2",
  "--ink-3",
  "--ink-4",
  "--hair",
  "--line",
  "--accent",
  "--sev-low",
  "--sev-medium",
  "--sev-high",
  "--sev-critical",
] as const;

export type PaletteToken = (typeof TOKENS)[number];
export type Palette = Record<PaletteToken, string>;

// Si un token no resolviera (hoja sin cargar), se queda VACÍO en vez de caer a un
// color inventado: un gris de repuesto en una figura pericial es un dato falso sobre
// la severidad. Un `fill` vacío lo hereda el SVG, y el fallo se ve, que es lo correcto.
function readPalette(): Palette {
  const computed = getComputedStyle(document.documentElement);
  const out = {} as Palette;
  for (const token of TOKENS) out[token] = computed.getPropertyValue(token).trim();
  return out;
}

export function useThemePalette(): Palette {
  const [palette, setPalette] = useState<Palette>(readPalette);
  useEffect(() => {
    const observer = new MutationObserver(() => setPalette(readPalette()));
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });
    // El atributo puede haber cambiado entre el primer render y este efecto.
    setPalette(readPalette());
    return () => observer.disconnect();
  }, []);
  return palette;
}
