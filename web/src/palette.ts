import { useEffect, useState } from "react";

// Los colores del sistema visual, LEÍDOS de index.css en tiempo de ejecución.
//
// Casi toda la interfaz usa `var(--ink)` y no necesita nada de esto. El dibujo de
// la línea temporal sí: es un SVG que se DESCARGA, y un fichero que se abre en un
// visor o se pega en un informe no tiene las variables CSS de la aplicación, así
// que `stroke="var(--ink)"` se pintaría en negro por defecto y una figura de tema
// oscuro saldría ilegible. Leyendo los tokens aquí, el DOM ya lleva el color
// literal y serializar el SVG produce un fichero fiel a lo que el perito vio.
//
// La otra alternativa era duplicar la paleta en TypeScript, y entonces index.css
// dejaría de ser la única fuente de la paleta.

const TOKENS = [
  "ink",
  "ink-2",
  "ink-3",
  "ink-4",
  "ink-5",
  "ink-6",
  "hair",
  "hair-2",
  "line",
  "track",
  "surface",
  "inset",
  "accent",
  "accent-soft",
  "accent-wash",
  "danger",
  "warning",
  "ok",
] as const;

export type PaletteToken = (typeof TOKENS)[number];
export type Palette = Record<PaletteToken, string>;

// Colores de fase de ATT&CK: agrupación editorial de Agentopsy, categóricos,
// IGUALES en ambos temas, son taxonomía, no decoración. Los comparten la matriz
// (MitreAttackPage) y la banda de fases del dibujo del timeline, que tienen que
// leerse como la misma clasificación.
export const PHASE_COLOR: Record<string, string> = {
  prep: "#64748b",
  access: "#d97706",
  root: "#ea580c",
  act: "#db2777",
  goal: "#dc2626",
};

function leerPaleta(): Palette {
  const style = getComputedStyle(document.documentElement);
  const paleta = {} as Palette;
  for (const token of TOKENS) {
    // El respaldo cubre el instante anterior a que la hoja de estilos aplique;
    // no es una paleta alternativa, es tinta neutra para no pintar en blanco.
    paleta[token] = style.getPropertyValue(`--${token}`).trim() || "#000000";
  }
  return paleta;
}

/**
 * La paleta del tema activo, releída cuando el tema cambia.
 *
 * Observa el atributo `data-theme` del documento en vez de depender del contexto
 * del tema: `ThemeProvider` escribe ese atributo en su propio efecto, y los
 * efectos de un hijo corren ANTES que los del padre, así que leer la paleta al
 * cambiar el valor del contexto la leería todavía con el tema anterior.
 */
export function useThemePalette(): Palette {
  const [paleta, setPaleta] = useState<Palette>(leerPaleta);

  useEffect(() => {
    const observador = new MutationObserver(() => setPaleta(leerPaleta()));
    observador.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });
    setPaleta(leerPaleta());
    return () => observador.disconnect();
  }, []);

  return paleta;
}
