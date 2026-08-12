import { createContext, useContext, useEffect, useState } from "react";
import type { ReactNode } from "react";

// Apariencia = PALETA × MODO, dos ejes independientes.
//
// La paleta elige el temperamento (papel cálido o acero frío) y el modo elige
// claro u oscuro. Son ortogonales a propósito: quien trabaja de noche no tiene
// por qué renunciar a la identidad que prefiere, y cada combinación se resuelve
// en el CSS con tokens, sin duplicar una sola regla de componente.
type Theme = "light" | "dark";
export type Palette = "papel" | "acero";

export const PALETTES: { id: Palette; name: string; description: string }[] = [
  {
    id: "papel",
    name: "Papel",
    description: "Crema cálido y terracota. Expediente, archivo, papel.",
  },
  {
    id: "acero",
    name: "Acero",
    description: "Gris frío y azul de instrumento. Sobria, de laboratorio.",
  },
];

interface ThemeCtx {
  theme: Theme;
  toggle: () => void;
  // El conmutador de Configuración elige un tema CONCRETO, no alterna: pulsar
  // «Claro» estando en claro no debe llevarte a oscuro.
  setTheme: (t: Theme) => void;
  palette: Palette;
  setPalette: (p: Palette) => void;
}

const THEME_KEY = "forensia-theme";
const PALETTE_KEY = "forensia-palette";

function getInitialTheme(): Theme {
  try {
    const stored = localStorage.getItem(THEME_KEY);
    if (stored === "light" || stored === "dark") return stored;
  } catch {}
  return "light";
}

// «papel» es la paleta original y sigue siendo la de partida: un valor guardado
// que ya no exista (una paleta retirada) cae aquí en vez de dejar la interfaz
// sin tokens.
function getInitialPalette(): Palette {
  try {
    const stored = localStorage.getItem(PALETTE_KEY);
    if (PALETTES.some((p) => p.id === stored)) return stored as Palette;
  } catch {}
  return "papel";
}

const ThemeContext = createContext<ThemeCtx>({
  theme: "light",
  toggle: () => {},
  setTheme: () => {},
  palette: "papel",
  setPalette: () => {},
});

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(getInitialTheme);
  const [palette, setPalette] = useState<Palette>(getInitialPalette);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem(THEME_KEY, theme);
    } catch {}
  }, [theme]);

  useEffect(() => {
    document.documentElement.setAttribute("data-palette", palette);
    try {
      localStorage.setItem(PALETTE_KEY, palette);
    } catch {}
  }, [palette]);

  const toggle = () => setTheme((prev) => (prev === "light" ? "dark" : "light"));

  return (
    <ThemeContext.Provider value={{ theme, toggle, setTheme, palette, setPalette }}>
      {children}
    </ThemeContext.Provider>
  );
}

export const useTheme = () => useContext(ThemeContext);
