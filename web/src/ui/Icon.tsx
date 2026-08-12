import type { ReactNode, SVGProps } from "react";

// Juego de iconos ÚNICO de la interfaz.
//
// Antes convivían dos sistemas: SVG dibujados a mano en el sidebar y glifos de
// texto (✓ ⚠ ▾ ● ○) incrustados en el JSX del resto de vistas. Los glifos son
// caracteres Unicode: los resuelve la fuente del sistema, no IBM Plex, así que
// cambian de forma, de peso y de alineación vertical entre macOS, Windows y
// Linux, y Agentopsy corre en los tres. Aquí se dibujan, y se ven igual.
//
// REGLA: en la interfaz, un icono es un <Icon>. Los glifos sólo son legítimos
// dentro de bloques MONOESPACIADOS donde forman parte del texto: el árbol de
// actividad del agente en ChatPage (`▸ ✓ ✗ ★`), que imita una traza de terminal
// y se lee como tal.

export type IconName =
  | "check"
  | "cross"
  | "alert"
  | "chevron-down"
  | "selector"
  | "plus"
  | "copy"
  | "folder"
  | "inbox"
  | "file-upload"
  | "panel-collapse"
  | "panel-expand"
  | "dot-filled"
  | "dot-empty";

interface IconProps extends Omit<SVGProps<SVGSVGElement>, "name"> {
  name: IconName;
  size?: number;
}

const PATHS: Record<IconName, ReactNode> = {
  check: <polyline points="20 6 9 17 4 12" />,
  cross: (
    <>
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </>
  ),
  alert: (
    <>
      <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </>
  ),
  "chevron-down": <polyline points="6 9 12 15 18 9" />,
  selector: (
    <>
      <polyline points="8 9 12 5 16 9" />
      <polyline points="16 15 12 19 8 15" />
    </>
  ),
  plus: (
    <>
      <line x1="12" y1="5" x2="12" y2="19" />
      <line x1="5" y1="12" x2="19" y2="12" />
    </>
  ),
  copy: (
    <>
      <rect x="9" y="9" width="13" height="13" rx="1" />
      <path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1" />
    </>
  ),
  // Fichero entrando: ancla la zona de arrastre. Va grande y centrado, así que
  // es el único que se usa como ilustración y no como marca junto a un texto.
  "file-upload": (
    <>
      <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
      <polyline points="14 3 14 8 19 8" />
      <line x1="12" y1="18" x2="12" y2="12" />
      <polyline points="9 15 12 12 15 15" />
    </>
  ),
  // Plegar y desplegar el panel lateral. El marco con la barra a la derecha
  // dibuja el propio panel, así que se entiende sin leer el tooltip — un `›`
  // suelto no dice a qué se refiere ni hacia dónde va.
  "panel-collapse": (
    <>
      <rect x="3" y="4" width="18" height="16" rx="1" />
      <line x1="15" y1="4" x2="15" y2="20" />
      <polyline points="10 10 12 12 10 14" />
    </>
  ),
  "panel-expand": (
    <>
      <rect x="3" y="4" width="18" height="16" rx="1" />
      <line x1="15" y1="4" x2="15" y2="20" />
      <polyline points="12 10 10 12 12 14" />
    </>
  ),
  // Carpeta: examinar ficheros del equipo del perito.
  folder: (
    <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
  ),
  // Bandeja: la carpeta ./evidence del host, donde se depositan las imágenes
  // antes de registrarlas. La forma de bandeja de entrada es lo que distingue
  // «mirar lo que ya hay depositado» de «buscar en mi ordenador».
  inbox: (
    <>
      <polyline points="22 12 16 12 14 15 10 15 8 12 2 12" />
      <path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z" />
    </>
  ),
  "dot-filled": <circle cx="12" cy="12" r="5" fill="currentColor" stroke="none" />,
  "dot-empty": <circle cx="12" cy="12" r="5" />,
};

export function Icon({ name, size = 14, ...rest }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      // Hereda el color del texto que acompaña, así el mismo icono sirve en un
      // badge crítico y en uno neutro sin declarar nada.
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      // Decorativo por defecto: el significado lo lleva el texto de al lado.
      // Cuando el icono va SOLO, quien lo usa pasa aria-label y role="img".
      aria-hidden="true"
      focusable="false"
      style={{ flexShrink: 0, verticalAlign: "-0.15em", ...rest.style }}
      {...rest}
    >
      {PATHS[name]}
    </svg>
  );
}
