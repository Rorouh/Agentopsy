import React from "react";
import { createRoot } from "react-dom/client";

// Tipografía SERVIDA DESDE EL PROPIO BUNDLE, no desde Google Fonts. Agentopsy no
// contacta con dominios externos (SECURITY INVARIANT 7) y el perito suele
// trabajar en un laboratorio aislado de red: un @import remoto dejaría la
// interfaz con la fuente del sistema justo donde más importa. Vite emite estos
// .woff2 como assets del build, así que viajan dentro de la imagen `web`.
// Subconjunto `latin-*` a propósito: el genérico arrastra cirílico, griego y
// vietnamita que esta interfaz no usa.
import "@fontsource/ibm-plex-sans/latin-400.css";
import "@fontsource/ibm-plex-sans/latin-500.css";
import "@fontsource/ibm-plex-sans/latin-600.css";
import "@fontsource/ibm-plex-sans/latin-700.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "@fontsource/ibm-plex-mono/latin-500.css";
import "@fontsource/ibm-plex-mono/latin-600.css";

import "./index.css";
import { App } from "./App";

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
