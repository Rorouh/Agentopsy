import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// La SPA se sirve en la RAÍZ del servicio `web` (nginx) — base "/". En
// producción nginx proxifica /api y /ws hacia http://api:8000 (red interna del
// compose); en desarrollo el proxy de Vite reproduce esa misma topología
// contra el puerto que el compose publica en 127.0.0.1:8000, de modo que la
// app es SIEMPRE mismo-origen con su backend y no hay que pelear con CORS.
export default defineConfig({
  base: "/",
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": { target: "http://127.0.0.1:8000", changeOrigin: false },
      "/ws": { target: "http://127.0.0.1:8000", changeOrigin: false, ws: true },
    },
  },
  build: { outDir: "dist", emptyOutDir: true },
});
