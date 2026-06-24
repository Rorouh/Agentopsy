# FORENSIA — Frontend Journal

Registro técnico de decisiones y cambios en la capa de presentación.
Propósito: dar contexto a todo el equipo (frontend, backend, lógica forense) más allá de lo que los commits explican.
No reemplaza ni contradice `ARCHITECTURE.md` ni `THREAT_MODEL.md`; los complementa desde la perspectiva del renderer.

---

## Entrada 2026-06-24 (tarde) — Demo visual navegable, rama `feature/saas-theming`

**Cubre:** trabajo posterior a `37aa036`, todavía sin commitear al cierre de esta entrada.
**Autores:** equipo frontend FORENSIA
**Objetivo de la sesión:** dejar una demo navegable y presentable (capturas para el equipo), sin tocar backend, Electron main/preload, ni la arquitectura local-first. Cero `fetch` directo, cero APIs falsas en `window.forensia`, cero librerías nuevas (Router/Zustand/Redux/Tailwind/UI libs).

### Qué se añadió

**6 pantallas nuevas** en `src/pages/`: `GuidePage`, `RepositoryPage` (antes "repositorio de evidencia", ahora "Casos y evidencias"), `InvestigationPage` (envuelve `ChatPage` sin tocarlo, añade panel de hallazgos), `TimelinePage`, `DocumentViewerPage`, `MitreAttackPage`, más `SettingsPage` (Apariencia, Operador, Reportes, Modelos/IA, Seguridad y privacidad, Diagnóstico, Acerca de).

**Navegación centralizada**: `src/navigation/navItems.ts` exporta `ViewId`, `NavItem`, `NAV_ITEMS` (con `section: "primary" | "secondary"`) y `DEFAULT_VIEW`. `App.tsx` sigue siendo el único dueño del estado `activeView` (`useState`, sin Router). Las páginas reciben un prop opcional `onNavigate?: (view: ViewId) => void` para los CTAs de flujo (Guía→Repositorio→Investigación→Timeline→Documentos→MITRE); `App.tsx` les pasa literalmente `setActiveView`.

**Contratos de dominio**: `src/types/domain.ts` (`CaseSummary`, `EvidenceFile`, `ReportDocument`, `TimelineEvent`, `MitreTechniqueMatch`, `InvestigationFinding`, `GuideStep`, `LoadState`) pensados para mapear 1:1 con las futuras respuestas de `forensia/routers/*`. Mock data en `src/mocks/frontendPreviewData.ts`, importado **solo** en `App.tsx` y pasado como props — ninguna página importa mocks directamente, así que el día que haya backend real solo cambia `App.tsx`.

**Primitivos UI nuevos** en `src/ui/`: `PageHeader`, `PageSection`, `MetricCard`, `KeyValueList`, `ContextBanner` (muestra caso/evidencia activa — usado en Repositorio/Investigación/Timeline/Documentos/MITRE para que se entienda visualmente que esas pantallas dependen de una evidencia seleccionada), `LoadingState`, `ErrorState`, `EmptyState`, `Badge`.

**El topbar global perdió el `ThemeToggle`.** Vivía flotando en todas las pantallas; ahora el toggle de tema vive únicamente en Configuración → Apariencia. Se quitó `<div className="topbar">` de `AppShell.tsx` y la regla `.topbar` de `index.css` (quedó sin uso). El banner de error de conexión (antes con `color: "#ff6b6b"` hardcodeado, una violación a la regla de tokens que ya existía antes de esta sesión) ahora pasa por el nuevo `ErrorState`, que usa `var(--danger)`.

**Limpieza menor:** se quitó `.investigation-context-bar` de `index.css` (quedó muerta tras adoptar `ContextBanner` en `InvestigationPage`). Se corrigió `var(--fg-dim)` en `SystemStatusPage.tsx` — un token que nunca existió en `:root`, reemplazado por `LoadingState`.

### Lo que NO cambió

- `ChatPage.tsx` — cero ediciones. `InvestigationPage` lo monta tal cual y le añade contexto alrededor.
- `global.d.ts`, `preload.cjs`, `main.cjs` — sin tocar. Ninguna pantalla nueva llama a `window.forensia` directamente; todo lo que muestran es mock data tipada.
- Tokens de `:root` / `[data-theme="dark"]` — sin tocar. Todo lo nuevo consume `var(--token)` existente, cero hex nuevos.

### Para quien integre backend real

Cada página recibe sus datos por props (`activeCase`, `activeEvidence`, `evidenceFiles`, `events`, `documents`, `matches`, `findings`). El punto de integración es exclusivamente `App.tsx`: sustituir los `mock*` de `frontendPreviewData.ts` por el resultado de las llamadas reales a `forensia/routers/*` (vía la cadena `window.forensia.*` ya existente, no por `fetch`). El tipo `EvidenceFile` ya incluye `osProfile?: string` para cuando el backend lo provea.

### Deuda no resuelta (sigue igual que en la entrada anterior)

`evidence_id` vacío en `ChatPage.tsx`, parser de markdown manual, estilos inline hardcodeados en `ChatPage.tsx` (no tocados, siguen siendo del owner de chat), `typecheck` no conectado a CI. Nada de esto se tocó en esta sesión — es trabajo de UI puramente visual sobre páginas nuevas.

### Pregunta abierta nueva

La entrada anterior decía "revisar React Router cuando haya más de 4-5 vistas". Hoy `navItems.ts` ya tiene 8 (6 primarias + Estado del Sistema + Configuración). Sigue funcionando bien con `useState<ViewId>` y no hay urgencia, pero queda anotado como punto a discutir en equipo, no como decisión tomada unilateralmente.

---

## Entrada 2026-06-24 — Rama `feature/saas-theming`

**Commits cubiertos:** `d8e7dfa` → `37aa036` (6 commits sobre `main`)
**Autores:** equipo frontend FORENSIA
**Archivos netos modificados:** 13 (+910 líneas, −797 líneas)

---

### Session Summary

Esta sesión tuvo dos focos diferenciados que conviene entender por separado:

**1. Migración visual total: retro RPG → SaaS profesional**

El punto de partida en `main` (commit `30d1999`) tenía un sistema visual tipo videojuego retro: fuentes pixel de Google Fonts, fondo animado con `@keyframes pan-bg`, overlay CRT en `body::after`, `image-rendering: pixelated`, variables `--color-bg-dark`, `--font-pixel`. Todo eso se eliminó por completo.

Se reemplazó por un sistema de tokens SaaS basado en CSS custom properties, con modo claro y oscuro conmutable por el usuario. El cambio es profundo: afecta a cómo se deben escribir todos los estilos futuros. Ningún color puede ser `#hex` hardcodeado en CSS nuevo — todo debe pasar por las variables de `:root`.

**2. Refactor estructural de `App.tsx`**

En `main`, `App.tsx` tenía 434 líneas: contenía estado de conexión, lógica de chat, render del sidebar, render de status del sistema, parser de markdown, chips de acceso rápido, y la shell visual completa. Todo junto.

Ahora `App.tsx` tiene 42 líneas: es exclusivamente un ensamblador de contexto (estado de conexión + routing de tab) que delega a componentes. La lógica de chat no se tocó, se movió literalmente.

---

### Architectural Changes

**Confirmación: Electron desktop local-first, no SaaS web**

Aunque el nombre de la rama dice "saas-theming", el término se refiere solo a la estética visual (limpia, profesional, modo claro/oscuro). No hay ningún cambio en la arquitectura de distribución. FORENSIA sigue siendo una app Electron desktop con un sidecar Python. No hay ningún `fetch` desde el renderer hacia internet, no hay sesiones remotas, no hay backend en la nube.

**El sistema de theming usa `data-theme` en el `<html>`**

El toggle de tema escribe `document.documentElement.setAttribute("data-theme", "dark"|"light")`. Esto activa el bloque `[data-theme="dark"]` en `index.css`, que sobrescribe las variables de `:root`. Es la técnica estándar para theming CSS-native sin dependencias adicionales.

La preferencia se persiste en `localStorage` con clave `"forensia-theme"`. Si el almacenamiento falla (contexto restrictivo), el tema vuelve a `"light"` sin romper nada.

**Nota importante sobre `electron-store`:** Existe un TODO explícito en `ThemeProvider.tsx` para migrar la persistencia de `localStorage` a `electron-store`. Esta migración requiere IPC (un canal nuevo en `main.cjs` y `preload.cjs`). **No se ha implementado**. No tocar ese TODO sin coordinarlo con quien lleve la capa de persistencia de Electron.

**Separación de capas dentro del renderer**

Antes de esta rama, todo el renderer vivía en un único `App.tsx`. Ahora hay tres capas bien diferenciadas:

```
src/
├── ThemeProvider.tsx   contexto React + lógica de tema
├── ThemeToggle.tsx     control visual del toggle
├── App.tsx             ensamblador: estado de conexión + routing de tab
├── layout/
│   ├── AppShell.tsx    frame visual: grid app, sidebar, topbar, error banner
│   └── Sidebar.tsx     nav-list + branding + status de conexión
├── pages/
│   ├── ChatPage.tsx    toda la lógica e interfaz de chat (literalmente movida)
│   └── SystemStatusPage.tsx  dashboard de capacidades del sidecar
└── ui/
    ├── Button.tsx      variantes chip e icon (send-btn)
    ├── Card.tsx        status-card con prop fullWidth
    └── StatusDot.tsx   indicador online/offline
```

Esta estructura no pretende ser definitiva. Es la separación mínima necesaria para que el código sea mantenible. **No hay Router, no hay estado global, no hay librería de UI.**

**`App.tsx` ya no es el monolito — pero `ChatPage.tsx` sí lo es**

`ChatPage.tsx` tiene 282 líneas con lógica mezclada: estado UI, lógica de envío, parser de markdown casero, formateo de mensajes, chips de acceso rápido. Se dejó así intencionadamente: la lógica de chat pertenece a otro miembro del equipo y moverla implica riesgo de romper comportamiento. Tiene deuda técnica, pero no es deuda nuestra asumir sin coordinar.

---

### Frontend Surface Affected

| Archivo | Responsabilidad técnica |
|---|---|
| `src/index.css` | **Única fuente de tokens de diseño.** Define `:root` (modo claro) y `[data-theme="dark"]`. Todos los componentes dependen de estas variables. No añadir colores hexadecimales directos en estilos nuevos. |
| `src/ThemeProvider.tsx` | Contexto React de tema. Lee `localStorage` al arrancar, escribe `data-theme` en el `<html>`, expone `useTheme()`. |
| `src/ThemeToggle.tsx` | Control de usuario para cambiar tema. Pill con dos opciones: Claro/Oscuro. No tiene estado propio; lee y escribe a través de `useTheme()`. |
| `src/App.tsx` | Ensamblador de nivel raíz. Llama a `window.forensia.health()` y `window.forensia.capabilities()` al montar. Gestiona tab activa (`chat` \| `system`). |
| `src/layout/AppShell.tsx` | Frame visual de la app. Grid de dos columnas (sidebar + main). Contiene el topbar con `ThemeToggle` y el banner de error de conexión. |
| `src/layout/Sidebar.tsx` | Navegación lateral. Botones de tab (chat / sistema) + status dot de conexión con versión del sidecar. |
| `src/pages/ChatPage.tsx` | Interfaz de chat completa. **Tiene ownership de otro miembro del equipo.** Contiene el único consumidor real de `window.forensia.query()`. |
| `src/pages/SystemStatusPage.tsx` | Dashboard de capacidades. Consume el objeto `Capabilities` que llega de `window.forensia.capabilities()`. |
| `src/ui/Button.tsx` | Primitivo de botón con variantes `chip` e `icon`. Thin wrapper que pasa className y props sin modificar comportamiento. |
| `src/ui/Card.tsx` | Wrapper de `status-card` con prop `fullWidth`. |
| `src/ui/StatusDot.tsx` | Punto visual de estado online/offline. |
| `desktop/package.json` | Añadido script `"typecheck": "tsc --noEmit -p renderer/tsconfig.json"` ejecutable desde `desktop/`. |
| `global.d.ts` | **Contrato de tipos de la API.** Define la interfaz de `window.forensia`. Si el backend expone un endpoint nuevo, este es el primer archivo que hay que actualizar. |
| `desktop/preload.cjs` | **Puerta de entrada de toda llamada del renderer al proceso principal.** No se modificó en esta rama, pero es el punto de extensión correcto para nuevas APIs. |

---

### Integration Notes for Backend / Logic Developers

Esta sección es la más importante si trabajáis en el backend, el agente o la lógica forense.

**El renderer nunca llama al sidecar directamente.**

Toda comunicación pasa por la cadena: `React → window.forensia.X() → IPC → main.cjs → HTTP al sidecar`. El renderer no conoce la URL ni el token del sidecar. Este diseño está documentado en `THREAT_MODEL.md` (gate 12) y no debe romperse bajo ningún concepto.

```
renderer (React)
    └─ window.forensia.query(req)       ← único punto de contacto
         └─ ipcRenderer.invoke("forensia:query", req)
              └─ ipcMain.handle → sidecarPost("/api/agent/query", req)
                   └─ HTTP POST con X-Forensia-Token → sidecar Python
```

**Si exponéis un endpoint nuevo en el sidecar, el flujo de integración es:**

1. Añadir el endpoint en `backend/forensia/routers/` (thin adapter, sin lógica)
2. Añadir un handler en `main.cjs`: `ipcMain.handle("forensia:tuEndpoint", () => sidecarFetch("/api/tu-ruta"))`
3. Añadir la firma en `preload.cjs`: `tuEndpoint: () => ipcRenderer.invoke("forensia:tuEndpoint")`
4. Añadir el tipo en `desktop/renderer/src/global.d.ts` dentro de `Window.forensia`
5. Consumir desde React con `window.forensia.tuEndpoint()`

Saltarse cualquier paso de esta cadena rompe la integración. No hay forma de llamar al sidecar desde React que no pase por `preload.cjs`.

**Qué datos consume hoy el frontend del sidecar**

`window.forensia.capabilities()` devuelve un objeto tipado como `Capabilities` (`global.d.ts:1-9`):

```typescript
{
  platform: string;     // "darwin" | "win32" | "linux"
  os: string;           // "macOS 14.2" — legible para mostrar en UI
  arch: string;         // "arm64" | "x64"
  python: string;       // versión del intérprete del sidecar
  packaged: boolean;    // true si es distribución producción
  tools: Record<string, boolean>;   // maletín forense: nombre → disponible
  models: Record<string, boolean>;  // modelos: nombre → disponible
}
```

`SystemStatusPage.tsx` itera `caps.tools` y `caps.models` directamente. Si añadís campos nuevos al objeto de capabilities, el frontend los ignorará silenciosamente (TypeScript los rechazará si intentáis usarlos sin actualizar `global.d.ts`).

**El chat es UI temporal / semi-funcional**

`ChatPage.tsx` llama a `window.forensia.query({ prompt, os_profile, evidence_id })` y recibe `{ status, reply, evidence_id, os_profile }`. El campo `reply` es texto plano (o markdown básico) que el componente parsea manualmente con regex. La lógica de parsing está en `formatMessageContent` y `renderBoldText` dentro de `ChatPage.tsx`.

Lo que no existe todavía: selección de modelo, adjuntar evidencia real, streaming de respuesta, historial de sesión. El campo `evidence_id` se envía vacío (`""`). **No asumir que el chat representa el flujo final de análisis forense.**

**Persistencia de tema: NO usar `electron-store` todavía**

El tema se persiste en `localStorage`. Hay un TODO anotado en `ThemeProvider.tsx` para migrar a `electron-store`, pero esa migración requiere un nuevo canal IPC. No implementar ese IPC sin coordinar primero: afecta a `main.cjs`, `preload.cjs` y `ThemeProvider.tsx` simultáneamente.

---

### UI / Theme Decisions

**Decisión validada: CSS custom properties como sistema de tokens**

Se eligió CSS nativo sobre soluciones como Tailwind o styled-components porque:
- Sin dependencias adicionales que gestionar
- Compatible con cualquier componente sin configuración
- El `data-theme` en `<html>` activa el tema dark de forma instantánea y sin parpadeo

Los tokens están definidos exclusivamente en `index.css`. Cualquier componente nuevo debe consumirlos con `var(--nombre-token)`. Lista de tokens disponibles: `--bg`, `--surface`, `--sidebar-bg`, `--border`, `--text-primary`, `--text-secondary`, `--text-muted`, `--accent`, `--accent-bg`, `--accent-text`, `--success`, `--danger`, `--warning`, `--font-sans`, `--font-mono`, `--radius-card`, `--radius-pill`.

**Tipografía: `system-ui` en vez de Google Fonts**

El proyecto anterior importaba fuentes pixel de Google Fonts. Ahora se usa `system-ui, -apple-system, 'Inter', sans-serif` sin ninguna importación de red. Relevante porque la app opera en entornos air-gapped (máquinas forenses sin internet).

**Experiencia desktop, no web SaaS**

Aunque el tema visual es "SaaS", la app es Electron desktop. No hay diseño responsive. La app tiene un layout fijo `grid-template-columns: 260px 1fr` pensado para ventana de 1200×800 mínimo. No convertir esto en una SPA web ni añadir breakpoints para móvil.

**Los estilos inline del chat son intencionales (por ahora)**

`ChatPage.tsx` contiene estilos inline con colores hardcodeados como `color: "#ffffff"` y `background: "rgba(255,255,255,0.08)"`. No son un descuido: son el código original del componente de chat, propiedad de otro miembro del equipo, que se movió literalmente sin modificar. Cualquier limpieza de esos estilos requiere coordinación con el dueño.

---

### Current Technical Debt

| Deuda | Archivo | Impacto | Prioridad |
|---|---|---|---|
| Parser de markdown manual | `ChatPage.tsx:11-99` | Fragile ante respuestas complejas del agente; no soporta tablas, código multilínea, blockquotes | Alta — bloquea respuestas ricas |
| Estilos inline hardcodeados | `ChatPage.tsx` en múltiples líneas | No respetan el sistema de tokens; no cambian con el tema | Media — visible solo en modo oscuro |
| Sin capa API/hook | `ChatPage.tsx:143-163` | La lógica de fetch vive dentro del componente; imposible reutilizar o testear aisladamente | Media |
| Sin typecheck en CI | — | `npm run typecheck` existe pero no está conectado a ningún pipeline | Media |
| `evidence_id` siempre vacío | `ChatPage.tsx:147` | El agente recibe `""` como ID de evidencia; imposible rastrear análisis | Alta — bloquea flujo forense real |
| TODO `electron-store` | `ThemeProvider.tsx:32` | La preferencia de tema no sobrevive a un `localStorage.clear()` ni a perfiles Electron separados | Baja en MVP |
| Sin tests de ningún tipo | — | Ni unitarios ni de integración en el renderer | Baja hasta MVP funcional |
| `getGreeting()` sin usar | `ChatPage.tsx:4-9` | La función está definida pero no se llama en el render actual | Baja |

---

### Recommended Next Steps

Orden sugerido por impacto/riesgo:

1. **Coordinar contrato de datos de evidencia con backend** antes de tocar `ChatPage.tsx`. El campo `evidence_id` vacío es la brecha más grande entre UI y lógica forense real. Esta coordinación desbloquea el flujo de análisis.

2. **Extraer `useChatApi` hook** en `src/hooks/useChatApi.ts` que encapsule el `window.forensia.query()`, el estado de `busy`, y el manejo de errores. Actualmente todo eso vive dentro del componente. No requiere librería externa.

3. **Reemplazar el parser manual de markdown** por `react-markdown` (librería pequeña, sin dependencias complejas) en cuanto el agente empiece a devolver respuestas con estructura real. Hacerlo antes bloquea la visibilidad del problema.

4. **Conectar `npm run typecheck` a CI** (`.github/workflows/ci.yml`) para que los errores de tipos no lleguen a `main`.

5. **Migrar tema a `electron-store`** cuando se consolide la capa de IPC. No antes — `localStorage` es suficiente mientras no haya perfiles de usuario.

6. **Limpiar estilos inline del chat** coordinando con el owner del componente. Alinearlos a los tokens del sistema para que el modo oscuro funcione correctamente en el chat.

---

### Deferred / Not Now

**React Router:** Con dos tabs gestionadas por un `useState<"chat"|"system">` en `App.tsx`, no hace falta Router. Añadirlo ahora introduce historial de navegación en una app desktop que no tiene URLs propias. Revisarlo cuando haya más de 4-5 vistas distintas.

**Zustand / Redux:** El estado compartido actual es: tab activa, caps, version, error. Todo vive en `App.tsx` y se pasa por props. No hay problema de prop-drilling que justifique un store global. Revisarlo si la profundidad de árbol crece o si hay estado que se comparte entre ramas no relacionadas.

**`electron-store` para tema:** `localStorage` funciona y persiste entre sesiones dentro del mismo perfil de Electron. La migración a `electron-store` añade un canal IPC por una mejora marginal. Revisarlo cuando haya más configuración de usuario que persistir (no hacerlo solo para el tema).

**Vitest / Testing Library:** El MVP necesita foco en flujo funcional completo (evidencia → agente → informe). Añadir una suite de tests ahora en el renderer es coste sin retorno inmediato. Añadirlo cuando haya lógica estabilizada en hooks extraíbles.

**Responsive / adaptativo:** Esta app se ejecuta en ventanas Electron controladas. El layout fijo de 260px sidebar + contenido flexible es adecuado. No añadir media queries hasta que haya un caso de uso real (pantalla pequeña, modo compacto, etc.).

**CSP más estricta en dev:** `main.cjs` carga `http://localhost:5173` en modo dev. Afinar la CSP en producción es necesario antes del empaquetado final, no ahora.

---

### Team Communication Notes

- **Para integrar nuevas APIs del sidecar:** no llaméis al backend desde React directamente ni useis `fetch()`. El flujo correcto es siempre `main.cjs` → `preload.cjs` → `global.d.ts` → componente. Cualquier atajo rompe el modelo de seguridad documentado en `THREAT_MODEL.md`.

- **Si necesitáis exponer una acción del sidecar nueva**, el PR debe tocar estos cuatro archivos juntos: `backend/forensia/routers/`, `desktop/main.cjs`, `desktop/preload.cjs`, `desktop/renderer/src/global.d.ts`. Un PR que toque solo el backend sin actualizar `preload.cjs` y `global.d.ts` no integra — el frontend no puede llamarlo.

- **El tema claro/oscuro está validado por el equipo.** No cambiéis los tokens de `:root` ni `[data-theme="dark"]` en `index.css` sin comentarlo en el canal de frontend. Un cambio de token afecta a todos los componentes simultáneamente.

- **No tocar `ChatPage.tsx` sin coordinar con su owner.** Tiene lógica de chat, estado de UI y estilos mezclados. Un cambio mal coordinado puede romper la experiencia de chat mientras el agente está en desarrollo activo.

- **`npm run typecheck` desde `desktop/`** verifica todos los tipos del renderer. Ejecutadlo antes de abrir un PR que toque cualquier archivo en `desktop/renderer/src/`. Tarda menos de 5 segundos.

- **La próxima limpieza de frontend debe preservar comportamiento visual actual.** Hay estilos inline en `ChatPage.tsx` con colores que no respetan los tokens de tema. Cuando se limpien, deben quedar alineados al sistema de variables — no simplemente eliminar los `style={}` o el dark mode del chat se romperá.

- **El `evidence_id` que llega al agente hoy siempre es `""`** (string vacío). Si el backend ya implementa `EvidenceManager`, la integración entre UI y evidencia real requiere definir el contrato de datos antes de tocar `ChatPage.tsx`. Coordinad eso antes de asumir que el chat funciona de extremo a extremo.

---

### Open Questions

1. **Ownership de `ChatPage.tsx`:** ¿Quién tiene ownership del componente de chat? El código está en el renderer pero la lógica de interacción con el agente es del equipo de lógica/backend. Necesita propietario definido antes de cualquier refactor.

2. **Contrato de `evidence_id`:** ¿Cómo se obtiene un `evidence_id` válido? ¿Lo genera el frontend al cargar un archivo? ¿Lo devuelve el backend al registrar evidencia? El flujo UI de carga de evidencia no existe todavía. Definir esto desbloquea el flujo forense real.

3. **Streaming de respuestas:** El agente responde hoy con un JSON completo `{ reply: string }`. Si el agente tarda 30+ segundos en analizar un volcado de memoria, el usuario verá "Pensando..." todo ese tiempo. ¿Se implementa streaming (WebSocket / SSE) o se mantiene polling? Afecta tanto a `main.cjs` como a `ChatPage.tsx`.

4. **Alineación de `@types/react`:** El proyecto tiene `@types/react: ^19.2.17` con `react: ^18.3.0`. Combinación intencionalmente dejada así por compatibilidad. No actualizar React a 19 sin revisar el impacto en Electron 30 y en el resto del equipo.

5. **`shared/api/forensiaClient.ts`:** ¿Conviene crear una capa de abstracción sobre `window.forensia` en el renderer? Facilitaría testing y typing más fuerte, pero añade indirección. Decisión pendiente de si los hooks de API crecen en número.

6. **Capa de modelos en UI:** El dashboard de capabilities muestra `caps.models` como booleanos (disponible / no disponible). ¿El usuario podrá seleccionar modelo en algún momento? Si es así, el contrato de `Capabilities` necesita más detalle (nombre legible, contexto máximo, si es local o cloud). Coordinar con quien lleve `backend/forensia/models/`.
