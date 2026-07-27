# Plan de migración — rediseño de la interfaz web

Reconocimiento previo (encargo 0 de [`prompts-claude-code.md`](prompts-claude-code.md)).
Documento de **lectura**: no se ha tocado ni un fichero de `web/`.

Contrastado contra el mock destino
[`mocks/rediseno-final.dc.html`](mocks/rediseno-final.dc.html) (1.331 líneas: marcado de
las siete vistas + dos modales, y el bloque `<script type="text/x-dc">` con `PHASES`,
`UTILITIES`, `CUSTODY`, `SETTINGS_TABS`, `ENGINES`, `HEADERS` y los métodos
`phaseRow()` / `engineRow()` / `renderVals()`), el mock de partida
[`mocks/ui-actual.dc.html`](mocks/ui-actual.dc.html), y el código real de `web/src/`
en la rama `redesign` (commit `2130976`).

Tamaño de la superficie afectada: **12.561 líneas** en `web/src`, de las que
**2.917 son `index.css`** (532 selectores de clase distintos, ~708 reglas).

---

## 1. Equivalencias de vistas

El mock conmuta con un `sc-if` por vista; hoy `App.tsx:73-90` conmuta con
`activeView === "<ViewId>"`. La correspondencia es de **siete a siete**, pero
sólo cuatro son limpias.

| `sc-if` del mock | `data-screen-label` | Cabecera (`HEADERS`) | `ViewId` actual | Fichero que la implementa hoy | ¿1:1? |
|---|---|---|---|---|---|
| `isEvidence` | Evidencia | Fase 1 de 5 · «Evidencia» | `repository` | `pages/RepositoryPage.tsx` (1.143 l.) | **No** — ver §1.1 |
| `isInvestigation` | Investigación | Fase 2 de 5 · «Investigación» | `investigation` | `pages/InvestigationPage.tsx` (497 l.) → envuelve `pages/ChatPage.tsx` (974 l.) | Sí (dos ficheros) |
| `isMitre` | ATT&CK | Fase 3 de 5 · «Correlación ATT&CK» | `mitre` | `pages/MitreAttackPage.tsx` (787 l.) | Sí |
| `isTimeline` | Timeline | Fase 4 de 5 · «Timeline forense» | `timeline` | `pages/TimelinePage.tsx` (771 l.) | Sí |
| `isReport` | Informe | Fase 5 de 5 · «Informe pericial» | `document-viewer` | `pages/DocumentsPage.tsx` (656 l.) | **No** — ver §1.2 |
| `isSettings` | Configuración | Servicio · «Configuración» | `settings` | `pages/SettingsPage.tsx` (459 l.) | **No** — ver §1.3 |
| `isGuide` | Guía | Servicio · «Guía de uso» | `guide` | `pages/GuidePage.tsx` (105 l.) | Sí (pero muere `WorkflowGraph`) |
| `newCaseOpen` (modal) | — | — | — | Formulario inline dentro de `RepositoryPage.tsx` | **No** — ver §1.4 |
| `actaOpen` (modal) | — | — | — | Modal de acta ya existente en `RepositoryPage.tsx:126-133, 515-535` | Sí |

Etiquetas de navegación: el mock renombra **cinco de siete**.

| `ViewId` | Etiqueta hoy (`navItems.ts:23-31`) | Etiqueta del mock (`PHASES` / `UTILITIES`) |
|---|---|---|
| `repository` | Casos y evidencias | **Evidencia** |
| `investigation` | Chat Investigación | **Investigación** |
| `timeline` | Timeline | Timeline |
| `document-viewer` | Documentos | **Informe pericial** |
| `mitre` | MITRE ATT&CK | **Correlación ATT&CK** |
| `settings` | Configuración | Configuración |
| `guide` | Guía | Guía |

Los **valores** de `ViewId` no se tocan: `initialView()` (`App.tsx:22-30`) descarta de
`localStorage` cualquier valor que no esté en `NAV_ITEMS`, así que renombrar la clave
`document-viewer` → `report` mandaría a la vista por defecto a todo el que tuviera la
app abierta, sin ganancia funcional.

### 1.1 «Evidencia» ≠ `RepositoryPage` (el caso más grande)

El mock llama **Evidencia** a lo que hoy es `RepositoryPage` («Casos y evidencias»),
y no es sólo un cambio de rótulo: **la mitad de la página se va del cuerpo al armazón**.
`RepositoryPage.tsx` hace hoy dos trabajos:

1. **Gestión del caso** — listar, crear, editar, cerrar/reabrir y **borrar** casos;
   `ActiveCaseHeader`; `CaseSearchModal`.
2. **Evidencia del caso** — bandeja `./evidence`, subida, registro asíncrono, tabla de
   evidencias, cadena de custodia y acta de adquisición.

En el mock, (1) desaparece del cuerpo: el caso activo vive en el **bloque de caso del
sidebar** (nombre · `os_profile · estado` · «cambiar caso» → `CaseSearchModal`), el alta
es el **modal «Nuevo caso»** que abre el botón en píldora del sidebar, y el cuerpo de la
vista es **sólo (2)**, en cuatro bloques: cifras · zona de alta · tabla · custodia.

**El borrado de caso con confirmación por nombre no aparece en ninguna parte del mock.**
Es funcionalidad viva (`RepositoryPage.tsx:607`, `POST /api/cases/{id}/delete`) y no
puede evaporarse en el rediseño — ver riesgo R3.

### 1.2 «Informe pericial» ≠ `DocumentsPage`

`document-viewer` está enrutado hoy a `DocumentsPage.tsx`, que es la implementación viva
(lista + visor + verificar/firmar/PDF/generar). Existe además
**`pages/DocumentViewerPage.tsx` (87 l.), que no importa nadie**: es la versión anterior
sobre datos mock. El mock rediseña `DocumentsPage`; `DocumentViewerPage` es basura previa
al rediseño y arrastra consigo `ui/ContextBanner.tsx` y `types/domain.ts` (§3.4).

### 1.3 El mock no tiene vista «Sistema» — y el código tampoco, ya

El enunciado del encargo dice que el contenido de «Sistema» pasa a una pestaña de
Configuración. **Eso ya ocurrió**: `navItems.ts` no declara `system` en `ViewId`, y
`SettingsPage.tsx:23-27` ya tiene las tres pestañas
`executors | system | appearance`, con el diagnóstico de maletines dentro.

Lo que queda pendiente es de dos tipos, y conviene no confundirlos:

- **Borrado**: `pages/SystemStatusPage.tsx` (88 l.) sigue en el árbol **sin que lo importe
  nadie** — es el duplicado huérfano de esa pestaña.
- **Forma**: las etiquetas y la estructura de las pestañas cambian.

| `SETTINGS_TABS` del mock | Pestaña actual (`SettingsPage.tsx:26-28`) |
|---|---|
| `executors` → «Motor de análisis» | `executors` → «Ejecutores / IA» |
| `system` → «Sistema · Maletín» | `system` → «Sistema / Maletín» |
| `appearance` → «Apariencia» | `appearance` → «Apariencia» |

El cambio real de la pestaña de ejecutores es de **estructura**: hoy son dos secciones
separadas (estado de los 4 ejecutores + un `<select>` de `DEFAULT_EXECUTOR` bajo «claves
de configuración», `SettingsPage.tsx:178-268`); el mock (`ENGINES` + `engineRow()`) las
funde en **una fila desplegable por motor** con disponibilidad, ámbito nube/local, marca
de «por defecto» y modelo en la misma línea.

### 1.4 El modal «Nuevo caso» es nuevo como modal

Hoy el alta de caso es un formulario dentro de `RepositoryPage`. El mock lo saca a un
modal con `Escape` para cerrar, campos nombre / examinador / descripción y — importante —
una nota que **niega explícitamente** que ahí se elija el perfil de SO: «el orquestador lo
deriva del contenido de la evidencia al registrarla. Agentopsy no lo adivina por ti».
Es RULE 2 dicha al usuario; hay que conservar esa frase.

---

## 2. Tokens

### 2.1 Los que existen hoy

`index.css:3-37`: 18 variables en `:root`, 14 de ellas redefinidas en
`[data-theme="dark"]`. Conteos por `grep -c` — **CSS** = `web/src/index.css`,
**TSX** = estilos inline en `web/src/**/*.tsx`:

| Token actual | Valor claro / oscuro | CSS | TSX | **Total** | Token del mock que lo sustituye |
|---|---|---:|---:|---:|---|
| `--bg` | `#ffffff` / `#0d1117` | 40 | 0 | **40** | ⚠ **se parte en dos**: `--shell` (armazón) y `--surface` (panel de contenido) |
| `--surface` | `#fafafa` / `#161b22` | 51 | 1 | **52** | ⚠ **`--inset`** — *colisión de nombre*, ver §2.3 |
| `--sidebar-bg` | `#f1f5f9` / `#010409` | 2 | 0 | **2** | `--shell` |
| `--border` | `#e2e8f0` / `#21262d` | 131 | 3 | **134** | ⚠ **se parte en dos**: `--hair` (separadores) y `--line` (bordes de control) |
| `--text-primary` | `#0f172a` / `#e2e8f0` | 65 | 7 | **72** | `--ink` |
| `--text-secondary` | `#64748b` / `#8b949e` | 69 | 6 | **75** | `--ink-2` |
| `--text-muted` | `#94a3b8` / `#6e7681` | 91 | 9 | **100** | `--ink-4` |
| `--accent` | `#1d4ed8` / `#3b82f6` | 64 | 0 | **64** | `--accent` (mismo nombre, `#8c3a2b` / `#d1745c`) |
| `--accent-bg` | `#dbeafe` / `#172554` | 35 | 0 | **35** | `--accent-wash` |
| `--accent-text` | `#1d4ed8` / `#60a5fa` | 34 | 0 | **34** | `--accent` (el mock no separa texto de acento) |
| `--success` | `#16a34a` / `#3fb950` | 24 | 3 | **27** | `--ok` |
| `--danger` | `#dc2626` / `#f85149` | 53 | 1 | **54** | **sin equivalente** — severidad de hallazgo, se conserva (§2.4) |
| `--warning` | `#b45309` / `#d29922` | 32 | 1 | **33** | **sin equivalente** — ídem |
| `--focus-ring` | `var(--accent)` | 7 | 0 | **7** | **sin equivalente** — el mock no modela foco (§2.4) |
| `--font-sans` | IBM Plex Sans | 72 | 0 | **72** | sin cambio (el mock la escribe literal) |
| `--font-mono` | IBM Plex Mono | 74 | 1 | **75** | sin cambio |
| `--radius-card` | `4px` | 51 | 0 | **51** | → **`0`** (esquinas rectas) |
| `--radius-pill` | `999px` | 26 | 0 | **26** | sobrevive (botón «Nuevo caso», compositor) |

**953 referencias** en total (921 en CSS + 32 inline en TSX); **729** si se descuentan
tipografía y radios. Los estilos inline se concentran en ocho ficheros:
`InvestigationPage` (11), `GuidePage` (6), `ChatPage` (6), `ui/MetricCard` (4),
`SettingsPage` (4), `ExecutorLoginModal` (2), `ui/EmptyState` (1),
`DocumentViewerPage` (1).

### 2.2 Los que hay que inventar (17, sin equivalente actual)

`--shell`, `--inset`, `--ink-3`, `--ink-5`, `--ink-6`, `--hair-2`, `--line`, `--track`,
`--accent-hover`, `--accent-soft`, `--pending`, `--next`, `--invert-bg`, `--invert-fg`,
`--code-bg`, `--code-fg`, `--code-dim`.

Cuatro de ellos son **semánticos, no decorativos**, y el rediseño no funciona sin ellos:

- `--pending` / `--next` — estados de la escalera de fases del sidebar (`phaseRow()`).
- `--invert-bg` / `--invert-fg` — la acción única e invertida de la cabecera contextual,
  y el conmutador de tema de Configuración.
- `--code-bg` / `--code-fg` / `--code-dim` — el bloque de comandos `docker compose exec`
  de la Guía, que es oscuro **en los dos temas**.

### 2.3 El riesgo del alias: `--surface` colisiona

La estrategia de alias del encargo 1 (`--bg: var(--shell)`, `--border: var(--hair)`, …)
funciona para todos menos para uno. **`--surface` existe en los dos sistemas con
significados distintos**:

- hoy: `#fafafa`, el gris suave de relleno de tarjetas sobre un fondo blanco (51 usos);
- mock: `#ffffff`, el panel blanco de contenido sobre el papel `--shell`.

No se puede escribir `--surface: var(--inset)` porque el propio mock define `--surface`.
Los 52 usos actuales hay que reasignarlos a `--inset` **en el mismo encargo que introduce
los tokens**, no diferirlos al alias. Es el único token que no admite migración perezosa.

`--bg` (40) y `--border` (134) tampoco son 1:1 —cada uno se parte en dos— pero ahí el
alias sí sirve de puente: `--bg: var(--shell)` y `--border: var(--hair)` dejan la app
coherente aunque no óptima, y el reparto fino (`--surface` para `.main-content`, `--line`
para bordes de control) se hace vista a vista.

### 2.4 Lo que escapa al sistema de tokens

Un cambio de paleta no alcanza lo que está escrito en hexadecimal:

| Qué | Dónde | Nota |
|---|---|---|
| **8 colores categóricos de timeline** `.tl-cat--*` | `index.css:2910-2917` | Paleta fría saturada (`#f87171`, `#c084fc`, `#2dd4bf`, `#60a5fa`…) sobre fondos `rgba()`. Chocan de frente con el papel cálido. |
| **4 colores de fase MITRE** | `index.css:2212-2215` | `#64748b`, `#d97706`, `#ea580c`, `#db2777`. Son **taxonomía**: idénticos en claro y oscuro, y coinciden con `PHASE_COLOR` del mock. No se tocan. |
| **La quinta fase, `goal`** | `index.css:2216` | Usa `var(--danger)`, que **sí cambia con el tema** — incoherente con las otras cuatro. El mock la fija a `#dc2626`. |
| **`var(--critical, #ef4444)`** | `index.css:186` | `--critical` **no está definido en ninguna parte**: siempre cae al fallback. Bug latente, no del rediseño. |
| 15 literales `#fff` / `#ffffff` | texto sobre acento, badges | Hoy funcionan sobre azul; hay que revisarlos sobre terracota. |
| 46 `rgba()` literales | sombras y fondos | El encargo 1 retira las sombras salvo la de modal (`0 32px 80px rgba(20,16,13,.28)`). |
| 12 bordes `1.5px` | sidebar, tarjetas | El rediseño es de filete de 1px. |
| 137 `border-radius` | toda la hoja | 51 vía `--radius-card`; el resto, literales a barrer. |

### 2.5 Atributo de tema

El mock usa `[data-om-theme="dark"]` porque es la convención de su runtime.
El nuestro es **`data-theme`**, escrito sobre `documentElement` por
`ThemeProvider.tsx:27`, con la clave `forensia-theme` en `localStorage`
(`ThemeProvider.tsx:11`). Ni el atributo ni la clave se tocan.

---

## 3. Inventario de componentes

Mapa de importaciones verificado con grep sobre todo `web/src`.

### 3.1 `web/src/ui/` (13 ficheros)

| Componente | Lo importan | Destino |
|---|---|---|
| `Badge.tsx` | 9 ficheros | **Cambia de forma** — el mock no usa píldoras de color: etiqueta mono uppercase 10px con borde de 1px. |
| `Button.tsx` | 13 ficheros | **Cambia de forma** — sin radio; la variante primaria pasa a invertida (`--invert-*`). El más extendido: tocarlo repinta media app. |
| `Card.tsx` | 5 ficheros (uno de ellos `PageSection`) | **Cambia de fondo** — el mock **no tiene tarjetas**: separa por filetes y espacio. Queda como envoltorio semántico casi vacío, o se retira. |
| `ContextBanner.tsx` | sólo `DocumentViewerPage` | **Muere** con él (§3.4). |
| `EmptyState.tsx` | 7 ficheros | **Sobrevive**, pero el mock exige vacíos **explicativos** (super-timeline, documentos), no un «sin datos». |
| `ErrorState.tsx` | `AppShell`, `CaseSearchModal`, `RepositoryPage` | Sobrevive tal cual (repintado). |
| `KeyValueList.tsx` | `SettingsPage`, `SystemStatusPage` | **Sobrevive** vía `SettingsPage`; encaja además en la trazabilidad del informe (`traceRows`) y en `serviceRows`. |
| `LoadingState.tsx` | 3 ficheros | Sobrevive tal cual. |
| `MetricCard.tsx` | **nadie** | **Ya está muerto hoy.** Las cuatro cifras de Evidencia en el mock no son tarjetas. Borrar. |
| `Modal.tsx` | `ExecutorLoginModal`, `CaseSearchModal`, `RepositoryPage` | **Sobrevive**, repintado (recto, sombra `0 32px 80px`, `Escape`). Gana dos usuarios: «Nuevo caso» y el acta. |
| `PageHeader.tsx` | **8 páginas** | **Se vacía**: la cabecera pasa al `<main>` del armazón. Es el borrado con más radio de acción del rediseño. |
| `PageSection.tsx` | sólo `RepositoryPage` | **Cambia de forma** — pasa a ser «etiqueta mono + filete que ocupa el resto del ancho», el patrón que el mock repite en todas las vistas. Buen candidato a generalizar. |
| `StatusDot.tsx` | `SettingsPage`, `SystemStatusPage` | Sobrevive vía `SettingsPage`. |

### 3.2 `web/src/components/` (7 ficheros)

| Componente | Lo importan | Destino |
|---|---|---|
| `ActiveCaseHeader.tsx` (154 l.) | sólo `RepositoryPage` | **Se solapa** con el bloque de caso del sidebar + la cabecera del armazón. Candidato a desaparecer, absorbido por los dos. |
| `CaseSearchModal.tsx` (229 l.) | sólo `RepositoryPage` | **Sobrevive y gana importancia**: es el destino de «cambiar caso» del sidebar, disponible desde cualquier vista. |
| `EvidenceInbox.tsx` (469 l.) | sólo `RepositoryPage` | **Cambia de forma**, conserva contrato: multi-subida, 409 informativo, autoselección del `.E01`, etiquetado de continuaciones. |
| `EvidenceTable.tsx` (177 l.) | sólo `RepositoryPage` | **Cambia de forma**: seis columnas del mock, sin cebrado, filete de 1px. |
| `ExecutorLoginModal.tsx` (373 l.) | `SettingsPage`, `ChatPage` | **Sobrevive intacto en comportamiento**; sólo repintado. Es la «acción de conexión» de un ejecutor sin sesión. |
| `Pagination.tsx` (26 l.) | `CaseSearchModal`, `EvidenceTable` | **Sobrevive.** El mock no la dibuja (3 filas de ejemplo), pero los volúmenes reales la necesitan: no darla por muerta. |
| `WorkflowGraph.tsx` (419 l.) | sólo `GuidePage` | **Candidato claro a borrar**: el mock sustituye el grafo por `guideSteps`, una lista de seis pasos numerados con estado. 419 líneas que se van. |

### 3.3 `web/src/layout/`

- `AppShell.tsx` (23 l.) — **se reescribe**: rejilla `272px 1fr` (hoy 260px vía `.app`),
  y el `<main>` incorpora la cabecera contextual.
- `Sidebar.tsx` (115 l.) — **se reescribe entero**. Hoy es un menú plano de botones con
  siete iconos SVG; pasa a ser el estado del caso (marca → caso activo → «Nuevo caso» →
  escalera de fases → utilidades → tema). **Los iconos desaparecen**: el mock no usa
  ninguno en la navegación salvo el `+` del botón.

### 3.4 Ficheros ya huérfanos hoy (antes de tocar nada)

`App.tsx` importa siete páginas. Estas tres islas no las importa **nadie**:

| Fichero | Líneas | Nota |
|---|---|---|
| `pages/SystemStatusPage.tsx` | 88 | Duplicado de la pestaña «Sistema» de `SettingsPage`. |
| `pages/DocumentViewerPage.tsx` | 87 | Versión mock previa a `DocumentsPage`. |
| `mocks/frontendPreviewData.ts` | 145 | Exporta `mockActiveCase`, `mockEvidenceFiles`, `mockReportDocuments`, `mockTimelineEvents`, `mockFindings`, `guideSteps`. Ninguna página lo consume. |

Y arrastran, en cascada, dos más:

- `ui/ContextBanner.tsx` (40 l.) — sólo lo importa `DocumentViewerPage`.
- `types/domain.ts` (74 l.) — sólo lo importan `frontendPreviewData`, `ContextBanner` y
  `DocumentViewerPage`; los tres de la lista.

**Total del código muerto identificado: ~434 líneas** en 5 ficheros, más
`ui/MetricCard.tsx` (25 l.) que tampoco importa nadie. Ninguno se borra ahora: es el
encargo final, y hay que re-verificar con grep entonces.

> Nota: el comentario de `App.tsx:70-72` («Demo visual con mock data — ver
> `src/mocks/frontendPreviewData.ts`») ya no es cierto. Las siete páginas enrutadas
> llaman al backend.

---

## 4. Riesgos

Ordenados por lo que costaría no verlos.

### R1 · Sondeo de capacidades y selector de ejecutor (RULE 2)

`App.tsx:49-64` sondea `/api/capabilities` una vez al montar y pasa `caps` a
`InvestigationPage` y `SettingsPage`, con un `onCapsRefresh` que re-sondea tras conectar
un CLI. Tres cosas se rompen fácil:

1. **El ejecutor arranca vacío a propósito**: `ChatPage.tsx:245`
   (`useState<ExecutorId | "">("")`) y sólo se rellena desde
   `DEFAULT_EXECUTOR` **si el operador lo fijó antes** (`ChatPage.tsx:270-276`,
   `setExecutor((prev) => prev || def.preview)`). Eso **no** es un default silencioso:
   es una preferencia persistida del operador. Al reescribir el compositor es tentador
   «arreglar» el estado vacío con un `?? "ollama"`; sería exactamente la RULE 2 rota.
2. **Los no disponibles se muestran, no se ocultan** (`ChatPage.tsx:618-619, 674-689`):
   deshabilitados, con la razón accionable de `capabilities` en el tooltip y, si son CLI
   cloud, con su acción de conexión. El mock lo respeta (`ENGINES` con `available:false` y
   `note`), pero un rediseño que «limpie» el selector filtrando los no disponibles
   destruye la degradación explícita.
3. **`caps` puede ser `null`** (api caída): hoy `SettingsPage:441` pinta «Sin conexión con
   el servicio api» y `executorEntries` cae a `[]`. La cabecera contextual nueva y la
   escalera de fases del sidebar tienen que aguantar ese `null` sin inventar estado.

Además, la lista de modelos por proveedor sale de `/api/executors/{id}/models`
(`client.ts:executorModels`) y se persiste con `MODEL_CONFIG_KEY`
(`ChatPage.tsx:205-211`). `ENGINES` del mock trae modelos **cableados** («Sonnet»,
«GPT-5.5», «Llama 3.1 8B»): son ejemplo del prototipo, no la fuente.

### R2 · Subida y registro asíncrono de evidencia (el más frágil)

`RepositoryPage.tsx:99-449` es maquinaria fina que un cambio de forma rompe sin ruido:

- **`registerJobRef` ata el sondeo a SU caso** (`:103-104`, `:387`). Si el operador cambia
  de caso, el job sigue vivo en el servidor y el sondeo se detiene en vez de preguntar por
  un job ajeno (que daría 404). Mover el bloque de caso al sidebar hace el cambio de caso
  **mucho más fácil de disparar** — desde cualquier vista, sin pasar por Evidencia.
  Este acoplamiento pasa de raro a cotidiano.
- **Re-enganche al montar**: `api.evidence.listRegisterJobs` existe para que cerrar la
  pestaña no aborte nada. Si la vista rediseñada no lo llama al montar, el registro sigue
  corriendo en el servidor y la UI miente diciendo que no pasa nada.
- **La barra de progreso es real**, no decorativa: `phase ∈ {hashing, copying, verifying}`,
  `seg_index/seg_count`, `bytes_done/bytes_total` (total = 3× el tamaño del set, porque el
  hash-gate recorre cada byte tres veces). El mock **no dibuja esta barra en ninguna
  parte** — su tabla enseña «calculando…» y ya. Es una **omisión del mock**, no una
  retirada: hay que conservarla y darle sitio.
- **El 409 de subida es informativo**, no un error (`:288-340`, `uploadNotice` vs
  `uploadError`). Un rediseño que unifique «todo lo que devuelve 4xx es rojo» convierte
  «ya está en la bandeja» en un fallo aparente.
- **`uploadProgress`** (0..1) es una segunda barra, distinta de la del registro, y se
  reparte entre los ficheros del lote (`:308-312`). Son dos progresos con vidas separadas.

### R3 · Borrado de caso con confirmación por nombre

`RepositoryPage.tsx:87-94`, `:607`, `:1110`, `:1134`: modal tipo-a-confirmar; el botón se
habilita sólo si `deleteConfirmName === activeCase.name` y el backend **revalida**
`confirm_name` respondiendo 409 si no coincide.

**El mock no lo dibuja.** Con la gestión de caso saliendo del cuerpo de la vista, es lo
más fácil de perder por el camino sin que nadie lo note hasta que haga falta. Hay que
decidir explícitamente dónde vive (candidato: dentro de `CaseSearchModal`, o una acción
destructiva al pie del bloque de caso del sidebar) y **no relajar la doble confirmación**:
borra evidencia, audit log encadenado, hallazgos y artefactos, y es irreversible.

### R4 · Los dos ejes de la matriz ATT&CK

`MitreAttackPage.tsx:17-24` lo deja escrito: dos ejes que nunca se funden — propuesta del
agente (`mitre_hints` + `annotate_mitre`) y dictamen del perito (auditado, con
justificación obligatoria). **Una celda gris es «no evaluada», nunca «ausente».** El mock
conserva la frase literal en la leyenda; se queda.

Tres detalles concretos:

- **El mock tiene cuatro estados en la leyenda; el código tiene cinco.**
  `MitreStatus = "confirmada" | "sospechosa" | "descartada"` (`types.ts:439`), y
  `MitreAttackPage:603` pinta el swatch de **descartada**, que no aparece en el mock
  (`mitreStatus()` sólo devuelve confirmada/sospechosa/propuesta). «Descartada» es
  precisamente el estado que distingue «el perito lo evaluó y lo negó» de «nadie lo
  miró»: si se copia la leyenda del mock tal cual, se pierde. **Hay que añadirlo.**
- Los colores de fase son taxonomía: idénticos en ambos temas (§2.4), con `goal` a
  fijar en `#dc2626` en vez de `var(--danger)`.
- Se conservan el catálogo Enterprise real, el dictamen con justificación y la exportación
  Navigator (`exportMitreNavigator`) y CSV (`exportMitreCsv`).

### R5 · Acciones de documentos (verificar / firmar / PDF)

`DocumentsPage.tsx:191-239` sobre `client.ts`: `verifyDocument` (recalcula el SHA-256 y
compara), `signDocument` (borrador → final, auditado), `deleteDocument`,
`downloadDocumentPdf` (blob con token en cabecera — un `<a href>` no puede) y
`generateReport`.

- **Un documento final no se borra**: la acción sólo aparece si
  `selectedDoc.status === "draft"` (`:495`). Es cadena de custodia. Si la barra de acciones
  se rehace uniforme, esa condición se cae sola.
- **El resultado de verificar tiene dos caras** (`:507-511`), y la mala —hash recalculado
  ≠ registrado— es la que importa. No puede quedarse en un icono.
- **El PDF no es un enlace**: pasa por `fetch` con `X-Forensia-Token` y `URL.createObjectURL`.
  Convertirlo en `<a href>` por estética lo rompe (401).
- **SEC INV 8**: hoy no hay ni un `dangerouslySetInnerHTML` en todo `web/src` (verificado
  con grep). El markdown del informe se pinta como texto. Es la tentación número uno de
  esta pantalla.

### R6 · La cabecera contextual acopla armazón y páginas

El encargo 2 mueve la cabecera al `<main>` con un contexto ligero que cada página
alimenta. Dos páginas tienen la acción **dependiente de su estado interno**:

- Timeline: «Exportar CSV» sólo en la capa `investigation`, «Generar super-timeline» sólo
  en las de sistema de ficheros (`renderVals()` lo modela; `TimelinePage.tsx:25` tiene tres
  capas: `investigation | filesystem | relevant`).
- ATT&CK: exportar layer depende de si hay caso y cobertura.

El riesgo es el clásico: para que el armazón sepa qué acción pintar, alguien mete lógica
de negocio en el armazón (RULE 3) o enhebra props por `App.tsx`. El contexto de cabecera
tiene que transportar *datos ya resueltos por la página*, no reglas.

### R7 · La escalera de fases obliga a datos que hoy nadie pide junta

`PHASES` del mock trae meta por fase: «3 ficheros · 2 verificados», «en curso · 2
hallazgos», «2 técnicas propuestas», «sin generar», «1 borrador · 1 final». Cada dato
existe (`listEvidence`, `listFindings`, `listMitreCoverage`, `getPersistedFsTimeline`,
`listDocuments`), pero **hoy los pide cada página por separado, al entrar**. El sidebar
está siempre visible: o se centraliza esa carga en el proveedor de caso activo, o se
convierte en cinco llamadas en cada render.

Y la regla de RULE 2: si un dato no está disponible, la fase se queda en `pending` con
meta vacía. **No se inventa un contador** para que la escalera se vea llena.

### R8 · Estimación previa al análisis: existe en tipos, no en el cliente

El encargo 4 pide «conservar» el aviso de estimación (iteraciones, tokens, tiempo, coste,
con su `basis`). `types.ts:482-525` define `AnalysisEstimate`, `AnalysisEstimateRange`
(`basis: "history" | "heuristic"`) y `AnalysisCostEstimate`… pero **`client.ts` no tiene
método `estimate` y ninguna página lo pinta** (verificado con grep). Lo único vivo es el
descargo textual de `GuidePage.tsx:78`.

O sea: no hay nada que conservar, hay algo que **construir**, y hace falta el endpoint.
Anotarlo como TODO en `docs/operacion/proximos-pasos.md` antes que fabricar rangos en el
cliente — inventar una estimación en la UI sería a la vez RULE 2 y RULE 3.

### R9 · Menores, pero reales

- **Selección automática de evidencia en Timeline**: `TimelinePage.tsx:204` hace
  `setSelectedEvidence(evs[0].evidence_id)`. Es un «coge la primera» que roza RULE 2;
  el mock dibuja un selector explícito (`workstation-disk.E01 ▾`). Buen momento para
  revisarlo, o al menos para no propagarlo.
- **Colapso del panel de investigación**: `InvestigationPage.tsx:236` usa
  `1fr 300px` ↔ `1fr 28px`; el mock usa `minmax(0, 1fr)`, que es lo correcto para que el
  argv largo no desborde la rejilla. Cambio pequeño con efecto real.
- **La media query de 1180px** del mock (`#inv-grid` / `#inv-aside`) no existe hoy: por
  debajo de ese ancho la conversación no cabe junto al panel.
- **`.tl-cat--*`** (§2.4): ocho colores fríos que hay que rehacer, no sólo repintar.
- **Aviso de desajuste de perfil de SO** (`InvestigationPage.tsx:213-228`): banner que
  aparece cuando el triage discrepa del perfil del caso, con la instrucción exacta de qué
  hacer. No está en el mock; se conserva.
- **Anillo de foco**: sólo 2 usos de `--focus-ring` en toda la hoja
  (`index.css:1390`, `:1625`); el resto del foco se marca cambiando `border-color`.
  Sobre papel cálido con acento terracota eso puede quedar por debajo de lo visible.
  Hay navegación por teclado real (`Escape` cierra modales): el rediseño debería
  **mejorar** esto, no barrerlo.

---

## 5. Resumen para los encargos siguientes

- Lo que el mock **añade**: escalera de fases, cabecera contextual, modal «Nuevo caso»,
  motores como filas desplegables, vacíos explicativos.
- Lo que el mock **omite y no puede perderse**: barra de progreso del registro asíncrono
  (R2), borrado de caso con confirmación por nombre (R3), estado «descartada» de ATT&CK
  (R4), paginación (§3.2), aviso de desajuste de perfil (R9).
- Lo que **ya está hecho** y el enunciado daba por pendiente: la vista `system` no está
  en la navegación y su diagnóstico ya vive en una pestaña de Configuración (§1.3).
- Lo que **no existe** y el enunciado daba por vivo: la estimación previa al análisis (R8).
- El punto de mayor riesgo técnico del encargo 1: **`--surface` cambia de significado**
  (§2.3) — es el único token que no admite alias transitorio.
