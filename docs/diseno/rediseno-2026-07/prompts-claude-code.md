# Prompts para ejecutar el rediseño con Claude Code

Ocho prompts encadenados que llevan la SPA de `web/` desde la interfaz actual
(navegación plana, acento azul, esquinas redondeadas) hasta el mock
[`mocks/rediseno-final.dc.html`](mocks/rediseno-final.dc.html) (flujo de cinco
fases del caso, paleta de papel, acento terracota, esquinas rectas).

## Cómo usar esta guía

- **Una sesión de Claude Code por prompt.** Entre uno y otro, `/clear`. Cada prompt
  es autocontenido: no asume que la sesión recuerde nada de la anterior, solo que el
  commit anterior está en el árbol.
- **Un commit por prompt**, en la rama `redesign`. Convención del repo: mensajes en
  español, `feat(web): …` / `refactor(web): …` / `docs(…): …`. **RULE 0**: ninguna
  atribución a IA en el commit.
- **Revisa el diff antes de encadenar.** El prompt 0 no toca código: sirve para que
  Claude Code se oriente y para que tú valides el mapa de equivalencias antes de
  que empiece a mover ficheros.
- **Orden no negociable.** 1 y 2 son los cimientos (tokens y shell); 3-6 los
  consumen. Saltarse el orden multiplica los conflictos.
- Claude Code lee `CLAUDE.md` solo. Aun así, cada prompt repite las invariantes que
  puede erosionar, porque son las que un rediseño visual rompe sin darse cuenta.

## Invariantes que ninguno de los ocho prompts puede erosionar

Vale la pena tenerlas presentes al revisar cada diff:

| Invariante | Cómo se rompe en un rediseño |
|---|---|
| **RULE 2 — sin defaults silenciosos** | Preseleccionar un ejecutor «para que el chat no se vea vacío». El selector arranca sin selección y el envío falla con razón accionable. |
| **RULE 3 — superficies finas** | Meter lógica de orquestación en un componente porque «así queda mejor la tarjeta». La UI solo pinta lo que devuelve `api/client.ts`. |
| **SEC INV 8 — evidencia como texto** | Un `dangerouslySetInnerHTML` para renderizar un informe o la salida de una herramienta. Jamás: la evidencia es dato hostil. |
| **Degradación explícita** | Ocultar una capacidad no disponible en vez de mostrarla con su motivo. Si un maletín o un ejecutor no está, se dice y se dice por qué. |
| **RULE 4 / RULE 6** | Cerrar sin actualizar docs ni pasar `npm run typecheck` + `npm run build`. El prompt 7 existe para esto. |

---

## Prompt 0 · Reconocimiento y mapa de equivalencias (sin código)

````
Vas a preparar el rediseño de la interfaz web de Agentopsy. Este primer encargo es
de LECTURA: no modifiques ningún fichero de `web/`.

Lee, en este orden:
1. `docs/diseno/rediseno-2026-07/README.md` y el mock destino
   `docs/diseno/rediseno-2026-07/mocks/rediseno-final.dc.html`. Es un documento de
   Claude Design: HTML con estilos inline y una capa de plantillas (`<sc-for>`,
   `<sc-if>`, `{{ bindings }}`). Lo que te interesa está en dos sitios: el marcado
   de cada vista (delimitado por `<sc-if value="{{ isEvidence }}">`,
   `isInvestigation`, `isMitre`, `isTimeline`, `isReport`, `isSettings`, `isGuide`)
   y el bloque `<script type="text/x-dc">` del final, donde viven las constantes
   `PHASES`, `UTILITIES`, `CUSTODY`, `SETTINGS_TABS`, `ENGINES` y `HEADERS`, más
   los métodos `phaseRow()`, `engineRow()` y `renderVals()`.
2. `docs/diseno/rediseno-2026-07/mocks/ui-actual.dc.html` — la UI de partida
   capturada como mock, para comparar.
3. El código real: `web/src/index.css`, `web/src/App.tsx`,
   `web/src/navigation/navItems.ts`, `web/src/layout/`, `web/src/ui/`,
   `web/src/pages/` y `web/src/components/`.

Escribe `docs/diseno/rediseno-2026-07/plan-migracion.md` con:

- **Tabla de equivalencias de vistas**: cada `sc-if` del mock ↔ el fichero de
  `web/src/pages/` que la implementa hoy. Señala explícitamente los tres casos que
  no son 1:1 — el mock no tiene vista «Sistema» (su contenido pasa a una pestaña de
  Configuración), llama «Evidencia» a lo que hoy es `RepositoryPage` y «Informe
  pericial» a lo que hoy es `DocumentsPage`.
- **Tabla de tokens**: cada variable CSS de `:root` y `[data-theme="dark"]` en
  `index.css` ↔ la variable del mock que la sustituye, o «sin equivalente» si hay
  que inventarla. Cuenta cuántos usos tiene cada variable actual en el CSS
  (`grep -c`), para dimensionar la migración.
- **Inventario de componentes**: qué hay en `web/src/ui/` y `web/src/components/`,
  cuáles sobreviven tal cual, cuáles cambian de forma y cuáles se quedan sin uso
  (candidatos a borrar en el prompt final). Comprueba con grep qué páginas importa
  hoy `App.tsx`: hay ficheros en `pages/` que ya no están enrutados.
- **Riesgos**: lista de sitios donde el rediseño puede romper funcionalidad viva.
  Como mínimo revisa y cita: el sondeo de capacidades y el selector de ejecutor,
  la subida y registro asíncrono de evidencia con su polling de progreso, el
  borrado de caso con confirmación por nombre, los dos ejes independientes de la
  matriz ATT&CK, y las acciones de documentos (verificar / firmar / PDF).

No propongas todavía código. El entregable es ese documento.
````

---

## Prompt 1 · Tokens, tipografía y primitivas visuales

````
Migra el sistema visual de la SPA de Agentopsy a la paleta del mock
`docs/diseno/rediseno-2026-07/mocks/rediseno-final.dc.html`. Este encargo es SOLO
de capa visual: no muevas ficheros, no cambies la navegación ni la estructura de
ninguna página. Al terminar, la app debe funcionar exactamente igual y verse de
papel cálido en vez de azul.

**1. Sustituye el bloque de tokens de `web/src/index.css`.** El mock los define en
su `<style>` de cabecera; cópialos con estos mismos nombres:

  Claro (`:root`):
    --shell #fbf9f6 · --surface #ffffff · --inset #faf7f3
    --ink #1b1815 · --ink-2 #55504a · --ink-3 #7a736b · --ink-4 #a39a90
    --ink-5 #b8b0a6 · --ink-6 #c3bbb1
    --hair #e5dfd6 · --hair-2 #f0ebe4 · --line #d8d2c9 · --track #ece6de
    --accent #8c3a2b · --accent-hover #6d2b1f · --accent-soft #d8c4bd
    --accent-wash #f4eeea
    --ok #4a7c59 · --pending #ddd6cc · --next #c0a49c
    --invert-bg #1b1815 · --invert-fg #ffffff
    --code-bg #12100e · --code-fg #f4f1ec · --code-dim #8a827a

  Oscuro (`[data-theme="dark"]`):
    --shell #101214 · --surface #16191c · --inset #1d2125
    --ink #eceae6 · --ink-2 #b6b0a8 · --ink-3 #8f8880 · --ink-4 #6f6862
    --ink-5 #5a5450 · --ink-6 #4a4542
    --hair #262a2e · --hair-2 #202428 · --line #333940 · --track #2a2f34
    --accent #d1745c · --accent-hover #e08e77 · --accent-soft #6b3d31
    --accent-wash #241a17
    --ok #6fae7e · --pending #3a4046 · --next #7a5347
    --invert-bg #eceae6 · --invert-fg #16191c
    --code-bg #0b0d0e · --code-fg #f4f1ec · --code-dim #8a827a

**IMPORTANTE — el atributo del tema es `data-theme`, el nuestro.** El mock usa
`data-om-theme` porque es una convención de su propio runtime. No toques
`web/src/ThemeProvider.tsx` ni la clave de localStorage `forensia-theme`.

**2. Migra por alias, no de golpe.** `index.css` tiene ~2.900 líneas escritas
contra los nombres viejos. Conserva los nombres actuales como alias apuntando a los
nuevos, para que nada se rompa mientras las páginas se migran una a una en los
prompts siguientes:

    --bg: var(--shell);  --sidebar-bg: var(--shell);
    --border: var(--hair);
    --text-primary: var(--ink);  --text-secondary: var(--ink-2);
    --text-muted: var(--ink-4);
    --accent-bg: var(--accent-wash);  --accent-text: var(--accent);
    --success: var(--ok);

Deja un comentario encima diciendo que son alias transitorios y que el prompt final
del rediseño los retira. `--danger` y `--warning` NO son alias: son severidad de
hallazgo, mantienen su semántica; reajusta sus valores para que convivan con la
paleta cálida sin perder contraste (verifícalo también en tema oscuro).

**`--surface` es la excepción y no admite alias: hay que migrarlo en ESTE commit.**
Existe en los dos sistemas con significados distintos — hoy es `#fafafa`, el gris de
relleno de tarjeta sobre fondo blanco; en el mock es `#ffffff`, el panel de contenido
sobre el papel `--shell`. No puedes escribir `--surface: var(--inset)` porque el mock
define `--surface`. Reasigna sus ~52 usos actuales a `--inset` a la vez que introduces
la paleta; diferirlo deja la app en un estado incoherente y difícil de depurar.

**3. Geometría y tipografía.**
- `--radius-card: 4px` pasa a `0`. El rediseño es de esquinas rectas y filetes de
  1px; los únicos elementos con radio son los que el mock dibuja como píldora
  (`--radius-pill`, botón «Nuevo caso» y caja del compositor de chat).
- Sombras: fuera, salvo la de los modales (`0 32px 80px rgba(20,16,13,.28)`).
- Bordes: 1px sólido `var(--hair)` para separadores estructurales, `var(--line)`
  para bordes de control. Elimina los `1.5px` sueltos.
- Las fuentes ya son correctas (IBM Plex Sans / Mono). Lo que cambia es el uso:
  **la mono es la voz de los metadatos.** Etiquetas de sección, eyebrows, contadores,
  hashes, argv, IDs de herramienta y estados van en mono, minúscula de 9,5-11,5px,
  `text-transform: uppercase` y `letter-spacing: .1em-.16em`, en `var(--ink-4)`.
  Añade una clase reutilizable para esto (p. ej. `.eyebrow`) en vez de repetirlo.
- Escala de texto: título de vista 21px/600 con `letter-spacing: -0.015em`; texto de
  cuerpo 13,5-14,5px con `line-height: 1.6`; tablas 13,5px.
- Scrollbars: 8px, pulgar `var(--pending)`, pista transparente.
- Anillo de foco visible y con contraste sobre la paleta cálida: NO lo elimines por
  estética. Es accesibilidad y hay navegación por teclado real (Escape cierra
  modales).

**4. Actualiza `web/src/ui/*`** (Badge, Button, Card, MetricCard, StatusDot,
PageHeader, PageSection, KeyValueList, ContextBanner, Modal, EmptyState,
ErrorState, LoadingState) para que respiren la paleta nueva: sin radios, filetes de
1px, jerarquía por peso tipográfico y espacio en vez de por relleno de color.

**No toques**: `web/src/api/`, `web/src/pages/*` salvo que un cambio de token
obligue a un ajuste puntual de una clase, la navegación, ni nada de `backend/`.

**Verificación** (obligatoria antes de commitear, RULE 6): desde `web/`,
`npm run typecheck` y `npm run build` deben pasar. Levanta la SPA y recorre las
siete vistas en tema claro Y oscuro comprobando que no queda ningún azul
(#1d4ed8 / #3b82f6) ni esquina redondeada fuera de las píldoras. Reporta cualquier
sitio donde el contraste quede por debajo de lo legible en vez de darlo por bueno.

Commit: `refactor(web): paleta de papel y esquinas rectas — tokens del rediseño`
````

---

## Prompt 2 · Shell: sidebar de fases y cabecera contextual

````
Reestructura el armazón de la SPA de Agentopsy según el mock
`docs/diseno/rediseno-2026-07/mocks/rediseno-final.dc.html`. El cambio conceptual:
**el sidebar deja de ser un menú de secciones y pasa a ser el estado del caso.**

Lee en el mock: el `<aside>` inicial, el `<header>` del `<main>`, y en el bloque
`<script type="text/x-dc">` las constantes `PHASES`, `UTILITIES` y `HEADERS` y el
método `phaseRow()`.

**1. `web/src/navigation/navItems.ts`.** El menú plano actual pasa a dos grupos:

- **Fases del caso**, en este orden, con etiqueta y línea de meta:
  `repository` → «Evidencia», `investigation` → «Investigación`,
  `mitre` → «Correlación ATT&CK», `timeline` → «Timeline»,
  `document-viewer` → «Informe pericial».
- **Utilidades**: `settings` → «Configuración», `guide` → «Guía».

**Conserva los valores actuales de `ViewId`** (`repository`, `document-viewer`, …)
aunque las etiquetas cambien. Renombrarlos obligaría a migrar la clave de
localStorage `forensia-active-view` y a tocar decenas de sitios sin ganar nada
funcional; si aun así se renombran algún día, hará falta una migración de esa clave
porque `initialView()` en `App.tsx` descarta valores desconocidos.

El sidebar del mock ya no lista la vista de sistema: **quita `system` de la
navegación**. Su contenido se absorbe en Configuración en el prompt 6; hasta
entonces, `SystemStatusPage` queda huérfano — no lo borres todavía.

**2. `web/src/layout/Sidebar.tsx`**, 272px, en este orden vertical:

  a. Marca: «AGENTOPSY» en mono 15px/600 con `letter-spacing: .26em`, y debajo
     «Análisis post-mortem» en mono 10px uppercase `.16em` en `var(--ink-4)`.
  b. **Bloque de caso activo**: nombre del caso, línea mono con
     `os_profile · estado`, y una acción «cambiar caso» en `var(--accent)` que
     abre el `CaseSearchModal` existente. Sale de `useActiveCase()`
     (`web/src/state/activeCase.tsx`). **Sin caso activo el bloque no se inventa
     uno**: muestra el estado vacío y lleva a seleccionar caso.
  c. Botón «Nuevo caso» a ancho completo, en píldora, borde `var(--line)`, fondo
     `var(--inset)`, con el icono `+`. Abre el modal de creación de caso (prompt 3).
  d. **Escalera de fases**, bajo la etiqueta «FASES DEL CASO». Rejilla de dos
     columnas (18px para el raíl, 1fr para el texto): un punto por fase, unidos por
     una línea vertical de 1px, y a la derecha etiqueta + meta en mono 11px.

     Aquí va la decisión importante del diseño, y hay que respetarla:
     **son dos señales independientes.** El PUNTO dice dónde está el CASO y no
     depende de qué vista tengas abierta:
       - `done` → relleno `var(--ok)` con un «✓», y el tramo de línea que sale de
         él también en `var(--ok)`;
       - `current` → aro de `var(--accent)` sobre `var(--surface)`;
       - `next` → aro de 1,5px en `var(--next)`, sin relleno;
       - `pending` → aro punteado de 1,5px en `var(--pending)`.
     La FILA dice dónde estás TÚ: la vista seleccionada lleva una barra interior
     de 2px a la izquierda en `var(--ink)` y su etiqueta en peso 600.

     El estado de cada fase se deriva del caso activo, no se cablea: evidencias
     registradas y verificadas, si hay hallazgos, si hay técnicas propuestas, si la
     super-timeline está generada, cuántos documentos hay. Si un dato aún no está
     disponible en el cliente API, deja la fase en `pending` con meta vacía y
     anótalo como TODO — **no inventes un contador** (RULE 2).
  e. Utilidades (Configuración, Guía) tras un filete superior.
  f. Conmutador de tema al pie, como el glifo textual del mock («● oscuro» /
     «○ claro»), llamando al `toggle()` de `ThemeProvider`.

**3. `web/src/layout/AppShell.tsx`.** Rejilla `272px 1fr`, altura `100vh`, sin
scroll en el contenedor; el scroll vive dentro del `<main>`. El `<main>` incorpora
la **cabecera contextual** del mock: `padding: 24px 44px 20px`, filete inferior, y
tres piezas — eyebrow mono («Fase N de 5» para las fases, «Servicio» para
Configuración y Guía), título 21px/600, y a la derecha un meta en mono 11,5px más
UNA acción invertida (`var(--invert-fg)` sobre `var(--invert-bg)`, mono 11px
uppercase, `padding: 10px 18px`, sin radio).

Meta y acción son contextuales y algunos dependen del estado interno de la página
(en Timeline, por ejemplo, la acción es «Exportar CSV» en la capa de investigación
y «Generar super-timeline» en la de sistema de ficheros). Resuélvelo con un
contexto ligero de cabecera que cada página alimenta al montarse — no con props
enhebradas por `App.tsx`, y sin duplicar lógica de negocio en el shell (RULE 3).
Las páginas dejan de pintar su propia cabecera; retira ese bloque de cada una y
adapta `web/src/ui/PageHeader.tsx` o retíralo si se queda sin uso.

El área de contenido de las páginas lleva `padding: 34px 44px 48px` y su propio
scroll vertical.

**No toques**: `web/src/api/`, el interior de las páginas más allá de quitarles la
cabecera propia, ni `backend/`.

**Verificación**: `npm run typecheck` y `npm run build` desde `web/`. Comprueba a
mano que navegar entre las siete vistas funciona, que la vista activa sobrevive a
un F5 (localStorage) y que con y sin caso activo el sidebar se comporta —
especialmente el estado sin caso, que es el que más fácil se rompe.

Commit: `feat(web): sidebar de fases del caso y cabecera contextual`
````

---

## Prompt 3 · Fase 1 · Evidencia

````
Rediseña la vista de evidencia de Agentopsy (`web/src/pages/RepositoryPage.tsx`,
`ViewId` = `repository`, etiquetada «Evidencia») según el bloque
`<sc-if value="{{ isEvidence }}">` del mock
`docs/diseno/rediseno-2026-07/mocks/rediseno-final.dc.html`. Mira también la
constante `CUSTODY` y el modal de acta al final del mock.

Estructura destino, de arriba abajo:

1. **Cuatro cifras en fila**, separadas por filetes verticales, sin tarjetas ni
   fondos: registradas, con hash verificado, pendientes, y el examinador del caso.
   Número grande en `var(--ink)`, etiqueta en mono uppercase en `var(--ink-4)`.
2. **Zona de alta de evidencia**: área de arrastre con filete punteado, título
   «Añadir evidencia», una línea explicando que Agentopsy calcula el SHA-256
   baseline y deja la evidencia en solo lectura antes de que ninguna herramienta la
   toque, y una acción secundaria «Examinar bandeja» hacia el contenido de
   `./evidence`.
3. **Tabla de evidencias del caso**: fichero · tipo · tamaño · SHA-256 (abreviado,
   en mono) · integridad · acción. Cabecera en mono uppercase, filas separadas por
   filete de 1px, sin cebrado. El estado verificado va en `var(--ok)`; el pendiente
   en `var(--accent)` con la acción «Verificar ahora».
4. **Cadena de custodia**: una línea por evidencia registrada con nombre, tamaño,
   sha256 abreviado, estado de la cadena y un enlace «Acta de adquisición» que abre
   un modal con los campos del mock (caso y examinador, origen, SHA-256 baseline,
   tamaño en bytes, fecha de registro, nivel de solo-lectura, enlace de la cadena
   encadenada por hash, verificación y herramienta). El acta **muestra los datos de
   SU evidencia**, no los de la primera de la lista.

**Todo lo que ya funciona aquí se conserva; esto es un cambio de forma, no de
comportamiento.** En concreto, verifica antes de tocar y vuelve a verificar después:

- **Subida a la bandeja**: selección múltiple y arrastre de varios ficheros a la
  vez; un 409 es informativo («ya está en la bandeja», la evidencia nunca se
  sobrescribe), no un error rojo.
- **Sets EWF multi-segmento**: se autoselecciona el `.E01` del lote y las
  continuaciones se listan etiquetadas como «segmento EWF · se registra desde el
  .E01», no seleccionables.
- **Registro asíncrono**: `POST /api/cases/{id}/evidence/async` devuelve un
  `job_id`; la UI puentea el progreso real (`phase` ∈ hashing/copying/verifying,
  `seg_index/seg_count`, `bytes_done/bytes_total`) y **se re-engancha al montar**
  listando los trabajos del caso, para que cerrar la pestaña no aborte nada. Esa
  barra de progreso tiene que sobrevivir al rediseño con su fase y sus bytes.
- **Borrado de caso**: confirmación escribiendo el nombre exacto; distinto → 409 y
  no se borra nada. El destructivo se marca con `var(--danger)`, sin adornos.
  **El mock no lo dibuja en ninguna parte** y la gestión de caso se va del cuerpo de
  esta vista al sidebar, así que es lo más fácil de perder por el camino. Decide
  explícitamente dónde vive — candidatos: dentro de `CaseSearchModal`, o como acción
  destructiva al pie del bloque de caso del sidebar — y no relajes la doble
  confirmación: borra evidencia, audit log, hallazgos y artefactos, y es irreversible.
- **El progreso del registro tampoco está en el mock** (su tabla enseña «calculando…»
  y ya). Es una omisión del prototipo, no una retirada: consérvalo con su fase y sus
  bytes, y dale sitio. Ojo además a que son DOS progresos con vidas separadas — el de
  subida del lote y el del registro.
- **`CaseSearchModal` y `ActiveCaseHeader`**: siguen siendo los puntos de cambio de
  caso; realinéalos a la paleta y a la cabecera nueva del shell (el título de la
  vista ya lo pinta el shell, no la página).

Reutiliza `web/src/components/EvidenceInbox.tsx` y `EvidenceTable.tsx` en vez de
reescribirlos desde cero; si su estructura ya no encaja, refactorízalos conservando
su contrato con `api/client.ts`, que **no se toca**.

Nada de lógica nueva en la página: sigue siendo un adaptador fino sobre el cliente
API (RULE 3). Si un dato que el mock muestra no existe hoy en la API, no lo
inventes: omítelo y anótalo como TODO con el endpoint que haría falta.

**Verificación**: `npm run typecheck` + `npm run build`. Prueba el ciclo completo
con un fichero real pequeño: arrastrar → aparece en la bandeja → registrar →
progreso por fases → verificado → abrir su acta. Y el caso sin evidencias, que es
el estado en el que entra un usuario nuevo.

Commit: `feat(web): fase de evidencia con cadena de custodia y acta de adquisicion`
````

---

## Prompt 4 · Fase 2 · Investigación

````
Rediseña la vista de investigación de Agentopsy
(`web/src/pages/InvestigationPage.tsx`, que envuelve a `web/src/pages/ChatPage.tsx`)
según el bloque `<sc-if value="{{ isInvestigation }}">` del mock
`docs/diseno/rediseno-2026-07/mocks/rediseno-final.dc.html`.

**Layout.** Rejilla de dos columnas: `minmax(0, 1fr) 300px` con el panel abierto,
`minmax(0, 1fr) 28px` colapsado, con un tirador («›» / «‹») siempre visible. Por
debajo de 1180px de ancho el panel se retira y la conversación ocupa todo (el mock
lo resuelve con una media query; el motivo es que la conversación no cabe al lado
del panel y se prefiere la conversación).

**Conversación.** Cada turno arranca con la hora en mono en un raíl izquierdo
estrecho y el rol en mono uppercase («Perito», «agentopsy-windows»). Sin burbujas
de chat: bloques separados por filetes, ancho de lectura limitado.

Tres tipos de bloque:
- **Cadena de ejecución**: agrupa las llamadas a herramientas de un turno en un
  bloque plegable con encabezado («N pasos · registrada») y una línea por
  ejecución: marca de resultado, el **argv literal en mono** y un resumen corto
  del resultado. El argv es la verdad auditada — se muestra tal cual, sin
  reescribir ni embellecer, y **como texto** (SEC INV 8: nunca HTML; la salida de
  una herramienta es contenido derivado de evidencia hostil).
- **Respuesta del agente**: prosa a 14,5px con `line-height: 1.6`.
- **Hallazgo**: aviso destacado con filete de acento a la izquierda, severidad en
  mono uppercase, título, y la técnica ATT&CK propuesta cuando la haya —
  etiquetada como propuesta, nunca como confirmada (los dos ejes no se mezclan).
- **Estado en vivo**: mientras corre una herramienta, la línea con el punto que
  late y el comando en curso.

**Compositor.** Caja en píldora con el marcador de ejecutor a la izquierda
(«Claude Code · Sonnet»), adjuntar y enviar. Debajo, atajos de prompt en mono
(«buscar persistencia», «analizar conexiones de red», «generar timeline del sistema
de ficheros», «redactar informe») que rellenan el campo — **no lo envían**.

**Panel de contexto** (derecha), tres secciones con encabezado mono y contador:
Hallazgos (título, resumen de una línea, severidad · herramienta), Herramientas
(id de herramienta y número de ejecuciones correctas) y Coste (total en tokens y
una fila por ejecutor con barra de magnitud). En la barra de coste: un solo tono
de acento por magnitud, no una paleta categórica, y **«no reportado» tiene que
distinguirse visualmente de un cero real** — Codex no reporta tokens y pintar un 0
sería mentir.

**Comportamiento que se conserva íntegro:**
- **El ejecutor no tiene default (RULE 2).** Sin selección, el envío no ocurre y se
  explica por qué. Un ejecutor no disponible se muestra con su razón accionable y
  su acción de conexión (`ExecutorLoginModal`), no oculto.
- **Estimación previa al análisis**: OJO, esto NO es «conservar». `api/types.ts`
  define `AnalysisEstimate` / `AnalysisEstimateRange` / `AnalysisCostEstimate`, pero
  `client.ts` no tiene método `estimate` y ninguna página lo pinta: los tipos están,
  la implementación no (`CLAUDE.md` § Status dice lo contrario y está desactualizado
  en este punto). El mock sí dibuja el aviso. **No fabriques los rangos en el
  cliente** — sería RULE 2 y RULE 3 a la vez. O cableas el endpoint real
  `GET /api/cases/{id}/analyze/estimate` con su `basis` y su descargo, o lo dejas
  fuera y lo anotas en `docs/operacion/proximos-pasos.md`. Dime cuál eliges antes de
  implementarlo.
- Persistencia de la conversación (`session_id`), refresco de hallazgos tras cada
  turno, y el aviso de desajuste de perfil de SO cuando el triage discrepa del
  perfil del caso.

**No toques** `web/src/api/client.ts` ni `types.ts`, ni nada de `backend/`.

**Verificación**: `npm run typecheck` + `npm run build`. Prueba con un caso real:
sin ejecutor seleccionado (debe negarse con motivo), con Ollama, y con el panel
colapsado y por debajo de 1180px. Comprueba que un turno largo con varias
herramientas se lee bien y que el argv no se desborda.

Commit: `feat(web): investigacion con cadena de ejecucion y panel de contexto`
````

---

## Prompt 5 · Fases 3 y 4 · ATT&CK y Timeline

````
Rediseña dos vistas de Agentopsy según el mock
`docs/diseno/rediseno-2026-07/mocks/rediseno-final.dc.html`: los bloques
`<sc-if value="{{ isMitre }}">` y `<sc-if value="{{ isTimeline }}">`. Ficheros:
`web/src/pages/MitreAttackPage.tsx` y `web/src/pages/TimelinePage.tsx`.

## Correlación ATT&CK

Estructura: conmutador Matriz / Línea temporal, buscador de técnica o ID, y
conmutadores de sub-técnicas y «solo cubiertas». Debajo, un **raíl de fases** con
una barra de progreso por fase, tres contadores grandes (confirmadas · sospechosas
· tácticas cubiertas) y la matriz en columnas por táctica: nombre en español,
nombre canónico en inglés y total en mono, cobertura, y las técnicas como celdas
apiladas con su número de sub-técnicas.

**La regla que no se puede erosionar** (está en `CLAUDE.md` y es el corazón de esta
pantalla): **propuesta del agente y dictamen del perito son dos ejes distintos y no
se fusionan jamás.** La leyenda del mock los separa en cuatro estados —
confirmada por el perito, sospechosa, propuesta del agente sin dictaminar, y no
evaluada — y añade la aclaración literal «gris = no evaluada, nunca "ausente"».
Esa frase se queda. Un color no puede dar a entender que una técnica se descartó
si nadie la evaluó.

**Y el mock se queda corto aquí: son cinco estados, no cuatro.** `MitreStatus` en
`api/types.ts` incluye `descartada`, y la página la pinta hoy. «Descartada» es
justamente lo que distingue «el perito lo evaluó y lo negó» de «nadie lo miró»: si
copias la leyenda del mock tal cual, se pierde el estado más informativo de los
cinco. Consérvalo.

Conserva: la matriz sobre el catálogo Enterprise real, el dictamen del perito
(que exige justificación y queda en el audit log encadenado) y la exportación de
capa para ATT&CK Navigator.

Los colores categóricos de fase (prep / access / root / act / goal) ya existen en
`index.css` (`.mitre-phase-dot--*` / `.mitre-phase-fill--*`) y **deben ser
idénticos en tema claro y oscuro**: son taxonomía, no decoración. Cuatro ya están
fijados en hexadecimal; `goal` es la excepción — usa `var(--danger)`, que cambia
con el tema. Fíjalo a `#dc2626`, como los otros cuatro y como el mock
(`PHASE_COLOR`). Lo que se realinea a la paleta es todo lo demás.

## Timeline

Pestañas de capa con su contador, la aclaración «Todas las horas en UTC» siempre
visible, buscador cuyo texto de ayuda cambia según la capa («herramienta, argv,
hallazgo o técnica» en la de investigación; «ruta, MACB o inode» en la de sistema
de ficheros) y, en las capas de sistema de ficheros, el selector de evidencia.

Los eventos se agrupan por día con un encabezado de día y contador; cada fila lleva
hora en mono en el raíl izquierdo, tipo y fuente en mono uppercase, y el cuerpo.

Cuando la super-timeline no está generada, el vacío es **explicativo**: se dice que
se construye ejecutando `tsk_fls -m` sobre la evidencia seleccionada y que es un
trabajo asíncrono que corre mientras se sigue investigando. No un «sin datos» seco.

La acción de la cabecera es contextual y la resuelve el contexto de cabecera del
shell: «Exportar CSV» pertenece SOLO a la capa de investigación, «Generar
super-timeline» solo a las de sistema de ficheros.

**No toques** `api/client.ts` ni `backend/`. Si alguna de las dos páginas conserva
datos mock, sustitúyelos por la llamada real si el endpoint existe; si no existe,
déjalo marcado como TODO en vez de dar el mock por real.

**Verificación**: `npm run typecheck` + `npm run build`. Comprueba la matriz con un
caso con propuestas y sin ellas, el cambio de capa en Timeline con su acción de
cabecera correspondiente, y ambas vistas en tema oscuro (la matriz es donde antes
se veía peor).

Commit: `feat(web): matriz ATT&CK y timeline realineadas al rediseno`
````

---

## Prompt 6 · Fase 5 · Informe, Configuración y Guía

````
Rediseña las tres vistas restantes de Agentopsy según el mock
`docs/diseno/rediseno-2026-07/mocks/rediseno-final.dc.html` — bloques
`isReport`, `isSettings` e `isGuide`. Ficheros: `web/src/pages/DocumentsPage.tsx`,
`SettingsPage.tsx` y `GuidePage.tsx`.

## Informe pericial (`document-viewer`)

Dos columnas: a la izquierda la lista de documentos del caso con buscador, filtros
Todos / Borrador / Final y agrupación por evidencia; a la derecha el documento
seleccionado.

Sobre la lista, el generador de borrador: explica que el informe se redacta desde
los hallazgos, la cadena de custodia y la correlación MITRE **reales del caso**, y
recoge los datos opcionales del perito (nombre, nº de colegiado, organización,
contacto, versión) advirtiendo que sin ellos figura el examinador.

El documento se pinta con una barra de metadatos en mono (id · estado, páginas,
sha256, integridad verificada) y secciones numeradas: objeto del análisis,
hallazgos como fichas con severidad + título + técnica, y trazabilidad como pares
clave-valor. Conserva las acciones vivas: verificar integridad, firmar
(borrador → final, auditado), borrar **solo borradores** — un documento final no se
borra, es cadena de custodia — y descargar el PDF.

El contenido del documento se renderiza **como texto** (SEC INV 8). Nada de
`dangerouslySetInnerHTML`, por muy cómodo que resulte para el markdown.

Si al abrir no hay documentos, el vacío explica que el informe se genera desde los
hallazgos del caso — no un «sin resultados».

## Configuración

Tres pestañas. **Cuidado con una premisa falsa**: el traslado de «Sistema» a
Configuración **ya ocurrió** — `navItems.ts` no declara `system` y `SettingsPage.tsx`
ya tiene las tres pestañas `executors | system | appearance` con el diagnóstico de
maletines dentro. Lo que queda es (a) cambiar etiquetas y estructura, y (b) borrar
`SystemStatusPage.tsx`, que sigue en el árbol como duplicado huérfano (eso lo hace el
encargo 7). No rehagas un traslado que ya está hecho.

1. **Motor de análisis.** Encabezado que dice quién ejecuta el análisis y que hay
   que elegir: «Agentopsy no lo hace por ti» — esa frase ES la RULE 2 dicha al
   usuario. Una fila por motor, desplegable, con punto de disponibilidad, nombre,
   ámbito (nube / local), marca de «por defecto» y modelo elegido en la MISMA fila.
   Al desplegar: la nota de estado (por ejemplo «Sin sesión en el contenedor», con
   su acción de conexión), las opciones de modelo y la acción de fijarlo por
   defecto. Debajo, el tiempo máximo por ejecución y la nota «sin API keys ·
   sesiones y ajustes solo en tu máquina».

   Un motor no disponible **se muestra con su motivo**, no se oculta ni se
   deshabilita en silencio. Las opciones de modelo salen de las capacidades reales;
   no cablees una lista inventada.
2. **Sistema · Maletín.** Estado de los dos maletines (`toolkit-windows`,
   `toolkit-unix`) con su punto, catálogo de herramientas con disponibilidad por
   herramienta, y datos del servicio. Cuando el api no alcanza un maletín, se dice
   con su razón accionable — nunca un `false` mudo.
3. **Apariencia.** Claro / Oscuro, con la nota de que se guarda en este navegador
   y se aplica a toda la aplicación. Enchufado al `ThemeProvider` existente.

## Guía

Tres bloques: el **flujo de trabajo** en seis pasos numerados cuyo estado refleja el
caso activo (Hecho / En curso / Pendiente, con el color correspondiente); **iniciar
sesión en un ejecutor**, con los tres comandos `docker compose exec` sobre fondo
oscuro en mono; y **lo que debes saber**, cuatro notas: ejecutor cloud y privacidad
(RGPD), coste y tiempo orientativos, principios forenses, y alcance académico.

El aviso de egreso cloud vive aquí desde que se retiró el consentimiento por caso
(2026-07-16): **no lo pierdas ni lo suavices** — dice que al elegir un ejecutor
cloud salen datos derivados de la evidencia, posiblemente personales, bajo la
suscripción del propio usuario, y que Ollama es la alternativa 100% local.

Los estados del flujo se derivan del caso activo; sin caso, se muestran como
pendientes, no como hechos.

**Verificación**: `npm run typecheck` + `npm run build`. Recorre las tres pestañas
de Configuración con un ejecutor conectado y otro sin sesión, comprueba que el
cambio de tema sigue persistiendo tras F5, y abre un documento final para
confirmar que no se puede borrar.

Commit: `feat(web): informe, configuracion en tres pestanas y guia`
````

---

## Prompt 7 · Cierre: limpieza, documentación y gates

````
Cierra el rediseño de la interfaz web de Agentopsy. No quedan pantallas nuevas: este
encargo es de limpieza, documentación y verificación.

**1. Retira los alias transitorios.** El prompt 1 dejó en `web/src/index.css` los
nombres viejos de token (`--bg`, `--border`, `--text-primary`, `--text-secondary`,
`--text-muted`, `--accent-bg`, `--accent-text`, `--success`, `--sidebar-bg`) como
alias de los nuevos. Migra los usos que queden a los nombres definitivos y borra los
alias. Comprueba con grep que no queda ninguna referencia — incluidos los estilos
inline dentro de los `.tsx`.

**2. Código muerto.** Borra lo que el rediseño dejó sin uso. Verifica cada uno con
grep antes de tocarlo, y no borres nada que siga importado: `SystemStatusPage.tsx`
(absorbido en Configuración), `DocumentViewerPage.tsx` si `DocumentsPage` lo dejó
huérfano, los datos de `web/src/mocks/frontendPreviewData.ts` que ya no consume
ninguna página, y los componentes de `web/src/ui/` que quedaron sin importar. Si
algo sigue en uso, déjalo y dilo.

**3. Documentación (RULE 4).** Sin esto no se puede empujar:
- `docs/ai-context/frontend.md` — es el contexto operativo del frontend para
  sesiones de IA: refresca el árbol de `src/`, la navegación (fases + utilidades,
  sin vista `system`) y la sección de deuda técnica.
- `docs/operacion/frontend-journal.md` — añade la entrada del rediseño: qué cambia,
  por qué (el sidebar pasa de menú a estado del caso), y la decisión de conservar
  los valores de `ViewId` pese al cambio de etiquetas.
- `docs/README.md` — comprueba que `docs/diseno/rediseno-2026-07/` sigue dado de alta
  en el índice (se registró al subir el material).
- `CLAUDE.md` § Status — actualiza la frase sobre la SPA si dejó de ser cierta.
- Si algún endpoint quedó marcado como TODO durante la migración (datos que el mock
  muestra y la API no expone), recógelos en `docs/operacion/proximos-pasos.md`, que
  es el inventario único de deuda; no abras una lista paralela.

**4. Gates de CI (RULE 6).** Reproduce localmente lo que corre `.github/workflows/ci.yml`
y confirma que pasa TODO antes de empujar:
- desde `web/`: `npm ci`, `npm run typecheck`, `npm run build`;
- desde `backend/`: `pip install -e ".[dev,mcp]"`, `ruff check .`, `pytest -q` — el
  rediseño no debería tocar el backend, pero `backend/tests/test_web_surface.py`
  cubre la superficie web y es exactamente el gate que un cambio de UI puede tumbar;
- `docker compose config --quiet` y `docker compose build api web`. Si no tienes
  Docker disponible, **dilo explícitamente** y no afirmes que el push es seguro para
  CI.

**5. Repaso final contra el mock.** Abre
`docs/diseno/rediseno-2026-07/mocks/rediseno-final.dc.html` al lado de la app y
recorre las siete vistas en tema claro y oscuro. Escribe un informe corto con las
divergencias que queden, separando las deliberadas (porque el dato real no existe o
porque la invariante lo impide) de las pendientes. **No maquilles las diferencias
con datos inventados**: una divergencia declarada vale más que un mock bonito
mintiendo sobre el estado del caso.

Commit: `refactor(web): limpieza del rediseno + docs (RULE 4)`
````

---

## Después

Si al terminar quedan divergencias del punto 5, entran en
`docs/operacion/proximos-pasos.md` como deuda, no en una lista aparte.

La **landing pública** (`mocks/landing.dc.html`) quedó fuera de alcance: es una
página de producto que hoy no existe en el proyecto y que no forma parte de la SPA
servida por el compose. Si más adelante se decide hacerla, es un encargo
independiente — no la mezcles con esta migración.
