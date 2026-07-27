# Rediseño de la interfaz web — julio 2026

Material de referencia del rediseño de la SPA (`web/`): los mocks navegables que
fija el equipo como destino visual y estructural, y la secuencia de prompts con la
que se ejecuta la migración.

> **Estado: aplicado (2026-07-27).** Las siete vistas y los dos modales de
> `mocks/rediseno-final.dc.html` están en el código. El mock sigue siendo la
> **fuente autoritativa** de la forma: ante una duda, se lee el mock. Lo que el
> mock omite y el producto conserva —barra de progreso del registro asíncrono,
> borrado de caso con confirmación por nombre, estado ATT&CK «descartada»,
> paginación y aviso de desajuste de perfil— está justificado en el §5 de
> [`plan-migracion.md`](plan-migracion.md) y anotado en la entrada del
> [journal](../../operacion/frontend-journal.md) del 2026-07-27.

## Contenido

| Ruta | Qué es |
|---|---|
| [`prompts-claude-code.md`](prompts-claude-code.md) | **La guía de trabajo.** Ocho prompts encadenados para ejecutar el rediseño, uno por sesión/commit. |
| [`mocks/rediseno-final.dc.html`](mocks/rediseno-final.dc.html) | **El destino.** Prototipo navegable de las siete vistas + modales. Es la referencia autoritativa. |
| [`mocks/ui-actual.dc.html`](mocks/ui-actual.dc.html) | La UI de partida, capturada como mock para comparar lado a lado. |
| [`mocks/direcciones-visuales.dc.html`](mocks/direcciones-visuales.dc.html) | Exploración previa: tres direcciones de paleta y tipografía. Histórico. |
| [`mocks/direcciones-layout.dc.html`](mocks/direcciones-layout.dc.html) | Exploración previa: tres layouts para la vista de investigación. Histórico. |
| [`mocks/landing.dc.html`](mocks/landing.dc.html) | Página de aterrizaje pública. **Fuera del alcance** de esta migración; se conserva como referencia. |
| `capturas/` | Capturas de detalle: matriz ATT&CK actual y recortes del sidebar, la etiqueta de ejecutor y el botón de chat nuevos. |

## Cómo abrir los mocks

Son documentos de Claude Design (`.dc.html`): HTML con una capa de plantillas
(`<sc-for>`, `<sc-if>`, `{{ bindings }}`) que resuelve `support.js` en el navegador.
Se abren directamente con doble clic — **conservando los ficheros hermanos**
(`support.js`, `mitre-catalog.js`, `data/`), que se cargan por ruta relativa.

Para leerlos como fuente (que es lo que hace Claude Code) no hace falta el
navegador: los estilos van inline y el estado del prototipo vive en el bloque
`<script type="text/x-dc">` del final — ahí están las constantes `PHASES`,
`UTILITIES`, `HEADERS`, `ENGINES` y `SETTINGS_TABS` que definen la estructura.

## Qué cambia, en una línea

De una navegación plana con acento azul a un **flujo de cinco fases del caso** con
paleta de papel y acento terracota: el sidebar deja de ser un menú y pasa a ser el
estado del caso, la cabecera dice en qué fase estás, y el diagnóstico del sistema
se repliega dentro de Configuración. El alcance completo y las invariantes que no
se tocan están en [`prompts-claude-code.md`](prompts-claude-code.md).
