# 04 — Resultados

> Índice: [`README.md`](README.md).

## Tabla de resultados

| Salida | Cantidad | Dónde vive |
|---|---|---|
| Evidencias en custodia | **1** | `evidence/a35686e4…/` |
| Evidencias verificadas | **1** (`verified: true`) | `verification.json` |
| Hallazgos (`findings`) | **0** | `findings.jsonl` — no existe |
| Artefactos (`ArtifactRun`) | **0** | `artifacts/` — vacío (0 B) |
| Conversaciones del agente | **0** | `chats/` — vacío (0 B) |
| Documentos / informes | **0** | `documents/`, `reports/` — vacíos (0 B) |
| Super-timeline | **0** | no generada |
| Técnicas ATT&CK propuestas | **0** | — |
| Técnicas ATT&CK dictaminadas | **0** | — |
| Tokens consumidos | **0** | ningún `agent_run_start` en el audit |

**El único resultado del caso es la evidencia en custodia, verificada y con el
perfil determinado.** No hay análisis.

## Sobre los «188k tokens» del nombre del caso

El caso se llama «Prueba 188k tokens», pero **este caso no ha consumido tokens**:
no hay ninguna ejecución del agente en su audit log. Si esa cifra viene de una
sesión anterior, es de otro caso — hay 13 casos más en `projects/cases/`.

Merece aclararse antes de usar el número como referencia de coste.

## Por qué no hay resultados

Descartando causas una por una, con los datos de [`00-plataforma.md`](00-plataforma.md):

| Causa posible | ¿Fue esto? |
|---|---|
| Herramientas no disponibles | **No** — 31/31 disponibles, ninguna degradada |
| Maletines caídos | **No** — los dos `running: true` y healthy |
| Sin ejecutor utilizable | **No** — Claude Code, Codex y Ollama disponibles |
| Paquete de agente sin cargar para `windows` | **No** — `forensia-windows` cargado, 28 herramientas |
| Evidencia sin verificar | **No** — `verified: true` a las 12:25:48 |
| Perfil sin resolver (409) | **No** — anclado a `windows` automáticamente |
| **Nunca se lanzó el análisis** | **Sí** |

La causa es simple: el flujo se paró justo antes del agente. Todo lo necesario
estaba en su sitio.

## Lo que se habría producido

Para que la foto sirva de referencia cuando sí se ejecute, esto es lo que
tendría que aparecer y dónde:

1. **`chats/main.jsonl`** — la conversación persistida, turno a turno.
2. **`artifacts/<run_id>/`** — un directorio por ejecución de herramienta, con
   `out/` y el SHA-256 de cada fichero de salida.
3. **`findings.jsonl`** — un hallazgo por línea, cada uno citando `tool_id`,
   `params`, `run_id` y `artifact_sha256`.
4. **Audit log** — `agent_run_start`, un evento por egress si el ejecutor es
   cloud, y un `agent_finding` por hallazgo.
5. **Timeline** — solo si se dispara el builder o el agente encadena
   `tsk_fls -m` → `tsk_mactime`. **Ojo:** sobre un volcado de RAM ese pipeline no
   aplica; la ruta correcta aquí es Volatility3.
6. **`documents/<id>.json`** — el informe. **No se produciría solo:** la síntesis
   del informe a partir de los hallazgos **no está implementada**. El store queda
   vacío hasta que algo llame a `POST …/documents`.

Ese punto 6 es el hueco estructural: aunque el agente corriera y llenara
`findings.jsonl`, **el informe pericial no se generaría solo**. Ver
`docs/agentes/INTERNO-revision-flujo-y-autonomia.md` §2 y
`docs/agentes/contrato-paquetes.md` §5.bis.

## Qué falta para cerrar el ciclo completo

Ordenado por lo que bloquea a lo siguiente:

1. **Lanzar el análisis** — elegir ejecutor y consultar. Es lo único que falta
   para tener material de agente que documentar.
2. **Registrar el `.vmdk`** si se quiere el caso con las dos evidencias. Hoy está
   en la bandeja, fuera de custodia.
3. **Síntesis del informe** — no implementada; es trabajo de producto, no de este
   caso.
4. **`MitreTechniqueMatch[]` con `confidence`** — tampoco lo produce nadie.

Cuando (1) ocurra, esta carpeta debería reescribirse con datos reales de agente:
[`02-decisiones.md`](02-decisiones.md) dejaría de tener la sección «Decisiones
tomadas por el agente: ninguna», y [`03-acciones.md`](03-acciones.md) pasaría de
3 entradas a decenas.
