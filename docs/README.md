# Agentopsy — Documentación

Índice de la documentación técnica. La fuente única de alcance y planificación del TFM vive en [`FORENSIA_Alcance_y_Planificacion.md`](../FORENSIA_Alcance_y_Planificacion.md) (raíz del repo); este árbol contiene los documentos de diseño, decisiones y operación que sostienen ese plan.

## Diseño general

- [`arquitectura.md`](arquitectura.md) — decisiones de arquitectura bloqueadas, servicios del compose, capas, capa de ejecución (los cuatro ejecutores), paquetes de agente, MCP.
- [`modelo-amenazas.md`](modelo-amenazas.md) — superficies de ataque (API HTTP, tool-calling, ejecutores respaldados por cloud, sesiones CLI en el volumen `forensia-cli-auth`) y gates de seguridad 1-19.
- [`soundness-forense.md`](soundness-forense.md) — cadena de custodia, read-only a nivel de bloque, audit log encadenado.
- [`storage.md`](storage.md) — layout en disco caso-como-carpeta (en el compose, anclado a `./projects/`), invariantes y contratos por manager.
- [`timeline.md`](timeline.md) — timeline forense de dos capas (investigación determinista + super-timeline MACB del sistema de ficheros bajo demanda), endpoints y UTC explícito.

## Agentes

- [`agentes/contrato-paquetes.md`](agentes/contrato-paquetes.md) — contrato declarativo de `agentes/<id>/`: layout, schema de `agent.yaml`, validación.
- [`agentes/diseno-fase2.md`](agentes/diseno-fase2.md) — diseño de la capa de agentes (Fase 2 de la propuesta): orquestador + sub-agentes, RAG, evals, MCP interno.

## Maletín forense

- [`maletin/inventario-tools.md`](maletin/inventario-tools.md) — catálogo extendido de herramientas CLI candidatas con estado de viabilidad por SO.
- [`maletin/inventario-mcps.md`](maletin/inventario-mcps.md) — inventario priorizado P0-P3 de servidores MCP que Agentopsy expone.
- [`maletin/mcp-toolkit-s1.md`](maletin/mcp-toolkit-s1.md) — plan de implementación del `mcp-toolkit` (Sprint S1, cerrado el 2026-06-29).

## Operación y estado

- [`operacion/proximos-pasos.md`](operacion/proximos-pasos.md) — inventario único de deuda técnica y trabajo pendiente (incluye el estado del pivote 2026-07-02 a compose + ejecutores).
- [`operacion/frontend-journal.md`](operacion/frontend-journal.md) — bitácora histórica de decisiones de la capa de presentación.

## Diseño de la interfaz

- [`diseno/rediseno-2026-07/`](diseno/rediseno-2026-07/README.md) — rediseño de la SPA (julio 2026): mocks navegables del destino visual y estructural, plan de migración y la secuencia de encargos con la que se ejecuta.

## Contexto para asistentes IA

- [`ai-context/frontend.md`](ai-context/frontend.md) — contexto operativo persistente para sesiones de IA tocando el frontend web.
