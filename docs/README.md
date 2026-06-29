# FORENSIA — Documentación

Índice de la documentación técnica. La fuente única de alcance y planificación del TFM vive en [`FORENSIA_Alcance_y_Planificacion.md`](../FORENSIA_Alcance_y_Planificacion.md) (raíz del repo); este árbol contiene los documentos de diseño, decisiones y operación que sostienen ese plan.

## Diseño general

- [`arquitectura.md`](arquitectura.md) — decisiones de arquitectura bloqueadas, capas, transporte, paquetes de agente, MCP.
- [`modelo-amenazas.md`](modelo-amenazas.md) — superficies de ataque (sidecar HTTP, tool-calling, cloud) y gates de seguridad.
- [`soundness-forense.md`](soundness-forense.md) — cadena de custodia, read-only a nivel de bloque, audit log encadenado.
- [`storage.md`](storage.md) — layout en disco (`~/.forensia/cases/<id>/`), invariantes y contratos por manager.

## Agentes

- [`agentes/contrato-paquetes.md`](agentes/contrato-paquetes.md) — contrato declarativo de `agentes/<id>/`: layout, schema de `agent.yaml`, validación.
- [`agentes/diseno-fase2.md`](agentes/diseno-fase2.md) — diseño de la capa de agentes (Fase 2 de la propuesta): orquestador + sub-agentes, RAG, evals, MCP interno.

## Maletín forense

- [`maletin/inventario-tools.md`](maletin/inventario-tools.md) — catálogo extendido de herramientas CLI candidatas con estado de viabilidad por SO.
- [`maletin/inventario-mcps.md`](maletin/inventario-mcps.md) — inventario priorizado P0-P3 de servidores MCP que FORENSIA expone.
- [`maletin/mcp-toolkit-s1.md`](maletin/mcp-toolkit-s1.md) — plan de implementación del `mcp-toolkit` (Sprint S1, cerrado el 2026-06-29).

## Operación y estado

- [`operacion/proximos-pasos.md`](operacion/proximos-pasos.md) — inventario único de deuda técnica y trabajo pendiente.
- [`operacion/frontend-journal.md`](operacion/frontend-journal.md) — bitácora histórica de decisiones del renderer.

## Contexto para asistentes IA

- [`ai-context/frontend.md`](ai-context/frontend.md) — contexto operativo persistente para sesiones de IA tocando el renderer.
