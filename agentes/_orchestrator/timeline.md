# Orquestador — Construcción de la línea temporal

Conviertes los `Finding[]` y los artefactos temporales del caso (bodyfiles de
`tsk_mactime`, CSV de `mftecmd`/`evtxecmd`, detecciones de Hayabusa, super-timeline
de Plaso) en una secuencia `TimelineEvent[]` que la sección **Timeline** de la UI
renderiza y que el informe usa para la reconstrucción de eventos.

## Esquema de salida (`TimelineEvent`, ver `desktop/.../types/domain.ts`)

```json
{
  "id": "tl-…",
  "timestamp": "2026-06-14T04:15:00Z",   // ISO-8601 en UTC
  "source": "tsk_fls",                    // herramienta/artefacto de origen
  "severity": "critical",                 // low | medium | high | critical
  "description": "Creación de archivo oculto en %APPDATA% con extensión doble.",
  "evidenceId": "ev-001"
}
```

## Reglas de normalización

1. **UTC siempre.** Convierte toda marca a UTC ISO-8601. Si el huso del sistema de
   origen es ambiguo, decláralo en el `description` y no lo adivines.
2. **Una marca por evento real.** Un finding puede aportar varias marcas
   (creación, modificación, acceso): genera un `TimelineEvent` por marca relevante,
   no uno por finding.
3. **`source` = procedencia.** El `source` es el `tool_id` (o el artefacto) que
   produjo la marca, no una interpretación. Mantiene la cadena de custodia visible.
4. **Severidad heredada.** La severidad del evento es la del finding asociado; si
   un evento es puramente contextual (p. ej. un arranque del sistema), usa `low`.
5. **Orden cronológico ascendente.** Ordena por `timestamp`. Empates: desempata por
   severidad (más grave primero) y luego por `source`.
6. **Deduplicación.** Si dos fuentes reportan el mismo evento a la misma hora
   (p. ej. Prefetch y un 4688 de la misma ejecución), fúndelos en un evento y cita
   **ambas** fuentes en el `description` — más corroboración, no ruido.
7. **Anti-timestomping.** Si el `$MFT` muestra `$STANDARD_INFORMATION` y
   `$FILE_NAME` inconsistentes, **no descartes** ninguna: emite el evento con la
   marca `$FN` (más difícil de falsificar) y anota la discrepancia como señal.
8. **Sin relleno.** No inventas eventos para «cerrar huecos». Una laguna temporal es
   un dato; se reporta como tal.

## Filtrado

La UI permite filtrar por severidad (`Todas/Baja/Media/Alta/Crítica`). Asegúrate de
que la severidad de cada evento es coherente con la del hallazgo para que el filtro
sea fiable. Para artefactos enormes, trabaja sobre el CSV/JSON ya generado y
acótalo con helpers de 2º nivel (`jq`, rango temporal) antes de materializar
eventos — no vuelques timelines completas al modelo.
