# `_orchestrator/` — Pack de síntesis (nivel 2)

Este directorio **no es un sub-agente de investigación** y la registry lo
**ignora a propósito** (su prefijo `_` hace que `AgentRegistry` lo salte, igual
que los ficheros ocultos — ver `backend/forensia/agent/registry.py`). No tiene
`agent.yaml`: no se carga como agente con `os_profile`.

Es el **paquete declarativo del orquestador**: los prompts y el conocimiento que
definen el **contrato** de los tres entregables de la propuesta. La consolidación
que hoy los produce es **determinista** (`forensia.reports.generator`,
`forensia.mitre.coverage`, `forensia.timeline`), **no un LLM**: estos prompts son el
esquema objetivo que esa síntesis —o un futuro LLM de síntesis— debe cumplir, no un
modelo que se invoque hoy para consolidar. Cada prompt lleva ese banner en cabecera.

1. **Informe pericial** (`reporter.md`) → `ReportDocument` (informe pericial PDF,
   `forensia.reports.build_pericial_report`).
2. **Línea temporal** (`timeline.md`) → `TimelineEvent[]` (ver `web/src/api/types.ts`).
3. **Correlación MITRE ATT&CK** (`mitre.md` + `knowledge/`) → doble eje
   propuesta/veredicto (`MitreCoverageEntry`); el `MitreTechniqueMatch[]` con
   `confidence` **sintetizado** sigue sin producirse (ver
   `docs/agentes/contrato-paquetes.md` §5.bis).

## Por qué vive aquí y no como tercer agente `os_profile`

El orquestador es **agnóstico del SO**: trabaja sobre `Finding[]` ya estructurados
(con su cadena de custodia), no sobre la imagen cruda. Encajarlo en el enum
`os_profile ∈ {unix, windows}` sería forzado y rompería la regla «un agente por
perfil». Mantenerlo como pack ignorado por la registry permite **entrenarlo con
prompts** (mi rol) sin tocar el motor ni el schema del paquete. La alternativa
—extender el schema con `role: investigation | synthesis`— está descrita como
decisión abierta D-2 en `docs/agentes/diseno-fase2.md`.

## Disparadores (desde la UI)

- `[proceed-to-report]` → ejecuta síntesis: informe + timeline + MITRE.
- `[back-to-analysis]` → vuelve al nivel 1 (investigación) sin descartar hallazgos.

## Qué NO hace el orquestador

- No ejecuta herramientas forenses sobre la imagen (eso es nivel 1).
- No inventa hallazgos, técnicas ni atribuciones: todo cita procedencia.
- No deja salir bytes de evidencia a cloud sin la redacción del caso.
