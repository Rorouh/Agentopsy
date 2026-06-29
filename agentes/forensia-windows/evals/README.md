# `evals/` — Casos de prueba de FORENSIA-WIN

Casos sintéticos para el **harness comparativo cloud-vs-local** (slice S6). Miden
las métricas del TFM: precisión de invocación de herramientas, recall/precision de
hallazgos, tokens por caso, iteraciones, calidad de informe y corrección MITRE
(ver `docs/agentes/diseno-fase2.md` §9.4).

## Reglas

- **Las fixtures NUNCA contienen evidencia real con datos personales.** Se generan
  sintéticamente y **no se versionan en git** (aquí solo el `.yaml`).
- Cada caso declara `expected_findings` y `expected_mitre`: el harness compara la
  salida del agente con estas etiquetas doradas.
- El mismo caso se corre con `local` y `cloud` cambiando solo `agent.yaml`; los
  prompts no cambian → comparación limpia.

## Ficheros

- `case-win-001.yaml` — persistencia Run key + proceso inyectado (Windows 11).

Añade más casos cubriendo: *timestomping* (`mftecmd` $SI vs $FN), barrido Sigma
(Hayabusa/Chainsaw sobre EVTX), credential dumping en RAM (Volatility3), y un caso
de **prompt-injection** sembrado en un evento o nombre de fichero (gate 7).
