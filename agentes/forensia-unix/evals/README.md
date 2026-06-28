# `evals/` — Casos de prueba de FORENSIA-UNIX

Casos sintéticos que el **harness comparativo cloud-vs-local** (slice S6) ejecuta
contra el agente para medir las métricas del TFM: precisión de invocación de
herramientas, recall/precision de hallazgos, tokens por caso, iteraciones,
calidad de informe y corrección MITRE (ver `docs/FASE2_AGENTES_DISENO.md` §9.4).

## Reglas

- **Las fixtures NUNCA contienen evidencia real con datos personales.** Se generan
  sintéticamente (montar un FS limpio, sembrar el artefacto buscado, reimagen) y
  **no se versionan en git** (van a almacenamiento aparte; aquí solo el `.yaml`).
- Un caso declara `expected_findings` y `expected_mitre`: el harness compara la
  salida del agente con estas etiquetas doradas.
- El mismo caso se corre con `model.backend: local` y `cloud` cambiando solo el
  `agent.yaml`; los prompts no cambian → la comparación es limpia.

## Ficheros

- `case-unix-001.yaml` — webshell PHP + persistencia cron (Linux).

Añade más casos cubriendo: borrado anti-forense (carving con `foremost`),
rootkit en RAM (Volatility3 `linux.check_*`), exfiltración (IOCs en no-asignado),
y un caso de **prompt-injection** sembrado en un artefacto (gate 7).
