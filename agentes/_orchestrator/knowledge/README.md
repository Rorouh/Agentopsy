# `knowledge/` — Base de conocimiento recuperable (RAG)

Hogar del corpus que la capa de síntesis recupera para razonar (sin confiarlo a la
memoria del modelo). Hoy el catálogo de herramientas cabe en el system prompt; el
RAG real (slice S5) indexa este directorio y recupera por similitud.

## Contenido

- `mitre_attack_seed.md` — **semilla** de técnicas/tácticas MITRE ATT&CK relevantes
  para los casos de evaluación y para el DFIR común. Es la enum cerrada que
  `mitre.md` puede emitir hoy. En S5 se sustituye/amplía por el corpus completo de
  ATT&CK (Enterprise) versionado.

## Pendiente (S5)

- Guías de interpretación de artefactos (Amcache, Prefetch, ShimCache, ShellBags,
  SRUM, `wtmp/btmp`, `auth.log`).
- Mapeos artefacto → técnica.
- Catálogo de reglas YARA/Sigma de referencia.

> Las fuentes deben ser públicas/redistribuibles. No metas aquí evidencia real ni
> datos personales.
