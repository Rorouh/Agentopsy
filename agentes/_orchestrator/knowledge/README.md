# `knowledge/` — Base de conocimiento recuperable (RAG)

Hogar del corpus que la capa de síntesis recupera para razonar (sin confiarlo a la
memoria del modelo). Hoy el catálogo de herramientas cabe en el system prompt; el
RAG real (slice S5) indexa este directorio y recupera por similitud.

## Contenido

- `mitre_attack_seed.md` — **semilla** de técnicas/tácticas MITRE ATT&CK relevantes
  para los casos de evaluación y para el DFIR común. Es la enum cerrada que
  `mitre.md` puede emitir hoy. En S5 se sustituye/amplía por el corpus completo de
  ATT&CK (Enterprise) versionado.
- `artefactos-windows.md` — **guías de interpretación de artefactos Windows**
  (artefacto → interpretación → técnica MITRE). Corpus recuperable (RAG) para la
  capa de síntesis: cómo leer Amcache, Prefetch, ShimCache/AppCompatCache,
  ShellBags, `$MFT` ($SI vs $FN), USBSTOR y los EVTX clave
  (4624/4625, 4688, 4720, 7045, 1102, 4698). Cada `technique_id` que citan existe
  en `mitre_attack_seed.md` (enum cerrada) y cada `tool_id` en el catálogo; respetan
  la cadena de custodia (`tsk_fls` → `tsk_icat` → artefacto derivado, soundness §7).

## Pendiente (S5)

- Guías de interpretación de artefactos **Linux/macOS** (SRUM, `wtmp/btmp`,
  `auth.log`, artefactos de Unix); las de Windows ya están en
  `artefactos-windows.md`.
- Mapeos artefacto → técnica **más allá del subconjunto curado** (ampliar la
  semilla al corpus ATT&CK completo).
- Catálogo de reglas YARA/Sigma de referencia.

> Las fuentes deben ser públicas/redistribuibles. No metas aquí evidencia real ni
> datos personales.
