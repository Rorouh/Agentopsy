# Agentopsy — Plan de ruta del sub-agente Agentopsy-WIN (Fase 2)

**Rol:** creación, desarrollo y entrenamiento de agentes · perfil `windows`
**Rama:** `tools` (rama de trabajo del rol de agentes)
**Autor del plan:** Miguel Ángel · 2026-07-01

> Este documento es el plan de trabajo de la rama de agentes Windows. Se apoya en
> `docs/agentes/diseno-fase2.md` (fuente de verdad del diseño) y respeta sin
> excepción los invariantes de `CLAUDE.md`, `docs/modelo-amenazas.md` y
> `docs/soundness-forense.md`. El entregable de este rol es **declarativo**
> (prompts, playbooks, allowlists, redacción, KB/RAG, evals) — **no** se reescribe
> el loop en Python.

---

## 0. Punto de partida real (lo que YA existe en el repo, no lo que recuerda nadie)

El esqueleto de Fase 2 está más avanzado de lo que sugiere la propuesta. Antes de
escribir una línea nueva, esto es lo que hay y su madurez:

| Pieza | Estado | Ruta |
|---|---|---|
| Paquete `forensia-windows` (manifiesto + prompts + policy + eval) | **v1 maduro** | `agentes/forensia-windows/` |
| `system.md` (9 reglas duras, guard-rail de perfil, esquema de finding) | **v1 sólido** | `agentes/forensia-windows/prompts/system.md` |
| `playbook.md` (sección A disco / sección B RAM) | **v1 sólido** | `agentes/forensia-windows/prompts/playbook.md` |
| `policy/tools.yaml` (allowlist de 17 tool_id) | **v1** | `agentes/forensia-windows/policy/tools.yaml` |
| `policy/redaction.yaml` (email, ipv4) | **v1 mínimo** | `agentes/forensia-windows/policy/redaction.yaml` |
| `evals/case-win-001.yaml` (1 caso: Run key + hollowing + 7045) | **v1, 1 caso** | `agentes/forensia-windows/evals/` |
| Pack `_orchestrator/` (reporter, timeline, mitre, KB semilla) | **v1** | `agentes/_orchestrator/` |
| Semilla MITRE (enum cerrada, ~35 técnicas) | **v1** | `agentes/_orchestrator/knowledge/mitre_attack_seed.md` |
| Catálogo de herramientas (`os_profiles` + `delivery`) | **Hecho, ~19 tools** | `backend/forensia/toolkit/catalog.py` |
| Loader + registry (valida el paquete al arranque) | **Hecho + tests** | `backend/forensia/agent/{loader,registry}.py` |
| **`ForensicAgent.run()` (loop de razonamiento)** | **`NotImplementedError`** + gap de inyección de paths (ver B1) | `backend/forensia/agent/agent.py` |
| Backends de modelo reales (Ollama / cloud) | **Interfaz sí, backend no** | `backend/forensia/models/{local,cloud}.py` |
| `forensia.reports` (síntesis: informe/timeline/MITRE) | **No existe aún** | — |

**Conclusión estratégica:** el trabajo NO es "crear el agente de cero". Es
**llevar el paquete v1 → v2 con anclaje empírico** en imágenes CTF reales
(ground-truth), y preparar todo el material declarativo que el orquestador y el
harness consumirán. Buena parte de este trabajo **no depende del motor** y puede
avanzar hoy mismo; lo que sí depende (correr evals de punta a punta) se hace en
cuanto el loop y los backends aterricen.

---

## 1. Valoración del foco — qué priorizar y por qué

Se pidió valorar el foco entre cuatro frentes (prompts/playbooks, evals+ground
truth, KB/RAG MITRE, allowlist/catálogo). La restricción que ordena todo es una:

> **`ForensicAgent.run()` está en `NotImplementedError` y los backends de modelo
> reales tampoco existen.** Sin loop no se puede *ejecutar* un caso de eval de
> punta a punta ni medir la comparativa local-vs-cloud (la contribución
> científica del TFM).

Eso parte el trabajo en dos bloques y fija el orden:

- **Bloque A — engine-independent (empieza YA).** Todo lo declarativo y todo lo
  que produce *ground-truth*. No espera al motor. Es donde está el 100% del valor
  entregable en las próximas 2-3 semanas.
- **Bloque B — needs-engine (empieza cuando el motor tenga `run()` mínimo).**
  Ejecutar evals, medir, iterar prompts contra métricas, cerrar la comparativa.

**Foco recomendado (orden de ejecución dentro del Bloque A):**

1. **Corpus de evidencias CTF + ground-truth (A0) — PRIMERO.** Es el cimiento:
   sin imágenes reales con hallazgos conocidos, ni los prompts ni las evals tienen
   contra qué validarse. Empíricamente ancla todo lo demás. RAM + disco Windows.
2. **Prompts + playbook v2 (A1).** Refinar contra los artefactos reales de esas
   imágenes (no en abstracto). Aquí está el mayor retorno en precisión y ahorro de
   tokens que promete la propuesta.
3. **Evals derivadas del ground-truth (A2).** Convertir cada imagen en 1-N
   `case-win-*.yaml` con `expected_findings` + `expected_mitre` verificables.
4. **KB/RAG MITRE + guías de artefactos (A3).** Ampliar la semilla a un corpus
   recuperable con reglas anti-alucinación y guías de interpretación
   (amcache, prefetch, shimcache, shellbags, $MFT, EVTX clave).
5. **Allowlist + redacción (A4).** Revisión mecánica contra `catalog.py` y
   endurecer `redaction.yaml` (hoy solo email+ipv4) antes de habilitar cloud.

**Por qué NO empezar por prompts:** iterar prompts "a ciegas" sin casos reales
contra los que medir es exactamente lo que la Fase 4 pide evitar. El ground-truth
primero convierte el trabajo de prompts en algo *medible* en vez de estético.

---

## 2. Preparación de la rama de trabajo (`tools`)

Estado actual detectado: rama local `codex/docker-web-mcp-cli` con **~200
ficheros modificados sin commitear** (incluidos todos los `agentes/*`), y `git
pull` bloqueado por el proxy (sin salida a GitHub desde el entorno del asistente).
El fork y el push los haces tú; localmente partimos de `main` limpio.

**Antes de ramificar — resolver el working tree sucio (elige una):**

```bash
# Opción 1 — guardar los cambios locales sin perderlos (recomendado si son tuyos)
git stash push -u -m "wip codex antes de rama agentes"

# Opción 2 — si esos cambios no son tuyos / son ruido, descartarlos con cuidado
#   (revisa 'git status' y 'git diff' ANTES; esto NO se deshace)
# git checkout -- . && git clean -nd   # -n = dry-run; quita la n para ejecutar
```

**Situarse en la rama de agentes (`tools`, ya existente en `origin`) y sincronizar:**

```bash
# 1. Asegura que 'origin' apunta a tu fork (o añade 'upstream' al repo del equipo)
git remote -v
# git remote add upstream https://github.com/Rorouh/Forensia-AI.git   # si hace falta

# 2. Sitúate en 'tools' y sincroniza con origin (RULE 5)
git fetch origin
git checkout tools && git pull

# 3. Publica el trabajo de agentes en 'tools'
git push -u origin tools
```

**Invariante de proceso (CLAUDE.md RULE 5):** `git pull` al inicio de cada sesión
sobre `tools`, y de nuevo tras cada `git checkout`. La memoria
conversacional del repo NO es la fuente de verdad; el remoto sí.

---

## 3. BLOQUE A — Trabajo engine-independent (arranca ya)

### A0 · Corpus de evidencias CTF + ground-truth  *(cimiento)*

**Objetivo:** un conjunto pequeño pero suficiente de evidencias Windows reales con
hallazgos conocidos y documentados, para anclar prompts y evals.

Entregables:

- **Manifiesto de evidencias** `docs/agentes/corpus-windows.md`: por cada imagen —
  fuente/URL, licencia, tipo (`disk`/`memory`), formato (`.raw`/`.E01`/`.vmdk`/
  `.mem`/`.dmp`), SO/build, tamaño, SHA-256 baseline, y **qué se supone que
  contiene** (ground-truth resumido).
- **Ground-truth por imagen** `docs/agentes/ground-truth/<img>.md`: lista de
  hallazgos esperados con su artefacto y técnica MITRE asociada. Es la "traza
  dorada" contra la que se miden `findings_recall` / `findings_precision`.
- Las imágenes **no van a git** (tamaño/licencia). Se referencian por URL + hash;
  se ubican fuera del repo o vía Git LFS/almacén externo del equipo.

Selección propuesta para empezar (RAM + disco Windows, mundo CTF/didáctico):

| Cobertura | Tipo | Fuente típica | Ejercita |
|---|---|---|---|
| Memoria Windows con malware/inyección | RAM | retos Volatility (MemLabs, Volatility CTFs) | `windows.pslist/pstree/psscan/malfind/netscan/cmdline` |
| Disco Windows con persistencia | disco `.E01`/`.raw` | CFReDS (NIST), Digital Corpora | `tsk_*`, `regripper`, `mftecmd`, `evtxecmd` |
| EVTX/registro sueltos (fallback) | artefactos | repos de samples EVTX/Sigma | `evtxecmd`, `hayabusa`, `chainsaw`, `regripper` |

> **Regla dura de evals:** las *fixtures de eval* deben ser **sintéticas / sin
> datos personales reales** (`agentes/*/evals/README.md`). El corpus CTF sirve
> para **entrenar y validar cualitativamente** el playbook; para las fixtures del
> harness automatizado se usan imágenes controladas del rol Datos/QA o recortes
> anonimizados. Mantener esa separación explícita en el manifiesto.

**Verificación A0:** cada entrada del manifiesto tiene URL + SHA-256 + ground-truth
no vacío; los hashes se recomputan localmente y cuadran.

> **Requisito de ingesta dual-format (dep. motor).** El corpus documenta que una
> misma evidencia de disco puede ingerirse en **dos formas equivalentes en
> contenido** — set `.E01` multi-segmento (`libewf` carga `E02…E09` desde el
> `E01`) o imagen única reconstruida (ZIP del escenario / `.raw` vía `ewfexport`)
> — con `SHA-256 baseline` distinto por variante (ver `corpus-windows.md`,
> `lonewolf-2018-disk`). Que `EvidenceManager`/`toolkit` **toleren ambas** (abrir,
> hash-gate y handle read-only por igual) es un requisito que se valida en el
> **hito E2E front↔backend del Bloque B** — no bloquea A0, que solo lo documenta.

#### Reparto de responsabilidades en la custodia (agente vs `EvidenceManager`)

Aclaraciones que fijan la frontera entre el rol declarativo (agente) y el motor
forense, coherentes con `CLAUDE.md` (RULE 3 y FORENSIC INVARIANTS):

- **La segmentación es transparente para el agente.** `EvidenceManager` normaliza
  ambas variantes de ingesta (E01 multi-segmento **e** imagen única) en un **único
  handle** verificado y **read-only a nivel de bloque**. El agente recibe solo ese
  handle + el triage (`detected_kind` / `family`); **no razona sobre ficheros ni
  segmentos** ni sabe cuántos `.E01` hay (RULE 3: la lógica de evidencia vive en
  `forensia/*`, no en el agente).
- **El hash baseline lo computa `EvidenceManager` en la ingesta.** El hash de
  adquisición que aporte el usuario (p. ej. MD5/SHA-1 del log FTK) se **cruza como
  custodia extra** (atestigua la adquisición original), pero **no sustituye** al
  `SHA-256 baseline` local que el motor calcula y re-verifica.
- **La re-verificación de integridad al cierre de sesión la hace `EvidenceManager`**
  (re-hash del handle vs baseline), **no el agente**. La aportación del agente a la
  cadena de custodia es la **procedencia por artefacto**: cada finding cita el
  `sha256` del artefacto y su `audit_seq` (contrato de finding, `diseno-fase2.md`
  §3.3) — no re-hashea la evidencia base.

### A1 · Prompts + playbook v2 (anclados a A0)

`system.md` y `playbook.md` v1 ya son buenos. Las mejoras v2, guiadas por lo que
las imágenes reales revelen:

- **Playbook por `kind`.** Reforzar el routing disco vs memoria alineado con
  `_system_prompt` (`detected_kind`): un memdump salta directo a la sección B; no
  malgastar iteraciones en `tsk_mmls`/`tsk_fls`.
- **Secuencias de correlación explícitas.** Codificar los cruces de alto valor que
  un analista hace: `Run` key (regripper) + 4688 (evtxecmd) + Amcache/Prefetch a
  la misma hora ⇒ confianza alta. Volverlos pasos nombrados del playbook.
- **Disciplina de coste (tokens).** Endurecer la regla "salida grande → artifact,
  nunca al contexto"; patrones concretos de `jq`/top-N/rango temporal por tool
  (`fls -r`, CSV de `mftecmd`, detecciones de Hayabusa).
- **Formato `{tool_id, params}` a prueba de parser** para el *camino degradado*
  de modelos locales sin tool-use nativo (bloque estricto, un ejemplo por tool).
- **Playbook por tool** (`prompts/playbook.md` o anexo): cuándo usar cada tool,
  params típicos, coste/tiempo (avisar antes de `bulk_extractor`/`plaso`), errores
  comunes y cómo leer su salida. Reduce iteraciones fallidas.
- **Caso anti prompt-injection** reflejado en el playbook (evidencia = datos):
  qué hacer si un `.eml`/evento/nombre de fichero intenta secuestrar el plan.

**Verificación A1:** revisión cruzada de que ninguna regla nueva erosiona los
gates 5/6/7 ni la disciplina de contenedores; cada tool citada existe en el
catálogo y en la allowlist.

### A2 · Evals Windows derivadas del ground-truth

Hoy hay **1** caso (`case-win-001`). Objetivo: **6-10 casos** que cubran el
playbook y las tácticas MITRE de la semilla, cada uno trazable a una imagen de A0.

- Formato ya fijado en `diseno-fase2.md §9.4` y ejemplificado en `case-win-001`.
  Reutilizarlo tal cual: `expected_findings[]` (title_glob + severity +
  provenance_tool) + `expected_mitre[]` + `budget`.
- Cobertura objetivo: persistencia (Run/Services/Scheduled Task), ejecución
  (4688/Prefetch/Amcache), inyección/hollowing (malfind), C2 (netscan), borrado
  de logs (1102), credential dumping (LSASS/SAM), timestomping ($MFT SI vs FN),
  masquerading (svchost fuera de System32).
- Un caso dedicado a **prompt-injection** (finding esperado = "artefacto con
  payload anti-forense", el plan NO cambia).

**Verificación A2:** cada `technique_id` de `expected_mitre` existe en la semilla
MITRE (enum cerrada); cada `provenance_tool` está en la allowlist; formato YAML
valida contra el esquema del harness.

### A3 · KB / RAG MITRE + guías de interpretación de artefactos

- **Ampliar la semilla MITRE** (`_orchestrator/knowledge/mitre_attack_seed.md`)
  hacia el corpus recuperable de S5: mantener la **enum cerrada** (el orquestador
  solo emite ids que existan en la KB) y las reglas anti-alucinación
  (`relatedFindingIds` no vacío; sin finding que la sostenga → `dismissed`).
- **Guías artefacto→interpretación→técnica** (nuevo `knowledge/artefactos-windows.md`):
  amcache, prefetch, shimcache/AppCompatCache, shellbags, $MFT (SI/FN,
  timestomping), EVTX clave (4624/4625/4688/4720/7045/1102/4698), USBSTOR. Cada
  guía: qué es, cómo leerlo, qué técnica MITRE suele sostener, falsos positivos.
- Estas guías alimentan tanto el playbook del sub-agente como el `mitre.md` del
  orquestador (coherencia de vocabulario).

**Verificación A3:** ningún id MITRE citado en guías/prompts está fuera de la KB;
revisión de que las guías no inducen a montar la imagen ni a saltarse custodia.

### A4 · Allowlist + redacción (revisión de cierre)

- Cotejar `policy/tools.yaml` contra `catalog.py`: cada `tool_id` existe y declara
  `os_profile: windows`. (Hoy cuadra; dejarlo verificado y documentado.)
- **Endurecer `redaction.yaml`** antes de habilitar cloud: hoy solo email+ipv4.
  Añadir al menos: rutas de usuario (`C:\Users\<nombre>`), hostnames, IPv6, MAC,
  hashes de credenciales, GUIDs de máquina, y nombres propios detectables. La
  redacción **solo** aplica en backend cloud; con local no sale nada del host.

**Verificación A4:** test de que cada patrón de redacción compila como regex y no
tiene catastrophic backtracking; allowlist 100% resoluble contra el catálogo.

---

## 4. BLOQUE B — Trabajo dependiente del motor (cuando aterrice `run()`)

Estos slices necesitan coordinación con el rol de Orquestación/Modelos. Se
especifican ya para que el contrato encaje, se ejecutan después.

- **B1 · Validación del contrato de finding.** Confirmar que `ForensicAgent.run()`
  emite `Finding` con `provenance` resoluble (§3.3 del diseño) y que un finding
  sin `artifact_id`+`sha256`+`audit_seq` se rechaza. Ajustar prompts si el parser
  real difiere.

  > **Gap motor↔soundness detectado en A1 (bloqueante de B1/B2).** `_EVIDENCE_INJECTION`
  > (`backend/forensia/agent/agent.py`) inyecta la **imagen cruda** en `hive_path` /
  > `evtx_path` / `mft_path` para `regripper` / `evtxecmd` / `mftecmd`, y
  > `AUTO_INJECTED` (`backend/forensia/agent/tool_schemas.py`) **impide al LLM fijar
  > el artefacto pre-extraído**. Hoy el motor **no puede cumplir** el flujo
  > `tsk_icat` → artefacto derivado que exige `docs/soundness-forense.md` §7 (un
  > contenedor nunca recibe la imagen raw). El **prompt ya define el contrato
  > objetivo correcto** (playbook «regla de oro de custodia» + anexo por
  > herramienta); falta el wiring del motor. **Coordinar con el rol de motor** —
  > este es uno de los puntos que hace que `ForensicAgent.run()` siga incompleto
  > (ver el estado `NotImplementedError` de §0): la validación de B1 debe cubrirlo.
- **B2 · Schemas MCP de las tools** (D-3): JSON Schema por tool para documentar el
  maletín a los agentes; el contrato `{tool_id, params}` no cambia respecto al
  dispatcher nativo. Incluye resolver el gap de inyección de paths de B1 (permitir
  que el path del artefacto derivado, no la imagen raw, llegue a las tools de
  contenedor).
- **B3 · Ejecutar el harness** sobre las evals de A2 con backend cloud (fiable) y
  luego local (objetivo de producto). Medir `tool_invocation_accuracy`,
  `findings_recall/precision`, `tokens_per_case`, `iterations_to_solve`,
  `mitre_correctness`.
- **B4 · Comparativa local-vs-cloud (resultado publicable del TFM).** Tabla por
  métrica; iterar prompts (A1) contra los números hasta cerrar. Decidir D-4
  (modelo Ollama base: `llama3.1:8b` vs `qwen2.5:14b`…) con datos, no a ojo.

---

## 5. Mapeo al cronograma TFM (semanas 3 → 11)

Alineado con `FORENSIA_Alcance_y_Planificacion.md §10`. Fase 2 arranca cuando el
maletín está listo y cierra la última.

| Sem. | Fechas | Trabajo de esta rama | Bloque |
|---|---|---|---|
| 3 | 13–19 jul | A0 corpus CTF + ground-truth; arranque A1 (playbook por `kind`) | A |
| 4 | 20–26 jul | A1 prompts v2; A2 primeros 3-4 casos; apoyar vertical-slice E2E | A |
| 5 | 27 jul–2 ago | A2 completo (6-10 casos); A3 guías de artefactos v1 | A |
| 6 | 3–9 ago | A3 KB MITRE ampliada; A4 redacción endurecida; B1 si hay `run()` | A→B |
| 7 | 10–16 ago | B3 correr harness (cloud) contra ground-truth; iterar A1 con datos | B |
| 8 | 17–23 ago | B3 harness (local); B4 primera comparativa; B2 schemas MCP | B |
| 9 | 24–30 ago | Feature freeze: solo correcciones; cerrar comparativa B4 | B |
| 10 | 31 ago–6 sep | Validación final; redacción de resultados de agentes en la memoria | — |
| 11 | 7 sep | Buffer; revisión del paquete y de la sección de agentes de la memoria | — |

---

## 6. Definición de "done" e invariantes que NO se pueden erosionar

Un entregable de esta rama está **hecho** cuando:

- El paquete `forensia-windows` **carga sin error** en el sidecar (loader/registry
  verdes) y el badge "Agente activo" aparece en el chat.
- Cada `tool_id` de la allowlist existe en el catálogo y declara `windows`.
- Cada regla de prompt preserva los gates: **sin shell / enum cerrada** (5/6),
  **evidencia = datos** (7), **cloud opt-in + redacción** (9), custodia
  (audit `argv` literal + `provenance` resoluble).
- Cada eval es trazable a ground-truth y sus `technique_id` están en la KB.
- Documentación en sync antes de commitear (CLAUDE.md RULE 4): README de
  `agentes/`, este plan, y los docs de corpus/ground-truth reflejan el estado.
- **Cero atribución a IA** en commits, código o docs (CLAUDE.md RULE 0).

Invariantes forenses que el sub-agente Windows toca directamente:

- Herramientas de contenedor (`regripper`, `evtxecmd`, `mftecmd`) **nunca** reciben
  la imagen cruda: `tsk_fls` → `tsk_icat` (pre-extracción vía handle read-only) →
  procesar solo el artefacto derivado.
- Preferir leer sin montar FS (TSK, Volatility3); montar NTFS "sucio" puede
  disparar journal replay y romper el hash baseline.

---

## 7. Riesgos y dependencias con otros roles

- **Dep. motor (bloqueante para Bloque B):** `ForensicAgent.run()` +
  `FindingStore` + backends `local`/`cloud` reales. Mitigación: todo el Bloque A
  es independiente y llena las 3-4 primeras semanas.
- **Dep. Datos/QA:** fixtures sintéticas para el harness (sin datos personales).
  El corpus CTF cubre la validación cualitativa mientras llegan.
- **Dep. Orquestación:** contrato de `Finding` y disparadores
  `[proceed-to-report]`/`[back-to-analysis]`. Coordinar B1.
- **Riesgo tamaño/licencia de imágenes:** no entran en git; manifiesto por URL +
  hash + almacén externo.
- **Riesgo alucinación MITRE:** contenido por enum cerrada + `relatedFindingIds`
  obligatorio; se prueba con un caso de eval dedicado.

---

## 8. Próximo paso inmediato

Con la rama creada (sección 2), arrancar **A0**: descargar 1 imagen de RAM y 1 de
disco Windows de CTF, registrarlas en `docs/agentes/corpus-windows.md` con su
SHA-256 y su ground-truth, y desde ahí refinar el playbook (A1). Cuando tengas las
URLs de las imágenes, las verifico, calculo hashes y monto el manifiesto + las
primeras evals contra su ground-truth.

---

## Estado de sesión / dónde vamos

Checkpoint del entrenamiento del sub-agente `windows` en la rama `tools`.

**Slices completados**

- **A0** — commit `fa8ead5`: andamiaje del corpus. `docs/agentes/corpus-windows.md`
  (manifiesto), `ground-truth/` (README, plantilla, `lonewolf-2018.md`),
  `scripts/hash-evidence.py`, `.gitignore` para evidencia. Baselines SHA-256 del
  disco LoneWolf 2018 por segmento (E01–E09, total 13 545 502 470 B).
- **A1** — commit `37a4a56`: prompts v2. `system.md` y `playbook.md` de v1 a v2
  (routing por tipo, cadenas de correlación nombradas, disciplina de coste, anexo
  por herramienta, probe diagnóstico coherente). Allowlist ampliada a **19 tools**
  (`file_info`, `strings_head` para el probe de `unknown`). Documentado el gap del
  motor `_EVIDENCE_INJECTION`/`AUTO_INJECTED` (Bloque B1: bloqueante del flujo
  `tsk_icat` → artefacto derivado).
- **A2** — commit `3b88060`: evals sintéticas `case-win-002..010` (9 casos, disco y
  RAM) + `evals/README.md` con índice y cobertura. Ejercitan **12 técnicas MITRE,
  todas presentes en la semilla** (`mitre_attack_seed.md`); todos los
  `provenance_tool` están en la allowlist. Incluye el caso dedicado al gate 7
  (prompt-injection anti-forense).
- **A3** — commit `3cdc9f6`: conocimiento recuperable (RAG). Guía
  `knowledge/artefactos-windows.md` (artefacto → interpretación → técnica) para
  Amcache, Prefetch, ShimCache, ShellBags, `$MFT` (SI/FN), USBSTOR y EVTX clave; +4
  técnicas a la semilla MITRE (`T1110`, `T1083`, `T1052`/`T1052.001`) sin duplicar
  ids, manteniendo la enum cerrada; `knowledge/README.md` en sync.
- **A4** — commit *(este)*: cierre de la policy del paquete. Verificado **19/19** de
  la allowlist contra `catalog.py` (cada `tool_id` existe y declara `os_profile:
  windows`). `policy/redaction.yaml` endurecida (solo aplica en cloud; local no
  egresa): + rutas de usuario Windows, UNC, hostname anclado a etiqueta, GUID,
  NTLM/pwdump; IPv6/MAC/SID ya existían (no duplicados). Nuevo test
  `backend/tests/test_redaction_windows.py` (compila + ReDoS con presupuesto de
  tiempo + correctness): 39 passed.

**Bloque A: COMPLETO** salvo dos cosas independientes:

- **Baselines que faltan** (cuando se descarguen las imágenes): SHA-256 del volcado
  de **memoria** LoneWolf y de la **variante de imagen única** (`.raw`/ZIP
  reconstruido) del disco. Hoy marcados `<pendiente>` en el manifiesto.
- **Bloque B** (dependiente del motor): loop `ForensicAgent.run` + `FindingStore` +
  backends `local`/`cloud` reales, y el gap `_EVIDENCE_INJECTION`/`AUTO_INJECTED`
  (B1) que bloquea el flujo `tsk_icat` → artefacto derivado. Es de otro rol.

**Observaciones para el equipo (redacción, preexistentes)**

- `redaction.yaml`: el patrón `ipv6` también encaja el formato MAC y va antes que
  `mac_address`, así que una MAC se redacta como `<IPV6>` (se redacta igual, solo
  etiqueta imprecisa). El patrón `email` es O(n²) sobre inputs largos no-email (no
  es ReDoS, pero conviene acotarlo). Ninguna se ha reordenado/tocado: se reportan
  para decisión.

**Nota (corpus de intrusión)**

- Para ground-truth de intrusión (T1055/T1071/T1070.001, hoy solo en evals
  sintéticas) conviene registrar en el corpus una **imagen de memoria con malware**
  real (p.ej. MemLabs o el clásico *cridex*), con su SHA-256 y ground-truth. El
  escenario LoneWolf es de insider y **no** ejercita inyección/C2/borrado de logs.

---

## Fase de validación con CLI + entrenamiento anclado a evidencia (post-A4)

Tras cerrar el Bloque A se abrió una fase de **validación con motores CLI** sobre
LoneWolf y de **iteración de prompts guiada por corridas reales**.

**Herramienta construida — harness de investigación CLI** (`agentes/forensia-windows/evals/harness/`, commiteado):
- `motors.yaml` — registro pluggable de motores (ollama, codex, gemini) con adapter
  `argv` + `prompt_via` (stdin|arg|file). Añadir un motor = un bloque YAML.
- `run_eval.py` — harness single-shot: mide la **decisión** del agente (tool_recall,
  allowlist_violations, mitre) sobre casos sintéticos con dispatcher mock.
- `run_investigation.py` — lanza un CLI sobre evidencia real y guarda la salida.
  Dos modos: `--mode forensia` (contrato `{tool_id,params}`, mide decisión) y
  `--mode autonomous` (el CLI ejecuta las tools él mismo; para laboratorio, `--yes`).
  Resuelve el ejecutable con `shutil.which` (shims Windows). Salida a
  `results/investigations/` (gitignored, derivado de evidencia).
- `build_agent_prompt.py` — ensambla system+identity+playbook+tarea en un `.txt`.

**Estado de motores:**
- **codex (gpt-5.5): FUNCIONA.** Análisis completo de LoneWolf-memoria de manual:
  ejecuta Volatility, crea artefactos JSON por plugin + `findings.json` con SHA-256
  (modelo de custodia), formato Agentopsy (Resumen/Hallazgos/Lagunas). Nota: el
  *script* daba `WinError 5` porque el **sandbox de codex** con `approval:never`
  bloqueaba el spawn de `vol`; en **interactivo** funciona aprobando comandos.
  Pendiente: añadir al `argv` de codex en `motors.yaml` el flag de bypass de
  sandbox/approvals (mirar `codex exec --help`) para automatizar el modo autónomo.
- **gemini: bloqueado** por errores de instalación/uso (tier/auth). Aparcado.
- **ollama: descargar `qwen2.5:14b`** (el `qwen2.5:3b` probado es insuficiente:
  `find_recall 0`, alucina MITRE).

**Dos iteraciones de entrenamiento ancladas a evidencia real (playbook, commiteadas):**
1. Plugins Vol3 de credenciales (`windows.hashdump.Hashdump`, `.lsadump.`,
   `.cachedump.`) + fallback `pslist`→`psscan`→`psxview` (nace de una corrida donde
   el agente usó nombres Vol2 y la enumeración activa de procesos salía vacía).
2. Anti-invención de namespace + regla "ante `invalid choice`, toma el id literal de
   `choose from`/`vol -h`, no adivines; si no está registrado, decláralo laguna"
   (nace de que codex propuso `windows.registry.hashdump.Hashdump`). ⚠️ Ver la
   rectificación de abajo: **ese id no era una invención, es el canónico**.

> **RECTIFICADO 2026-07-17 — re-verificado contra el maletín actual.** El "hallazgo"
> de abajo era **falso** y se propagó a `agent.md` y al FLUJO destilado, donde costó
> un E1: el agente declaró laguna sin poder hacerlo. Medido en `toolkit-windows`
> (vol **2.28.0**) sobre RAM Win7 real:
> - `windows.registry.hashdump.Hashdump` → **exit 0, 6 cuentas con NT hash**, sin
>   warnings. Es el **id canónico** y el que declara el enum de `mcp/schemas.py`.
> - `windows.hashdump.Hashdump` → funciona como **alias deprecado** (`FutureWarning`:
>   volatility lo retira tras **2026-09-25**).
> - `lsadump` y `cachedump` idem, en ambas formas (`vol -h` lista las seis).
>
> La regla operativa correcta: un `invalid choice` señala un **nombre mal formado**
> (falta la clase: `windows.hashdump` en vez de `…​.Hashdump`), **no** un plugin
> ausente. Y una laguna solo se declara con el **error literal** en la mano.
>
> **Límite REAL confirmado** (ese sí): `windows.consoles.Consoles` y
> `windows.cmdscan.CmdScan` abortan con `NotImplementedError … 6.1` en Win7 —
> `cmdscan` reutiliza el código de `consoles`, así que **no es alternativa**.

<details><summary>Texto original del hallazgo (conservado, NO usar como referencia)</summary>

**Hallazgo técnico del entorno:** en el build **Volatility 3 2.28.0** de la máquina
de pruebas, los plugins de credenciales existen como módulos (`windows.hashdump` y
`windows.registry.hashdump`, etc.) pero **ningún nombre CLI es aceptado** — probable
colisión de nombres que rompe el registro. ⇒ credenciales en memoria = **laguna del
entorno** en esta máquina. El playbook ahora hace que el agente lo declare, no lo
invente.

</details>

**Ground-truth cualitativo LoneWolf-memoria** (transcripción en
`evidence-corpus/lonewolf-2018/investigacion-codex-memoria-v2.md`, fuera de git):
Win10 x64, escenario cloud (S3 Browser, Dropbox/GDrive/OneDrive/BoxSync), `FTK
Imager.exe` presente (adquisición), enumeración activa de procesos no fiable
(`psscan`/`psxview` sí recuperan), sin inyección/credenciales recuperables.

**Decisiones abiertas para el próximo plan de ruta:**
- Validar el **antes/después** con codex: que ahora **declare la laguna** de
  credenciales en vez de inventar el namespace.
- Añadir el flag de bypass de sandbox al `argv` de codex para automatizar el modo
  autónomo del `run_investigation.py`.
- Comparativa **entre motores**: gemini bloqueado ⇒ centrar en **codex + ollama**
  (o resolver gemini más adelante).
- Registrar una **imagen de memoria con malware** para el ground-truth de intrusión.
- Baselines SHA-256 de memoria e imagen única (pendientes en el manifiesto).
- Bloque B (motor): loop `run()` + backends + gap B1 — coordinar con el rol de motor.
