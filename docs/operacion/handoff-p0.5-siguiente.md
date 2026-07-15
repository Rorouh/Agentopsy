# Traspaso — P0.5-3 cerrado, siguiente: P0.5-4 / P0.5-5

> **ACTUALIZACIÓN 2026-07-14: P0.5-4 y P0.5-5 están CERRADOS** (ver
> `docs/operacion/proximos-pasos.md`, ítems P0.5-4/P0.5-5, para el detalle y los tests
> que los fijan). La sección 3 de este documento describe el diagnóstico con el que se
> abordaron y queda como registro; ya no es trabajo pendiente.
>
> Rama: `tools`. Estado al escribir el traspaso original: `HEAD == origin/tools ==
> 9252f06`; tras la actualización de arriba, el árbol de trabajo contiene los cambios
> de P0.5-4/P0.5-5 pendientes de commit. Léelo entero antes de tocar
> código — la fuente de verdad es el repo (`CLAUDE.md` + `tools/graph/CONTEXT.md`), no
> este resumen: si algo diverge, confía en el código y actualiza este documento.

---

## 0. Reglas de operación (no negociables, vienen de `CLAUDE.md`)

Léete `CLAUDE.md` completo primero — esto es solo el resumen operativo:

- **RULE 5**: `git pull` al empezar SIEMPRE, y de nuevo tras cualquier `git checkout`.
- **RULE 2**: cero fallbacks, cero defaults silenciosos. Un valor requerido ausente o
  inválido falla fuerte con mensaje accionable — nunca se adivina.
- **RULE 3**: la lógica vive en `backend/forensia/*`; routers y frontend son adaptadores
  finos.
- **RULE 4**: doc-sync ANTES de cada commit. Si tocas código, actualiza en el mismo
  commit la doc que describe ese comportamiento (`docs/storage.md`,
  `docs/soundness-forense.md`, `docs/operacion/*.md`, `docker/README.md`,
  `tools/graph/CONTEXT.md`).
- **RULE 6**: antes de cualquier `git push`, reproduce en local los tres jobs de
  `.github/workflows/ci.yml`:
  - `backend/`: `pip install -e ".[dev,mcp]"` (el extra `mcp` NO es opcional — sin él
    `pytest` falla al recolectar) → `ruff check .` → `pytest -q`.
  - `web/`: `npm ci` → `npm run typecheck` → `npm run build`.
  - raíz: `docker compose config --quiet` → `docker compose build api web` (y, si tocaste
    `docker/docker/forensic-toolkit/*`, también `toolkit-windows`/`toolkit-unix`).
  Si no tienes Docker a mano, dilo explícitamente — nunca declares "CI-safe" sin haberlo
  corrido.
- **RULE 0 / RULE 7**: nunca atribución IA en commits/código/docs; nunca API keys en el
  repo (`ANTHROPIC_API_KEY`/`OPENAI_API_KEY` no deben aparecer en `backend/`).
- **Nunca mockees en un test la propiedad que ese test dice probar.** Si escribes un test
  para "el gate rechaza X", el gate real debe ejecutarse — solo se fakea la red (maletín
  loopback) o el LLM (texto scriptado), nunca `dispatcher.execute`, `EvidenceManager`,
  `ArtifactStore` ni `AuditLog`.
- **Protocolo de auditoría** (el que se siguió en P0.5-3, repítelo): implementa un clúster
  de cambio cerrado → corre los gates → lanza un **subagente auditor nuevo, read-only**,
  dándole SOLO el objetivo + `CLAUDE.md` + `tools/graph/CONTEXT.md` + la lista exacta de
  ficheros tocados (nunca tus propias justificaciones) → corrige sus P0/P1 → repite hasta
  cero P0/P1 → entrega el informe con GO/NO-GO antes de proponer el commit.

---

## 1. Qué es FORENSIA (contexto mínimo si es tu primera vez aquí)

Herramienta pericial forense **post-mortem**, self-hosted vía `docker compose up --build`
(5 servicios: `web`, `api`, `ollama`, `toolkit-windows`, `toolkit-unix`). Un
**orquestador** enruta al **sub-agente** que corresponde al `os_profile` de la evidencia
(determinado por `forensia.triage`, nunca por el host); el sub-agente corre tools del
"maletín" (imagen del toolkit) a través del canal **api → exec-agent → maletín** y
devuelve hallazgos estructurados con cadena de custodia (cada finding cita
`tool_id`/`run_id`/`sha256`). El modelo emite `{tool_id, params}` tipados (enum cerrada) —
nunca un string de comando; el `dispatcher` resuelve el argv real desde un allowlist y
ejecuta `shell=False`.

Antes de tocar código, lee **`tools/graph/CONTEXT.md`** — mapa curado del código (capas,
abstracciones centrales, wrappers uniformes). Ahorra tiempo de exploración.

---

## 2. HECHO — P0.5-3 cerrado (commit `9252f06`, pusheado a `origin/tools`)

**Objetivo del slice**: que cada ejecución de tool anclada a un caso quede forensemente
verificable de principio a fin — qué evidencia exacta se tocó, con qué versión exacta de
la herramienta, y que un artefacto derivado no pueda mentir sobre su procedencia.

### 2.1 Contexto de evidencia obligatorio y autoritativo

- Toda ejecución con `case_id` **exige** un `EvidenceContext` verificado
  (`evidence_id` + `baseline_sha256`) — también las tools de solo input derivado
  (`tsk_mactime`, `plaso_psort`, `jq` sobre una ref). Sin contexto no hay `ArtifactRun`
  ni `tool_run_start`.
- El dispatcher **no confía** en el contexto que le pasan: lo revalida contra
  `EvidenceManager.get(case_id, evidence_id)` + `matches_handle()`. Un id inexistente,
  evidencia de otro caso, o un hash sintácticamente válido pero incorrecto, fallan
  fuerte antes de cualquier gate posterior.
- `EVIDENCE_INPUT` se confina al directorio de ESA evidencia verificada (no al `case_dir`
  entero): **mismo caso no es misma evidencia**.
- `CASE_INPUT` (parámetros auxiliares como `rules_path` de yara, `input_path` de jq,
  `sigma_dir`/`rules_dir` de chainsaw) tiene ahora vetados los subárboles reservados
  `artifacts/` y `evidence/` — tanto si el path cae DENTRO de ellos como si es un
  directorio ANCESTRO que los subsume (p. ej. `rules_path = case_dir` ya no cuela). Ver
  `backend/forensia/toolkit/dispatcher.py`, función `_gate_path_parameters` (bloque
  `reserved = {...}`).

### 2.2 Procedencia de artefactos derivados

- `ArtifactStore.start_run` ahora exige (keyword-only) `evidence_id` +
  `evidence_baseline_sha256` + `tool_version`, validados (sha 64-hex; versión no vacía y
  sin placeholders — ver 2.3) y persistidos en el manifiesto del run.
- Al consumir un `ArtifactRef` (`{run_id, relpath}`), el dispatcher carga el manifiesto
  del run PRODUCTOR **determinísticamente por `run_id`** (nunca por nombre/ruta) y
  verifica que su procedencia coincide EXACTAMENTE con el contexto del consumidor.
  Procedencia cruzada (derivado de la evidencia B consumido bajo contexto A) → rechazo
  antes del start. Manifiesto anterior a P0.5-3 sin procedencia → rechazo accionable
  ("re-ejecuta el productor").
- El enlace `derived_inputs` de `tool_run_start` ahora incluye `source_evidence_id`.

### 2.3 `tool_version` — versión autoritativa de cada tool

- **Build**: `docker/docker/forensic-toolkit/gen_versions.py` (nuevo, stdlib puro) corre
  como último paso de cada stage del `Dockerfile` y hornea el manifiesto **inmutable**
  `/opt/forensia/versions.json`. Una fuente designada por binario: paquete dpkg
  propietario (la mayoría), `importlib.metadata` (volatility3), el `ARG` pinneado del
  Dockerfile (`hayabusa`/`chainsaw`), el commit git exacto del clone (RegRipper), y la
  versión auto-reportada + SHA-256 del zip para las 10 EZ Tools .NET
  (`/opt/eztools/versions.tsv`). **El build ABORTA (exit 1)** si una tool declarada en
  `docker/docker/forensic-toolkit/tool-binaries.json` no tiene versión determinista y no
  vacía — nunca existe un manifiesto parcial ni un placeholder.
- `tool-binaries.json` es el espejo del catálogo (17 binarios base + 13 extra windows =
  30); un test (`test_tool_version.py::test_catalog_and_build_manifest_declare_the_same_binaries`)
  falla si diverge en silencio del catálogo real.
- **Exec-agent**: nuevo endpoint CERRADO `GET /versions` (sin parámetros, sin paths del
  caller, sin ejecutar comandos — solo lee el fichero horneado; ausente/corrupto → `500`
  accionable).
- **Cliente** (`forensia/toolkit/maletin.py`): `tool_versions()`/`tool_version()`
  consultan ese endpoint y rechazan placeholders — tanto de cadena completa
  (`"unknown"`, `"latest"`, `"null"`, `"none"`, vacío) como INCRUSTADOS a nivel de token
  (`"hayabusa latest"` también se rechaza). El mismo rechazo a nivel de token se aplica en
  `ArtifactStore.start_run` y en `gen_versions.py` (tres puntos, cada uno con su test).
- **Dispatcher**: la venue (binario local vs. maletín) y la versión se resuelven ANTES de
  reservar el `ArtifactRun` — orden: contexto → gate de rutas → venue → **versión → start
  → runner → finish**. Venue "api-PATH" (binario resuelto en el PATH del propio api, solo
  dev) en un run anclado se RECHAZA — no tiene manifiesto de build, así que no hay
  versión autoritativa que ofrecer, y no existe fallback local. Start y TODOS los
  finishes (éxito, exit≠0, excepción del runner) llevan la misma versión resuelta.
- `capabilities` reporta la identidad de versión por tool, o la razón concreta de su
  ausencia (sin manifiesto, venue sin build, versiones divergentes entre maletines).

### 2.4 E2E real por la superficie HTTP (antes: instanciaba el agente directamente)

`backend/tests/test_evidence_context_e2e.py` fue reescrito: `TestClient` real →
`POST /api/agent/query` (con token real) → router fino → `ForensicAgent` real →
`ExecutorBackend` real → un ejecutor Ollama **scriptado** (única sustitución: el texto
del LLM — lee la `ArtifactRef` real del prompt renderizado y la reenvía tal cual, sin
reconstruirla) → dispatcher real → **exec-agent loopback real** (con `GET /versions`
real, sirviendo un manifiesto real vía `FORENSIA_VERSIONS_MANIFEST` de test) →
`tsk_icat` → `ArtifactRef` completa → RegRipper. No se mockea `ForensicAgent`,
`dispatcher.execute`, `EvidenceManager`, `ArtifactStore` ni `AuditLog`.

### 2.5 Ficheros tocados (para referencia rápida)

Producción: `backend/forensia/toolkit/dispatcher.py`,
`backend/forensia/artifacts/store.py`, `backend/forensia/toolkit/maletin.py`.
Infra maletín: `docker/docker/forensic-toolkit/{exec_agent.py,Dockerfile,.dockerignore,
gen_versions.py*,tool-binaries.json*}` (`*` = nuevo).
Tests: `backend/tests/_custody.py*` (helpers compartidos: `register_evidence`,
`context_for`, `wire_dispatcher_custody`), `backend/tests/test_tool_version.py*`, y
`test_artifacts.py`, `test_binary_stdout_channel.py`, `test_derived_handoff.py`,
`test_dispatcher_case_anchored.py`, `test_evidence_context.py`,
`test_evidence_context_e2e.py`, `test_ewf_routing.py`, `test_exec_timeout_custody.py`,
`test_routers_storage.py`, `test_tool_path_policy.py`, `test_maletin.py`,
`test_e2e_chain.py`.
Docs: `docs/storage.md`, `docs/soundness-forense.md`, `docs/operacion/proximos-pasos.md`,
`docs/operacion/exec-agent.md`, `docker/README.md`, `tools/graph/CONTEXT.md`.

### 2.6 Estado de los gates (última corrida, todo verde)

- Backend Windows (`.venv`): `ruff check .` limpio; `pytest -q` →
  **786 passed, 20 skipped** (skips: E2E POSIX-only que corren en CI Linux, symlinks sin
  privilegio en Windows, 6 E2E de MCP que necesitan un caso real local).
- Backend Linux (`python:3.12-slim`, `pip install -e ".[dev,mcp]"`): `ruff check .`
  limpio; `pytest -q` → **800 passed, 6 skipped** (los 6 son los mismos E2E de MCP;
  **ningún test POSIX deseleccionado**).
- Web: `npm ci` / `npm run typecheck` / `npm run build` — los tres limpios.
- Compose: `docker compose config --quiet` OK; `build` de las 4 imágenes con exit 0
  (`toolkit-windows` se tuvo que reconstruir con `--no-cache` una vez por corrupción de
  capas causada por una crisis de disco lleno — si vuelve a pasar, purga
  `docker builder prune -af` y reconstruye).
- Verificación física: ambos `versions.json` horneados inspeccionados dentro de la imagen
  (`docker run --rm forensia/toolkit-{unix,windows}:1.0 cat /opt/forensia/versions.json`)
  y el `GET /versions` real probado en vivo levantando `toolkit-unix` con
  `docker compose up -d toolkit-unix`.

### 2.7 Auditoría adversarial (2 pasadas, subagente read-only en frío)

- **Pasada 1**: 0 P0, 1 P1, 9 P2. El P1 (un `CASE_INPUT` podía apuntar a
  `case_dir/evidence/<otra-evidencia>/` y leer bytes de otra evidencia del mismo caso bajo
  un audit que decía otra cosa) se corrigió. 3 P2 baratos también corregidos (placeholder
  de versión incrustado a nivel de token; nombre de test obsoleto; doc del override
  `FORENSIA_VERSIONS_MANIFEST`).
- **Pasada 2**: confirmó las correcciones y devolvió **"SIN P0/P1 RESTANTES"**, señalando
  un residual P2 (el caso ancestro: un `CASE_INPUT` de tipo directorio IGUAL a `case_dir`
  también subsume `evidence/`). Se cerró igualmente (mismo commit).
- P2 aceptados sin cambio, con motivo explícito (no son bloqueantes, pero quedan
  anotados para cuando toquen P0.5-4/5): consumir un artefacto de un productor cuyo run
  cerró con `status="error"` no está vetado hoy (pertenece al contrato de P0.5-5);
  `/health` del exec-agent no exige token aunque `/versions`/`/which`/`/exec` sí (solo
  expone `stage`, impacto bajo); sin caché de `/versions` por proceso (cada tool run
  hace un fetch — correcto forensemente, pero es una oportunidad de rendimiento si algún
  día molesta); el anclaje de `tools/graph/CONTEXT.md` sigue en un commit anterior — toca
  regenerar el grafo (`tools/graph/graph-build.ps1`) cuando quieras refrescar cifras.

---

## 3. QUÉ QUEDA — los dos slices siguientes (NO mezclarlos entre sí ni con nada más)

Ambos están anotados en `docs/operacion/proximos-pasos.md` (buscar "P0.5-4"/"P0.5-5") pero
sin diseño detallado todavía — lo primero que toca en cada uno es escribir el diagnóstico
con file:line, exactamente como se hizo para P0.5-3.

### 3.1 P0.5-4 — el argv EWF ejecutado debe coincidir con el solicitado

**El problema**: cuando una imagen es un contenedor EWF (`.E01`), el exec-agent reescribe
el token del argv que apunta al `.E01` por la ruta del bloque raw montado (`ewf1`) antes
de ejecutar la tool (ver `docker/docker/forensic-toolkit/exec_agent.py`, función
`ewf_mount`/el bloque `_exec` que llama a `ewf_mount`). Lo que se AUDITA hoy
(`tool_run_start.argv`) es el argv que el dispatcher construyó ANTES de esa reescritura
— con la ruta `.E01` original, no la `ewf1` efímera (es deliberado: la `.E01` es la
identidad estable ligada al hash baseline; el mountpoint `ewf1` es aleatorio y no
sobrevive a la corrida). El hueco: hoy **nadie verifica que la reescritura que hizo el
exec-agent fue exactamente sobre el token correcto** y que el argv REALMENTE ejecutado
solo difirió en ese token — el dispatcher confía ciegamente en que el exec-agent hizo
bien su trabajo.

**Puntos de partida concretos**:
- `backend/forensia/toolkit/dispatcher.py`: busca `ewf_image` (construcción del token,
  ~línea 201-205) y `_prepare_execution`/`_invoke_prepared` (dónde se pasa al maletín).
- `docker/docker/forensic-toolkit/exec_agent.py`: función que monta y reescribe (busca
  `ewf_mount`/`ewf_unmount`); hoy la respuesta del `/exec` no devuelve el argv
  EFECTIVAMENTE ejecutado (con `ewf1` en vez de `.E01`), solo `exit`/`stdout`/`stderr`.
- Test existente relacionado: `backend/tests/test_ewf_routing.py` (cubre la mecánica de
  montaje/desmontaje/error, pero no la verificación de que el argv ejecutado = argv
  auditado con el único token reescrito correctamente).

**Diseño a decidir** (no asumas nada, plantéalo antes de picar código): ¿el exec-agent
debería devolver el argv efectivo ejecutado para que el dispatcher lo compare token a
token contra el esperado (todo igual salvo el token EWF)? ¿o basta con que el exec-agent
audite/loggee internamente la reescritura y el dispatcher se limite a verificar que
`ewf_image` era un token literal del argv que él mismo construyó (ya lo hace
parcialmente — ver `test_exec_agent_ewf_image_must_be_argv_token`)? Sigue el mismo
protocolo: diagnóstico con file:line primero, luego diseño, luego implementación +
tests, luego auditoría adversarial.

### 3.2 P0.5-5 — contrato del canal `stdout.bin`

**El problema**: hoy el canal binario-seguro (`stdout_path`, para tools como `tsk_icat`
que emiten bytes crudos) tiene el mecanismo probado (round-trip exacto, SHA-256 estable —
ver `backend/tests/test_binary_stdout_channel.py`), pero el CONTRATO alrededor de él no
está completamente cerrado. Cosas concretas que quedaron anotadas durante la auditoría
de P0.5-3 y que P0.5-5 debería resolver:

- **Productor en `status="error"`**: hoy `_resolve_artifact_ref()` (dispatcher.py) re-hashea
  y verifica procedencia de un `ArtifactRef`, pero NO comprueba si el run productor
  terminó con `status="finished"` o `status="error"` (p. ej. un `icat` matado por
  timeout, cuyo `out/stdout.bin` parcial quedó igualmente hasheado por `fail_run`). Hoy
  ese artefacto parcial PUEDE alimentar a un consumidor (RegRipper) sin ninguna señal de
  que el productor no completó. Decidir: ¿se rechaza directamente, o se permite pero el
  `derived_inputs` debe llevar un campo `producer_status` explícito para que quede en el
  audit?
- Revisar si hace falta un límite de tamaño / streaming real para `stdout.bin` con
  imágenes grandes (hoy el mecanismo es correcto para el caso probado, pero no hay test
  de un volumen grande).
- Cerrar cualquier otro cabo que quede en `docs/soundness-forense.md`/`docs/storage.md`
  sobre el canal binario que hoy está descrito pero no completamente verificado por test.

**Punto de partida**: `backend/forensia/toolkit/dispatcher.py` función
`_resolve_artifact_ref` (busca `producer.evidence_id is None` — ahí está la verificación
de procedencia que SÍ existe hoy; el estado del productor iría al lado); `_binary_stdout`
en el mismo fichero; `backend/forensia/artifacts/store.py` (`fail_run`/`finalize_run`,
qué status queda en el manifiesto).

---

## 4. Detalles operativos que te van a ahorrar tiempo

- **Docker Desktop en este entorno de desarrollo es frágil**: se cerró solo varias veces
  durante la sesión anterior (posiblemente por la crisis de disco lleno). Si un
  `docker version` falla con `"the system cannot find the file specified"` o
  `"read-only file system"` en `containerd/meta.db`, la solución que funcionó: matar
  `Docker Desktop.exe`/`com.docker.backend`, `wsl --shutdown`, relanzar Docker Desktop,
  esperar a que el daemon responda, y si persiste corrupción de capas, `docker builder
  prune -af` + reconstruir con `--no-cache` la imagen afectada.
- **Espacio en disco**: el host puede llegar a 0 bytes libres con facilidad (evidencia
  sintética + cachés de build). Purgar primero cachés regenerables (`pip cache purge`,
  `npm cache clean --force`, `docker builder prune`) antes de tocar nada del repo.
- **Para correr el backend en Linux sin tener el repo montado en el contenedor con
  permisos de escritura** (el bind-mount `:ro` falla al hacer `pip install -e`), usa el
  patrón que se siguió en esta sesión: `tar` el contenido de `backend/ docker/ agentes/`
  hacia un contenedor `python:3.12-slim` con un pipe, en vez de montar el repo como
  volumen de escritura.
- **`backend/tests/_custody.py`** es el módulo de helpers compartido para TODOS los tests
  de custodia (`register_evidence`, `context_for`, `wire_dispatcher_custody`,
  `FAKE_TOOL_VERSION`). Si necesitas un test nuevo que registre evidencia real y ancle un
  contexto, usa estos helpers en vez de fabricar handles a mano.
- **`docs/operacion/handoff-p0.5-codex.md`** sigue como fichero SIN TRACKEAR en el repo
  (aparece en `git status` como `??`). Es un documento de encargo/protocolo anterior
  dirigido específicamente a un flujo con Codex CLI como ejecutor — decide si lo
  versionas, lo fusionas con este documento, o lo descartas; no lo he tocado.

---

## 5. Cómo continuar (checklist para arrancar la sesión siguiente)

1. `git pull` en `tools` (RULE 5) — confirma que sigues en `9252f06` o más adelante.
2. Lee `CLAUDE.md` y `tools/graph/CONTEXT.md` enteros.
3. Decide si empiezas por P0.5-4 o P0.5-5 (no mezcles ambos ni los mezcles con un tercer
   tema).
4. Diagnóstico con file:line PRIMERO — no implementes antes de tener el diagnóstico
   completo y, si vas a picar código, un diseño explícito (aunque sea breve) de la
   solución.
5. Implementa en un único clúster de cambio coherente, con doc-sync en el mismo commit.
6. Corre los gates de la sección 0 (RULE 6) en ambas plataformas si tocaste algo
   multiplataforma.
7. Lanza un auditor adversarial nuevo, read-only, con el objetivo + `CLAUDE.md` +
   `CONTEXT.md` + la lista exacta de ficheros tocados. Corrige P0/P1. Repite hasta cero.
8. Entrega el informe (diagnóstico, diseño, ficheros tocados, salidas de gates, resultado
   de auditoría, GO/NO-GO) y los comandos git exactos para que el operador los ejecute —
   tú no ejecutas `git commit`/`push` salvo que te lo pidan explícitamente.
