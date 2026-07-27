# Notas — Rediseño de los agentes (borrador de conversación)

> Documento de trabajo. Recoge la conversación con el perito sobre cómo rediseñar
> los agentes para reducir ineficiencia y gasto de tokens. **No es diseño cerrado**;
> se irá puliendo. Fecha de inicio: 2026-07-16.

## Problema de partida

Los agentes actuales se manejan con:

- un **playbook casi hardcodeado**,
- un **`identity.md`**,
- un **`system.md`**,

todos en formato Markdown. El resultado es **ineficiente y gasta demasiados tokens**:
se carga un prompt masivo al LLM y se lee toda la memoria de golpe, en lugar de ir
a buscar solo lo que hace falta según el caso.

## Objetivo

Reorientar los prompts hacia un **mapa de memoria**: el agente, según lo que necesite,
acude a un fichero u otro en vez de arrastrar todo el contexto en cada turno. Más
libertad para el perito, menos prompt masivo, ejecución más dirigida.

---

## 1. `identity.md` — pulir

Partir de esta base (Agentopsy-UNIX) e ir refinando:

- **Identidad:** analista forense post-mortem especializada en UNIX/Linux y macOS.
  Tono profesional, pausado, preciso, en español. Sin emojis. Nunca promete lo que
  no puede ejecutar.
- **Mensaje de presentación** (primer turno del chat): se presenta como Agentopsy-UNIX,
  agente forense post-mortem para imágenes Linux/macOS; trabaja en solo lectura sobre
  la evidencia ya registrada y verificada; pide qué reconstruir (accesos, persistencia,
  ejecución, exfiltración, ventana temporal) o propone un barrido inicial con plan.
- **Tono y hábitos:**
  - Habla del **caso** y la **evidencia** por su `id`, no por rutas de fichero.
  - Anuncia los pasos lentos **antes** de lanzarlos (p. ej. `bulk_extractor` sobre la
    imagen completa puede tardar; pregunta si lanzarlo o acotar primero).
  - Distingue **hecho** (lo que un artefacto demuestra) de **hipótesis** (lo que
    sugiere) y **etiqueta la confianza**.
  - Cuando algo no concluye, lo dice sin rodeos y sugiere agregar la herramienta X
    apropiada para ese caso concreto.

Se irá puliendo.

## 2. `system.md` — reorientar a mapa de memoria

- **Ineficiencia detectada:** de la línea 3 a la 9 casi le da una **segunda identidad**,
  redundante con `identity.md`. Eso debe salir del system.
- **Reglas no negociables:** no parecen mal. **Duda abierta:** dónde colocarlas —
  probablemente **se quedan en el `system.md`**.
- **Nuevo enfoque — mapa de memoria:** el system pasa a **trazar un mapa** de a qué
  fichero acudir según lo que se necesite. Ejemplo de redacción:

  ```
  Dependiendo de las instrucciones del perito vas a usar este mapa a modo de memoria.

  ## Ubicación de memoria según caso
  Si te piden X cosa, revisa la ruta X con el fin de ver Y.
  ```

## 3. Playbook — de hardcodeado a más libre

- Hoy está **completamente hardcodeado**.
- Debe ser **más libre**, para que el perito pueda usar las tools que sean más útiles
  según el caso concreto.
- **Añadir algún `.md` más** para mapear mejor la información, de modo que **no se
  cargue un prompt masivo** al LLM ni se lea toda la memoria de golpe.

## 4. Mapa de hallazgos y evidencias (nuevo)

- Crear **otro mapa**, dedicado a **hallazgos y evidencias**.
- Objetivo: ante peticiones específicas (ver el historial web, qué actividad se realizó
  del X al Y, etc.) la ejecución sea **más dirigida y eficiente**.
- **Se construye a medida que el agente avanza** (mapa vivo), no de golpe al inicio.

---

## Bugs de backend a arreglar en paralelo (no los resuelve ningún prompt)

Verificado en el código a partir de los transcripts reales del caso (contenedor Docker
DVWA, `original.raw`). El rediseño de prompts/mapas **reduce la frecuencia** con que el
agente tropieza con estos fallos (deja de re-lanzar herramientas), pero **no los arregla**:
son defectos de backend. Si solo tocamos prompts, `record_finding` seguirá guardando como
*hallazgo* lo que en realidad es una *inferencia no verificada* — inaceptable en forense.

Los ejes 1 y 4 los cubre el rediseño del agente (memoria/mapa vivo). Los ejes 2 y 3 exigen
tocar el backend.

> **Estado (2026-07-17):** Bugs 1, 2 y **3 ARREGLADOS** con test de regresión (Bug 3
> diagnosticado en vivo: el `stdin...` era ruido; el fallo de Codex va como evento JSONL
> en stdout y ahora se surfacea). **Bug 4 (desencapsulado de contenedor VMDK → TSK)** y
> **Bug 5 (builder de super-timeline por particiones)** **ARREGLADOS Y VERIFICADOS EN
> VIVO POR LA UI** (Playwright): un VMDK particionado lista su árbol de ficheros de
> punta a punta (UI → api → dispatcher → maletín → exec-agent → qemu FUSE → mmls +
> fls por partición). **Todos los bugs del registro original cerrados.** Suite backend:
> 1054 passed, 6 skipped; `ruff` limpio.

### Bug 1 — El bodyfile de `fls -m` nunca llega a ser artefacto referenciable (pipeline `tsk_fls → tsk_mactime` roto de raíz) — ARREGLADO

- `fls -m` escribe el bodyfile a **stdout**, no a un fichero.
- `tsk_fls` (`backend/forensia/toolkit/catalog.py:225`) está declarado `returns="artifact"`
  pero **no** es `binary_stdout` y **no** tiene ningún parámetro `RUN_OUTPUT` que capture
  stdout a un fichero dentro de `out/`.
- Por eso `ArtifactStore._scan_out_dir` (`backend/forensia/artifacts/store.py:132`) no
  encuentra nada → `output_files: []`.
- `tsk_mactime` pide su `bodyfile_path` como ArtifactRef `{run_id, relpath}`, que
  `resolve_output_file` (`store.py:386`) exige que esté registrado como output file.
  Al no estarlo → `KeyError: produced no output file 'bodyfile.txt'`. **Es el error literal
  del transcript.**
- Agravante: el `stdout_sample` que el agente sí ve va recortado a 2000 chars
  (`backend/forensia/agent/agent.py:812`), así que tampoco puede reconstruir el bodyfile
  leyéndolo inline. Resultado: el agente **infiere** la timeline en vez de materializarla.
- **Arreglado:** nuevo campo `Tool.stdout_artifact_param` (dual-mode). `tsk_fls` lo declara
  `="body_format"`: en modo `-m` su stdout se captura byte-exacto y hasheado a
  `out/stdout.bin` (mismo canal que `binary_stdout`/icat), que `tsk_mactime` resuelve como
  `{run_id, relpath}`. El modo listado normal sigue inline (sin desviar stdout). El builder
  determinista `run_filesystem_timeline` (`_read_run_stdout`) ahora lee el bodyfile de
  `out/stdout.bin`. Ficheros: `toolkit/tool.py`, `toolkit/dispatcher.py`
  (`_stdout_to_artifact`), `toolkit/catalog.py`, `timeline/builder.py`. Regresión:
  `tests/test_binary_stdout_channel.py::test_fls_body_mode_materialises_referenceable_bodyfile`
  y `::test_fls_listing_mode_stays_inline_no_stdout_artifact`.

### Bug 2 — Al agente se le muestran `run_id` truncados que luego reutiliza → `invalid run_id (expected UUID4)` — ARREGLADO

- El ledger de runs que se persiste en el contexto del modelo renderiza `run={run_id[:8]}`
  (`backend/forensia/agent/history.py:168` y `backend/forensia/agent/context.py:98`).
- El `run_id` completo solo viaja en el payload del resultado del **mismo turno**
  (`backend/forensia/agent/agent.py:809`). Turnos después el agente solo tiene el prefijo de
  8 chars (`7e2b9d14`, `99def13e`…) y lo copia como referencia.
- `ArtifactStore._run_dir` (`store.py:128`) lo rechaza por validación UUID4 estricta →
  `invalid run_id (expected UUID4)`. **Es el otro error del transcript.**
- Es un footgun de diseño: se le enseña un id *lossy* que no puede round-trippear.
- **Arreglado:** el ledger (`history.py`) y el stub de resultado elidido (`context.py`)
  ahora imprimen el `run_id` completo (`run={run_id}`), no el prefijo `[:8]`. Coste en
  tokens despreciable (~28 chars extra por entrada, tope 30) frente a que sea la clave de
  recuperación del artefacto.

### Bug 3 — Fallo de Codex CLI (`Reading additional input from stdin...`, exit 1) — DIAGNOSTICADO EN VIVO Y ARREGLADO

- Real (aparece en el transcript), independiente de los prompts. El ejecutor pasa
  `stdin=subprocess.DEVNULL` en el run real (`backend/forensia/executors/base.py`) y el
  prompt como argv posicional (`backend/forensia/executors/codex.py:89`).
- **Repro en vivo (2026-07-17, codex-cli 0.142.5):** confirmado que `Reading additional
  input from stdin...` es un **mensaje informativo inofensivo** (Codex lo imprime al leer de
  `stdin=DEVNULL`), NO la causa. El `exit 1` real viene de un **fallo del turno que Codex
  reporta como evento JSONL en STDOUT**: `{"type":"error","message":"…"}`. En la repro fue
  un **límite de uso de la cuenta** (`"You've hit your usage limit… try again at Jul 19th"`)
  — una condición de cuenta, no un bug de Agentopsy.
- **El bug de Agentopsy (arreglado):** el manejo de exit≠0 solo mostraba el `stderr` (el
  mensaje de stdin, ruido), ocultando la causa real del stdout. Además, como el turno falla,
  el `--output-last-message` queda vacío y el `_extract_text` viejo daba *"Codex CLI no
  escribió el fichero…"* — críptico. **Arreglo:** nuevo hook `_extract_error(stdout, stderr)`
  en `executors/base.py` (default `None`), usado en la rama exit≠0 para preferir una causa
  accionable sobre el stderr; `CodexExecutor._extract_error` parsea el evento
  `{"type":"error"}` del JSONL y surfacea su `message`. Ahora el operador ve
  *"Codex CLI terminó con exit code 1. You've hit your usage limit… try again at Jul 19th"*
  (RULE 2: fallar fuerte con lo accionable). Regresión: `tests/test_executors.py` (+3:
  surfacing en run, parseo del evento, y `None` sin evento de error). **Verificado en vivo**
  invocando el executor en el contenedor `api` y por el reply de `/analyze` con `executor=codex`.

### Bug 4 — La evidencia `.vmdk` no la puede abrir TSK (el maletín no trae libvmdk): ni se cablea el formato ni se desencapsula el contenedor (NUEVO — es el fallo de la prueba de `ftkimager`)

> **CORRECCIÓN (2026-07-17, tras verificar el maletín).** La primera redacción de este
> bug asumía que bastaba con «anclar `image_format=vmdk` (`-i vmdk`)». **Es falso para el
> build real del maletín.** El TSK del maletín **NO** está compilado con libvmdk:
> `mmls -i vmdk` → *"Unsupported image type"* (documentado en
> `docs/pruebas/grupo-b/README.md:24` y `docs/pruebas/grupo-b/metasploitable2-linux/`).
> `vmdkinfo`/`vmdkmount` (libvmdk-utils) **no están instalados**
> (`docs/maletin/inventario-tools.md:45-46`). El `vmdk` que aparece en
> `_VALID_IMG_FORMATS` de los wrappers es **aspiracional**, no refleja el binario que
> corre. Ver «Arreglo» abajo, reescrito.

> Diagnosticado a partir del transcript real de la prueba de `ftkimager` (2026-07-17,
> caso `58fbf33c…`, evidencia `original.vmdk`). **No lo cubre ningún prompt ni el
> rediseño de mapas** — es un defecto de enrutado en el backend, distinto de los
> Bugs 1-3.

**Qué pasó (del transcript).** El perito pidió *"utiliza FTKimager para listar el
sistema de carpetas/ficheros"*. El agente:

1. `ftkimager format=raw verify=true` → **OK**: desencapsula el VMDK y produce
   `imagen.001` (40 GiB) con MD5+SHA1 en *Match*. El wrapper recién pusheado funciona.
2. `tsk_mmls image_format=raw` → `mmls -i raw …` → **exit 1** (sin stdout/stderr).
3. `tsk_fls image_format=raw filesystem=ntfs long_format=true` → `fls -f ntfs -i raw …`
   → **exit 1**, stderr literal `Invalid magic value (Not a NTFS file system (magic))`.

**Causa raíz (verificada en código).** La evidencia es un **VMDK sparse monolítico**
(`original.vmdk`). En el offset 0 hay la cabecera del contenedor VMDK, no una tabla de
particiones ni un boot sector NTFS. TSK con `-i raw` lee el fichero como `dd` plano →
la cabecera del contenedor no es NTFS → *Invalid magic value*. **El bug es que a TSK se
le pasa `image_format=raw` sobre un VMDK.** La cadena determinista para hacerlo bien ya
existe, pero está **desconectada**:

- **La triage YA sabe que es un VMDK.** `_classify_header`
  (`backend/forensia/triage.py:330-331`) reconoce el magic `KDMV` y devuelve
  `kind="container_disk"`, señal `vmdk_sparse`. Es una **determinación forense**
  (contenido de la evidencia), no un guess.
- **TSK del maletín NO abre el VMDK de ninguna forma.** Los wrappers declaran
  `_VALID_IMG_FORMATS = {raw, ewf, aff, vmdk, vhd}` (`wrappers/tsk_fls.py:15`,
  `wrappers/tsk_mmls.py:23`), pero **el binario no lo respalda**: `-i vmdk` →
  *"Unsupported image type"* (sin libvmdk). Es el mismo patrón que el `.E01`: TSK
  **tampoco** lee EWF nativo (`exec_agent.py:36`), y por eso el EWF se resuelve
  exponiéndolo como bloque raw con `ewfmount` alrededor del run. Para VMDK **no existe el
  equivalente**: no hay `vmdkmount` instalado, así que hoy no hay ninguna vía por la que
  TSK reciba los bytes de dentro del VMDK.
- **El puente que falta es doble.** (1) El `container_disk`/`vmdk_sparse` de la triage
  nunca se traduce a nada operable, y (2) en `container.py:201-202` el reescritor de path
  solo trata `.E01` (EWF → `ewfmount`); un `.vmdk` cae en *"non-EWF image (raw/vmdk) →
  None, no change"* — se entrega tal cual y TSK lo lee como `dd`. Falta un
  **desencapsulado del VMDK** análogo al de EWF, no un mero flag `-i`.

**Por qué "sigue fallando" pese al rediseño.** El rediseño atacó *repetición* de tokens
(mapas §2-4) y dos bugs de pipeline (1 y 2). Este es un eje **nuevo**: enrutado de
**formato de contenedor**. No es falta de memoria (el mapa vivo §4 no evita un fallo
estructural del primer intento), no es ninguno de los dos bugs arreglados. Es una
determinación (`vmdk_sparse`) que se calcula y se tira.

**Doble derroche de tokens (lo que ve el perito).** *"Gasta la mayor parte de los tokens
en ejecutar cosas que fallan"* son dos capas encadenadas:

1. Cada llamada TSK-con-`raw` está **estructuralmente condenada** → quema tokens.
2. Al fallar, el agente propone el rodeo *ftkimager → re-anclar la evidencia a
   `imagen.001`* — diagnóstico **correcto**, pero **callejón sin salida**: los tools no
   aceptan un path de entrada del agente (SECURITY INVARIANT: `EvidenceManager` es el
   único dueño; el LLM nunca nombra paths), así que el raw derivado **no puede
   re-inyectarse** como nueva evidencia del caso sin un mecanismo de re-registro que hoy
   no existe. El agente lo dice: *"no puedo redirigirlos yo al imagen.001"*.

**Arreglo — reescrito tras el hallazgo del maletín (ninguna pieza implementada aún).**
Como TSK no abre el VMDK, el arreglo NO es un flag: hay que **desencapsular el contenedor**
y darle a TSK bytes raw. Dos vías reales:

**VÍA ELEGIDA Y VERIFICADA EN VIVO (2026-07-17): A — desencapsulado FUSE tipo `ewfmount`,
con `qemu-storage-daemon` (NO `vmdkmount`).**

Al probar en el maletín corriendo se descubrió que **el PPA GIFT no empaqueta `vmdkmount`**
(solo la librería `libvmdk`, sin tools; no hay `libvmdk-utils`). Pero **`qemu-storage-daemon`
YA está en el maletín** (viene con `qemu-utils`, junto a `qemu-img`) y su **FUSE export**
expone cualquier contenedor qemu (vmdk/vdi/qcow2/vhd/vhdx) como fichero **raw**, read-only a
nivel de bloque, **sin copia**. Experimento reproducible (VMDK sintético con tabla de
particiones):

```
qemu-storage-daemon \
  --blockdev driver=file,filename=t.vmdk,node-name=f,read-only=on \
  --blockdev driver=vmdk,file=f,node-name=v,read-only=on \
  --export type=fuse,id=e,node-name=v,mountpoint=/tmp/exported.raw,writable=off &
mmls -i raw /tmp/exported.raw     # -> lista la tabla de particiones (antes: fallo)
md5sum t.raw /tmp/exported.raw    # -> IDÉNTICOS (byte-exacto, sound)
```

Resultado medido: `exported.raw` muestra el tamaño del disco completo (no del `.vmdk`
sparse), `mmls -i raw` **lee la tabla de particiones**, y el md5 de la vista FUSE coincide
con el raw original. **RULE 1 ya se cumple** (herramienta ya horneada; NO toca el Dockerfile)
y es sound (FORENSIC INVARIANT 3: bloque RO, NO monta el FS de la evidencia).

**Implementación (HECHA, 2026-07-17):**
- **exec-agent** (`docker/docker/forensic-toolkit/exec_agent.py`): campos de payload
  `qemu_image` (token exacto del argv, como `ewf_image`) + `qemu_format` (enum cerrado
  `vmdk|vdi|qcow2|vpc|vhdx`, elegido por el api, no por el LLM). Helpers `qemu_mount`/
  `qemu_unmount` + handler `_exec_with_qemu` espejo de `_exec_with_ewf`: arranca
  `qemu-storage-daemon` con FUSE export (RO), espera (poll) a que el mountpoint esté
  servido, reescribe el token del argv al raw `raw.img`, ejecuta y en `finally` para el
  daemon + `fusermount -u` + rmtree. Mutuamente excluyente con `ewf_image`. `424` accionable
  si el binario/FUSE falta o el daemon muere (RULE 2).
- **api** (`toolkit/dispatcher.py`): `_qemu_format_for_path` (extensión → driver qemu) junto
  a `_is_ewf_path`; `execute()` detecta el contenedor y pasa `qemu_image`/`qemu_format` por
  `_prepare_execution`; `maletin.run_argv_in_maletin` los reenvía en el POST `/exec` y
  `_verify_executed_argv` verifica la reescritura al basename `raw.img` (custodia,
  FORENSIC INVARIANT 4). Venue api-PATH (dev): no soportado (igual que EWF) — el producto es
  el maletín.
- **anclaje de `image_format`:** al desencapsular, el `dispatcher` fuerza
  `image_format=raw` (descarta un `image_format=vmdk` del modelo — daría "Unsupported image
  type" sobre el bloque ya raw). RULE 2: cierra el guess del LLM.
- **tests:** `backend/tests/test_vmdk_routing.py` (28, espejo de `test_ewf_routing.py`):
  predicado de formato, decisión del dispatcher, anclaje de `image_format`, mecanismo del
  exec-agent (reescritura + teardown + teardown-en-fallo), validación (enum, token del argv,
  exclusión mutua), y prueba de custodia del cliente maletín. Suite backend: 1046 passed.
- **verificado en vivo** en el `toolkit-unix` corriendo: VMDK sintético → `POST /exec` con
  `qemu_image`/`qemu_format` → `executed_argv` reescrito a `…/raw.img` y `mmls -i raw` lista
  la tabla de particiones; daemon y mount desmontados tras el run (sin zombies).

> **(B) descartada como principal:** conversión `qemu-img convert -O raw` + re-anclaje de
> evidencia (re-hash/custodia) — copia completa de 40 GiB y necesita un mecanismo de
> re-registro que hoy no existe. Queda como puente manual ya documentado
> (`docs/pruebas/grupo-b/metasploitable2-linux/tsk_mmls.md:45`), no como la vía del producto.
>
> La redacción original de este bug («basta `-i vmdk`») era **incorrecta**: el maletín no
> trae libvmdk; el arreglo real es el desencapsulado FUSE de arriba.

### Bug 5 — El builder de super-timeline corría `tsk_fls -m` en el offset 0: fallaba en cualquier disco particionado (ARREGLADO)

> Detectado al re-probar el Bug 4 en la UI (2026-07-17): sobre un VMDK **particionado**
> (el caso realista), el botón «Generar super-timeline» daba
> `RuntimeError: tsk_fls terminó con exit_code 1 … stderr: Cannot determine file system type`.
> Es un bug **pre-existente e independiente del cableado VMDK** (afecta a cualquier disco
> particionado, raw o vmdk).

**Causa.** `run_filesystem_timeline` (`backend/forensia/timeline/builder.py`) ejecutaba
`tsk_fls -m -r` directamente sobre `image_path`, es decir en el **offset 0**. En un disco
particionado el offset 0 es la tabla de particiones, no un sistema de ficheros → *"Cannot
determine file system type"*. Solo funcionaba con imágenes que son un FS plano en offset 0
(un volcado de partición), no con discos completos — que son casi todos los reales. (El
desencapsulado VMDK del Bug 4 sí funcionaba: el error cambió de *"Unsupported image type"* a
*"Cannot determine…"*, señal de que TSK ya leía los bytes; el fallo era el offset.)

**Arreglo (verificado en vivo por la UI).** El builder ahora **enumera particiones con
`tsk_mmls` primero** y corre `tsk_fls -m -r -o <offset>` por cada partición con sistema de
ficheros, fusionando los bodyfiles en una única super-timeline (rutas prefijadas con
`/p<slot>` por partición). Política acordada con el perito (**emitir lo legible + listar las
saltadas**): una partición sin FS legible (swap, unallocated) se registra en
`skipped_partitions` y **no aborta** — solo se falla fuerte si NINGUNA partición da FS. Una
imagen **sin tabla de particiones** (mmls sale ≠0 → señal de FS plano, no error) mantiene el
`fls` único en offset 0. Persistencia y re-query actualizados a **lista** de runs
(`fls_run_ids`, con compat del `fls_run_id` único antiguo); `consultar_actividad` fusiona los
bodyfiles de todas las particiones. mmls/fls van por el desencapsulado qemu del Bug 4 (ambos
son tools de disco → el dispatcher los enruta). Regresión:
`backend/tests/test_timeline.py` (+5 tests: merge por particiones, skip no-fatal, fallo si
ninguna da FS, merge en la query, compat del id único). **Verificado en la UI:** un VMDK
particionado ahora lista `/p2/secret.txt`, `/p2/home_evidencia`, `/p2/lost+found`.

> Relación con Bug 001 (`docs/bugs/001-…`): aquel es el **agente** entrando en bucle por
> prompt sobre un FS plano; esto es el **builder determinista** («Generar»), otro código.
> Complementarios: el builder ahora es robusto a disco particionado Y a FS plano.

### Nota de diseño — por qué los tools NUNCA aceptan un path del agente (a tener presente para el arreglo)

> Recogido a petición del perito (2026-07-17). Es una **propiedad de diseño deliberada**,
> no una limitación accidental — importa para decidir cómo re-anclar la evidencia (Bug 4,
> arreglo *(b)*) y para cualquier solución que roce el path de la evidencia.

Que el agente *"no pueda redirigir TSK al `imagen.001`"* no es un fallo: es exactamente lo
que blinda la cadena de custodia y el modelo de amenaza. Tres invariantes lo imponen a la
vez:

- **`EvidenceManager` es el único dueño de la evidencia** (FORENSIC INVARIANT 1). Ningún
  tool ni agente toca un path `.raw`/`.vmdk`/dump directamente; piden un **handle**
  hash-verificado y read-only a nivel de bloque. El `image_path` que ve un wrapper lo
  **inyecta Agentopsy** desde el handle del caso — el LLM no lo pone.
- **El LLM emite un id de tool de enum cerrado + params tipados, nunca una cadena de
  comando ni un path** (SECURITY INVARIANT 5). El backend resuelve el argv real desde un
  allowlist. Un path arbitrario del modelo no tiene por dónde entrar.
- **Todo path se canonicaliza en el backend y se confina a `evidenceRoot`** (SECURITY
  INVARIANT 6): se rechazan traversal, symlink-escape y absolutos. Aunque el modelo
  intentara colar un path, se rechazaría.

**Por qué es así (el porqué que interesa):** la evidencia es **dato hostil** — un
sospechoso puede sembrarla con payloads de prompt-injection. Si el agente pudiera nombrar
paths, un byte de la evidencia que dijera *"analiza `/host/…/.ssh/id_rsa`"* o *"apunta a
este otro fichero"* se convertiría en una acción sobre el host o en una salida de la
cadena de custodia. Al obligar a que el path lo ponga solo `EvidenceManager` desde un
handle hasheado, **ningún contenido de la evidencia puede desviar qué fichero se analiza**.

**Consecuencia para el Bug 4 / re-anclaje:** por esto mismo, "convertir a raw y trabajar
sobre el raw derivado" **no puede ser una acción del agente** — sería un path suministrado
por el LLM, prohibido por diseño. Tiene que ser un **mecanismo de backend**: registrar el
artefacto derivado (`imagen.001`) como nueva evidencia del caso, con re-hash y su entrada
en el log de custodia, de modo que `EvidenceManager` pase a exponer *ese* handle. Es
decir, el re-anclaje es una operación del operador/backend sobre el store de evidencia, no
un argumento que el agente redirige. (Y aun así, el arreglo *(a)* — anclar `image_format`
desde la triage para que TSK lea el VMDK nativo — evita necesitar el re-anclaje en este
caso.)

### Eje 4 — Repetición / coste (lo cubre el rediseño)

- tsk_fls ×15, 207.978 tok, $9.89, 36 ejecuciones re-descubriendo lo ya establecido.
- No es un bug: es la ausencia de memoria persistente que el mapa vivo de hallazgos/evidencias
  viene a resolver. Ver secciones 2 y 4 de arriba.

---

## Estado de implementación (2026-07-17)

El rediseño se implementó de principio a fin, en hitos, con verificación adversarial por
hito y tests. Decisiones tomadas con el perito: mapa de memoria **híbrido**, mapa vivo
como **tool de consulta backend** (no `.md` del LLM), playbook **conservador**.

1. **`identity.md`** (unix + windows) — reescrito como persona/voz, separado de reglas.
   Reglas no negociables: **se quedan en `system.md`**, cuya apertura ya no da una
   "segunda identidad".
2. **Mapa de memoria (híbrido)** — `knowledge:` declarativo en `agent.yaml`, cargado y
   path-confinado por el loader; tool interna `consultar_conocimiento(doc_id)` que sirve
   por id desde memoria; bloque compacto «## Mapa de memoria» en el system prompt. Docs
   iniciales: `knowledge/artefactos-{unix,windows}.md`. Ver `contrato-paquetes.md` §3.bis.
3. **Mapa vivo de hallazgos/actividad** — tool interna `consultar_actividad(...)`:
   proyección determinista sobre la super-timeline persistida (filtro por fecha/categoría/
   ruta) **sin re-ejecutar `tsk_fls`**. Resuelve los fallos del transcript.
4. **Playbook conservador** — pipelines fijos → «puntos de partida sugeridos» + índice
   «objetivo → herramientas»; el catálogo de artefactos sale del prompt siempre-cargado y
   pasa a `knowledge/` (consultado bajo demanda).

Bugs de backend: **1, 2, 3, 4 y 5 arreglados** (Bug 4 = desencapsulado de contenedor VMDK
vía FUSE export de `qemu-storage-daemon`; Bug 5 = builder de super-timeline por particiones
—ambos verificados en vivo por la UI con Playwright—; Bug 3 = Codex surfacea su error real
del JSONL en vez del ruido de stdin, diagnosticado y verificado en vivo). **Todo el registro
original de bugs queda cerrado.** El único trabajo abierto de este documento es la
implementación de la **bitácora** (§5, diseño cerrado, sin código aún).

---

## 5. Bitácora de aciertos/fallos por herramienta+evidencia (PROPUESTA — solo anotado, sin implementar)

> Idea del perito (2026-07-17), a raíz del transcript de `ftkimager`: *«un apartado
> donde el agente anote un happy path y uno que no funciona, así aprende de lo que le
> funciona y de lo que no»*. Ejemplos de la forma que tendría cada entrada:
> - **happy:** *"`ftkimager` con un `.raw`/`.vmdk` funciona muy bien para verificar
>   integridad (MD5+SHA1 Match)."*
> - **fallo:** *"`tsk_fls`/`tsk_mmls` con `-i raw` sobre una evidencia `.vmdk` siempre
>   falla (`Invalid magic value`) porque TSK no abre el VMDK (el maletín no trae libvmdk)
>   — hay que desencapsular el contenedor primero (ver Bug 4, vías A/B)."*

**Qué sería.** Un **cuarto mapa**, distinto de los tres del rediseño: no es catálogo
estático de artefactos (§2 `knowledge/`) ni proyección de la timeline (§3-4 mapa vivo de
actividad). Es una **bitácora de heurísticas de herramienta**: pares
`(tool, forma-de-evidencia, formato) → resultado` que el agente **acumula a medida que
ejecuta** (mapa vivo, como §4) y **consulta antes de lanzar** una herramienta, para no
re-intentar caminos ya sabidos-que-fallan y para preferir los sabidos-que-funcionan.

**Forma tentativa de una entrada** (a decidir en diseño):

```
- clave: { tool: "tsk_fls", evidence_kind: "container_disk/vmdk_sparse", image_format: "raw" }
  veredicto: FALLA
  motivo: "Invalid magic value (Not a NTFS); -i raw no desencapsula el contenedor VMDK"
  remedio: "TSK no abre VMDK (sin libvmdk); desencapsular primero (vmdkmount/qemu-img)"
  visto_en: [run_id...]     # evidencia real, no inventado
```

**Cómo encaja con lo ya decidido (mismos principios del rediseño):**

- **Backend, no `.md` del LLM.** Como el mapa vivo §4, sería una **tool de consulta**
  (`consultar_heuristicas(tool, evidence_kind)` o similar) sobre un store determinista,
  no un prompt siempre-cargado. No infla el contexto: se consulta bajo demanda.
- **Se construye a medida que avanza** (mapa vivo), no de golpe.
- **Rigor forense:** una heurística NO es un hallazgo. Vive en su propio store; jamás se
  mezcla con `record_finding`. Y una entrada "FALLA" debe anclarse a `run_id` reales
  (verificable), no a una corazonada del modelo — coherente con RULE 2 y con no dejar que
  el LLM invente estado.
- **Alcance:** ¿bitácora **por caso** (aislada, chain-of-custody estricta) o **global
  entre casos** (aprende de verdad, pero arrastra sesgos entre evidencias distintas)?
  Sin decidir. La versión conservadora es **por caso**; una capa global de "lecciones
  de herramienta" (independiente del contenido de la evidencia, p. ej. *"un VMDK hay que
  desencapsularlo antes de dárselo a TSK"*) podría ser semilla estática en `knowledge/`.

**Relación honesta con el Bug 4.** Esta bitácora **mitiga el síntoma** (dejar de requemar
tokens re-intentando `-i raw` una vez que ya falló), pero **no es el arreglo**: el arreglo
es cablear el formato determinado por la triage (Bug 4, arreglo *(a)*), que evita el primer
fallo entero. La bitácora es **complementaria** — reduce el coste del error residual y de
otros caminos que no podemos determinar a priori; no sustituye a corregir el enrutado.
Con Bug 4 arreglado, la entrada de ejemplo de arriba ni llegaría a generarse.

**Estado:** solo anotado. No se ha tocado código ni prompts para esto.

### 5.bis — Refinamiento tras revisión de expertos (2026-07-17)

Se sacaron tres análisis breves en paralelo (coste de tokens, solidez forense/seguridad,
encaje arquitectónico). **Convergen** en las mismas correcciones. La idea del perito es la
capa correcta para el **coste residual y la transparencia**, y encaja limpia sobre la
infraestructura §2-4 — pero con tres correcciones **no negociables**. Se anotan como el
diseño de referencia si se implementa; la forma tentativa de arriba (§5) queda **enmendada
por esto**.

**A) Coste de tokens — el ahorro depende de UN detalle: no añadir un turno por consulta.**

- El coste no es *leer* la entrada (pequeña; además el windowing de `context.py:47-56`
  la elide a stub tras `K=4` turnos). El coste es el **round-trip extra**: el ejecutor es
  stateless y Agentopsy reenvía el transcript entero cada iteración (`context.py:4-8`), así
  que cada consulta re-shippea todo el contexto una vez más (~5-8k tok de input) — O(N²)
  sobre el caso.
- **Bien diseñada** (consulta rara/condicional, filtrada en backend a 1-5 filas, que evita
  una ejecución pesada condenada): ahorra ~5-20× por camino malo evitado → **decenas de
  miles de tokens** en un caso como el del Eje 4.
- **Mal diseñada** = el anti-patrón literal de §5 *"consulta antes de lanzar cada
  herramienta"*: +1 turno completo × ~36 tools ≈ **+150-220k tok**, del mismo orden que
  TODO el derroche que pretendía eliminar. **Ese texto de §5 queda descartado.**
- **Matiz clave (gratis, ya en el código):** el **ledger de runs** (`history.py:140-188`)
  ya lista cada ejecución con su exit code y le dice al agente que no reintente las
  fallidas — sin tool nueva ni turnos extra. Dentro de una sesión, la no-repetición ya
  está cubierta. El valor incremental *real* de la bitácora sobre el ledger es solo:
  **persistencia entre sesiones/casos** y cargar el **remedio**, no solo el "falló".
- **Regla de oro:** **no añadir un turno; pre-computar e inyectar.** El backend ya conoce
  `evidence_kind` (triage) y el tool que se va a lanzar → **fundir las 0-3 heurísticas
  aplicables dentro del ledger que el agente YA recibe** (`history.py`), no una tool que
  gasta round-trips. Coste marginal ≈ 0 turnos. Es el patrón del anclaje de backend del
  Bug 4: una determinación que se **ancla**, no que el LLM **pregunta**. (Si aun así se
  quiere tool, que sea **condicional/post-fallo**, filtre en servidor, tope ~5 filas, sea
  `role=="tool"` — cae bajo el windowing — y **nunca en el system prompt**.)

**B) Solidez forense/seguridad — adoptar solo advisory, descriptiva y por caso.**

- **Envenenamiento (riesgo estructural, el más grave):** un sospechoso puede sembrar la
  evidencia para que un tool que le incrimina falle puntualmente; si el agente aprende "no
  sirve" y deja de mirarlo → **falso negativo silencioso en la cadena probatoria**. Choca
  con RULE 2 ("no try the other tool") y con "evidencia = dato hostil". → **La bitácora
  NUNCA suprime ni reordena un tool. Es advisory/read-only para el perito.**
- **El campo `remedio` viola RULE 2 se mire por donde se mire:** si lo infiere el LLM es un
  *guess* prohibido; si es determinista, es un bug de enrutado que va en el código (Bug
  4a), no una heurística aprendida. → **Solo registro DESCRIPTIVO** (tool+kind+format →
  `exit`+`stderr` anclado a `run_id`); **se elimina el campo `remedio` prescriptivo** de
  la forma de entrada de §5. El enrutado correcto se cablea, no se aprende.
- **Auto-acción vs mostrar-al-perito:** **solo surfacear al operador**, nunca auto-cambiar
  enrutado (coherente con cómo `os_profile` unknown/low-confidence escala al operador).
- **Alcance:** ~~por caso~~ **GLOBAL de producto** — decisión del perito (2026-07-17), ver
  **§5.ter**. La recomendación previa de «por caso» queda **anulada**: no cumple el objetivo
  de que *Agentopsy entera* sea más inteligente. El riesgo de envenenamiento que motivaba «por
  caso» se resuelve haciendo el store global **contenido-independiente y de aprendizaje
  ADITIVO** (solo aprende recuperaciones que funcionan, nunca «evita X» — §5.ter/§5.quater),
  no aislándolo por caso.

**C) Encaje arquitectónico — stores separados, escribe el dispatcher, reutiliza §2-4.**

- **Frontera (stores separados):** `consultar_actividad` = lo que hizo el **sospechoso**
  (contenido de evidencia, `untrusted=True` en `agent.py:539`); bitácora = lo que hicieron
  las **herramientas** (meta de ejecución). Claves disjuntas. El `motivo`/stderr puede
  arrastrar bytes hostiles → surfacearlo como **untrusted** aunque la clave
  (tool/kind/format/exit) sea meta de confianza. Store propio (p. ej.
  `case_dir/heuristics/<evidence_id>.jsonl`), no mezclado con `record_finding`.
- **Quién escribe: el dispatcher, no el LLM.** El veredicto `PASA/FALLA` es función
  determinista de datos que el dispatcher ya tiene al cerrar el run (`dispatcher.py`, junto
  al audit log): `tool_id`, `image_format`, `exit_code`, `stderr`, `run_id`,
  `evidence_kind`. Espeja el patrón del mapa de actividad (el builder materializa, el
  agente solo lee). RULE 3 limpio.
- **Reutilización alta:** store del timeline (`builder.py` — path confinado, escritura
  atómica tmp+replace, lectura tolerante a corrupto→`None`), scaffolding de tool interna
  (`agent.py`, `tool_schemas.py`) y el gating "no ofrezcas la tool si el store está vacío"
  se copian casi directos. Implementación pequeña.

**Orden recomendado.** La bitácora **mitiga síntoma, no sustituye enrutado**: si entra
antes que el Bug 4 (vía A), corre el riesgo de **enmascarar** la ruta determinista que falta —
el mismo motivo por el que cada fallback tuvo que deshacerse. → **Primero el Bug 4 (vía A)**
(barato, quita la mayor fuente de derroche); la bitácora **después**, ya acotada a su
nicho: lo genuinamente no-determinable a priori, advisory, descriptiva. *(Bug 4 y 5 ya
están hechos — la bitácora es el siguiente paso natural.)*

### 5.ter — Decisión de alcance (perito, 2026-07-17): la bitácora es GLOBAL de producto, no per-usuario

**Corrección** a la duda de alcance de §5 y a la recomendación «por caso» de §5.bis-B. La
bitácora es para **Agentopsy entera**: un **activo del producto** que se versiona en el repo
y viaja en la imagen (RULE 1), para que **cada despliegue sea más inteligente** con el
tiempo. NO es estado que cada usuario acumula por separado en su máquina, ni un store
per-caso aislado. El objetivo es que *Agentopsy aprenda* qué le funciona y qué no, y ese
aprendizaje beneficie a todos, no solo al caso en curso.

**Qué guarda: heurísticas GENERALES de herramienta**, independientes del contenido de una
evidencia concreta — `(tool, forma-de-evidencia, formato) → happy/fail + porqué + remedio`.
Ejemplos: *"un VMDK hay que desencapsularlo (qemu FUSE) antes de dárselo a TSK"*,
*"`ftkimager` verifica bien la integridad de raw/E01 (MD5+SHA1)"*, *"`tsk_fls -m` en offset 0
falla en disco particionado → `mmls` primero"*. Son verdades sobre las **herramientas y los
formatos**, ciertas en cualquier caso — de hecho, los Bugs 4 y 5 de este documento SON
justo esa clase de lección.

**Reconciliación con el envenenamiento (§5.bis-B) — aprendizaje ADITIVO, sin gate humano
(decisión del perito: autónomo).** El peligro era un store que aprende a *suprimir* («tool X
no sirve») desde un fallo sembrado. Se elimina de raíz haciendo que **solo aprenda
recuperaciones que FUNCIONAN**, nunca evitaciones:

- La lección tiene forma `(tool, formato, failure_class) → acción Y que SÍ funcionó después`.
  Captura el disparador (el fallo) **y** el remedio (lo que funciona), pero **solo puede
  AÑADIR un paso válido, jamás quitar una herramienta**.
- Consecuencia clave: un fallo sembrado **sin** recuperación válida **no genera lección** —
  Agentopsy se comporta como hoy (lo intenta). **Nunca aprende a dejar de mirar** → imposible
  de cegar. (Bugs 4 y 5 SON justo esta forma: «vmdk + fls-raw falla → desencapsular qemu →
  funciona».)
- Se consolida **sola, por corroboración**: una regla se activa cuando la misma firma
  abstracta se repite en **M casos independientes** (un fluke no llega al umbral) y **se
  auto-retira** si al aplicarla empieza a fallar (confianza sube con aciertos, baja con
  fallos). **Sin cola de candidatos ni revisión humana.**
- Las entradas son sobre **comportamiento de herramienta/formato**, nunca sobre los bytes de
  una evidencia concreta.

**NO lleva información sensible — solo «cosas que funcionan» (perito, 2026-07-17).** Como es
un activo global que viaja en el repo y en la imagen, la bitácora contiene **únicamente
lecciones generales de herramienta/formato**, jamás nada derivado de una evidencia real:
- **Prohibido en el store global:** rutas o nombres de fichero de casos reales, hashes de
  evidencias, `case_id`/`run_id` de casos reales, nombres de perito/examinador, y **stderr
  verbatim** — puede arrastrar bytes derivados de evidencia hostil o datos personales (GDPR;
  el producto no debe hornear datos de personas — coherente con SECURITY INVARIANT 7 y la
  «untrusted stderr» de §5.bis-C).
- **Permitido:** `tool`, forma-de-evidencia (`kind`/`format`), comportamiento (`exit`,
  «funciona / falla»), el **porqué generalizado** y el **remedio** — todo redactado en
  abstracto («un VMDK se desencapsula antes de TSK»), sin identificar caso ni persona.
- **La parte cruda se queda per-caso:** el `run_id`/stderr real de un fallo vive en el
  **audit log del caso** (per-caso, no global); lo que se guarda como regla es solo la
  **firma abstracta saneada** (`tool, formato, failure_class → acción`), no el crudo. La
  observación de runtime *dispara* la lección; no la copia tal cual.

En una frase: **conocimiento de producto que crece de forma autónoma** (por corroboración de
lo que Agentopsy observa que funciona), **sin datos sensibles ni de casos**, y **sin revisión
humana por entrada**. Lo demás de §5.bis sigue en pie: **inyectar, no consultar por turno**
(A, eficiencia), y **advisory, sin auto-skip** (B, rigor). Dónde vive: un fichero versionado
del repo servido como `knowledge/` (candidato:
`agentes/_orchestrator/knowledge/heuristicas-herramientas.md` o un data-file estructurado),
horneado en la imagen — pendiente de decidir formato en implementación.

### 5.quater — Convergencia: que aprenda sin crecer sin fin ni inundarnos (perito, 2026-07-17)

Riesgo que plantea el perito: si Agentopsy «sigue aprendiendo y mandándonos info», ¿converge
o crece/spamea sin parar? **Converge por construcción**, con cuatro piezas:

1. **Firma canónica, no stderr crudo.** Cada observación se normaliza a una CLAVE
   contenido-independiente: `(tool_id, kind/format, failure_class)`, donde `failure_class`
   es uno de un **enum pequeño** de patrones conocidos (`unsupported-image-type`,
   `cannot-determine-fs`, `invalid-magic`, …). El stderr real (rutas, offsets, ids) NO entra
   en la clave — solo su clase. Mil fallos idénticos colapsan a **una** firma. (Además cuadra
   con «sin datos sensibles»: la clave ya es abstracta.)
2. **Espacio finito → techo natural.** El nº de firmas distintas está acotado: catálogo de
   tools × puñado de formatos × puñado de clases de fallo = **decenas, no infinito**. La
   bitácora tiene un punto fijo; no puede crecer sin límite.
3. **Confianza por corroboración + auto-retiro (en vez de un gate humano).** Una firma se
   **activa sola** cuando su regla se corrobora en **M casos independientes** (la confianza
   sube con cada acierto). Y **se retira sola** si, al aplicarla, empieza a fallar (la
   confianza baja con cada contradicción). No es acumulación monótona que se pueda fijar una
   vez: se **autocorrige**. Las reglas sólidas persisten con confianza alta; el ruido nunca
   se activa; lo que deja de funcionar decae. → punto fijo **sin cola de candidatos ni
   revisión por entrada**.
4. **Umbral anti-fluke.** Una regla solo se activa tras **≥ M corroboraciones** (un contador
   de la firma, no del contenido). Un fallo/acierto puntual no genera ruido; solo patrones
   robustos y repetidos suben.

**Cómo el aprendizaje es «global» sin phone-home (opción B, decisión del perito).** Agentopsy
no hace llamadas de salida (SECURITY INVARIANT 7): un despliegue de cliente **no manda
nada**. Modelo: (1) Agentopsy viaja con una **semilla** de reglas consolidadas en el repo, así
cada instalación arranca lista; (2) **cada despliegue sigue aprendiendo solo** encima, local;
(3) en los despliegues de **desarrollo/prueba del propio equipo**, las reglas de alta
confianza se **vuelcan mecánicamente al repo** (fichero → repo) al preparar cada versión — no
es revisión por candidato (el *qué* lo decide la corroboración, autónomo), solo un merge de
datos al liberar. Así el aprendizaje llega a todos **vía release**, nunca por telemetría; las
copias de cliente no comparten entre sí ni llaman a casa.

**Resultado:** el fichero **converge** (espacio finito + confianza que estabiliza), **no
inunda** (dedup por firma + umbral + auto-retiro), y **no filtra** (clave abstracta; el stderr
crudo se queda en el audit log per-caso). Piezas a implementar: el **normalizador
stderr→`failure_class`** (enum extensible), el **modelo de confianza por firma**
(corroboración/contradicción + umbral M + auto-retiro), la **inyección** de las reglas activas
en el ledger (§5.bis-A) y el **volcado semilla↔repo** para el release (opción B).
