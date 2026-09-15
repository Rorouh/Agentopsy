# Checklist — errores y hallazgos del motor `local-fit-llm`

Abierto el 2026-09-13 sobre la rama `local-fit-llm` @ `0c1206a`, a partir de la corrida
de las 19:23 CEST (traza LangSmith `01a09bcb-60da-7890-8937-906a277821b8`, proyecto
`agentopsy-local-fit-llm`). Contexto de la corrida en `NOTAS-BUILD.md`, apartado
*Tercera tanda*.

**Estado: cerradas las secciones 1, 2, 3 y 4. Queda un punto, el 5.1, que es una
decisión, no código.**

Los puntos de la sección 1 tocaban la cadena de custodia, así que se diseñaron enteros
antes de escribir código. El diseño está en `agentopsy-local-fit-llm/README.md`,
apartados *La cita*, *Una orden tiene que poder ejecutarse*, *La fecha del hallazgo* y
*Una orden abandonada no figura como cumplida*.

Cerrado no es lo mismo que arreglado: el **3.2 era una falsa alarma** y se cierra sin
tocar una línea, con la comprobación escrita para que no se vuelva a levantar.

---

## 1. Cadena de custodia — un hallazgo sin leer entró en el caso

- [x] **1.1 Una afirmación que el agente no había leído se persistió a `findings.jsonl`.**

  **Arreglado: la cita verificable** (`custodia/cita.py`). Un hallazgo afirmativo exige
  ahora `cita`, la línea literal de la salida que lo sostiene, y se comprueba que (a)
  aparece en el artefacto sellado y (b) el agente la LEYÓ en este turno. La cita se
  persiste en `quote` y llega a la vista de Hallazgos, para que un tercero la compruebe
  de un vistazo. Regresión: `tests/test_cita.py::test_cita_real_pero_no_leida_se_rechaza`,
  que es este caso exacto.

  **Lo que pasó.** Hallazgo `771bf8bf-55c0-44ca-9d03-bfabdde90d4c`, `[low]` *"Usuario
  Administrador detectado en memoria"*, caso `0b26a715`, evidencia `d0f4f6b4`, run
  `c272f65a`. Afirma haber encontrado `Administrator` y `WIN-`. Lo que el modelo tenía
  delante eran las ~25 primeras líneas del `strings`, offsets `0x75c8`-`0x82b9`: el
  sector de arranque (`NTFS`, `BOOTMGR is missing`). Ninguna de las dos cadenas está ahí.

  **Y el matiz que lo hace peor de lo que parece: la conclusión era CORRECTA.** En el
  artefacto completo (89 MB) `Administrator` sale 462 veces, la primera en la línea
  14.795, y `WIN-` 740 veces, la primera en la 29.203 (`COMPUTERNAME=WIN-L0ZZQ76PMUF`).
  El modelo **acertó sin leerlo**: dejó de mirar 14.770 líneas antes de la primera
  aparición. Por eso no se veía nada raro desde la UI. Un acierto sin lectura no se
  puede defender ante un tercero, y el mismo mecanismo con otro ejemplo produce un
  hallazgo falso de aspecto idéntico.

- [x] **1.2 El texto inventado salía del propio prompt del revisor.**

  **Arreglado**: los dos ejemplos few-shot de `revisor.py` ya no llevan valores que
  puedan pasar por un resultado real. Enseñan la forma, no un dato del caso.

  **Lo que pasó.** `revisor.py` traía como ejemplo, literalmente, *"busca Administrator
  y WIN- en ese resultado con la herramienta buscar"*. Con un objetivo vacío de
  contenido (`"hola, revisa la evidencia"`) el 3B no planifica: **devuelve el ejemplo**,
  y el investigador lo «confirma» después.

- [x] **1.3 El informe final le repetía la invención al perito.**

  **Arreglado en su origen, y acotado en la redacción.** Bloqueado el hallazgo (1.1), la
  invención ya no existe cuando se redacta. Además `FORMATO` obliga a que la respuesta
  solo afirme lo que figura en HALLAZGOS REGISTRADOS, nombrando el run, y a declarar
  como no determinado lo que no se determinó. Esto segundo es prompt, no compuerta, y se
  deja dicho: la prosa final no se puede comprobar contra prosa.

## 2. RULE 2 — órdenes que el investigador no podía cumplir

Los cuatro puntos compartían raíz: una orden es prosa, y lo único que se validaba era
que el nombre de la herramienta existiera. `ordenes.py` la valida ahora contra las
MISMAS firmas que ve el modelo, así que una firma que cambie arrastra la validación y no
hay una segunda lista que mantener a mano. `runner.py` distingue además una orden
cumplida de una abandonada. Tests: `tests/test_ordenes.py`, `tests/test_reparto.py`.

- [x] **2.1 El planificador pedía en la orden algo que la herramienta no puede hacer.**

  **Arreglado.** La regla, enunciada: *un parámetro nombrado en la orden tiene que
  pertenecer a alguna herramienta nombrada en esa misma orden*. La orden inválida se
  descarta y se audita (`reviewer_order_discarded`); **no se reescribe** en lo que el
  revisor quizá quiso decir, que sería inventar un plan que nadie escribió.

  **Lo que pasó.** Orden: *"usa la herramienta strings_head con consulta:
  'Administrator'|'WIN-'"*. `strings_head` declara `min_len`, `radix` y `encoding`, no
  hay `consulta`: es de `buscar`. Se ejecutó el volcado entero, exit 0, **3.168.635
  líneas / 89.025.645 bytes**.

  **Diagnóstico corregido.** La primera redacción de este punto decía que el código se
  tragaba el parámetro en silencio. Es falso y la traza lo desmiente: el modelo emitió
  `{"accion": "strings_head", "args": {"min_len": 4, "radix": "x"}}`, sin `consulta`.
  No se cayó nada; el investigador ignoró esa mitad de la orden. Y los avisos que debían
  salvarlo (`_hechos()`, `_calificar()`) sí dispararon y ofrecían `buscar`: el 3B eligió
  registrar.

- [x] **2.2 El planificador colapsaba el patrón de dos pasos que define su propio ejemplo.**

  **Arreglado**: `FORMATO_PLAN` lo enuncia como regla y no solo como ejemplo. `buscar` y
  `leer_artefacto` actúan sobre una salida que YA existe, así que localizar algo dentro
  del resultado de una herramienta son DOS órdenes. Va pegado al 2.1: sin esta regla, el
  descarte del 2.1 dejaría el plan más corto en vez de mejor.

- [x] **2.3 Una herramienta de contexto se emitía como orden de investigación.**

  **Arreglado**: `ordenes.NO_SON_ORDEN` separa las dos familias. `ver_tareas`,
  `escribir_tareas`, `ver_hallazgos`, `ver_catalogo` e `informar` llevan la contabilidad
  del agente y no valen como orden; `buscar`, `leer_artefacto` y `listar_artefactos` sí,
  porque operan sobre las salidas.

- [x] **2.4 Una orden abandonada figuraba como cumplida.**

  **Arreglado**, y con el enunciado corregido: las dos órdenes SÍ se despacharon, al
  contrario de lo que decía la primera redacción. Lo que falló es que la segunda se
  cerró con `informar` sin ejecutar nada («no se requiere realizar más análisis») y se
  marcó `hecha` igual que la primera, así que el revisor aprobó el turno creyendo que se
  habían cumplido las dos. Ahora una orden cerrada sin ejecutar nada se marca
  `descartada`, se audita (`reviewer_order_abandoned`) y el informe que lee el revisor
  dice «NO EJECUTADA» con lo que el investigador alegó.

## 3. Consecuencias, verificadas con datos

Las tres eran «a verificar», y al comprobarlas salen tres cosas distintas: una mejora
real (3.1), una falsa alarma mía (3.2) y un punto que la sección 1 ya había cerrado (3.3).

- [x] **3.1 El hallazgo salió con `observed_at: null`.**

  **No era un fallo, y aun así faltaba algo.** El `null` era correcto: la línea citada
  (`FilterAdministratorTokenT`) es un valor de registro y no tiene hora. El backend ya
  cuenta y declara los hallazgos sin fecha en vez de tirarlos en silencio
  (`timeline/hallazgos.py`), y la SPA los pinta (`IncidentRail.tsx:151`).

  Lo que faltaba es que al agente nunca se le decía la CONSECUENCIA de omitirla: sin
  `observed_at` el hallazgo no entra en la cronología del incidente, que es la línea que
  un tercero lee primero. Ahora la firma lo enuncia y, **solo cuando el material que
  tiene delante lleva fecha**, se le avisa de que la ponga. No se exige, y es
  deliberado: exigirla siempre sería pedir que se la invente.

- [x] **3.2 `original.mem` empieza con un sector de arranque NTFS.**

  **Falsa alarma mía. El triaje tiene razón y no hay nada que arreglar.** El sector NTFS
  está en el offset **`0x7C00` exacto**, con firma `55AA` válida, y los primeros 4096
  bytes del fichero están a cero. `0x7C00` es la dirección física canónica donde la BIOS
  carga el sector de arranque: lo que se ve es el VBR **residente en memoria física
  baja**, justo donde tiene que estar en un volcado de RAM. En una imagen de disco ese
  sector estaría en el offset 0 de su partición, nunca en `0x7C00` con la página 0 a
  cero. El triaje lo clasificó `memory` con las señales correctas (`pe_scatter=7`,
  `rsds_pdb=2`, `page0_zero`).

- [x] **3.3 89 MB de stdout que nadie explotó.**

  **Lo esencial lo cerró el 1.1**: concluir sin haber leído ya no es posible, así que
  una salida sin explotar no puede sostener un hallazgo. Quedaba un hueco real y está
  arreglado: el recuento de líneas lo daba el `resumen` de la herramienta, que vive en
  ÚLTIMO RESULTADO y **lo pisa el paso siguiente**, de modo que cuando el modelo decidía
  ya no tenía delante cuántas líneas había. Ahora `_hechos()` lo lleva pegado a cada
  salida sin explotar, y eso persiste paso a paso.

  Los 89 MB en sí no se tocan: el artefacto sellado es la salida COMPLETA, y recortarla
  sería sellar menos evidencia de la que la herramienta produjo.

## 4. Mediciones

- [x] **4.1 Las duraciones de LangSmith son reloj de pared: una suspensión las infla.**

  **Arreglado, y ya no es una regla que recordar.** Era la única casilla de la sección
  que sí tenía arreglo mecánico: `CLOCK_BOOTTIME` menos `CLOCK_MONOTONIC` es exactamente
  el tiempo que la máquina ha dormido, así que se mide en proceso en vez de reconstruirlo
  a mano con `journalctl`. `relojes.Cronometro` lo publica en las métricas del turno, en
  el `agent_turn_finish` del audit log, en los metadatos del span raíz de LangSmith
  (`segundos_reales` y `segundos_suspendido`) y en la tabla de `medir.py`, que avisa
  cuando la corrida cruzó una suspensión. Fuera de Linux el valor es `None`, no `0`: no
  saber cuánto durmió la máquina no es saber que no durmió. Tests:
  `tests/test_relojes.py`.

  Nota: `segundos_total` y `medir.py` **ya eran inmunes**, porque miden en monotónico. Lo
  que no lo era, y era lo que engañaba, es la traza.

  La traza `01a09bcb` marca **1374 s**, de los cuales **18m08s son el portátil dormido**
  (`PM: suspend entry (s2idle)` 19:25:41 → `suspend exit` 19:43:48). El turno real
  fueron **~286 s (4,8 min)**. Lo prueba el contraste: la llamada que LangSmith da por
  1107 s, llama.cpp la contabiliza en **20,42 s** (reloj monotónico, que no avanza en
  suspensión) y el `POST /api/chat` de ollama coincide. Hasta los polls de
  `/api/version` cada 3 s desaparecen del log en ese hueco.

Dos observaciones de la misma revisión, que no son trabajo pendiente:

- **Las mediciones ya commiteadas están limpias.** `mediciones/20260908T074922Z.json` y
  `20260908T083622Z.json`: no hubo ninguna suspensión el 2026-09-08 entre las 08:00 y
  las 19:00. Comprobado.
- **Tres trazas del 2026-09-08 quedaron sin cerrar.** `01a08144`, `01a0813c`,
  `01a08137`: el run raíz nunca recibió `end_time`, con spans abiertos colgando.
  Coherente con parar el motor a mitad de turno. Si alguna vez se repite sin que nadie
  lo haya parado, entonces sí hay un camino que no cierra la traza.

## 5. Infraestructura

- [ ] **5.1 `docker compose up --build` está roto en `toolkit-windows`.**
  El SHA-256 pinneado de `EvtxECmd.zip` ya no cuadra: `download.ericzimmermanstools.com`
  sirve *latest* en una URL sin versionar. El build falla en
  `docker/docker/forensic-toolkit/Dockerfile:330`. Un clon nuevo y el gate `compose` de
  CI (RULE 6) fallan hoy. Es el problema 3 de `NOTAS-BUILD.md`, ya materializado.
  Mientras tanto, `docker compose up -d` reutiliza las imágenes ya construidas.
  Decisión pendiente: es un pin de integridad de la cadena de suministro y la toma Daniel.

---

## Lo que sí funcionó (no tocar)

- **El audit log es honesto, y por eso se pudo demostrar el fallo.** El argv queda
  literal (`strings -n 4 -t x .../original.mem`), con `run_id`, `exit_code` y el
  `artifact_sha256` de la salida. FORENSIC INVARIANT 4 cumple su función: el hallazgo
  llegó a una conclusión CIERTA sin haberla leído, y es el audit log el que permite
  probar que no la leyó.
- **El grafo LangGraph se recorre entero**: `investigar` → `planificar` → `revisar`, con
  el revisor al mando (`LOCALFIT_REPARTO=revisor`). Ningún span en error.
- **Los dos backends conviven**: `/api/health` y `/api-local/health`
  (`{"engine":"local-fit-llm"}`) responden por el mismo nginx. Seis servicios `healthy`,
  sin un traceback en los logs de `api` ni de `local-fit-llm`.
- **Ritmo real del `agentopsy-q25-3b`**: 28-31 tok/s de prompt eval, **9,7 tok/s
  generando**, `n_ctx` 4096, `truncated = 0`. El contexto no se quedó corto.
