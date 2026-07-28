# 08 — Análisis comparativo: por qué el agente de Agentopsy falla y el flujo de `prueba-agentes` no

> Comparación entre la corrida #001 del agente de Agentopsy
> ([`07-corrida-agente-001.md`](07-corrida-agente-001.md)) y el análisis del **Caso
> Murciélago** en `../../prueba-agentes/fase1/`, **sobre la misma evidencia**.
> Índice: [`README.md`](README.md).

---

## 1. Por qué esta comparación vale: es un control casi perfecto

Los dos análisis se hicieron **el mismo día, sobre los mismos ficheros, con el mismo
maletín**:

| | Agentopsy | `prueba-agentes` |
|---|---|---|
| Evidencia RAM | `ram.raw` · sha `a0ad93b2…b240` | **el mismo** `a0ad93b2…b240` |
| Evidencia disco | `IE11-Win7-VMWare-disk1.vmdk` | **el mismo** fichero |
| Herramientas | maletín Docker de Forensia | **el mismo**, como caja negra |
| Ejecutor | Claude Code CLI | Claude Code CLI (opus-4-8) |
| Pregunta | *«¿Se accedió a los documentos confidenciales, y en qué fecha y hora?»* | P1 del enunciado: **la misma pregunta** |

Lo único que cambia es **cómo se organiza el trabajo**. Por eso las diferencias de
resultado son atribuibles al diseño del flujo, no a la evidencia, ni a las
herramientas, ni al modelo.

> Salvedad honesta: `prueba-agentes` declara `opus-4-8`; el audit de Agentopsy solo
> registra `model_name: "Claude Code"` — **no guarda qué modelo facturó**. No se
> puede afirmar que fueran idénticos. (Que no se pueda saber es, en sí, un hallazgo
> menor: ver §4.8.)

---

## 2. Los resultados, enfrentados

| | Agentopsy #001 | `prueba-agentes` |
|---|---|---|
| Duración | 10 min | 2 h 30 (1 h 11 de API) |
| Coste | **$4,13** | **$39,45** |
| Herramientas ejecutadas | 4 (+2 internas, 1 fallida) | ~25 |
| **Respuesta a la pregunta** | **ninguna** | **P1 respondida** |
| Hallazgos persistidos | **0** | ficha completa + informe pericial v1 |
| Documentos confidenciales | no identificados | **`CLIENTES DEL BANCO.xls` y `Plan_de_cuentas.xls`**, recuperados de RAM |
| Cronología | no construida | timeline del ataque, 11 hitos, TZ resuelta |
| Cuentas | no enumeradas | 6 cuentas, incluida `testuser` admin creada a las 19:07:38 |
| Anti-forense | no detectado | **`sdelete64.exe`**, firma `SDELTEMP`/`ZAP*.tmp` en `$UsnJrnl` |
| Custodia | evidencia aceptada | **BLOQUEO: el hash no cuadra con el oficial** |

**Agentopsy es 10× más barato y produce cero.** El coste por pregunta respondida es
$13 en `prueba-agentes` e **infinito** en Agentopsy. El eje de comparación no puede
ser el gasto absoluto.

---

## 3. La causa que lo explica casi todo

> **Agentopsy obliga al modelo a manejar una INDIRECCIÓN que no necesita, y el
> modelo la rompe. `prueba-agentes` no tiene esa indirección: la salida es un
> fichero en una ruta.**

### En Agentopsy

Una herramienta escribe su salida en un `ArtifactRun`. Para encadenar, el modelo
debe emitir una referencia `{run_id, relpath}` con el UUID4 exacto del run
productor. En la iteración 8 emitió:

```json
{"tool_id": "tsk_mactime", "params": {"bodyfile_path": "dict", "timezone": "UTC"}}
```

La cadena literal `"dict"` — el **nombre del tipo**, no un valor. El pipeline se
rompió ahí y la corrida murió.

Y hay un agravante estructural: el windowing de contexto colapsa los resultados de
turnos viejos a stubs. **El `run_id` que el modelo necesitaba en la iteración 8 se
generó en la 4.** El arreglo del Bug 2 (dejar de truncar el id a 8 caracteres) fue
correcto pero insuficiente: el problema ya no es que el id esté recortado, es que
**el turno entero se ha elidido** cuando hace falta citarlo.

### En `prueba-agentes`

No hay protocolo de referencia. Cada ejecución deja
`output/<caso>/<NN>_<tool>/` con la salida cruda, la vista legible y un `_run.md`.
La entrada de la siguiente herramienta es **una ruta**:

```
vol -f /in/ram.raw -o /dump windows.dumpfiles --physaddr {0x13d6be070,…}
```

El sistema de ficheros ES el almacén de artefactos. No hay nada que construir mal.

**Diagnóstico:** Agentopsy resolvió el Bug 1 (que el bodyfile fuese *referenciable*)
y el Bug 2 (que el id no llegase *truncado*). Ambos arreglos funcionan — el bodyfile
existe, 107 MB con su sha256. Lo que no se arregló es que **el modelo tenga que
construir la referencia a mano**. Se movió el fallo un escalón, no se eliminó.

---

## 4. Las otras siete diferencias, por peso

### 4.1 · Una herramienta por iteración vs. lotes

Agentopsy ejecuta **una** herramienta por iteración y corta a las 12. La corrida
#001 gastó sus 9 iteraciones en 4 herramientas útiles.

`prueba-agentes` lanza **lotes en un solo contenedor**: *«contexto + preguntas de
memoria en UN contenedor (cache caliente, sin `set -e`)»* — `pslist`, `netscan`,
`cmdline`, `malfind`, `dlllist`, `handles`, `filescan`, `dumpfiles` en una tanda.

El impacto económico es el que manda: el ejecutor es stateless y Agentopsy
**reenvía el transcript entero en cada iteración**. El coste crece con
`contexto × turnos`. Menos turnos y más gordos es dramáticamente más barato por
herramienta ejecutada. Es exactamente la lección que `prueba-agentes` documenta en
su `CONSUMO.md`: *«el gasto NO es el tamaño del contexto (419k), sino contexto × nº
de turnos»* — 51,4M de cache-read en una conversación que "pesa" 419k.

**Los dos sistemas sufren el mismo motor de coste.** Agentopsy lo sufre además con
un rendimiento por turno mucho peor.

### 4.2 · El estado en el disco — pero `prueba-agentes` TAMPOCO lo aprovecha

> **Corrección del perito (2026-07-28).** Una primera redacción de esta sección
> daba a entender que `prueba-agentes` resuelve el problema de contexto porque
> escribe a disco. **Es falso, y el dato lo desmiente:** pagó **$39,45** con
> **51,4M de cache-read** precisamente porque **arrastró toda la conversación
> durante 2 h 30**. Escribió los documentos *además* de cargar el contexto, no
> *en lugar de*. El disco fue un subproducto, no un mecanismo de ahorro.

Lo que sí tiene `prueba-agentes` es **persistencia**: cuatro documentos vivos
(`FICHA`, `FLUJO`, `REGISTRO`, `PETICIONES`) escritos **mientras** ocurre lo que
describen, con la regla *«un hallazgo sin documentar todavía no cuenta como
hallazgo»*. Eso le da trazabilidad y le permite reanudar en una sesión nueva.

Pero durante la sesión, el coste lo pagó igual. Los dos sistemas fallan en lo
mismo por caminos distintos:

| | Agentopsy | `prueba-agentes` | Lo que hay que hacer |
|---|---|---|---|
| ¿Persiste el hallazgo? | **No** (0 `record_finding`) | Sí, en `.md` vivos | Sí |
| ¿Descarga el contexto? | No — reenvía todo y elide lo viejo | **No** — arrastra todo | **Sí, referenciando** |
| Coste | $4,13 / nada | $39,45 / caso resuelto | El objetivo |

**Ninguno de los dos hace lo correcto.** Uno pierde el estado, el otro lo carga
entero. Ver §4.2.bis.

### 4.2.bis · Lo correcto: el chat como memoria de punteros, no de contenido

**Principio del perito.** El chat es la **memoria principal**, pero guarda
**hallazgos y punteros**, no contenido:

> Se documenta el hallazgo en el momento, y en la conversación queda una línea:
> *«el resto está en `/casos/<caso>/artefactos-registro.md`»*. El contenido **solo
> se carga cuando hace falta**. Con varios `.md` así, cada caso acaba siendo un
> **grafo de conocimiento** navegable — el *spiderweb*.

Por qué esto sí ataca el motor de coste: el gasto es `contexto × turnos`. Escribir
a disco no lo baja **si el contenido sigue viajando en cada turno**. Lo que lo baja
es que en el prompt viaje **el puntero** (una línea) y el contenido se traiga
**bajo demanda, una vez, y solo cuando se necesita**. Especialmente con salidas
grandes: un bodyfile de 107 MB o un árbol `fls` de 52 MB no pueden estar en el
contexto de ninguna manera — pero su **conclusión** («árbol NTFS estándar, 4
particiones, detalle en `NN_fls/`») ocupa una línea.

**Agentopsy ya tiene la mitad del mecanismo construida.** `consultar_conocimiento`
(`agent/tool_schemas.py:469`, `:637`) hace exactamente esto: el system prompt lleva
un «Mapa de memoria» con **solo las descripciones**, y el contenido completo se
sirve por `doc_id` cuando el agente lo pide. Su propia descripción lo dice: *«NO
cargues todo de antemano — consulta solo el doc que necesites para la tarea en
curso (economía de contexto)»*.

Lo que falta son las dos piezas que lo convierten en grafo por caso:

1. **El lado de ESCRITURA.** Hoy `consultar_conocimiento` es de **solo lectura**
   sobre documentos **estáticos** que vienen en el paquete (`knowledge/`). El
   agente no puede **escribir** un nodo nuevo del grafo mientras trabaja.
2. **El ámbito POR CASO.** El mapa de memoria es del paquete, igual para todos los
   casos. Un grafo de conocimiento **del caso** —lo que se ha encontrado, dónde
   está, qué queda abierto— no existe.

Con esas dos piezas, `record_finding` deja de ser solo una fila en `findings.jsonl`
y pasa a ser **un nodo del grafo del caso**, con sus enlaces a los artefactos que
lo sostienen. Y el contexto del agente puede quedarse en el índice.

> Ojo al matiz de rigor: los nodos que escriba el agente son **conocimiento del
> caso**, nunca sustituyen al audit log ni a `findings.jsonl`. El grafo es para
> **navegar y no recargar**; la cadena de custodia sigue siendo la de siempre.

### 4.3 · Conocimiento aprendido y escrito vs. playbook estático

Las heurísticas que `prueba-agentes` **aprendió durante la corrida** son las que
ganaron el caso:

- **h1 — el maletín no tiene todos los plugins.** `consoles`/`cmdscan` no soportan
  Win7; `hashdump`/`lsadump`/`cachedump` **no están** en el build. Comprobar antes
  de prometer.
- **h3 — ⭐ la palanca que rescató el caso.** Sin `hashdump` y con el disco
  inaccesible: `windows.registry.hivelist --dump` saca **todos los hives desde la
  RAM**, y `regripper` sobre ellos responde zona horaria, USB, cuentas y documentos
  recientes **sin tocar el disco**.
- **h5 — no usar `set -e` en un lote**, o un plugin no soportado aborta los demás.

Agentopsy **no tiene mecanismo para esto**. Es precisamente la *bitácora* diseñada
en `notas-rediseno-agentes.md` §5 y nunca implementada. Su forma canónica —
`(tool, formato, clase-de-fallo) → acción que SÍ funcionó` — es literalmente h1, h3
y h5.

### 4.4 · El pivote está prohibido por diseño

La jugada ganadora de `prueba-agentes` fue **pivotar**: el disco no abre → volcar
hives desde RAM → responder por otra vía.

Agentopsy no puede hacer eso. RULE 2 dice *«no try the other tool when this one
fails»*, y el loop no tiene ningún concepto de «esta ruta está cerrada, cambio de
familia de artefacto». Cuando `mactime` falló, el agente **siguió empujando la
misma puerta**.

> **Matiz que importa:** RULE 2 prohíbe el fallback **silencioso** — sustituir una
> herramienta por otra sin decirlo. Un pivote **declarado, con su porqué, visible
> para el perito** es otra cosa: es exactamente lo que hizo `prueba-agentes`, y lo
> dejó escrito en el registro. La regla no impide el pivote; impide ocultarlo.
> Hoy el agente no tiene forma de expresarlo.

### 4.5 · «No elijas la tool, elige el ARTEFACTO»

El corazón del método de `prueba-agentes`:

> *«No se elige la tool, se elige el **artefacto** que responde la pregunta, y el
> artefacto dice la tool.»*

Con su tabla pregunta → artefacto → tool: *acceso a documentos* → MFT, **LNK,
jumplists, shellbags, RecentDocs** → `tsk_fls`+`mactime`, `mftecmd`, `regripper`.

El agente de Agentopsy fue directo a las herramientas: `mmls` → `fls` → `fls -m` →
`mactime`, construyendo una timeline genérica de todo el disco para una pregunta
sobre **unos pocos documentos**.

**Lo desolador:** en su respuesta final el agente nombró los artefactos correctos
—LNK, Jump Lists, RecentDocs, `$MFT` con `$SI` vs `$FN`—. **Sabía la respuesta al
método.** La aplicó después de quemar 9 iteraciones. El conocimiento estaba; el
**orden** no estaba impuesto.

### 4.6 · Custodia: baseline autorreferencial vs. hash externo

El hallazgo más serio del análisis.

```
Hash oficial del enunciado : …d7e45b385 9 7068
Hash del fichero real      : …d7e45b385 4 7068
                                       ↑ un carácter (índice 58)
```

`prueba-agentes` **comparó contra el hash oficial, no cuadró, y BLOQUEÓ el
análisis**: *«no se analiza como verificada una evidencia cuyo hash no cuadra»*.

Agentopsy **registró ese mismo fichero sin inmutarse**, con
`sha256: 60919a3a…b38497068` como baseline, y su cadena de custodia dice
`verified: true` para el RAM dump y nada anómalo para el disco.

**No es un bug: es un hueco conceptual.** Agentopsy demuestra que *la copia es
idéntica al origen*. Nunca demuestra que *el origen es la evidencia que dice ser*.
No existe el campo «hash esperado» en ningún sitio: ni en el registro, ni en
`baseline.json`, ni en el acta de adquisición.

Para un producto que se presenta con rigor pericial, **es la diferencia entre
verificar integridad y verificar autenticidad**, y hoy solo hace la primera.

### 4.7 · La hipótesis del encargo no es un hallazgo

`prueba-agentes` lo escribe como regla de trabajo:

> *«La hipótesis del enunciado no es un hallazgo. Se puede refutar. Buscar solo lo
> que confirma la sospecha es el sesgo clásico del perito.»*

Y lo aplicó con consecuencias reales: al fechar los USB detectó que los del 23-03
eran **del propio perito** (kit de adquisición: Magnet, DumpIt, Wintriage) y los
**excluyó** de la actividad del sospechoso. Sin esa separación, el informe habría
atribuido al empleado la huella de quien tomó la evidencia.

Agentopsy no tiene ninguna regla equivalente. Su system prompt tiene «no inventas»
(que funcionó), pero nada sobre **sesgo de confirmación** ni sobre **separar la
actividad del perito de la del sospechoso**.

### 4.8 · El audit no registra qué modelo facturó

`model_name: "Claude Code"` — el nombre del CLI, no del modelo. Con `$4,13` en la
factura y sin saber si fue Opus, Sonnet o qué versión, **el coste no es
atribuible ni reproducible**. `prueba-agentes` sí lo tiene: `opus-4-8`, 202,5k
output, 51,4M cache-read.

---

## 5. Lo que Agentopsy hace MEJOR (y no hay que tirar)

Sería un error leer esto como «el producto no sirve». Hay cosas que Agentopsy hace
y `prueba-agentes` **no pudo**:

1. **⭐ Abrir el VMDK.** `prueba-agentes` se estrelló: `nbd` y libguestfs no
   funcionan en el host (amd64 emulado sin KVM) y convertir a raw exigía espacio
   que no había — *«disco lleno, Docker caído»*. **Agentopsy sí lo leyó**: el
   desencapsulado FUSE con `qemu-storage-daemon` (Bug 4) le dio `mmls` con 4
   particiones y el árbol completo con `fls`. Es una capacidad real del producto
   que el flujo manual no tiene.
2. **Audit hash-encadenado con el argv literal.** Los `_run.md` de
   `prueba-agentes` son disciplina humana: buenos, pero no a prueba de
   manipulación. Agentopsy encadena hashes y registra lo que **se ejecutó**, no lo
   que se dijo que se iba a ejecutar.
3. **Custodia mecánica:** copia inmutable, `chmod 0444`, registro atómico,
   read-only a nivel de bloque. En `prueba-agentes` eso lo sostiene el cuidado del
   operador.
4. **No inventar bajo presión.** Con una pregunta directa sin responder, el agente
   dijo *«prefiero reportarte el estado real a inventar una respuesta»*. La regla 4
   del system prompt aguantó, y eso en forense vale mucho.
5. **Autodiagnóstico preciso.** Identificó su propio `icat inode=0` como *«un paso
   en falso, no aporta»* y la causa exacta del fallo de `mactime`.

---

## 6. Síntesis: qué explica el fracaso, en orden

| # | Causa | Peso | ¿Toca un invariante? |
|---|---|---|---|
| 1 | El modelo debe construir a mano la referencia `{run_id, relpath}`, y el windowing le borra el turno donde estaba | **Decisivo** — mató la corrida | No |
| 2 | Una herramienta por iteración, tope 12, transcript reenviado entero | Alto — coste y alcance | No |
| 3 | El estado viaja en el prompt en vez de vivir en un grafo por caso que se referencia bajo demanda (§4.2.bis) — **`prueba-agentes` tampoco lo resuelve: por eso pagó $39,45** | Alto | No |
| 4 | Sin memoria de lo que funciona y lo que no (bitácora sin implementar) | Alto | No |
| 5 | Sin ruta pregunta → artefacto → tool: elige tools, no artefactos | Alto | No |
| 6 | Sin capacidad de pivotar declaradamente cuando una vía se cierra | Medio | Roza RULE 2 — **hay que redactarlo bien** |
| 7 | Baseline autorreferencial: no compara contra un hash externo | Medio en coste, **alto en rigor** | **Amplía** custodia, no la erosiona |
| 8 | El audit no guarda qué modelo facturó | Bajo | No |

**Siete de las ocho no requieren tocar ningún invariante forense ni de seguridad.**
La sexta necesita redacción cuidadosa —distinguir *fallback silencioso* (prohibido)
de *pivote declarado* (que es buena praxis)—. La séptima **refuerza** la cadena de
custodia en vez de debilitarla.

Ninguna es un problema de infraestructura: las 31 herramientas estaban
disponibles, los maletines sanos y el enrutado fue correcto.

---

## 7. Enlaces

- La corrida analizada: [`07-corrida-agente-001.md`](07-corrida-agente-001.md).
- Requisitos ya catalogados: [`06-debe-hacerlo-sola.md`](06-debe-hacerlo-sola.md).
- Notas del perito: [`05-notas-perito.md`](05-notas-perito.md) §N5.
- La bitácora diseñada y sin implementar:
  [`../agentes/notas-rediseno-agentes.md`](../agentes/notas-rediseno-agentes.md) §5.
- Objeciones sobre enrutado y autonomía:
  `../agentes/INTERNO-revision-flujo-y-autonomia.md`.
- El flujo comparado: `../../prueba-agentes/fase1/FLUJO.md` y su
  `FICHA-caso-murcielago.md`.
