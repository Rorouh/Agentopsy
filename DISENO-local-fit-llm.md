# Agentopsy `local-fit-llm` — documento de diseño

**Estado**: implementado en `agentopsy-local-fit-llm/` (dos agentes: investigador y
revisor; ver su `README.md`). En medición. **Revisión 2** — 2026-09-08.
Requisitos que cumple: [`REQUISITOS-local-fit-llm.md`](REQUISITOS-local-fit-llm.md).
Mediciones que lo sustentan: [`NOTAS-BUILD.md`](NOTAS-BUILD.md).

> **Qué cambió respecto a la revisión 1**: aquella ponía la secuencia de
> herramientas en código y reducía el modelo a contestar preguntas cerradas.
> **Se descarta.** El agente conserva su agencia: decide qué herramientas usa y
> en qué orden. Lo que cambia no es *quién decide*, sino *cómo se le da el
> contexto*.

---

## 1. Objetivo

Un análisis forense básico y completo, autónomo, en un equipo de **8 GB de RAM
sin GPU**, con **respuestas en menos de 10 minutos** (deseable: menos de 5),
conservando intacta la cadena de custodia.

Modo alternativo que el operador elige. No sustituye al camino agéntico con
modelo de nube.

---

## 2. Por qué el motor actual no llega

No es cuestión de elegir mejor modelo. Está medido:

| magnitud | valor |
|---|---|
| prompt del agente | 70.543 chars ≈ **17.846 tokens** |
| prefill en CPU (7B Q4) | **9,7 tokens/s** |
| coste de leer el prompt | **~30 min por llamada** |
| iteraciones de una investigación real | **19** |

Y el prompt **se reenvía entero cada vuelta** — el propio texto lo dice: *«Every
turn re-sends the whole conversation»*. Eso son **~340.000 tokens de prefill**,
casi **10 horas solo leyendo**.

### El efecto colateral, y la clave del nuevo diseño

Con ventana de 16.384, Ollama recorta la entrada a la mitad **conservando la
cola**. El playbook está al 16 % del prompt: desaparece. Lo último que el modelo
lee es un ejemplo que menciona «mmls plus fls», y el modelo emitió `mmls` y
`fls` sobre un volcado de RAM. Obedeció lo único que le llegó.

**La prueba B lo confirmó por A/B sobre el prompt real:**

| condición | primera herramienta | coste |
|---|---|---|
| ventana 16k, prompt tal cual | `tsk_fls` ❌ | 1052 s |
| 16k + la instrucción **al final** | **`file_info`** ✅ | 1039 s |
| ventana 32k, prompt entero | **`file_info`** ✅ | 3082 s |

**Cuando la instrucción llega, el modelo pequeño elige bien.** Ese dato es el
que justifica dejarle la agencia en vez de quitársela: el problema nunca fue su
criterio, fue que no leía las instrucciones porque no cabían.

---

## 3. Principio de diseño: el agente tira, no se le empuja

El motor actual **empuja** todo el estado al modelo en cada llamada: playbook
completo, catálogo de 38 herramientas, contexto del caso, conversación entera.
Por si acaso.

Aquí se invierte. **El agente es un experto en su área** —la pericia viene con
él, no reinyectada como un muro de texto— y **pide lo que necesita** según lo
que tiene delante y con lo que cuenta.

Consecuencia práctica: el agente dispone de **dos familias de herramientas**.

### 3.1 Herramientas forenses

Las del maletín. El agente elige cuál y con qué parámetros. Se accionan por
HTTP contra `exec_agent.py`, igual que hoy.

### 3.2 Herramientas de contexto

Lo que convierte «recibirlo todo» en «pedir lo que hace falta»:

| herramienta | para qué |
|---|---|
| `ver_tareas()` / `escribir_tareas(lista)` | leer y reescribir su propia lista de trabajo |
| `listar_artefactos()` | qué salidas hay ya, con tamaño y herramienta de origen |
| `leer_artefacto(id, desde, n)` | leer **un trozo** de una salida, no la salida entera |
| `buscar(consulta)` | localizar dónde está algo, sin traérselo todo |
| `ver_catalogo(filtro)` | qué herramientas existen para un tipo de evidencia |
| `registrar_hallazgo(...)` | dejar constancia de una conclusión |
| `ver_hallazgos()` | qué lleva concluido |

Ninguna carga el caso completo en el contexto. Todas devuelven **recortes
acotados**, con un tope de tamaño fijado por el sistema.

---

## 4. El bucle

ReAct, con una diferencia respecto al motor actual: **el propio modelo escribe y
mantiene su lista de tareas**, como hacen Antigravity y similares. El sistema no
le entrega un plan; le da la capacidad de escribirlo, revisarlo y marcarlo.

```
1. El perito escribe algo.
2. El agente lee su lista de tareas (o la crea si no hay).
3. Elige UN paso. Llama a una herramienta — forense o de contexto.
4. El sistema ejecuta, persiste el raw, devuelve un resumen acotado.
5. El agente actualiza su lista: marca, reordena, añade lo que ha descubierto.
6. Vuelve a 3 hasta que la lista está cerrada o toca responder al perito.
```

**Un paso cada vez.** Es lo que evita que se mate intentando resolverlo todo en
una ventana corta, y lo que hace que cada llamada quepa holgadamente.

La lista de tareas es además **la columna vertebral de la memoria**: es lo que
sobrevive entre llamadas y lo que hace que el agente sepa siempre qué está
haciendo y qué le queda. Y es **visible para el operador**, que ve el plan del
agente en vivo en lugar de un spinner.

---

## 5. El prompt de cada paso

Esqueleto fijo y pequeño. Presupuesto orientativo, a ajustar con el spike:

| bloque | contenido | tokens aprox. |
|---|---|---|
| identidad | quién es y cómo trabaja. **Corto** — la pericia está en el modelo | ~200 |
| lista de tareas | la suya, tal como la dejó | ~150 |
| último resultado | salida del paso anterior, **acotada** | ~400 |
| herramientas | firmas compactas de lo que puede llamar ahora | ~300 |
| punteros del caso | evidencia, `kind`, nº de artefactos, nº de hallazgos — **referencias, no contenidos** | ~100 |
| lo que pidió el perito | | ~100 |
| **total** | | **~1.250** |

**Nunca la conversación entera. Nunca el catálogo completo. Nunca el contenido
de un artefacto sin haberlo pedido.**

A ese tamaño, un paso cuesta del orden de 30-60 s en CPU. Diez pasos entran en
el objetivo de 10 minutos.

---

## 6. La memoria: dos caminos, y se miden

Requisito RA-9. Ambos se implementan detrás de **la misma interfaz**, para poder
intercambiarlos y compararlos con datos.

### Camino A — estado estructurado (sin embeddings)

- Lista de tareas del agente.
- Hallazgos registrados.
- Índice de artefactos: id, herramienta, tamaño, líneas, `exit_code`.
- Resumen de los últimos N pasos.

A favor: no añade otro modelo en RAM, sin latencia por consulta, determinista y
auditable. El agente navega con `buscar()` y `leer_artefacto()`.

### Camino B — recuperación por embeddings

Lo del camino A, más un índice vectorial sobre mensajes, entradas y salidas de
herramientas. `buscar()` recupera por significado en vez de por coincidencia.

A favor: encuentra en salidas largas —13.000 líneas de `strings`— lo que una
búsqueda literal no. En contra: otro modelo en RAM y latencia por consulta, en
un presupuesto de 8 GB.

### Cómo se decide

Mismo caso, mismo modelo, mismos pasos. Se comparan tiempo total, pasos
necesarios y hallazgos conservados. **Gana el que mida mejor, no el que suene
mejor.**

---

## 7. Los artefactos crudos y la custodia

Cada ejecución persiste su salida **tal cual, antes de que ningún modelo la
lea**:

```
artifacts/<run_id>/
    stdout.txt      stderr.txt      out/      manifest.json
```

**La cadena de custodia se cierra en el instante en que la herramienta
termina**, no cuando un modelo interpreta la salida. De ahí se siguen dos cosas:

- El agente puede leer trozos, resumir o equivocarse: el original no se toca.
- Cualquier agente futuro puede reprocesar el mismo material sin romper nada.

Las siete propiedades innegociables (RC-1 … RC-7):

1. SHA-256 de la evidencia al ingestar, antes de leerla.
2. Evidencia en solo lectura para todo lo que la procese.
3. Registro por ejecución: `argv` literal, versión real de la herramienta,
   `exit_code`, hash de `stdout` y `stderr`, timestamp UTC.
4. Registros encadenados por hash.
5. Salida cruda persistida y direccionable por `run_id`.
6. Rutas confinadas al directorio del caso.
7. Leer la salida más tarde no afecta a la cadena.

Son ~150 líneas. El valor no está en el código: está en saber qué propiedades no
se pueden perder.

---

## 8. El modelo

### Intercambiable sin tocar código

El nombre del modelo se lee de configuración en cada petición. Los Modelfiles
viven versionados en `modelos/`. Probar otro es cambiar un valor, no editar
fuentes — requisito para comparar varios y quedarse con el mejor.

### Razonamiento acotado

Se admite que razone: se busca que las interacciones tengan sentido. Pero
**acotado, y el backend lo controla desde la propia llamada** (`think`,
`num_predict` u opción equivalente).

Esta es una capacidad nueva: el motor actual manda solo `model`, `prompt`,
`stream` y `temperature`, así que **padece** el razonamiento por defecto sin
poder tocarlo. Medido: `qwen3:4b` gastó 2.357 tokens y 351 s respondiendo a un
prompt de 34 tokens. Con la palanca en la mano, ese presupuesto se mide y se
fija por paso.

### La ventana

Ya no se fija a priori. Con prompts de ~1.250 tokens sobra con poco, y lo que
sobre en ventana se paga en KV cache — RAM que en 8 GB no sobra. Se ajusta con
el tamaño real que salga del spike.

---

## 9. Conmutación desde la web

Requisitos RF-6 … RF-9: elegir el modo cambia el backend, sin reiniciar nada.

Los dos backends **conviven levantados** y el nginx del servicio `web` los
publica bajo prefijos distintos:

```
/api/         →  api            (motor agéntico actual)
/api-local/   →  local-fit-llm  (motor nuevo)
```

La web mantiene el prefijo activo como estado de sesión. Elegir el modo local
cambia el prefijo y nada más: sin reinicio, sin editar ficheros, sin recargar.
Y la UI **muestra en todo momento cuál está atendiendo**, para que el operador
no tenga que deducirlo.

Ventaja de tener los dos vivos: se puede comparar el mismo caso en ambos motores
sin levantar y bajar servicios.

---

## 10. Qué se conserva del sistema actual

### Los maletines, tal cual

Son la parte cara: PPA GIFT, plaso, sleuthkit, volatility3, .NET 9, EZ Tools,
hayabusa, chainsaw. Su `exec_agent.py` ya es un servicio HTTP autónomo:

```
GET  /health    ·  GET  /versions  ·  POST /which  ·  POST /exec
```

Cualquier motor puede accionarlos. No se toca nada.

### AVISO: el maletín no sabe construir el argv

Es un ejecutor tonto: recibe un `argv` y lo corre. **La lógica que construye ese
argv son 38 ficheros del lado del `api`**, no del contenedor. Y encodifica
hallazgos que no se adivinan, salidos de self-tests:

- `bstrings` en Linux consume por **stdin**; sus modos `-f`/`-d` no funcionan.
- `PECmd` y `SrumECmd` **no arrancan** en Linux.
- `hayabusa` requiere el build **musl**: el gnu exige glibc ≥ 2.38.
- Los entrypoints de `python-evtx` vienen **rotos** en el wheel de PyPI.
- `ewfmount` debe venir de GIFT, no del `ewf-tools` de Ubuntu.

Como ahora el agente elige libremente, **no se sabe de antemano qué subconjunto
hace falta**. Estrategia: portar primero los de la ruta más probable en
`kind=memory` —`file_info`, `strings_head`, `xxd_head`, `volatility3`,
`bulk_extractor`, `hashdeep`— y ampliar según lo que el agente pida de verdad en
el spike. Lo que no esté portado debe fallar con un mensaje claro, nunca en
silencio.

Todo lo demás es nuevo.

---

## 11. Estructura

```
agentopsy-local-fit-llm/
    runner.py        el bucle ReAct
    maletin.py       cliente HTTP del maletín
    herramientas/    forenses (argv) + de contexto (§3.2)
    memoria/         camino A y camino B tras la misma interfaz
    custodia/        las 7 propiedades
    artefactos/      escritura y lectura de artifacts/<run_id>/
    modelos/         Modelfiles versionados, intercambiables
    api.py           HTTP para la web
```

Un solo agente en la primera versión (RA-11). La arquitectura admite repartir
funciones entre varios después, si la medición lo justifica — no necesariamente
dos.

---

## 12. Riesgos

- **El agente elige mal la herramienta.** Es el riesgo de devolverle la agencia.
  Mitigación: prompts cortos (la prueba B demuestra que así acierta), errores de
  herramienta devueltos con texto accionable, y la lista de tareas obligándole a
  descomponer en vez de improvisar. **A medir en el spike.**
- **Razonar se come el presupuesto de tiempo.** Mitigación: el backend acota
  desde la llamada. **A medir.**
- **El agente se pierde entre pasos.** Es lo que atacan la lista de tareas y los
  dos caminos de memoria. **A medir.**
- **Un wrapper que falta corta la investigación.** Mitigación: fallo explícito
  con el nombre de lo que falta, nunca silencioso.

---

## 13. Validación

En orden. No dar nada por bueno sin medir.

1. **Bucle mínimo**: un agente, camino de memoria A, los seis wrappers de la
   ruta probable, contra el volcado de referencia. Sin UI, sin custodia.
2. **Medir reloj de pared de una respuesta.** Objetivo **< 10 min**, deseable
   **< 5**. *Este es el criterio que decide.*
3. **Medir si el agente mantiene el hilo**: en el paso N, ¿sabe qué hizo antes y
   qué le queda?
4. **Comparar camino A contra camino B** (§6) con las mismas condiciones.
5. **Comparar modelos** con el ganador de 4.
6. **Contar hallazgos** frente a la corrida de referencia, para poner número al
   criterio de aceptación 5, que hoy no lo tiene.
7. Solo entonces: custodia completa, servicio HTTP, conmutación desde la web.

---

## Anexo — de dónde salen las cifras

Todas en [`NOTAS-BUILD.md`](NOTAS-BUILD.md):

| dato | sección |
|---|---|
| 4,7 tok/s, contexto truncado | «Pruebas Ollama» |
| comparativa 4B / 7B / sonnet | «¿Qué modelo local podría completar un análisis?» |
| 70.543 chars, recorte a 8.194, A/B de posición | «Prueba B» |
| 19 iteraciones, 20 hallazgos, 10 tool_run | «Prueba con ejecutor de nube» |
