# Agentopsy `local-fit-llm` — documento de diseño

**Estado**: propuesta, sin implementar. **Fecha**: 2026-09-08.
**Origen**: las mediciones de [`NOTAS-BUILD.md`](NOTAS-BUILD.md), § «Pruebas Ollama»,
«¿Qué modelo local podría completar un análisis?» y «Prueba B».

---

## 1. Objetivo

Un modo de ejecución que corra un análisis forense **básico y completo** en un
equipo de **8 GB de RAM totales, sin GPU** (referencia: MacBook Intel), en
minutos y no en horas.

«Básico» quiere decir: identificar la evidencia, ejecutar el conjunto de
herramientas que corresponde a su tipo, razonar sobre la salida y producir
hallazgos con cadena de custodia intacta. No quiere decir la investigación
adaptativa que hace un modelo de frontera.

Es un **modo alternativo**, elegido explícitamente por el operador
(«local model on reduced RAM»), no un reemplazo del camino agéntico.

---

## 2. Por qué el diseño actual no llega

No es una cuestión de elegir mejor modelo. Las tres explicaciones que se
barajaron —capacidad del modelo, ventana de contexto, cuantización— quedaron
descartadas por medición. El problema es **el tamaño del prompt y su reenvío**.

### Las cifras

Medido sobre un i7-1260P (16 hilos, DDR5, sin GPU aprovechable), que es
**más rápido** que la máquina objetivo:

| magnitud | valor |
|---|---|
| prompt del agente | 70.543 chars ≈ **17.846 tokens** |
| prefill en CPU (7B Q4) | **9,7 tokens/s** |
| coste de leer el prompt | **~30 min por llamada** |
| generación (7B Q4) | 5,6 tokens/s |
| generación (3B Q4) | 15,5 tokens/s |

Y el prompt **se reenvía entero en cada iteración**. El propio texto del agente
lo dice: *«Every turn re-sends the whole conversation»*.

### El presupuesto real de una investigación

Un análisis completo de un volcado de RAM con Claude Code (sonnet) consumió
**19 iteraciones**. Trasladado a local:

```
19 iteraciones × ~18.000 tokens reenviados ≈ 340.000 tokens de prefill
340.000 / 9,7 tok/s                        ≈ 9,7 HORAS solo leyendo
```

Ese es el muro. No lo mueve una cuantización mejor ni un modelo más listo.

### Los efectos secundarios ya observados

Con ventana de 16.384, Ollama recorta el prompt de entrada a la mitad
(8.194 tokens) **conservando la cola**. Consecuencias medidas:

- El playbook —que está al 16 % del prompt— **desaparece**. La instrucción
  «empieza por `file_info`, siempre» nunca llega al modelo.
- Lo último que el modelo lee es un ejemplo que menciona «mmls plus fls». El
  modelo emitió `mmls` y `fls`. Obedeció lo único que le llegó.
- El formato también se degrada: con el prompt recortado devolvió JSON
  malformado (`{{"action"...}}`); con el prompt completo, JSON limpio.
- **Nada avisa de ello.** Ni el chat, ni el audit log, ni la UI.

Conclusión: un prompt que no cabe no falla, **miente en silencio**.

---

## 3. Arquitectura propuesta

Dos ideas, y ambas atacan el reenvío, no el modelo.

### 3.1 El plan va en código

En vez de entregar al modelo un playbook de 17.000 tokens y pedirle que decida,
el flujo es una **máquina de estados por tipo de evidencia**:

```
kind=memory:
    file_info                       (determinista, sin LLM)
    ├─ ¿reconoce formato de volcado?   → volatility3
    └─ no                              → strings_head + bulk_extractor + xxd_head
```

El LLM no elige herramientas: **responde preguntas cerradas** y el código
traduce la respuesta a la siguiente ejecución.

Consecuencia estructural: **desaparecen las llamadas malformadas**. El modelo
nunca emite un `tool_id` ni un objeto de parámetros, así que no puede mandar
`doc_id: ''` ni inventar una herramienta. Es imposible por construcción, no por
validación.

### 3.2 Dos agentes con funciones separadas

| | agente **conductor** | agente **analista** |
|---|---|---|
| trabajo | decidir el siguiente paso del plan | razonar sobre la salida cruda |
| prompt | 300-800 tokens | los artefactos, leídos una vez |
| salida | una palabra, un número, una rama | hallazgos y narrativa |
| sensible a | **latencia** | **calidad** |
| modelo | 3B rápido, local | el que se quiera |
| cuándo | en línea, durante la recolección | **puede ir en diferido** |

La clave: **el agente analista no tiene que correr ni a la vez ni en la misma
máquina**. Puede ejecutarse por lotes, más tarde, o directamente en un ejecutor
de nube. Se separa lo que debe ser rápido de lo que debe ser bueno.

### 3.3 Los artefactos crudos son la interfaz

Es lo que hace que la separación sea segura, y ya funciona así hoy. Cada
ejecución deja:

```
artifacts/<run_id>/
    stdout.txt      stderr.txt      out/      manifest.json
```

y el registro de auditoría guarda `stdout_sha256`, `stderr_sha256`,
`tool_version`, `exit_code` y `baseline_sha256`, encadenados por hash.

**La cadena de custodia se cierra en el instante en que la herramienta corre**,
no cuando un modelo lee la salida. Por eso un segundo agente que itere sobre
esos artefactos horas después no rompe nada: consume material ya sellado.

### 3.4 Presupuesto de cómputo resultante

```
ACTUAL
  19 iteraciones × 18.000 tokens reenviados   ≈ 340.000 tokens

PROPUESTO
  conductor: ~15 pasos × 500 tokens           =    7.500
  analista:  artefactos leídos una vez        ≈   25.000
                                                 ────────
                                                  ~32.500
```

**~11× menos.** Y no viene de un modelo mejor: viene de dejar de reenviar la
conversación entera en cada vuelta.

Con eso, un análisis básico pasa del orden de horas al orden de **20-30
minutos**, y cabe en 8 GB.

### 3.5 La arista de vuelta

Un corte estricto en dos fases —recolectar todo, luego razonar— pierde el
hallazgo dirigido. En la corrida de referencia, el analista encontró un dato
clave en el offset `452706110` porque leyó unas cadenas y **volvió** a lanzar
`xxd` en ese punto exacto.

Por eso el agente analista debe poder **encolar ejecuciones** para el conductor.
Sigue saliendo barato, porque la mayoría de las vueltas son las del conductor,
que cuestan 500 tokens.

---

## 4. Qué se conserva y qué se rehace

### Se conserva: los maletines

Las imágenes `toolkit-windows` y `toolkit-unix` son la parte cara: PPA GIFT,
plaso, sleuthkit, volatility3, .NET 9, EZ Tools, hayabusa, chainsaw. Varios GB
de build y muchas incompatibilidades ya resueltas.

Su `exec_agent.py` es un servicio HTTP autónomo en la red del compose:

```
GET  /health      ¿vivo? (+ stage)
GET  /versions    manifiesto inmutable de versiones
POST /which       ¿existen estos binarios?
POST /exec        ejecuta este argv
```

Cualquier motor, en cualquier lenguaje, puede accionarlos.

### AVISO: el maletín no sabe construir el argv

Es un ejecutor tonto: recibe un argv y lo corre. **La lógica que construye ese
argv vive en `backend/agentopsy/toolkit/wrappers/` — 38 ficheros — del lado del
`api`, no del contenedor.**

Y no es código trivial de rehacer, porque encodifica hallazgos que no se
adivinan y que salieron de self-tests:

- `bstrings` en Linux consume el fichero **por stdin**; sus modos `-f`/`-d` no
  funcionan fuera de Windows.
- `PECmd` y `SrumECmd` **no arrancan** en Linux (necesitan ntdll/ESENT).
- `hayabusa` requiere el build **musl**: el gnu exige glibc ≥ 2.38 y la base es
  Ubuntu 22.04.
- Los entrypoints de `python-evtx` vienen **rotos** en el wheel de PyPI.
- `ewfmount` debe venir de GIFT, no del `ewf-tools` de Ubuntu.

**Recomendación**: portar **solo los wrappers que el plan use**. Para `kind=memory`
son seis:

```
file_info · strings_head · xxd_head · volatility3 · bulk_extractor · hashdeep
```

Portar seis es una tarde. Redescubrir 38 a base de fallos son meses.

### Se rehace: todo lo demás

Bucle de agente, ensamblado de prompts, catálogo en el prompt, selección de
herramientas, almacenamiento y API.

### La custodia se rehace, y es barato

No es un módulo que haya que rescatar: es un conjunto de **propiedades**, unas
150 líneas. Estas son las que no se pueden perder:

1. **SHA-256 de la evidencia al ingestar** (baseline), antes de tocarla.
2. **Evidencia montada en solo lectura** para todo lo que la lea.
3. **Un registro por ejecución** con: `argv` literal, versión real de la
   herramienta, `exit_code`, hash de stdout y de stderr, timestamp UTC.
4. **Encadenado por hash**: cada registro incluye el hash del anterior.
5. **Salida cruda persistida** en `artifacts/<run_id>/`, direccionable.
6. **Rutas confinadas**: ningún parámetro puede salir del directorio del caso.

El valor nunca estuvo en el código. Estuvo en saber qué propiedades importan.

---

## 5. El modelo

No hace falta afinar nada. Un **Modelfile versionado en el repo** sobre
`qwen2.5:3b-instruct` basta:

```
FROM qwen2.5:3b-instruct
PARAMETER num_ctx 4096
```

Dos notas de las mediciones:

- Con preguntas de 300-800 tokens, **`num_ctx 4096` sobra**. Frente a los 16384
  que hacían falta con el prompt monolítico, son ~1 GB menos de KV cache — y es
  justo lo que compra caber en 8 GB.
- **Nada de modelos *thinking***. `qwen3:4b` razona por defecto y gastó 2.357
  tokens para responder una frase (351 s). No se puede desactivar desde el
  Modelfile: `PARAMETER think false` no existe y `/no_think` en el `SYSTEM` no
  surte efecto. Un instruct puro es obligatorio.

Afinar un modelo sí atacaría el problema de raíz —formato y catálogo pasarían a
los pesos en vez del prompt— pero es un proyecto aparte (dataset, GPU,
iteración). El andamio da la mayor parte del beneficio por una fracción del
esfuerzo. **Después, si acaso.**

---

## 6. Forma del servicio

Sustituye al servicio `api` cuando el operador elige el modo reducido:

```
agentopsy-local-fit-llm/
    planes/         memoria.py · disco.py · documento.py    ← el plan, en código
    preguntas/      las consultas cortas al modelo
    wrappers/       los 6 portados: argv + inyección de rutas
    custodia/       las 6 propiedades del § 4
    artefactos/     escritura y lectura de artifacts/<run_id>/
    runner.py       conductor: ejecuta → pregunta → ramifica
    analista.py     segundo agente: itera sobre los artefactos
    modelo/         Modelfile
```

Habla con los maletines por HTTP, igual que hoy. Los maletines no se enteran de
qué motor los acciona.

---

## 7. Qué se pierde

Hay que asumirlo por escrito, porque es real:

- **La investigación adaptativa.** Un motor guiado encuentra lo que su plan
  busca. El informe de referencia fue bueno porque el modelo *decidió* mirar un
  offset concreto que nadie le había dicho que mirara. La arista de vuelta
  (§ 3.5) recupera parte, no todo.
- **Un segundo comportamiento que mantener.** Hoy `agent.md` se declara «el
  ÚNICO fichero de comportamiento». Con dos motores hay dos definiciones: una en
  markdown y otra en código. Es asumible, pero debe ser una decisión consciente
  y quedar documentada, no una deriva.
- **Cobertura menor.** Seis wrappers en vez de 38. Los casos que necesiten
  herramientas fuera de ese conjunto no se cubren en modo reducido.

---

## 8. Validación antes de construir

No dar nada por bueno sin medir. El spike mínimo, en este orden:

1. **Plan de `kind=memory` en un script**, con los seis wrappers, contra un
   maletín ya levantado y el volcado de referencia. Sin UI, sin custodia.
2. **Medir reloj de pared** de un análisis básico completo. Objetivo:
   **< 30 minutos**. Si sale por encima de una hora, el diseño no cumple y hay
   que replantear antes de escribir nada más.
3. **Comparar los hallazgos** con los 20 de la corrida de referencia. No hace
   falta igualarlos: hace falta saber cuántos de los 8 críticos se conservan.
4. Solo entonces: custodia, servicio, integración y modo en la UI.

El punto 2 es el que decide. Todo lo demás es consecuencia.

---

## Anexo — de dónde salen las cifras

Todas las mediciones están en [`NOTAS-BUILD.md`](NOTAS-BUILD.md):

| dato | sección |
|---|---|
| 4,7 tok/s, contexto truncado | «Pruebas Ollama» |
| comparativa 4B / 7B / sonnet | «¿Qué modelo local podría completar un análisis?» |
| 70.543 chars, recorte a 8.194, A/B de posición | «Prueba B» |
| 19 iteraciones, 20 hallazgos, 10 tool_run | «Prueba con ejecutor de nube» |
