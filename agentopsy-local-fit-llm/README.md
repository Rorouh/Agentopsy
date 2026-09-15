# agentopsy-local-fit-llm

Motor de análisis alternativo para equipos de **8 GB de RAM sin GPU**. Convive
con el servicio `api` (motor agéntico) y lo sustituye cuando el operador elige
el modo local en la web. Los maletines forenses se conservan tal cual y se
accionan por HTTP.

Requisitos: [`../REQUISITOS-local-fit-llm.md`](../REQUISITOS-local-fit-llm.md).
Diseño: [`../DISENO-local-fit-llm.md`](../DISENO-local-fit-llm.md).

## Qué hace

Dos agentes sobre el mismo modelo local, un paso por llamada:

- **Investigador**: identifica la evidencia, ejecuta herramientas, lee sus
  salidas a trozos y registra hallazgos con su justificación, el `run_id` que
  los sostiene y la **línea literal** de esa salida que los sostiene (ver *La
  cita*, más abajo). Escribe y mantiene su propia lista de tareas.
- **Revisor**: lee lo reunido (tareas, hallazgos, artefactos, informe) y o
  aprueba y redacta la respuesta al perito, o devuelve órdenes cortas del tipo
  «revisa X con la herramienta Y», que vuelven al investigador como objetivo.

Cada llamada al modelo recibe un prompt pequeño (identidad, tareas, último
resultado acotado, firmas de herramientas, punteros del caso, lo que pidió el
perito). Nunca la conversación entera, nunca el catálogo completo, nunca un
artefacto sin haberlo pedido. El sistema comprueba que cabe en la ventana
**antes** de enviar.

## Estructura

| ruta | qué es |
|---|---|
| `runner.py` | el bucle: un turno del perito, investigador → revisor → órdenes → respuesta |
| `investigador.py` · `revisor.py` | los dos agentes: prompt de cada paso y lectura de su JSON |
| `ordenes.py` | qué orden del revisor es ejecutable, validada contra las firmas que ve el modelo |
| `relojes.py` | el trabajo real del turno y lo que la máquina durmió en medio, por separado |
| `agentes/*.md` | la identidad de cada agente (corta: la pericia va en el modelo) |
| `herramientas/forenses.py` | las seis herramientas portadas: argv desde parámetros tipados |
| `herramientas/contexto.py` | ver/escribir tareas, listar/leer artefactos, buscar, catálogo, hallazgos |
| `herramientas/ejecutor.py` | ejecuta una herramienta en el maletín con toda la custodia |
| `maletin.py` | cliente HTTP de `exec_agent.py` (`/health`, `/versions`, `/which`, `/exec`) |
| `memoria/` | camino A (`estructurada`) y camino B (`embeddings`) tras la misma interfaz |
| `custodia/` | ingesta con hash, registro encadenado, confinamiento de rutas |
| `artefactos/` | `artifacts/<run_id>/{stdout.txt, stderr.txt, out/, manifest.json}` |
| `estado.py` | lista de tareas, pasos y rondas por sesión (`agente/<sesion>/estado.json`) |
| `hallazgos.py` · `chats.py` · `casos.py` | los mismos ficheros y formatos que el api |
| `modelo.py` | cliente de Ollama: ventana garantizada, `think` y `num_predict` acotados |
| `configuracion.py` | entorno y `config.json`, releídos en cada petición |
| `api.py` · `trabajos.py` | HTTP bajo `/api-local/` para la web; jobs en segundo plano |
| `cli.py` | probar y medir sin la web |
| `modelos/` | Modelfiles versionados |
| `tests/` | bucle con modelo con guion, custodia, memoria, HTTP |

## Herramientas portadas

`file_info`, `xxd_head`, `strings_head`, `volatility3`, `bulk_extractor`,
`hashdeep`. Una herramienta del catálogo que no esté portada falla con su
nombre y la lista de las portadas, nunca en silencio. El modelo nunca escribe
rutas: la evidencia y el directorio de salida los inyecta el sistema.

## La terminal del maletín (opt-in)

`LOCALFIT_SHELL=true` añade una herramienta más: `shell(comando)`, una terminal
dentro del maletín forense. El agente escribe la orden que quiera (`grep`, `awk`,
`python3`, tuberías) con `$EVIDENCIA` apuntando a la evidencia en **solo lectura**
y `$OUT` como directorio de trabajo, que es el `out/` de esa ejecución.

Todo lo demás no cambia: el `argv` literal (`bash -lc ...`) va al registro
encadenado, la versión real del binario se le pregunta al propio maletín, el
`stdout` se sella y se hashea, y los ficheros que cree en `$OUT` se hashean uno a
uno como los de cualquier herramienta.

**Está apagada por defecto y con motivo.** Da la vuelta a dos reglas del repo: el
modelo deja de emitir un id de herramienta con parámetros tipados para emitir una
orden (SECURITY INVARIANT 5), y aparece un intérprete de comandos donde el diseño
decía que no había ninguno (SECURITY INVARIANT 4). La evidencia es dato hostil:
una cadena dentro del volcado puede intentar que el modelo ejecute algo, y con la
terminal encendida ese algo corre de verdad dentro del maletín, que tiene red
hacia el resto del compose. El contenedor es el sandbox, no el host, pero el
salto de un caso real a un `curl` de salida existe. Enciéndela para trabajar
rápido sobre evidencia propia; apágala para instruir un caso ajeno.

## Custodia

Las siete propiedades de RC-1 a RC-7, verificables releyendo `audit.jsonl`
(mismo formato encadenado que el api, así su timeline lo lee):

- SHA-256 de la evidencia al ingestar, antes de cualquier lectura; solo lectura
  (montaje `:ro` en el compose y `chmod 0444`).
- Por ejecución: `tool_run_start` con el argv literal y la versión real del
  maletín; `tool_run_finish` con exit code, hash de stdout y stderr y timestamp
  UTC. La cadena se cierra ahí: leer la salida después no la toca.
- Salida cruda persistida y direccionable por `run_id`; toda ruta confinada al
  caso o a la bandeja.
- Además: `model_call` por cada llamada al modelo (hash del prompt, tokens,
  segundos), `finding_recorded`, `reviewer_order`, `agent_turn_start/finish`.

## Configuración

Entorno o `AGENTOPSY_HOME/config.json` (entorno manda). Se relee en cada
petición: cambiar de modelo o de camino de memoria no exige reiniciar.

| clave | qué |
|---|---|
| `AGENTOPSY_HOME`, `AGENTOPSY_EVIDENCE_DIR` | los mismos directorios que el api |
| `LOCALFIT_HOME_MALETIN`, `LOCALFIT_EVIDENCE_DIR_MALETIN` | cómo ve el maletín esos directorios (compose: `/cases`, `/evidence`) |
| `AGENTOPSY_TOOLKIT_UNIX_URL`, `AGENTOPSY_TOOLKIT_WINDOWS_URL`, `OLLAMA_HOST` | servicios |
| `LOCALFIT_MODEL` | modelo Ollama; se elige en la web y queda en `config.json` |
| `LOCALFIT_MEMORIA` | `estructurada` (por defecto) o `embeddings` (+ `LOCALFIT_EMBED_MODEL`) |
| `LOCALFIT_NUM_CTX`, `LOCALFIT_NUM_PREDICT`, `LOCALFIT_NUM_PREDICT_REVISOR`, `LOCALFIT_THINK` | ventana y razonamiento |
| `LOCALFIT_MAX_PASOS`, `LOCALFIT_MAX_PASOS_ORDEN`, `LOCALFIT_MAX_RONDAS_REVISION` | presupuesto del bucle |

Ver `.env.example`.

## Probar sin la web

```
python -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
.venv/bin/python -m pytest -q tests
set -a; . .env; set +a
.venv/bin/python cli.py capacidades
.venv/bin/python cli.py caso "mi caso" "perito"
.venv/bin/python cli.py ingestar <case_id> memdump.mem memory --os-profile windows
.venv/bin/python cli.py turno <case_id> <evidence_id> "Analiza la evidencia y dime qué pasó"
.venv/bin/python cli.py estado <case_id>
.venv/bin/python cli.py verificar <case_id>
```

`turno` imprime cada paso según ocurre y, al final, las métricas (pasos,
llamadas al modelo, tokens, segundos): son los números del spike.

## Desde la web

El compose levanta `local-fit-llm` junto al `api`; nginx lo publica bajo
`/api-local/`. En el chat, el selector de ejecutor ofrece **Local fit LLM**:
elegirlo cambia el backend al que habla el chat (y la cabecera lo muestra en
todo momento); elegir cualquier otro ejecutor vuelve al `api`. Casos, evidencia
y hallazgos son los mismos ficheros para los dos motores.

El modelo se elige en el mismo selector (lista los instalados en Ollama) y se
guarda como `LOCALFIT_MODEL` en `projects/config.json`. Si el compose fija
`LOCALFIT_MODEL` por entorno, manda el entorno y el motor lo dice.

## Reparto de trabajo entre los dos agentes

`LOCALFIT_REPARTO=revisor` (por defecto): el revisor descompone la pregunta del
perito en 2-4 órdenes concretas («busca Administrator en el run de strings con
la herramienta buscar») y el investigador ejecuta cada una en
`LOCALFIT_MAX_PASOS_ORDEN` pasos; después el revisor aprueba o da órdenes
nuevas (`LOCALFIT_MAX_RONDAS_REVISION`). Las órdenes son la lista de tareas que
el operador ve. `LOCALFIT_REPARTO=investigador`: el investigador trabaja libre
sobre la pregunta y el revisor solo interviene al final. El revisor puede correr
en otro modelo (`LOCALFIT_MODEL_REVISOR`), por ejemplo un 7B planificando y un
3B ejecutando.

### Una orden tiene que poder ejecutarse

Una orden es prosa, y hasta el 2026-09-13 lo único que se comprobaba era que el
nombre de la herramienta existiera. `ordenes.motivo_inejecutable` descarta además
dos formas que el investigador no puede cumplir, las dos medidas en la misma
corrida (traza `01a09bcb`), que entre ellas consumieron el turno sin responder:

- **Un parámetro que la herramienta nombrada no tiene**: «usa la herramienta
  `strings_head` con consulta: 'Administrator'|'WIN-'». `consulta` es de `buscar`;
  `strings_head` no filtra. La regla, enunciada: **un parámetro nombrado en la orden
  tiene que pertenecer a alguna herramienta nombrada en esa misma orden**. Así la
  forma correcta del patrón de dos pasos sigue siendo válida, porque ahí `consulta`
  va con `buscar`, que está nombrada.
- **Una herramienta de contabilidad como orden**: «usa la herramienta `ver_tareas`».
  `buscar`, `leer_artefacto` y `listar_artefactos` sí valen: operan sobre las salidas.

La orden inválida se descarta y se audita (`reviewer_order_discarded`); **no se
reescribe** en lo que el revisor quizá quiso decir, que sería inventar un plan que
nadie escribió (RULE 2). Para que el plan no encoja por esto, el formato del plan
enuncia el patrón: si hay que localizar algo dentro del resultado de una
herramienta, son DOS órdenes.

La tabla de parámetros se deriva de las MISMAS firmas que se le ponen delante al
modelo, así que una firma que cambie arrastra la validación y no hay una segunda
lista que mantener a mano.

### La fecha del hallazgo, y por qué no se exige

`observado_en` es la marca del ARTEFACTO: cuándo ocurrió el hecho en el equipo
investigado, no cuándo lo registró el agente. Sin ella el hallazgo **no entra en la
cronología del incidente** (`backend/agentopsy/timeline/hallazgos.py`), que es la
línea que un tercero lee primero; el backend los cuenta y los declara, nunca los
tira en silencio, y la SPA los pinta como «sin fecha».

No se exige, y es deliberado: un valor de registro o una cadena en memoria no tienen
hora, y pedirla siempre sería pedir que se invente una. Lo que sí se hace es decir la
consecuencia en la firma, y **avisar solo cuando el material que el agente tiene
delante lleva fecha** (`_FECHA_RE` en `investigador.py`). Esa expresión pide año, mes,
día Y hora a propósito: un `20150902` suelto no cuenta, porque en este mismo caso vive
dentro de `sqlmap/1.0-dev-nongit-20150902` y no es la hora de nada.

### Una orden abandonada no figura como cumplida

El investigador puede cerrar una orden con `informar` diciendo que no se puede
cumplir. Si la cierra **sin haber ejecutado nada**, la tarea se marca `descartada`,
no `hecha`, se audita (`reviewer_order_abandoned`) y el informe que lee el revisor
dice «NO EJECUTADA» con lo que el investigador alegó. Antes se marcaba `hecha` igual
que una orden cumplida: el 2026-09-13 el revisor aprobó un turno creyendo que se
habían ejecutado dos órdenes cuando solo se ejecutó una.

El turno está expresado como grafo de LangGraph (`grafo.py`): planificar →
investigar → revisar → (fin | investigar). Los nodos son métodos de
`runner.Corrida`.

## Lo que el motor le pone fácil a un modelo pequeño

Un 3B acierta el formato de la llamada, pero se queda atascado si el sistema no le
quita del camino lo que no puede resolver. Medido y corregido:

- **Una herramienta que ya no sirve deja de ofrecerse.** Las de una sola vez ya
  ejecutadas y las que fallaron por una causa estructural (Volatility sin tabla de
  símbolos para este volcado) se retiran de la lista con su motivo, en vez de
  pedirle que se acuerde de no repetirlas.
- **La misma llamada con los mismos argumentos no se repite**, ni forense ni de
  contexto: se le devuelve lo que dio la vez anterior y se le pide el paso siguiente.
- **Una errata en el nombre se corrige** (`lee_artefacto` por `leer_artefacto`):
  cada paso cuesta entre 20 y 90 segundos, y no se gastan en deletrear.
- **`buscar` es literal, y varios términos se separan con `|` o coma**: el modelo
  escribe «Administrator|WIN-» esperando alternativas y antes eso devolvía cero.
  Una consulta sin letras ni dígitos se rechaza antes de gastar el paso.
- **La determinación pericial se le pone delante.** El crudo se sella siempre al
  terminar la herramienta; en cuanto hay una salida sin calificar, la instrucción
  final le pide decidir: registrar hallazgo citando el `run_id` **y la línea que
  lo sostiene**, o marcarlo como `descarte`. El revisor nunca decide qué es un
  hallazgo.

### La cita: un hallazgo se sostiene en una línea LEÍDA

Un hallazgo afirmativo no se registra sin `cita`: el texto literal de la salida
que lo sostiene. Se comprueban dos cosas, las dos deterministas:

1. **Que la cita esté en el artefacto sellado** del `run_id` que dice sostenerlo
   (`hallazgos.py`, en streaming: un `stdout.txt` puede pesar decenas de MB).
2. **Que el agente la haya leído** en este turno, es decir que aparezca en algo
   que se le puso delante (`estado.py`, registro de lecturas; la comprobación en
   `herramientas/contexto.py`, que es quien tiene el estado).

Por qué las dos. La regla anterior exigía `run_id` y comprobaba que ese run
existiera, lo cual impide citar una ejecución inventada pero no impide concluir
sobre una ejecución que no se ha leído. El 2026-09-13 un 3B registró «Usuario
Administrador detectado en memoria» citando un `strings_head` legítimo del que
solo había visto 25 líneas de 3.168.635, todas del sector de arranque. La
afirmación era **cierta** (la cadena estaba en la línea 14.795), pero el modelo
no la había leído: la copió del ejemplo de su propio prompt y acertó por
coincidencia. Un acierto sin lectura no se puede defender ante un tercero, y el
mismo mecanismo con otro ejemplo produce un hallazgo falso idéntico por fuera.

Un `descarte` queda exento: deja constancia de que una vía no aportó y no hay
línea que señalar. La cita viaja con el hallazgo hasta la vista de Hallazgos y
el informe, para que se compruebe de un vistazo.

**Lo que esto no garantiza**, y conviene tenerlo escrito: que la inferencia a
partir de la línea citada sea correcta. Eso es criterio, y el criterio es del
modelo. Lo que cambia es que una inferencia equivocada queda a la vista, porque
la línea que la sostiene viaja pegada al hallazgo.
- **La puerta de «esta orden no se puede cumplir» se abre en el segundo paso**, no
  en el primero: ofrecida antes, el modelo la tomaba sin intentar nada.

## Medir un turno sin que la suspensión mienta

`segundos_total` mide con `time.monotonic()`, que en Linux **no avanza mientras la
máquina está suspendida**: es trabajo real. La traza de LangSmith no: fecha el span con
reloj de pared, que sí cuenta el sueño. El 2026-09-13 eso hizo que un turno de ~286 s
figurara como **1374 s**, con una llamada al modelo aparentemente de 1107 s que en
realidad duró 20,42 s según el `print_timing` de llama.cpp.

`relojes.Cronometro` lo convierte en un dato del turno en lugar de una comprobación que
alguien tiene que acordarse de hacer: `CLOCK_BOOTTIME` menos `CLOCK_MONOTONIC` es
exactamente el tiempo dormido. Va a tres sitios:

- `metricas["segundos_suspendido"]`, y de ahí al `agent_turn_finish` del audit log.
- Los metadatos del span raíz de LangSmith (`segundos_reales` y `segundos_suspendido`),
  para poder corregir la duración sin salir de la traza.
- La tabla de `medir.py`, que avisa cuando la corrida cruzó una suspensión.

Fuera de Linux no hay `CLOCK_BOOTTIME` y el valor es `None`, no `0`: no saber cuánto ha
dormido la máquina no es lo mismo que saber que no ha dormido (RULE 2). `medir.py`
también lo dice en ese caso.

## Observabilidad (LangSmith)

Opt-in. Con estas variables el motor traza cada turno en LangSmith (`trazas.py`):

```
LANGSMITH_TRACING=true
LANGSMITH_API_KEY=...
LANGSMITH_PROJECT=agentopsy-local-fit-llm
# LANGSMITH_ENDPOINT=https://mi-langsmith/   # instancia propia
```

Jerarquía: turno → LangGraph → planificar / investigar / revisar → pasos del
investigador → llamadas `ollama.chat` (con tokens de entrada y salida) y
herramientas (forenses y de contexto, con sus argumentos y resúmenes).
Consultar desde la terminal con la CLI (`langsmith trace list --project
agentopsy-local-fit-llm --show-hierarchy`).

Aviso: con las trazas activas, los prompts y los resúmenes de las salidas de
las herramientas (contenido derivado de la evidencia) salen hacia el LangSmith
configurado. Sin las variables no se envía nada. Para un caso real, usar una
instancia autoalojada o dejarlo apagado: es la excepción explícita al
principio de «sin llamadas a la nube» del repo, y la activa el operador.

## HTTP

Bajo `/api-local/`: `session`, `health`, `capabilities`, `models`, `config`,
`cases` (listar, crear, ver, `os-profile`, `evidence/ingest`, `evidence`,
`evidence/{id}/verify`, `findings`, `artifacts`, `artifacts/{run_id}`,
`audit/verify`, `agent/state/{sesion}`, `chats/...`, `agent/jobs`),
`agent/query`, `agent/query/stream` (NDJSON), `agent/analyze`,
`agent/jobs/{id}`, `agent/jobs/{id}/cancel`, `agents`.

Eventos de progreso: los del api (`reasoning`, `tool_call`, `tool_result`,
`finding`, `final`, `done`, `error`) más `tareas`, `revision` y `orden`.
