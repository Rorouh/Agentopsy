# Requisitos — `agentopsy-local-fit-llm`

**Estado**: borrador, revisión 2. **Fecha**: 2026-09-08.
Mediciones que los sustentan: [`NOTAS-BUILD.md`](NOTAS-BUILD.md).

Cada requisito lleva id para poder trazarlo. **DEBE** es obligatorio;
**DEBERÍA** es deseable y negociable.

> **Revisión 2 — qué cambió**: la versión anterior ponía la secuencia de
> herramientas en código («el plan lo decide el sistema»). **Se revierte**: eso
> quitaba potencial al agente. El modelo mantiene su agencia; lo que cambia es
> *cómo* se le da el contexto, no *quién* decide.

---

## 0. Objetivo

Un modo de ejecución que corra un análisis forense **básico y completo** en un
equipo de 8 GB de RAM totales sin GPU, con respuestas en minutos, conservando
intacta la cadena de custodia.

No sustituye al camino agéntico con modelo de nube: es una alternativa que el
operador elige cuando su hardware no da para el otro.

---

## 1. Funcionales (RF)

| id | requisito |
|---|---|
| **RF-1** | El sistema **DEBE** completar un análisis básico de forma autónoma: identificar la evidencia, ejecutar herramientas, razonar sobre la salida y producir hallazgos. |
| **RF-2** | **El modelo DEBE decidir qué herramientas usar y en qué orden.** El sistema no impone la secuencia: aporta el contexto y las restricciones, no el plan. |
| **RF-3** | El sistema **DEBE** razonar sobre la evidencia y producir hallazgos con su justificación, no solo volcar la salida de las herramientas. |
| **RF-4** | El sistema **DEBE** sostener una conversación: el perito pregunta, el agente responde sobre el caso y lo que ya ha averiguado. |
| **RF-5** | El operador **DEBE** poder activar este modo explícitamente. Nunca se selecciona solo. |
| **RF-6** | Al seleccionar este modo en la web, el enrutado al nuevo backend **DEBE** ser **automático y transparente**: la propia elección del modelo cambia el backend que atiende la sesión. |
| **RF-7** | El cambio **NO DEBE** exigir reiniciar servicios, editar ficheros a mano ni recargar la página. |
| **RF-8** | Los dos backends **DEBEN** poder coexistir levantados; la web decide a cuál habla según el modo activo. |
| **RF-9** | La web **DEBE** mostrar en todo momento qué backend está atendiendo. |
| **RF-10** | El sistema **DEBE** accionar los maletines forenses existentes por HTTP, sin reimplementar ninguna herramienta forense. |
| **RF-11** | El sistema **DEBERÍA** informar del progreso durante la corrida, sin esperar al final. |

## 2. Arquitectura (RA)

| id | requisito |
|---|---|
| **RA-1** | **DEBE** ser un motor distinto del agéntico, con su propio camino de ejecución. No un parámetro del actual. |
| **RA-2** | **El agente es un experto en su área.** La pericia forense **DEBE** venir con él —en el modelo o en su definición— no reinyectada como un muro de texto en cada llamada. |
| **RA-3** | **El agente DEBE decidir qué necesita y pedirlo.** El sistema le da acceso a lo que hay (evidencia, artefactos previos, hallazgos, catálogo) y él saca lo que le hace falta según lo que tiene delante. Lo contrario de recibirlo todo por si acaso. |
| **RA-4** | Ninguna llamada al modelo **DEBE** superar su ventana de contexto. El sistema **DEBE** conocer la ventana y garantizarlo **antes** de enviar, no descubrirlo después. |
| **RA-5** | El bucle **DEBE** ser ReAct y **el propio modelo DEBE crear y mantener su lista de tareas**, como hacen Antigravity y similares. El sistema **NO** le entrega un plan: le da la capacidad de escribirlo, revisarlo y marcarlo. |
| **RA-6** | Esa lista **DEBE** persistir entre llamadas y ser visible para el operador. El agente trabaja **un paso cada vez**: nada de resolver todo en una sola ventana. |
| **RA-7** | **NO DEBE** reenviarse la conversación entera en cada iteración, **y tampoco DEBE** empezarse de cero. El agente **DEBE** saber en todo momento qué está haciendo, en qué paso va y qué ha averiguado ya. |
| **RA-8** | **DEBE** existir un mecanismo de memoria/caché que sostenga RA-7: qué se recupera, cómo se resume y qué se descarta. |
| **RA-9** | **DEBEN** implementarse **dos caminos de memoria** y medirse uno contra otro: (a) **con embeddings** sobre mensajes, entradas y salidas de herramientas; (b) **sin embeddings**, con estado estructurado (lista de tareas + hallazgos + índice de artefactos). El ganador se decide con datos, no a priori. |
| **RA-10** | La salida cruda de cada ejecución (`stdout`, `stderr`, ficheros) **DEBE** persistirse tal cual antes de que ningún modelo la lea. |
| **RA-11** | **La primera versión DEBE ser un solo agente**, para validar el flujo completo: hablar por el chat, razonar sobre la evidencia, ejecutar herramientas y producir hallazgos. |
| **RA-12** | La arquitectura **DEBERÍA** admitir **más de un agente** después, con funciones repartidas. No necesariamente dos: los que hagan falta. |
| **RA-13** | La estructura del proyecto **DEBE** mantenerse simple y legible de un vistazo. |

## 3. Rendimiento (RP)

| id | requisito | umbral |
|---|---|---|
| **RP-1** | Una respuesta al perito **DEBE** llegar por debajo de este tiempo. | **< 10 min** |
| **RP-2** | Objetivo deseable de respuesta. | **< 5 min** |
| **RP-3** | El prompt de cada paso **DEBE** mantenerse pequeño; el presupuesto exacto sale del spike. | **orientativo: ≤ 1.500 tokens** |
| **RP-4** | El sistema completo —contenedores, modelo y KV cache— **DEBE** caber en la RAM del equipo objetivo. | **≤ 8 GB** |
| **RP-5** | El razonamiento del modelo **DEBE** estar acotado por paso, para que no se coma el presupuesto de tiempo. | ver **RM-2** |

**Por qué estos umbrales son alcanzables**: con prompts de ~800-1.500 tokens, un
paso cuesta del orden de 30-60 s en CPU (prefill + generación medidos). Diez
pasos entran en el objetivo. Lo que no entra es el modelo actual: 17.846 tokens
por iteración, reenviados cada vuelta, a 9,7 tokens/s de prefill.

## 4. Cadena de custodia (RC)

**Innegociables.** Sin estos, la salida no es material de expediente.

| id | requisito |
|---|---|
| **RC-1** | **DEBE** calcularse el SHA-256 de la evidencia al ingestarla, antes de cualquier lectura. |
| **RC-2** | La evidencia **DEBE** exponerse en **solo lectura** a todo lo que la procese. |
| **RC-3** | Cada ejecución **DEBE** registrar: el `argv` literal, la versión real de la herramienta, el `exit_code`, el hash de `stdout` y de `stderr`, y el timestamp UTC. |
| **RC-4** | Los registros **DEBEN** encadenarse por hash: cada uno incluye el del anterior. |
| **RC-5** | La salida cruda **DEBE** quedar persistida y direccionable por identificador de ejecución. |
| **RC-6** | Ningún parámetro de herramienta **DEBE** poder salir del directorio del caso. |
| **RC-7** | Que un agente lea la salida más tarde **NO DEBE** afectar a la cadena: se cierra cuando la herramienta termina. |

## 5. Modelo (RM)

| id | requisito |
|---|---|
| **RM-1** | El modelo **DEBE** ser rápido en CPU, sin GPU. |
| **RM-2** | Se **ADMITE** razonamiento: se busca que las interacciones tengan sentido y sean inteligentes. El presupuesto por paso **DEBE** medirse, no fijarse a priori. |
| **RM-2b** | El backend **DEBE** controlar el razonamiento desde la propia llamada (parámetro `think` u opción equivalente).<br>*(Contexto: sin control, `qwen3:4b` gastó 2.357 tokens y 351 s para responder a un prompt de 34 tokens — es su comportamiento por defecto, no contexto heredado. El motor actual no manda ese parámetro y por eso lo padece; el nuevo sí puede.)* |
| **RM-3** | El modelo **DEBE** venir definido en un fichero versionado en el repo, reproducible. |
| **RM-4** | El sistema **DEBE** permitir **cambiar de modelo sin tocar código**, para poder probar varios y quedarse con el que mejor rinda. |
| **RM-5** | El modelo **NO DEBE** necesitar afinado para la primera versión. |

## 6. Alcance (RE)

| id | requisito |
|---|---|
| **RE-1** | El entregable es el **backend `local-fit-llm` funcional y con el modelo corriendo**, de punta a punta. |
| **RE-2** | **DEBEN** probarse **varios modelos** para determinar cuál rinde mejor en este flujo. |
| **RE-3** | **DEBEN** conservarse los maletines forenses tal cual están. Todo lo demás es nuevo. |
| **RE-4** | El servicio sustituye al `api` actual cuando el modo está activo. |
| **RE-5** | Se **DEBEN** portar los wrappers de argv que el agente pueda necesitar.<br>*(Aviso: el maletín ejecuta un `argv` pero no sabe construirlo. Esa lógica son 38 ficheros del lado del `api` y encodifica hallazgos no evidentes — qué subconjunto portar es decisión abierta, ver § 7.)* |
| **RE-6** | Todo se desarrolla y prueba **en local**. |

---

## 7. Criterios de aceptación

Sobre el volcado de RAM de referencia y en el hardware objetivo:

1. **Termina** un análisis básico sin intervención. *(RF-1)*
2. **Responde en menos de 10 minutos**, idealmente menos de 5. *(RP-1, RP-2)*
3. **El modelo elige las herramientas** y las llamadas salen bien formadas. *(RF-2)*
4. **Mantiene el hilo**: en el paso N sabe qué hizo en los anteriores y qué le queda. *(RA-7)*
5. **Produce hallazgos** con justificación. El número que se considera suficiente se fija tras el spike; hoy no hay base para comprometerlo. *(RF-3)*
6. **Cumple los siete requisitos de custodia**, verificable releyendo el registro de auditoría. *(RC-1 … RC-7)*
7. **Cabe en 8 GB** con el stack completo levantado. *(RP-4)*
8. **Elegir el modo en la web enruta al backend nuevo** sin ningún paso manual, y la UI dice cuál está activo. *(RF-6 … RF-9)*

El criterio 2 es el que decide.

---

## 8. Preguntas abiertas

Lo que el spike tiene que cerrar:

1. **¿Gana el camino con embeddings o el de estado estructurado (RA-9)?** Ambos
   se implementan y se miden. A favor del estructurado: no añade otro modelo en
   RAM ni latencia por consulta. A favor de los embeddings: recupera por
   significado sobre salidas de herramientas largas. Se decide con la medición.
2. **¿Cuánto razonamiento por paso (RM-2)?** Dónde está el punto entre
   «interacciones inteligentes» y comerse el presupuesto de tiempo, ahora que el
   backend puede acotarlo desde la llamada.
3. **¿Qué modelo?** Hay medida de velocidad (3B: 15,5 tok/s; 7B: 5,6 tok/s) pero
   ninguna de calidad eligiendo herramientas con contexto corto.
4. **¿Cuántos pasos tiene un análisis básico?** De ahí sale el presupuesto real
   de tiempo, no de una estimación.
5. **¿Cuántos hallazgos conserva** frente a la corrida de referencia? Sin esto,
   el criterio 5 no tiene número.
6. **¿Qué wrappers portar?** Depende de qué herramientas acabe pidiendo el
   agente, que ya no está predeterminado.
7. **¿Cuándo entra el segundo agente (RA-11)?** Qué señal del spike indica que un
   solo agente no da.
