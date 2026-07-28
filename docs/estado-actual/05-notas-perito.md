# 05 — Notas del perito

> Documento del perito. Índice: [`README.md`](README.md).
>
> Los apartados de abajo son **semilla**: recogen lo que ya se planteó en voz alta
> durante la revisión del 2026-07-28, para que haya de dónde tirar. Todo lo demás
> lo escribe el perito.

---

## Objeciones ya planteadas (2026-07-28)

Recogidas en frío y desarrolladas en
`docs/agentes/INTERNO-revision-flujo-y-autonomia.md` (interno, no publicado). Se
resumen aquí porque este caso las ilustra en vivo.

### O1 — El enrutado determinista decide por el agente

> *«Esto me parece un fallo grande, esto debe arreglarse.»*

Lo que este caso muestra: la triage determinó `memory`/`windows` con tres
señales, ancló el perfil **automáticamente** (`decision: auto_set`) y —de haber
corrido el agente— le habría inyectado el bloque «Ruta del playbook — MEMORY
DUMP» y **borrado del prompt la rama de disco**.

Aquí acertó. La objeción no es que se equivoque: es que el agente recibe el
camino ya elegido y sin alternativa visible.

Tres ejes a separar: **determinar** (valioso, auditable) / **vincular**
(objetado) / **recortar el prompt** (lo más agresivo; se introdujo por coste de
tokens).

### O2 — El orquestador está a medias

`agentes/_orchestrator/` no es un agente: la registry lo salta por el prefijo `_`.
Sus prompts son contrato, no ejecutable. La síntesis la hace código determinista
— y en este caso no produjo nada porque no hay hallazgos.

El esquema de la propuesta (orquestador media → delega en sub-agente → consolida)
tiene la mitad del enrutado y ninguna de la síntesis.

### O3 — La autonomía hay que reanalizarla

Sin gate humano por herramienta; frenos automáticos (12 iteraciones, 3 fallos por
tool, nudge, windowing) que moldean el comportamiento por debajo de lo que se lee
en los prompts.

---

## Observaciones que salen de este caso concreto

### N1 — Subir ≠ registrar, y la UI no lo distingue

`IE11-Win7-VMWare-disk1.vmdk` se subió a la bandeja y en el primer intento se
quedó ahí. No hay evento de error ni de rechazo: simplemente no se lanzó el
registro. Desde la UI, un fichero subido y un fichero en custodia se parecen
demasiado.

*(¿Merece un aviso explícito en la UI? ¿Un estado «en bandeja, sin registrar»
visible en la vista del caso?)*

### N1.bis — El «bucle» de registro NO existía: la UI no se refresca al terminar

**Observado el 2026-07-28, 16:01-16:03.** El perito reportó que «seleccionar y
registrar entra en un bucle que no registra la evidencia». **No era un bucle: el
registro terminó correctamente y la vista no se enteró.**

Secuencia real, contrastada con el disco:

| Hora local | Qué pasaba |
|---|---|
| 16:01:08 | Barra de progreso al **74% · re-hash de la copia** (captura del perito) |
| 16:01:53 | **Registro COMPLETADO**: `baseline.json` escrito, directorio publicado con nombre UUID4 → el `os.rename` atómico se cerró |
| 16:02:42 | La UI sigue mostrando «1 fichero · 1 verificados» y la bandeja con el `.vmdk` (segunda captura) |

Evidencia resultante, en custodia y correcta:

```
cf54714e-3315-4eca-8eaf-bae0b19c0f0e
  original.vmdk · 21 931 950 080 B
  sha256 60919a3adc8450fa7e720ee68f6815d2179673c21c1844f198d7e45b38497068
  container_disk / windows · señal vmdk_sparse · confianza header
  registered_at 2026-07-28T14:01:53.260Z
```

**El fallo es de la SPA, no del backend:** al terminar el job de registro no
re-consulta `GET /api/cases/{id}/evidence` ni actualiza el contador de la fase
«Evidencia». El perito ve una barra que desaparece y un estado que no cambia, y
lo interpreta —razonablemente— como que no ha funcionado. El riesgo real es que
**se relance el registro del mismo fichero** creyendo que falló.

*(A verificar: ¿el polling del job termina en `state: done` y no dispara refetch,
o directamente se pierde el job al desmontar el componente?)*

### N1.ter — El flujo duplica el almacenamiento: 2× el tamaño de cada evidencia

Consecuencia medida del flujo bandeja → custodia:

| Fichero | Bandeja `./evidence` | Custodia `projects/cases/` |
|---|---|---|
| `IE11-Win7-VMWare-disk1.vmdk` | 20 GB | 20 GB |
| `ram.raw` | 5 GB | 5 GB |

La copia inmutable es **innegociable** (FORENSIC INVARIANT 2: el original nunca
se toca). Lo que sí es discutible es el camino: **subir 20 GB por el navegador a
una bandeja para acto seguido copiarlos otra vez** hace esperar dos veces y ocupar
el doble.

**Esto tumbó la máquina el 2026-07-28:** el disco llegó al **97% (14 GiB libres
de 460)** y la VM de Docker se cayó a mitad de sesión. Hubo que borrar 12 casos de
prueba y parte del corpus de la bandeja para recuperarla.

Preguntas que abre:

- ¿Puede el registro **mover** en vez de copiar cuando el origen ya está en la
  bandeja (mismo sistema de ficheros → `rename` instantáneo, cero duplicación)?
  ¿Rompe eso la custodia, si el hash baseline se calcula igual antes de exponer el
  handle?
- ¿O al revés: registrar **desde la ruta del host sin pasar por la bandeja**, para
  imágenes que el perito ya tiene en disco?
- ¿Debería la UI avisar del espacio necesario (**3× el tamaño en E/S, 1× extra en
  disco**) antes de empezar?

### N2 — El hash gate cuesta 3 pasadas sobre los bytes

5 GiB de evidencia → 16 GiB de lectura/escritura, 21,5 s en este host. Escala
lineal: un disco de 500 GB son ~1,5 TB de E/S. Está bien que sea asíncrono.

*(¿Se documenta esto en algún sitio de cara al usuario? Es la diferencia entre
«la app se ha colgado» y «esto tarda lo que tarda».)*

### N5 — 50k tokens es excesivo para decirme que no pudo hacer nada

**Perito, 2026-07-28.** Primera corrida real del agente sobre este caso:

> **Pregunta:** *«¿Se accedió a los documentos confidenciales, y en qué fecha y
> hora?»*
> **Respuesta, 10 minutos después:** *«No puedo aún afirmar si los documentos
> confidenciales fueron accedidos ni fecharlo.»*

| | |
|---|---|
| Tokens reportados | **49.446** |
| Coste real facturado | **$4,13** |
| Tiempo | 10 min 06 s |
| Iteraciones | 9 de 12 |
| Hallazgos persistidos | **0** |
| Respuesta a la pregunta | **ninguna** |

**Eso es excesivo.** Casi 50.000 tokens y cuatro euros para un «no he podido».

Lo que agrava el juicio: **no fue culpa de la infraestructura**. Las 31
herramientas estaban disponibles, los maletines sanos, la evidencia verificada y
el enrutado correcto. El agente leyó bien el disco NTFS, enumeró las particiones
y generó un bodyfile MAC(b) de 107 MB. Y aun así no respondió.

El desglose de dónde se fue el dinero está en
[`07-corrida-agente-001.md`](07-corrida-agente-001.md). Resumen: una referencia
de artefacto mal construida (`bodyfile_path: "dict"`), dos consultas a una
timeline que no existía, una llamada de 253 MB que el propio agente admite que
«no aporta», y cero llamadas a `record_finding` pese a escribir «Hallazgos
confirmados» en prosa.

**Y hay un agravante de medición:** los 49k son un **suelo**, no la cifra real. El
`input_tokens` sale constante (2501) en las nueve iteraciones, cuando el
transcript crece en cada una — porque solo se capturan `usage.input_tokens` y se
ignoran los campos de caché de Claude Code. Los $4,13 no cuadran con esos tokens
a ninguna tarifa publicada. **Se está midiendo por debajo.**

*(¿Cuál es el techo aceptable para un turno que no concluye? ¿Debería el agente
poder abortar antes cuando detecta que su pipeline está roto, en vez de gastar
seis iteraciones más?)*

### N4 — La verificación tras registrar la debe hacer la herramienta sola

**Decisión del perito, 2026-07-28.** Tener que pulsar «RE-VERIFICAR» a mano en
cada evidencia recién registrada es una pérdida de tiempo, y la herramienta debe
resolverlo sola.

Estado observado en este caso:

| Evidencia | Pasó el hash gate | `last_verification` |
|---|---|---|
| `a35686e4` · `ram.raw` 5 GB | sí | `verified: true` — **porque se pulsó el botón** |
| `cf54714e` · `original.vmdk` 20 GB | sí, idéntico gate | **`null`** |

Las dos pasaron exactamente el mismo control. La diferencia es solo que en una se
hizo clic.

**Lo que lo hace fácil y sound:** el registro **ya re-hashea la copia y aborta si
no cuadra** (`evidence.py:552-566`), que es literalmente lo mismo que hace
`verify()` después. Lo único que falta es **persistir esa comparación** en
`verification.json`. No es dar por verificado nada por decreto: es guardar un
resultado que se calculó de verdad. Coste en E/S: **cero** — los bytes ya se
leyeron las tres veces.

**El coste de no hacerlo no es solo tiempo del perito:** el playbook obliga al
agente a confirmar `verified=true` antes de tocar una herramienta, y a *«pedirlo y
esperar»* si no lo está. Con `last_verification: null`, un turno del agente puede
irse entero en pedir la verificación **sin analizar nada** — tokens quemados por
un botón sin pulsar.

Catalogado como trabajo pendiente en
[`../operacion/proximos-pasos.md`](../operacion/proximos-pasos.md) §2,
«`forensia.evidence` — la verificación tras registrar debe hacerla la herramienta».

### N3 — El nombre del caso promete tokens que no existen

«Prueba 188k tokens» no consumió ni uno. Si esa cifra viene de otra sesión, hay
que localizar de cuál antes de usarla como referencia de coste.

---

## Preguntas abiertas

*(Espacio del perito. Semilla:)*

- ¿Se lanza el análisis sobre este mismo caso para completar la foto, o se abre
  uno limpio?
- Sobre el RAM dump de Windows 7, ¿qué ruta se espera del agente y con qué
  ejecutor?
- ¿Se quiere medir el coste en tokens de una corrida completa aquí, para tener un
  número real que contrastar con los 188k del nombre?
- ¿El `.vmdk` entra en este caso o va a uno aparte?

---

## Notas libres

*(A partir de aquí, del perito.)*
