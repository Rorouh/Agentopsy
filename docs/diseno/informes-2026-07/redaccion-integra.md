# Redacción íntegra del informe — 2026-07-30

> **Este documento SUSTITUYE el motor de informes descrito en `README.md` y
> `plan-migracion.md` de esta misma carpeta.** El índice de
> [`plantilla-informe.md`](plantilla-informe.md) sigue vigente —de hecho es ahora
> el contrato— pero ya no lo ensambla Agentopsy sección a sección: lo redacta el
> modelo.

## 1. El encargo

Agentopsy rellenaba una plantilla: `build_pericial_report` montaba ocho secciones
desde los datos del caso, `narrative` elegía el orden y el tejido conectivo, y
`humanize` reescribía opcionalmente la prosa de §1 y §8. El resultado era un
informe correcto y **siempre igual**: dos casos distintos producían el mismo
molde con distintos huecos rellenos.

El encargo del 2026-07-30 lo cambia de raíz:

1. Por cada investigación se redacta un informe **único**.
2. Lo redacta **de principio a fin el modelo de IA seleccionado**.
3. Se genera **una sola vez, al finalizar la investigación**.
4. Lo único que un informe comparte con otro es **el índice**. La narrativa, el
   nivel de detalle y la longitud dependen por completo del caso.

## 2. Lo que se retiró

| Pieza | Qué hacía | Estado |
| --- | --- | --- |
| `forensia/reports/generator.py` | Ensamblaba las 8 secciones desde los datos | **eliminado** |
| `forensia/reports/narrative.py` | Elegía orden y tejido conectivo de la prosa | **eliminado** |
| `forensia/reports/humanize.py` | Reescribía la prosa de §1/§8 con un ejecutor | **eliminado** |
| `generate_draft_report` + `AUTO_DRAFT_TITLE` | Borrador automático al cerrar un análisis | **eliminado** |
| `_maybe_auto_draft` en `routers/agent.py` | Enganchaba el borrador auto a `/query`, `/analyze` y `/query/stream` | **eliminado** |
| `POST …/documents/generate` | Síntesis determinista, con humanización opcional | **eliminado** |
| Selector «Redacción» de `DocumentsPage` | Determinista vs. humanizada | **eliminado** |

No hay modo de repuesto. Si el ejecutor no está disponible o su respuesta no
valida, **no hay informe** y el error dice por qué (RULE 2: fallar fuerte, nunca
un sucedáneo silencioso).

## 3. Lo que hay ahora

```
POST /api/cases/{id}/documents/finalize      ← «Finalizar investigación»
   │  valida rápido: caso (404) · ≥1 hallazgo (422) · ejecutor (422) · disponible (503)
   ▼
job en segundo plano (forensia.agent.jobs, kind="report")
   │
   ├─ forensia.reports.material.build_material   ← TODO lo persistido, sin una frase
   │     caso+encargo · evidencias con custodia · hallazgos íntegros · trabajos
   │     (argv auditado) · uso de tools · ATT&CK con veredicto · revisiones ·
   │     traza · integridad de la cadena hash
   │
   ├─ forensia.reports.indice.INDICE             ← lo ÚNICO común entre informes
   │
   ├─ forensia.reports.writer.write_report       ← UNA llamada al ejecutor elegido
   │     prompt: identidad │ índice │ reglas │ tipos de bloque │ MATERIAL │ contrato
   │
   └─ cuatro puertas de custodia → DocumentStore.create (estado draft)

GET /api/cases/{id}/documents/jobs             ← reenganche al montar la vista
GET /api/cases/{id}/documents/jobs/{job_id}    ← sondeo del progreso
```

### 3.1 Módulos nuevos

- **`forensia/reports/indice.py`** — el índice canónico como CONSTANTE: 10
  secciones + 2 anexos, cada una con su `num`, su `title` y el `contrato` de
  contenido que viaja al prompt. Cambiar esa tupla cambia el índice de TODOS los
  informes: es una decisión de producto, no del modelo ni del caso.
- **`forensia/reports/works.py`** — «Trabajos realizados»: reensambla el
  `audit.jsonl` por `run_id` emparejando `tool_run_start` con su
  `tool_run_finish` y cruzando los hallazgos que lo citan. El `argv` es el
  auditado token a token; un run sin versión no inventa `"unknown"`; un run sin
  `finish` aparece como `incompleto`, no se descarta (era la Fase A del plan
  antiguo, ahora al servicio del redactor).
- **`forensia/reports/material.py`** — reúne todo lo anterior en el material.
  No redacta: las dos únicas decisiones de presentación son la **naturaleza** de
  cada evidencia (derivada del `detected_kind` del triaje) y el **orden por
  volatilidad**, y ambas son datos. Las colecciones largas se acotan con
  constantes declaradas y el recorte se anuncia en `truncado` para que el informe
  lo diga.
- **`forensia/reports/writer.py`** — el redactor y sus cuatro puertas.

### 3.2 El índice, exacto

`INDICE` fija los doce apartados de `plantilla-informe.md`:

| # | Sección |
| --- | --- |
| 1 | Control de versiones |
| 2 | Resumen ejecutivo |
| 3 | Línea de tiempo del incidente |
| 4 | MITRE ATT&CK TTPs |
| 5 | Descripción del incidente, alcance y dispositivos |
| 6 | Hallazgos |
| 7 | Trabajos realizados |
| 8 | Indicadores de compromiso (IOCs) |
| 9 | Conclusiones y limitaciones |
| 10 | Recomendaciones y plan de acción |
| A | Anexo — Traza de la investigación |
| B | Anexo — Verificación de integridad |

El validador exige la lista **completa, en ese orden, con esos títulos**. Falta
una, sobra una, se reordenan o se retitula una → la redacción se rechaza entera.

### 3.3 Las cuatro puertas de custodia

Lo que Agentopsy no delega, porque es custodia y no redacción. Todas se cruzan
**antes** de persistir: se publica el informe entero o no se publica nada.

1. **Índice exacto** (`_validar_indice`).
2. **Modelo de bloques** (`_normalizar_bloques`): solo los tipos que
   `DocumentStore` valida, con sus campos, acotados y coercionados. Una clave
   inventada por el modelo no llega al almacén.
3. **Referentes cerrados** (`_validar_referentes`): toda técnica `Txxxx`, todo
   UUID y toda cadena hexadecimal citada debe existir ya en el material. Un hash
   puede citarse por prefijo (así los abrevian los informes); un token que
   EXTIENDA un prefijo permitido es fabricación. Un número decimal largo no se
   confunde con un hash: el patrón exige al menos una letra `a-f`.
4. **Comandos literales** (`_validar_comandos`): cada bloque `code` debe
   coincidir con un `argv` auditado del caso, y el bloque queda **fijado** a la
   forma auditada. Los bloques `code` están reservados a eso; cualquier otra cosa
   —un endpoint, una ruta— va en prosa. Es FORENSIC INVARIANT 4 llevado al
   informe: se cita el comando que se EJECUTÓ, no el que el modelo cree que se
   ejecutó.

Cada puerta recoge **todas** sus violaciones antes de rechazar (no la primera):
un motivo que nombra los tres identificadores inventados se puede arreglar de una
vez; uno que nombra el primero se arregla de uno en uno.

### 3.3.bis La ronda de corrección

Rechazar entero es correcto; **tirar la redacción entera es caro y no protege
nada más**. Medido en un caso real (`TestCase4`, 2026-07-30): 6 min 32 s de
redacción descartados porque §1 citaba un identificador de documento que el
modelo se inventó —el informe que se está redactando aún no existe, así que no
tiene id ni SHA-256—. Dos cambios:

- **El contrato de §1 lo dice explícitamente** (`indice.py`): la revisión que se
  emite no cita su identificador ni su hash, se asignan al persistir. Y una regla
  nueva del prompt (`2.bis`) generaliza: lo que no tiene identificador en el
  material se nombra por su descripción, nunca con un id inventado.
- **`MAX_REPARACIONES = 1`**: cuando una puerta rechaza, el motivo exacto vuelve
  al modelo y se le pide que corrija ESO. Si el ejecutor sabe reanudar sesión
  (`supports_session_resume` + `session_id` devuelto), la corrección viaja como
  un **delta** sobre su propio borrador; si no, se reenvía el encargo completo
  con el fallo señalado. La ronda queda en el audit (`report_repair`: intento,
  motivo, si hubo reanudación) y el informe publicado registra en qué intento
  pasó (`report_written.attempts`) — un informe corregido no se disfraza de
  limpio.

**No es un fallback (RULE 2).** No se sustituye el informe por otra cosa, no se
publica a medias y no se relaja ninguna puerta: es el mismo ejecutor, con el
mismo contrato, arreglando su propio texto. Si la corrección tampoco pasa, no hay
informe y el error lo dice.

### 3.3.ter La tipografía del producto (2026-07-30)

Un informe pericial de Agentopsy **no lleva el signo `§`, ni el guion largo `—`,
ni emojis**. La regla vale igual para el texto de la aplicación web.

De dónde venía: la propia **regla 8 del prompt ordenaba** citar las referencias
cruzadas como «§3, §6.2, §9», y `contrato_del_indice()` le enseñaba al modelo el
formato `§1 — Control de versiones`. El informe hacía exactamente lo que se le
pedía. Ahora el índice se enuncia `1. Control de versiones`, la regla 8 exige
«apartado 6.2» y prohíbe el signo, y una **regla 9** nueva fija la tipografía:
prosa en texto plano, incisos entre comas o paréntesis, y la palabra en lugar del
pictograma.

Pedirlo no basta, así que hay una pasada **después** de las cuatro puertas,
sobre texto que ya cruzó la custodia: `_normalizar_estilo`.

- **No es una quinta puerta y no rechaza nada.** La tipografía no es un hecho del
  caso, y el material puede traer una raya que escribió el agente en el título de
  un hallazgo: copiarla fielmente no puede costar el informe entero.
- **Sustituye por lo que toca en cada sitio.** El inciso con rayas del español
  equivale al inciso con comas, así que «el informe —que aún no existe— no tiene
  id» sale «el informe, que aún no existe, no tiene id». Pegada a un signo de
  puntuación o al principio de la frase, la raya desaparece. `§6.2` pasa a
  «apartado 6.2»; tras la palabra «sección» solo se cae el signo.
- **Nunca toca un bloque `code`.** Ahí vive el argv auditado, carácter a carácter
  (FORENSIC INVARIANT 4). Si el comando que se ejecutó llevaba una raya, el
  informe la conserva: es el comando que corrió.
- **Un texto que ya cumple sale idéntico, byte a byte.** La limpieza de espacios
  solo actúa donde hubo sustitución: no es un corrector de estilo.
- **Queda auditado.** `report_written.style_normalized` cuenta cuántos campos se
  reescribieron; `0` significa que el modelo cumplió la regla 9 por sí mismo. Se
  normaliza a la vista, no en silencio.

El mismo criterio se aplicó a las otras dos fuentes que el prompt no puede
corregir: **`agentes/agent.md`** (apartado 9, «Cómo se escribe»), porque es el
texto que el modelo lee e imita y de ahí salen el `title` y el `summary` de cada
hallazgo, que viajan al informe; y **la interfaz web**, barrida entera (el hueco
de «sin dato» pasó de `—` a `n/d`). Lo fija en CI
`backend/tests/test_estilo_tipografia.py`, que recorre los literales de salida
del backend, todo `web/src` y `agent.md`. Quedan fuera, a propósito, tres sitios
donde la raya es **dato y no prosa**: la clave de transliteración del PDF
(`pdf._PUNCT`, que ya la convertía a guion antes de imprimir), el regex que
parsea las tácticas de la semilla ATT&CK y el propio `_RAYA_RE`.

### 3.4 El encargo, literal

`writer.ENCARGO` es la primera línea del prompt:

> Redacta un informe de peritaje forense completo, con una redacción
> profesional, basándote en todos los hallazgos y evidencias recopiladas en esta
> investigación.

Pulsar el botón **es** enviar esa petición al modelo. Todo lo que viene después
en el prompt no la matiza: la hace ejecutable — qué apartados (el índice), con
qué material (el del caso) y en qué formato (el contrato de respuesta).

### 3.5 Coste y tiempo

Una sola llamada por informe, con `context['timeout'] = REPORT_TIMEOUT_S` (900 s):
es la respuesta más larga que Agentopsy le pide a un modelo, y no cabe en el
`DEFAULT_TIMEOUT_S` de 300 s calibrado para un turno del agente. El operador
puede subirlo con `FORENSIA_EXECUTOR_TIMEOUT`. Si la respuesta se corta, el error
lo dice y sugiere revisar ese presupuesto.

La llamada se audita con su argv literal (vía `PromptExecutor.run` con el
`AuditLog` del caso en el contexto) y el resultado con **`report_written`**
(ejecutor, modelo, secciones, bloques por sección, caracteres, versión).

### 3.6 La superficie

Una sola acción en la vista **Informe pericial**: el botón **«Finalizar
investigación»**, equivalente a pedirle al modelo *«redacta un informe de
peritaje forense completo, con una redacción profesional, basándote en todos los
hallazgos y evidencias recopiladas»*. Junto a él, el selector del modelo que
redacta (persistido como `DEFAULT_EXECUTOR`, igual que en el chat) y los datos
opcionales del perito.

El botón dice por qué no se puede pulsar cuando no se puede: sin ejecutor
seleccionado, con el ejecutor no disponible (con su motivo accionable), o sin un
solo hallazgo registrado. Mientras redacta, una barra indeterminada con la fase
(`material` → `redactando` → `validando` → `corrigiendo`? → `listo`) y un
cronómetro anclado al `created_at` del job en el SERVIDOR: cambiar de sección o
recargar no lo reinicia, y cerrar la pestaña no aborta la redacción.

**Un rechazo se queda a la vista.** Una redacción que no publica nada dejaba la
vista idéntica a «no ha pasado nada» —el motivo solo vivía en un aviso que se
desvanecía a los seis segundos—, así que el perito buscaba un informe que no
existía. Ahora el fallo se pinta como bloque persistente con su motivo íntegro, y
al montar la vista se reengancha el ÚLTIMO job del caso, no solo uno en curso:
un intento fallido se puede leer después, no solo en el instante en que falla.

**Volver a pulsarlo emite una revisión nueva.** La versión se deriva de las
revisiones ya registradas (`v0.1`, `v0.2`…) salvo que el perito declare una, y §1
«Control de versiones» las lista. El caso NO se cierra: el estado del caso lo
sigue gobernando «Cerrar caso» del lateral.

## 4. Qué NO cambia

- El **almacén** (`store.py`): SHA-256 del contenido canónico, firmar como acto
  de estado, un final no se borra, todo auditado.
- El **PDF** (`pdf.py`): portada, índice, secciones numeradas, tablas, hallazgos
  y pie por página. Renderiza igual los `num` `A` y `B`.
- La separación de los **dos ejes ATT&CK** (propuesta del análisis ≠ veredicto
  del perito), que ahora es una regla del prompt y viaja en el material.
- El documento nace en **BORRADOR** y adquiere validez pericial al firmarse.

## 5. Gates

- `backend/tests/test_report_writer.py` — el informe es del modelo; el índice
  exacto; las cuatro puertas; el contrato de respuesta; dos casos comparten
  índice y NO contenido; la ronda de corrección (el motivo vuelve al modelo, la
  corrección se publica y queda trazada; un segundo rechazo no publica nada ni
  pide una tercera; con sesión viaja como delta y sin ella se reenvía el
  encargo); la tipografía (el encargo la prohíbe, el informe publicado no lleva
  raya ni `§` ni emoji, el `code` auditado conserva su forma literal, un texto
  limpio no se reescribe y una raya nunca cuesta el informe).
- `backend/tests/test_estilo_tipografia.py` — la regla en las tres fuentes que
  ningún prompt corrige: literales de salida del backend, `web/src` entero y
  `agentes/agent.md`.
- `backend/tests/test_report_material.py` — todo lo persistido llega al material;
  el material no trae prosa; naturaleza y volatilidad; recorte declarado.
- `backend/tests/test_reports_works.py` — argv token a token, runs fallidos
  presentes, versión no inventada, run sin `finish` incompleto, hallazgos
  cruzados.
- `backend/tests/test_finalize_investigation.py` — la superficie: `generate` ya
  no existe, RULE 2 en la puerta, redacción en segundo plano, un rechazo no
  persiste nada.
