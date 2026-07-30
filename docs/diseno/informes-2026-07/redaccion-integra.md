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
(`material` → `redactando` → `validando` → `listo`) y un cronómetro anclado al
`created_at` del job en el SERVIDOR: cambiar de sección o recargar no lo
reinicia, y cerrar la pestaña no aborta la redacción.

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
  índice y NO contenido.
- `backend/tests/test_report_material.py` — todo lo persistido llega al material;
  el material no trae prosa; naturaleza y volatilidad; recorte declarado.
- `backend/tests/test_reports_works.py` — argv token a token, runs fallidos
  presentes, versión no inventada, run sin `finish` incompleto, hallazgos
  cruzados.
- `backend/tests/test_finalize_investigation.py` — la superficie: `generate` ya
  no existe, RULE 2 en la puerta, redacción en segundo plano, un rechazo no
  persiste nada.
