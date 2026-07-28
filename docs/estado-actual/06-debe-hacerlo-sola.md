# 06 — Lo que la herramienta debe hacer sola

> Catálogo de **pasos manuales que no deberían serlo**: cosas que hoy exigen un
> clic o una decisión del perito y que Agentopsy puede resolver por su cuenta sin
> tocar ningún invariante forense.
> Índice: [`README.md`](README.md).

**Criterio de entrada en esta lista.** Un ítem entra aquí si cumple las tres:

1. El perito tiene que hacerlo **a mano** hoy.
2. El backend **ya tiene** el dato o ya ha hecho el trabajo — solo no lo persiste,
   no lo encadena o no lo expone.
3. Automatizarlo **no erosiona** ningún invariante (custodia, hash gate, audit
   encadenado, RULE 2).

Lo que **no** entra: cualquier automatización que sustituya una decisión del
operador por un default silencioso. Eso es RULE 2 y sigue prohibido. La
distinción es: *ejecutar solo un paso mecánico que ya está determinado* ≠
*elegir por el perito algo que él no ha elegido*.

---

## R1 — Verificar la evidencia al terminar el registro

**Estado:** abierto. Catalogado el 2026-07-28 por decisión del perito.

### El problema

Tras registrar una evidencia hay que pulsar **«RE-VERIFICAR»** a mano para que
aparezca como verificada. En este caso:

| Evidencia | Pasó el hash gate | `last_verification` |
|---|---|---|
| `a35686e4` · `ram.raw` 5 GB | sí | `verified: true` — **porque se pulsó el botón** |
| `cf54714e` · `original.vmdk` 20 GB | sí, el mismo gate | **`null`** |

Las dos pasaron exactamente el mismo control. La única diferencia es el clic.

### Por qué es sound automatizarlo

El registro **ya re-hashea la copia y aborta si no cuadra**
(`backend/forensia/evidence.py:552-566`):

```
sha256(origen) → copia → sha256(copia) → si difieren: OSError y se descarta el staging
```

Esa comparación **es exactamente la que ejecuta `verify()`** después. Lo único
que falta es **persistirla**: hoy `verification.json` solo lo escribe el
`verify()` bajo demanda (`evidence.py:786`).

No es declarar verificado por decreto — es **registrar un resultado que se
calculó de verdad**, con su marca de tiempo. Coste en E/S: **cero**; los bytes ya
se leyeron las tres veces.

### El coste de no hacerlo: no es solo tiempo del perito

El playbook obliga al agente a confirmar `verified=true` antes de tocar ninguna
herramienta, y a *«pedirlo y esperar»* si no lo está. Con
`last_verification: null`, **un turno del agente puede irse entero en pedir la
verificación sin analizar nada** — tokens quemados por un botón sin pulsar. En
una sesión donde se está midiendo el gasto, además, contamina la medida.

### Qué hay que tocar

- `backend/forensia/evidence.py` → `register()`: construir el
  `VerificationRecord` con el `copy_sha` **ya calculado** y llamar a
  `_write_verification` **dentro del staging**, antes del `os.rename` atómico —
  así se publica con el resto o no se publica nada.
- Emitir el evento `evidence_verify` en el audit, para que la cadena refleje la
  comprobación.
- **EWF multi-segmento:** el record debe ser el AND sobre `segments[]`, igual que
  hace `verify()` hoy (`evidence.py:749-780`).
- UI: distinguir «verificada en el registro» de una re-verificación manual
  posterior.

### Lo que NO cambia

La **re-verificación al cierre de sesión** sigue siendo otra cosa y sigue
haciendo falta (FORENSIC INVARIANT 2). Esto solo cubre el instante del registro.

### Seguimiento

Ficha de trabajo con estimación en
[`../operacion/proximos-pasos.md`](../operacion/proximos-pasos.md) §2 —
«`forensia.evidence` — la verificación tras registrar debe hacerla la
herramienta». Nota original del perito:
[`05-notas-perito.md`](05-notas-perito.md) §N4.

---

## R2 — Refrescar la vista cuando termina un registro

**Estado:** abierto. Observado el 2026-07-28.

El job de registro termina correctamente y **la SPA no se entera**: no vuelve a
pedir `GET /api/cases/{id}/evidence` ni actualiza el contador de la fase
«Evidencia». El perito ve una barra que desaparece y un estado que no cambia, y
lo interpreta —razonablemente— como que ha fallado.

**El daño real:** lleva a **relanzar el registro del mismo fichero** creyendo que
no funcionó. Eso ocurrió en este caso y contribuyó a llenar el disco.

Cronología y evidencia en [`05-notas-perito.md`](05-notas-perito.md) §N1.bis.

---

## R3 — No duplicar el almacenamiento de cada evidencia

**Estado:** abierto, requiere decisión de diseño. Observado el 2026-07-28.

Cada evidencia ocupa **dos veces** su tamaño: una en la bandeja `./evidence` y
otra en custodia. Con el `.vmdk` de este caso son 20 GB + 20 GB.

La copia inmutable es innegociable (FORENSIC INVARIANT 2). Lo discutible es el
camino: subir 20 GB por el navegador a una bandeja para copiarlos acto seguido
hace esperar dos veces y ocupar el doble. **Esto tumbó la máquina** en esta
sesión (disco al 97%, VM de Docker caída).

Vías a evaluar —ninguna decidida—: **mover** en vez de copiar cuando el origen ya
está en la bandeja y es el mismo sistema de ficheros (`rename` instantáneo, cero
duplicación, con el baseline calculado igual antes de exponer el handle);
registrar **desde una ruta del host** sin pasar por la bandeja; o al menos
**avisar del espacio necesario** antes de empezar (3× el tamaño en E/S, 1× extra
en disco).

Detalle en [`05-notas-perito.md`](05-notas-perito.md) §N1.ter.

---

---

## R4 — Medir el gasto de tokens de verdad (hoy se mide por debajo)

**Estado:** abierto. Detectado el 2026-07-28 en la corrida #001.

`ClaudeCodeExecutor._extract_usage`
(`backend/forensia/executors/claude_code.py:97-116`) captura **solo**
`usage.input_tokens` y `usage.output_tokens`. Claude Code reporta además
`cache_read_input_tokens` y `cache_creation_input_tokens`, donde va el grueso del
prompt reenviado en cada iteración.

**Síntoma medido:** `input_tokens` **constante en 2501** durante las nueve
iteraciones de la corrida #001 — cuando el transcript crece en cada una porque el
ejecutor es stateless y Agentopsy le reenvía la conversación entera. Y los
**$4,13** de `total_cost_usd` no cuadran con 22,5k de entrada + 26,9k de salida a
ninguna tarifa publicada.

**Por qué importa:** el perito está usando esta métrica para decidir si el gasto
del agente es aceptable. Medir por debajo, y con un error que **crece con la
longitud de la conversación**, invalida esa decisión. Además `estimate.py` ancla
sus estimaciones previas en estos mismos números del audit: la estimación hereda
el sesgo.

**Qué tocar:** capturar los campos de caché en `_extract_usage` y sumarlos (o
llevarlos como campos propios en el `Usage`, para poder distinguir entrada fresca
de entrada cacheada — que es información útil de por sí). Revisar los otros tres
ejecutores por el mismo patrón. Mientras tanto, **`cost_usd` es el dato fiable**:
lo calcula el propio CLI.

Detalle en [`07-corrida-agente-001.md`](07-corrida-agente-001.md).

---

## R5 — ✅ RESUELTO: la redacción cegaba al agente

**Estado:** arreglado el 2026-07-28. Se documenta porque es la causa raíz de todo
lo que §07 y §08 atribuyeron a fallo del modelo o de los prompts.

### El bug

`policy/redaction.yaml` declara un patrón `guid` para tapar el `MachineGuid` que
aparezca **dentro de la evidencia**. Pero `redact_messages` lo aplicaba como un
`re.sub` ciego sobre TODO el contenido de TODOS los mensajes salientes —
**incluidos los identificadores que la propia Agentopsy inyecta**. El agente veía:

```
run_id: <GUID>
```

…y a la vez se le exigía citar el `run_id` para encadenar `tsk_mactime`, para leer
un artefacto y para registrar un hallazgo. **Era imposible.** No alucinaba:
copiaba literalmente lo único que se le enseñaba.

Lo dijo él mismo, en su propio razonamiento:

> *«my previous `record_finding` was rejected because I echoed the masked `run_id`
> (`<GUID>`) literally, which fails the UUID4 validation»*

### Lo que explica

| Síntoma | Documentado en |
|---|---|
| `tsk_mactime` con `bodyfile_path: "dict"` | [`07`](07-corrida-agente-001.md) F1 — «decisivo» |
| `leer_artefacto rejected: invalid run_id: '<GUID>'` | corrida del 2026-07-28 19:46 |
| **0 hallazgos persistidos, siempre** | [`07`](07-corrida-agente-001.md) F4 — un hallazgo afirmativo EXIGE `run_id` |
| «el agente no sabe citar procedencia» | [`08`](08-analisis-comparativo.md) §3, la causa nº 1 |

**Coste medido de este único regex:** dos corridas completas, **$4,13 + $3,30**,
sin un solo hallazgo. Y semanas de diagnóstico apuntando al modelo y al playbook.

**Solo afectaba a ejecutores CLOUD**: con un backend local la redacción ni se
aplica. Todas las corridas medidas fueron con Claude Code.

### El arreglo

Los identificadores del **plano de control** (`run_id`, `case_id`, `evidence_id`,
`finding_id`) los genera Agentopsy, no salen de la evidencia y no contienen dato
personal: **no hay nada que minimizar**. Se pasan como `protected` y el texto se
**parte** por ellos, de modo que nunca llegan a pasar por un `re.sub` — es
imposible que se redacten por accidente. Un GUID que venga del **contenido** de la
evidencia se sigue tapando, que es para lo que existe el patrón.

De paso, `apply_in` deja de ignorarse: declaraba en qué modo aplica cada patrón y
el código los aplicaba todos. Ahora el modo es explícito (`strict`, el único
cableado y el comportamiento de siempre) — sin inventar un modo laxo que nadie ha
pedido (RULE 2).

Regresión: `backend/tests/test_redaction_no_ciega_al_agente.py` (13 tests,
incluido el gate de punta a punta con el paquete Windows real).

### La lección

Un regex de minimización de datos, pensado para proteger, **inutilizó el producto
entero durante semanas** sin dar un solo error propio. Todos los síntomas
aparecían lejos de la causa. Merece revisar si algún otro patrón de redacción pisa
metadatos que el agente necesita.

---

## Candidatos anotados, sin decidir

Estos rozan la frontera con RULE 2 y **no** están catalogados como requisitos:
se anotan para discutirlos, no para implementarlos.

- **Encadenar la verificación de cierre de sesión** automáticamente al cerrar el
  caso. Parece mecánico, pero hay que decidir qué pasa si falla: ¿bloquea el
  cierre? ¿Lo marca y deja cerrar?
- **Registrar automáticamente lo que se sube a la bandeja.** Tentador tras
  R2/R3, pero elimina un punto de decisión del perito (qué entra en custodia y
  qué no) y multiplicaría el problema de disco. Probablemente **no**.
