# 07 — Corrida del agente #001

> Primera ejecución real del agente en este caso, **2026-07-28 14:18:41 →
> 14:28:47 UTC**. Reconstruida de `chats/main.jsonl` y de los 41 eventos del
> audit log. Índice: [`README.md`](README.md).

## La pregunta y la respuesta

**Perito:** *«¿Se accedió a los documentos confidenciales, y en qué fecha y hora?»*

**Agente, 10 minutos después:** *«No puedo aún afirmar si los documentos
confidenciales fueron accedidos ni fecharlo […]. Prefiero reportarte el estado
real a inventar una respuesta.»*

## La factura

| Métrica | Valor |
|---|---|
| Ejecutor | Claude Code (cloud) |
| Iteraciones | **9** de 12 |
| Turnos del ejecutor | 9, todos `exit 0` |
| Tokens de entrada **reportados** | 22.511 |
| Tokens de salida | 26.935 |
| **Total reportado** | **49.446** |
| **Coste real facturado** | **$4,13** (`total_cost_usd`) |
| Tiempo de reloj | 10 min 06 s (447 s solo en el ejecutor) |
| Herramientas ejecutadas | 4 del catálogo + 2 internas + 1 fallida |
| Artefactos generados | 4 · **420 MB** en disco |
| **Hallazgos persistidos** | **0** — `findings.jsonl` no existe |

## Qué hizo, iteración a iteración

| It | Acción | Resultado |
|---|---|---|
| 1 | `tsk_mmls` | **OK** — 4 entradas, partición NTFS en offset 2048 |
| 2 | `tsk_fls -r -l` (offset 2048, ntfs) | **OK** — árbol Windows completo (52 MB) |
| 3 | `consultar_actividad` | «super-timeline no generada aún» |
| 4 | `tsk_fls -m` (bodyfile) | **OK** — bodyfile de 107 MB, sha256 `7b5020c1…` |
| 6 | `consultar_actividad` **otra vez** | «super-timeline no generada aún» |
| 7 | `tsk_icat inode=0` | **OK pero inútil** — 253 MB de zona raíz/$MFT |
| 8 | `tsk_mactime bodyfile_path="dict"` | **ERROR** — no se pudo resolver el run productor |
| 9 | Respuesta final | Sin responder a la pregunta |

## Los cuatro fallos, por orden de gravedad

### F1 — `tsk_mactime` rompe la cadena: el modelo emitió `"dict"` como referencia

La llamada de la iteración 8 fue literalmente:

```json
{"tool_id": "tsk_mactime", "params": {"bodyfile_path": "dict", "timezone": "UTC"}}
```

`bodyfile_path` espera un `ArtifactRef` `{run_id, relpath}`. El modelo emitió la
**cadena `"dict"`** — el nombre del tipo, no un valor. El backend rechazó con
*«no se pudo resolver el run productor»* y el mensaje de error reveló que la
referencia esperada llevaba un `run_id` literal `<GUID>` sin sustituir.

**Esto es exactamente el pipeline del Bug 1** (`tsk_fls -m` → `tsk_mactime`), que
se arregló para que el bodyfile fuese referenciable. **El arreglo funcionó**: el
bodyfile existe, tiene 107 MB y su sha256. Lo que falla ahora es un escalón
distinto — **el modelo no sabe construir la referencia**. El artefacto es
citable; el agente no lo cita.

Es el fallo que hunde la corrida: sin `mactime` no hay línea temporal, y sin
línea temporal no hay fecha ni hora que responder.

### F2 — `consultar_actividad` se llamó dos veces con la misma respuesta inútil

Iteraciones 3 y 6, ambas «super-timeline no generada aún». Entre medias, la
iteración 4 **generó el bodyfile** — pero `consultar_actividad` proyecta sobre la
super-timeline **persistida por el builder determinista**, que no es lo mismo que
un `tsk_fls -m` suelto del agente.

El agente lo diagnosticó bien en su propia respuesta final: *«el bodyfile se
generó pero la super-timeline no queda registrada hasta completar
`tsk_mactime`»*. Correcto — y es una **trampa de diseño**: la herramienta que
debería ahorrarle re-ejecutar `fls` no está disponible hasta cerrar un pipeline
que él no consigue cerrar (F1).

### F3 — `tsk_icat inode=0`: 253 MB tirados

Iteración 7. El inodo 0 no es un fichero: devolvió 253 MB de zona raíz. El propio
agente lo reconoce en el informe final: *«fue un paso en falso, no aporta»*.

Salió `exit 0`, así que **el guard-rail anti-bucle no lo cuenta como fallo** — el
corte a los 3 intentos solo mira `exit≠0`. Una llamada que triunfa técnicamente y
no aporta nada no tiene ningún freno.

### F4 — Cero hallazgos persistidos, pese a que el informe dice «Hallazgos confirmados»

`findings.jsonl` **no existe**. El agente escribió en prosa:

> **Volumen NTFS Windows único** (severity: low). `tsk_mmls` (exit 0) muestra una
> sola partición […]. Se generó el bodyfile MAC(b) completo (~107 MB, sha256
> `7b5020c1…`)

…pero nunca llamó a `record_finding`. **Ese hallazgo no existe para el sistema**:
no está en el store, no llega al informe pericial, no llega a la matriz MITRE.
Solo vive en el texto del chat.

La regla del playbook —*«registra en caliente, tras CADA herramienta con salida
útil»*— se incumplió las 4 veces. El nudge estructural (recordatorio tras 3
herramientas sin registrar) **no lo evitó**.

## Lo que el agente hizo BIEN — y conviene no perderlo

Sería injusto leer esto solo como fracaso:

- **No inventó nada.** Con presión para responder, dijo *«prefiero reportarte el
  estado real a inventar una respuesta»*. La regla 4 del system prompt («no
  inventas») **funcionó**.
- **Diagnosticó sus propios fallos con precisión**, incluido el `icat inode=0` y
  la causa exacta del error de `mactime` (*«referencié el run productor con un id
  inválido»*).
- **Distinguió laguna de tooling de laguna de evidencia**, que es justo lo que
  pide el formato de respuesta final.
- **Propuso tres rutas correctas y concretas** para desbloquear: cerrar
  `mactime` citando el UUID4 real; ir a LNK/Jump Lists con `lecmd`/`jlecmd` +
  `regripper` RecentDocs; y `$MFT` → `mftecmd` comparando `$SI` vs `$FN` para
  descartar timestomping. Son exactamente los artefactos que responden «qué
  documento se abrió y cuándo».
- **Se contuvo con MITRE**: propuso T1083 como aplicable *solo cuando confirme*
  accesos, en vez de pintar la matriz sin sostén.

El agente sabe qué hay que hacer. Se atasca en **la mecánica de referenciar un
artefacto**, no en el razonamiento forense.

## Un fallo de MEDICIÓN: los 49k son un suelo, no la cifra real

El `input_tokens` reportado es **2501 en las nueve iteraciones** (2503 en una).
Constante — cuando el transcript **crece en cada iteración** porque el ejecutor es
stateless y Agentopsy le reenvía la conversación entera.

Causa, verificada en código: `ClaudeCodeExecutor._extract_usage`
(`backend/forensia/executors/claude_code.py:97-116`) lee **solo**
`usage.input_tokens` y `usage.output_tokens`. Claude Code reporta además
`cache_read_input_tokens` y `cache_creation_input_tokens`, que es donde va el
grueso del prompt reenviado. **Esos campos no se capturan.**

La prueba está en el propio dato: **$4,13 facturados** no cuadran con 22,5k de
entrada + 26,9k de salida a ninguna tarifa publicada. El `total_cost_usd` sí es
real —lo da el CLI— y delata que la entrada real fue mucho mayor.

**Consecuencia para la medición en curso:** el contador de tokens del audit
**subestima**, y la magnitud del error crece con la longitud de la conversación.
Para medir de verdad hay que usar `cost_usd` (real) o capturar los campos de
caché. Catalogado en [`06-debe-hacerlo-sola.md`](06-debe-hacerlo-sola.md).

## Veredicto

**Nada de esto es infraestructura.** Las 31 herramientas estaban disponibles, los
maletines sanos, la evidencia verificada y el enrutado correcto. El disco NTFS se
leyó bien, las particiones se enumeraron bien y el bodyfile se generó bien.

Los 49k tokens y los $4,13 se fueron en: **una referencia de artefacto mal
construida** (F1), **dos consultas a una timeline inexistente** (F2), **una
llamada sin sentido de 253 MB** (F3) y **la ausencia de persistencia de lo poco
que sí concluyó** (F4).

De esos cuatro, **tres son de prompt/esquema y uno es de diseño de tools**.
Ninguno requiere tocar un invariante.

## Enlaces

- Nota del perito sobre el coste: [`05-notas-perito.md`](05-notas-perito.md) §N5.
- Requisitos derivados: [`06-debe-hacerlo-sola.md`](06-debe-hacerlo-sola.md).
- Bug 1 (pipeline `fls -m` → `mactime`) y su arreglo:
  [`../agentes/notas-rediseno-agentes.md`](../agentes/notas-rediseno-agentes.md).
- Las siete mejoras de playbook ya pendientes:
  [`../operacion/proximos-pasos.md`](../operacion/proximos-pasos.md) §2.
