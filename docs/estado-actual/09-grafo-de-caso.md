# 09 — Grafo de conocimiento por caso: dar al agente un lado de escritura

> Diseño propuesto, **sin implementar**. Sale de [`08-analisis-comparativo.md`](08-analisis-comparativo.md)
> §4.2.bis y de la decisión del perito del 2026-07-28.
> Índice: [`README.md`](README.md).

---

## 1. El hueco, explicado con `prueba-agentes`

`prueba-agentes` maneja **dos clases de documento**, y la distinción es exactamente
lo que le falta a Agentopsy:

| Documento | Ámbito | Qué contiene |
|---|---|---|
| `FLUJO.md` | **General** — cualquier caso | La receta. Tiene una sección *«Qué NO transfiere de un caso a otro»* |
| `FICHA-caso-murcielago.md` | **Este caso** | Los datos concretos. Abre con *«Ningún valor de esta ficha vale para otro caso»* |

**Agentopsy tiene el FLUJO y no tiene la FICHA.**

- Lo que tiene: `agentes/<id>/knowledge/artefactos-windows.md`, servido bajo demanda
  por `consultar_conocimiento(doc_id)`. Viaja en el paquete, **idéntico en todos los
  casos**. Dice *dónde suele vivir* un artefacto en Windows.
- Lo que no tiene: ningún documento que diga **qué se encontró en ESTE caso, dónde
  está y qué queda abierto**. El agente no puede escribir nada, así que todo lo que
  concluye o vive en el prompt (y se elide) o se pierde.

«Grafo» solo significa que en vez de una FICHA monolítica son **varios nodos
enlazados**, para poder cargar uno sin arrastrar los demás. Es el *spiderweb*.

---

## 2. Lo que se propone

Un **almacén de conocimiento por caso** que el agente puede **leer y escribir**,
separado de todo lo demás:

```
cases/<case_id>/
├── evidence/      ← INTOCABLE (read-only a nivel de bloque)
├── artifacts/     ← INTOCABLE (salidas de tools, hasheadas en el audit)
├── audit.jsonl    ← INTOCABLE (append-only hash-encadenado, lo escribe el backend)
├── findings.jsonl ← lo escribe `record_finding`
└── knowledge/     ← ★ NUEVO: los nodos del grafo, lo escribe el agente
    ├── perfil-sistema.md
    ├── cuentas.md
    ├── cronologia.md
    └── documentos-confidenciales.md
```

**Nunca sobre la evidencia. Nunca sobre la salida de las tools.** Un directorio
aparte, exactamente como el `output/` + fichas de `prueba-agentes`.

### Las dos tools internas

Simétricas a `record_finding` / `annotate_mitre` (canal lateral, en proceso, fuera
del catálogo y del allowlist del paquete):

| Tool | Qué hace |
|---|---|
| `anotar_conocimiento(doc_id, title, content)` | **Añade** un bloque al nodo `doc_id` del caso. Lo crea si no existe |
| `consultar_conocimiento(doc_id)` | **Ya existe** — se extiende para servir también los nodos del caso, no solo los estáticos del paquete |

### El índice es lo único que viaja en el prompt

El «Mapa de memoria» del system prompt gana una sección con **una línea por nodo**:

```
## Conocimiento de este caso
- perfil-sistema — Win7 SP1 x64, IEWIN7, volcado 2021-03-23 19:24:35 UTC, TZ Pacific (UTC−7)
- cuentas — 6 cuentas; testuser admin creada 19:07:38 → [[cronologia]]
- documentos-confidenciales — 2 XLS recuperados de RAM → [[cronologia]]
```

Tres líneas en el contexto en vez de tres documentos. El contenido se trae con
`consultar_conocimiento` **solo cuando hace falta**. Ese es todo el ahorro, y es el
mismo principio que la tool ya declara hoy en su descripción: *«NO cargues todo de
antemano — consulta solo el doc que necesites para la tarea en curso (economía de
contexto)»*.

---

## 3. Los controles (esto es lo que hace que sea aceptable)

Dar al agente un canal de escritura es **abrir una superficie nueva**. Siete
controles, todos derivados de invariantes que ya existen:

### C1 — El agente emite un ID, nunca una ruta

`doc_id` con juego de caracteres cerrado: `[a-z0-9][a-z0-9-]{0,63}`. Sin puntos,
sin barras, sin `..`. **El backend construye la ruta**;
`cases/<case_id>/knowledge/<doc_id>.md`.

Es el mismo patrón que `tool_id` (SECURITY INVARIANT 5: *el LLM emite un id de enum
cerrado, nunca una cadena de comando ni un path*). Con ese juego de caracteres, el
traversal no es que se rechace: **no es expresable**.

### C2 — Confinado y canonicalizado

La ruta resultante se canonicaliza y se verifica que cae bajo el `knowledge/` del
caso activo antes de abrir nada (SECURITY INVARIANT 6). Mismo control que ya
protege `evidenceRoot`.

### C3 — Append-only con vista consolidada · **DECIDIDO 2026-07-28**

El agente **nunca sobrescribe**, pero **releer no cuesta el histórico entero**. Se
consigue separando el registro de la vista:

```
knowledge/
├── perfil-sistema.md          ← VISTA consolidada (lo que se lee y lo que abre el perito)
├── cuentas.md
└── .historial/
    ├── perfil-sistema.jsonl   ← REGISTRO append-only (la garantía forense)
    └── cuentas.jsonl
```

**Escribir** = `anotar_conocimiento(doc_id, section, content)`:

1. Se **añade** un bloque `{section, content, ts, iteration, sha256}` al `.jsonl`.
   Nunca se modifica ni se borra una línea anterior.
2. Se **re-renderiza** el `.md` de forma atómica (tmp + `replace`): la **última
   versión de cada `section`**, en orden de primera aparición.

**Leer** (`consultar_conocimiento`) devuelve **solo el `.md`**: una sección por
tema, con su contenido vigente. El histórico está en disco y en el audit, pero no
viaja al contexto salvo que se pida explícitamente.

Qué garantiza cada mitad:

| | Registro `.jsonl` | Vista `.md` |
|---|---|---|
| Se puede borrar algo | **No, nunca** | Se supersede, no se borra |
| Lo lee el agente | No (salvo petición explícita) | **Sí** |
| Lo abre el perito | Si quiere auditar la evolución | **Sí — es su FICHA** |
| Coste en contexto | — | Acotado: crece con nº de temas, no con nº de escrituras |

Así se conserva la propiedad que importa —**evidencia hostil no puede lograr que el
agente borre lo que concluyó antes**; como mucho añade una versión posterior, y la
anterior sigue ahí y auditada— sin pagar el precio de un nodo que crece sin fin.

> Coste de implementación: hay que versionar por sección. Es la opción elegida
> conscientemente frente al append-only plano (más simple, pero encarece cada
> relectura).

### C4 — ⚠️ Lo que vuelve, vuelve marcado como NO CONFIABLE

**El control más importante y el menos obvio.**

El agente va a citar en sus notas cadenas derivadas de la evidencia: nombres de
fichero, líneas de log, rutas. La evidencia es **dato hostil**. Si esas notas se
releen como contexto de confianza, se ha construido un **canal de blanqueo**: los
bytes hostiles entran como «conocimiento propio del agente» y vuelven sin los
delimitadores que los marcan.

Por tanto: lo que devuelve `consultar_conocimiento` sobre un nodo **del caso**
vuelve envuelto en `<<EVIDENCIA_NO_CONFIABLE …>>` … `<<FIN_EVIDENCIA_NO_CONFIABLE>>`,
igual que la salida de cualquier herramienta. Los nodos **estáticos del paquete**
(`artefactos-windows.md`) siguen siendo de confianza: los escribió el equipo, no el
agente.

Es la misma frontera que `notas-rediseno-agentes.md` §5.bis-C ya estableció para la
bitácora: *«el motivo/stderr puede arrastrar bytes hostiles → surfacearlo como
untrusted aunque la clave sea meta de confianza»*.

### C5 — Auditado

Cada escritura emite un evento `knowledge_written` en el audit hash-encadenado:
`doc_id`, bytes, SHA-256 del bloque, iteración. **Metadatos y hash, nunca el
contenido** — igual que el resto de eventos del agente.

Así el grafo es reconstruible y se puede demostrar que un nodo no se tocó después
de cierto momento.

### C6 — Topes de tamaño

Cap por bloque (p. ej. 4 KB), por nodo y por caso. Un nodo no es un sitio donde
volcar un bodyfile de 107 MB: es donde va **la conclusión** y el puntero al
artefacto que la sostiene. Superar el cap es un error accionable, no un truncado
silencioso (RULE 2).

### C7 — Un nodo NO es un hallazgo

El grafo es **para navegar y no recargar**. No sustituye a `findings.jsonl` ni al
audit. Un hallazgo pericial sigue registrándose con `record_finding`, con su
procedencia (`tool_id`, `params`, `run_id`, `artifact_sha256`).

La relación sana entre ambos: el nodo del grafo **apunta** al finding y al run que
lo sostiene; el finding no vive en el nodo.

---

## 4. Cómo cambia una corrida como la #001

| | Hoy | Con el grafo |
|---|---|---|
| Tras `mmls` | El resultado viaja en el contexto y a los 4 turnos se elide | Nodo `particiones`: *«1 partición NTFS, offset 2048, run `4ba06311…`»* — 1 línea en el índice |
| Tras `fls -m` | 107 MB de bodyfile referenciados por un `run_id` que se pierde | Nodo `timeline-fs`: *«bodyfile generado, run `a91ad448…`, sha `7b5020c1…`»* — **el `run_id` deja de depender de la memoria del modelo** |
| Al cerrar sin respuesta | Todo se pierde; 0 findings | El grafo queda escrito: la siguiente sesión arranca leyendo el índice |
| Al preguntar de nuevo | Se re-ejecuta `fls` desde cero | `consultar_conocimiento("timeline-fs")` da el `run_id` sin re-ejecutar nada |

El fallo F1 de la corrida #001 —el modelo emitió `"dict"` en vez de la referencia—
**no se arregla del todo con esto**, pero deja de ser fatal: el `run_id` está
escrito en un nodo consultable en vez de en un turno elidido.

---

## 5. Qué habría que tocar

| Pieza | Dónde | Nota |
|---|---|---|
| Módulo del store | `backend/forensia/knowledge/` (nuevo) | Lógica pura: validación de `doc_id`, confinamiento, append atómico, lectura. Espeja `findings/store.py` |
| Tool interna de escritura | `agent/agent.py` (canal lateral) + `agent/tool_schemas.py` | Junto a `record_finding` / `annotate_mitre` |
| Extensión de lectura | `agent/tool_schemas.py` — `consultar_conocimiento` | Resolver primero nodos del caso, luego estáticos del paquete; marcar untrusted los del caso (C4) |
| Índice en el prompt | `agent/agent.py` `_system_prompt` | Sección «Conocimiento de este caso» con una línea por nodo |
| Evento de audit | `agent/agent.py` `_audit_event` | `knowledge_written` |
| Endpoint | `routers/` | Para que la UI pinte el grafo del caso |
| UI | `web/` | Vista del grafo — puede ir después |
| Prompts | `agentes/*/prompts/` | Regla de cuándo anotar. Espeja *«un hallazgo sin documentar todavía no cuenta como hallazgo»* |
| Tests | `backend/tests/` | Traversal imposible, confinamiento, append-only, untrusted al releer, caps, auditoría |

**Ningún invariante forense ni de seguridad se erosiona:** la evidencia sigue
intocable, los artefactos siguen hasheados, el audit sigue encadenado, y el LLM
sigue sin poder nombrar una ruta.

---

## 6. Decisiones tomadas (2026-07-28)

### D1 · Escritura → **append-only con vista consolidada**

Registro `.jsonl` append-only + vista `.md` re-renderizada con la última versión de
cada sección. Detalle en **C3**. Se asume el coste de versionar por sección a
cambio de que releer no encarezca con cada escritura.

### D2 · `doc_id` → **híbrido: núcleo fijo + libres con tope**

El paquete declara en `agent.yaml` un **núcleo estable** de nodos, y el agente
puede crear adicionales dentro del charset `[a-z0-9][a-z0-9-]{0,63}`, hasta un
**tope total** de nodos por caso.

- **Núcleo** (propuesta inicial, a afinar): `perfil-sistema`, `cuentas`,
  `cronologia`, `preguntas-abiertas`, `leads`, `artefactos`.
- **Libres:** para lo que un caso concreto necesite y el paquete no previó.
- **Tope:** superar el máximo es un error accionable que nombra los nodos
  existentes, no un truncado silencioso (RULE 2).

Predecible donde importa —el índice del prompt tiene forma conocida— y flexible
donde hace falta.

### D3 · Informe pericial → **anexo, marcado como derivado**

El grafo viaja al informe **como anexo**, etiquetado explícitamente como
*conocimiento derivado del análisis*, nunca como evidencia ni como hallazgo
probado. Aporta trazabilidad del razonamiento sin contaminar la sección de
hallazgos, que sigue citando procedencia (`tool_id`, `run_id`, `artifact_sha256`).

### D4 · Semilla → **NO es un formulario de apertura; es incremental**

> **Corrección del perito:** *«no siempre se dan todas las preguntas de golpe; a
> veces solo quiero consultar X, o que haga un volcado de la RAM.»*

La propuesta original —sembrar al crear el caso con encargo + preguntas + hash
esperado— **asumía un encargo completo por adelantado, y eso es falso**. El uso
real incluye peticiones sueltas sin caso formulado.

Consecuencias de diseño, **no negociables**:

1. **El grafo arranca vacío y eso es un estado válido.** Nada de un formulario que
   haya que rellenar para empezar. Ni el agente ni la UI pueden asumir que existe
   un encargo, una lista de preguntas o un objetivo declarado.
2. **`preguntas-abiertas` se llena solo, incrementalmente.** Cada petición del
   perito —«consulta X», «vuelca la RAM»— **es** una entrada de ese nodo, anotada
   cuando llega. El nodo se construye con la sesión, no antes de ella.
3. **El agente no puede exigir contexto que no se le ha dado.** Si le piden algo
   puntual, lo hace; no responde «primero dime el objetivo del caso». (Va en línea
   con la regla que ya existe en `agent.py:854`: no pedir confirmaciones que el
   operador no debe tener que dar.)
4. **El hash esperado va por otra vía.** Es **custodia**, no encargo, y no debe
   depender de que alguien rellene un nodo. Su sitio es el registro de la
   evidencia, opcional, y si está y no cuadra **bloquea** — el hueco de
   [`08-analisis-comparativo.md`](08-analisis-comparativo.md) §4.6. Se separa de
   esta decisión y se cataloga aparte.

**Lo que sí puede sembrarse**, si el operador lo aporta y sin obligar a nada:
el texto del encargo, cuando exista. Todo lo demás lo escribe el análisis.

---

## 7. Sigue abierto

- **Composición exacta del núcleo de `doc_id`** (D2): la lista de arriba es una
  propuesta, no está cerrada.
- **Tope de nodos por caso** (D2): número concreto sin decidir.
- **Caps de tamaño** (C6): por bloque, por nodo y por caso.
- **El hash esperado** como campo de custodia — extraído de D4, pendiente de
  catalogar como requisito propio.
