# Plantilla del informe pericial — 10 secciones

> ✅ **VIGENTE como ÍNDICE, superado como plantilla (2026-07-30 —
> [`redaccion-integra.md`](redaccion-integra.md)).** Las diez secciones + los dos
> anexos de este documento son ahora el índice canónico del código
> (`forensia.reports.indice.INDICE`) y lo ÚNICO que dos informes comparten: el
> validador del redactor los exige con este número, este título y este orden. Lo
> que ya NO se cumple al pie de la letra es la forma de cada bloque: el CONTENIDO
> —qué se dice, con qué prosa y con qué longitud— lo escribe el modelo
> seleccionado a partir del material del caso. Lo que sí sobrevive de cada
> apartado es su intención, que viaja al prompt como el `contrato` de la sección.
>
> Cada sección es un `{num, title, blocks[]}` del modelo de `forensia.reports.store`.
> Los tipos de bloque disponibles son los que el store ya valida: `p`, `h3`, `quote`,
> `list`, `code`, `kv`, `table`, `finding` (+ las dos figuras de la fase F).
>
> **Regla transversal (P2 / RULE 2):** una sección sin dato **se imprime igualmente**,
> con una nota explícita de qué falta y quién debe aportarlo. Nunca se omite ni se
> rellena con texto genérico.
>
> **Regla transversal de tiempo:** toda marca temporal se imprime en **UTC explícito**
> (`YYYY-MM-DDTHH:MM:SSZ`). Nunca hora local implícita — la guía lo exige (p. 109) y
> `forensia.timeline.TIMEZONE` ya lo fija.

---

## Portada (no numerada)

Ya existe en `pdf._cover`. Se añade:

| Campo | Origen |
| --- | --- |
| Título, resumen, perito, versión, fecha, `case_id`, SHA-256 del documento | ya presente |
| **Solicitante** | `ficha.solicitante` |
| **Estado del documento** | `BORRADOR` / `FIRMADO` en grande — hoy solo aparece al pie |
| **Clasificación** | «CONFIDENCIAL» (la guía pide clasificación de seguridad si aplica, p. 111) |

Tras la portada: **índice de contenidos con números de página** e **índice de
ilustraciones** (fase F).

---

## §1 — Control de versiones

**Origen:** `DocumentStore.list(case_id)`, filtrando `type == "pericial"`, más la
revisión que se está generando.

Tabla:

| Versión | Fecha (UTC) | Autor | Estado | SHA-256 del contenido |
| --- | --- | --- | --- | --- |
| v0.2 | 2026-07-29T10:14:03Z | *(esta revisión)* | borrador | *(se fija al persistir)* |
| v0.1 | 2026-07-28T17:02:11Z | J. Pérez | firmado | `9f2c…a41b` |

Párrafo de cierre, fijo:

> «El histórico de revisiones se deriva de los documentos periciales registrados en el
> caso. El SHA-256 corresponde al contenido canónico de cada revisión y permite
> verificar que una versión previa no ha sido alterada (`POST …/documents/{id}/verify`).»

Si es la primera revisión: la tabla lleva solo esa fila y una nota de que no hay
revisiones anteriores.

---

## §2 — Resumen ejecutivo

**Cota dura: 2 páginas** (guía p. 115). Se controla por presupuesto de caracteres —
`store._estimate_pages` ya calibra ~3000 chars/página, así que **≤ 6000 caracteres**;
si la síntesis lo excede, se recorta la enumeración de hallazgos a los de severidad
`critical` y `high` y se remite a §6.

Sin jerga y sin ids técnicos: es la sección que leen los no técnicos. Nada de
`run_id`, ni SHA-256, ni nombres de herramienta.

Estructura:

1. **Objeto** — una frase, de `ficha.encargo`. Sin ficha: *«No consta el objeto del
   encargo en la ficha pericial del caso.»*
2. **Alcance examinado** — nº de evidencias, tipo y perfil de SO determinado por triaje.
3. **Hallazgos clave** — lista de los `critical` y `high` por título, en lenguaje llano.
   Sin hallazgos: la constancia honesta que ya redacta el generador hoy.
4. **Conclusión principal** — una o dos frases; debe ser coherente con §9.
5. **Estado** — borrador o firmado, y qué implica.

---

## §3 — Línea de tiempo del incidente

**Origen (P1: hitos del incidente, no registro del analista):**

- Hallazgos con `observed_at` no nulo → un hito cada uno.
- Eventos MACB **relevantes** del super-timeline persistido
  (`forensia.timeline.load_filesystem_timeline` + `relevance.select_relevant_events`),
  si existe para alguna evidencia del caso.

Tabla, orden cronológico ascendente:

| Marca temporal (UTC) | Evento | Severidad | Origen | Referencia |
| --- | --- | --- | --- | --- |
| 2026-03-14T08:12:44Z | Creación de la tarea programada `updater` | alta | Hallazgo | §6.1 · `a1b2c3d4` |
| 2026-03-14T08:13:02Z | `C:\Users\Public\update.exe` — MACB `..cb` | — | Sistema de ficheros | run `7e9f…` |

Reglas:

- **Un hallazgo sin `observed_at` NO entra aquí.** Usar `created_at` fecharía el
  incidente con la hora del análisis. Se listan al final bajo *«Hallazgos sin anclaje
  temporal»* con su referencia a §6.
- Si no hay super-timeline persistido, se dice — y se indica que se genera desde la
  vista Timeline con `tsk_fls -m`.
- **Figura** (fase F): línea temporal dibujada, al estilo de la ilustración de la
  guía (p. 117). Entra en el índice de ilustraciones.
- Nota fija: los sellos temporales son los del sistema de origen; un reloj desajustado
  o una manipulación deliberada de marcas (*timestomping*) los desplaza. Es una
  limitación que §9 recoge.

---

## §4 — MITRE ATT&CK TTPs

**Origen:** `CoverageStore.coverage` + `forensia.mitre.catalog`. **Se conserva la tabla
actual** (`_correlacion_mitre`), que ya cumple: técnica, nombre, táctica, hallazgos que
la sostienen (id + título), veredicto. Los dos ejes ya están separados (P3).

Se añade:

- **Lista de TTPs en el formato de la guía** (p. 118) antes de la tabla, como bloque
  `list`: `T1053.003: Scheduled Task/Job – Cron`. Es lo que un lector técnico escanea.
- **Figura** (fase F): matriz de tácticas con las técnicas tocadas resaltadas, distinguiendo
  visualmente propuesta de confirmada. Entra en el índice de ilustraciones.
- Nota fija ya presente: una técnica propuesta y no dictaminada **no** cuenta como
  confirmada, y una celda sin color significa *no evaluada*, nunca *ausente*.

---

## §5 — Descripción del incidente, alcance y dispositivos

Funde los apartados «Descripción del incidente» (p. 119) y «Dispositivos
proporcionados» (p. 119) porque en Agentopsy comparten origen: la ficha pericial + la
custodia. Subapartados `h3`:

### 5.1 Objeto del encargo y solicitante
`ficha.encargo`, `ficha.solicitante`.

### 5.2 Descripción del incidente
`ficha.incidente` — **lo conocido ANTES del análisis**. Bloque `quote` para dejar visible
que es contexto aportado, no resultado del análisis. Distinción crítica: lo que el
análisis demuestra va a §6 y §9.

### 5.3 Marco temporal
`ficha.marco_temporal.inicio` / `.fin`, con zona explícita. Sin él: *«No consta el marco
temporal del incidente; el análisis no acota su ventana a un intervalo declarado.»*

### 5.4 Alcance y exclusiones
`ficha.alcance`. Se le añade, derivado, lo que Agentopsy **sabe** que no cubre: es
post-mortem (sin análisis en vivo ni adquisición desde el equipo original), y sin
contraste de IOCs contra Threat Intelligence (RULE 7).

### 5.5 Dispositivos y cadena de custodia
Una entrada por evidencia. La tabla `kv` de custodia que ya existe hoy
(`_cadena_custodia`) **se conserva íntegra** y se le anteponen los campos de la ficha:

| Campo | Origen |
| --- | --- |
| Procedencia (adquirido por el perito / proporcionado) | `ficha.dispositivos[].procedencia` |
| Entregado por / el | ficha |
| Descripción física (marca, modelo, nº de serie, precintos) | ficha |
| Identificador, fichero original, **segmentos EWF** | `EvidenceHandle` / `baseline.json` |
| SHA-256 baseline, tamaño | custodia |
| SO y tipo detectados por triaje, con confianza | `EvidenceHandle` |
| Nivel de solo-lectura | custodia |
| Hash de registro, cadena de auditoría verificada | `AuditLog` |

Si `procedencia == "adquirido"`, la guía exige que el proceso de adquisición figure en
§7 (p. 120): se emite una **referencia cruzada** a la subsección de esa evidencia.

Una evidencia registrada sin entrada en la ficha se imprime igual, con «procedencia: no
consta». Una entrada de ficha cuyo `evidence_id` no existe **no puede darse**: el store
la rechaza al escribir.

---

## §6 — Hallazgos

**Origen:** `FindingStore`. **Se conserva la estructura actual** (agrupación por
severidad, bloques `finding`, línea de procedencia de `_finding_provenance`). Cambios:

1. **Numeración estable y referenciable** — `6.1`, `6.2`… por hallazgo, para que §3, §8,
   §9 y §10 puedan citarlo. Hoy solo hay agrupación por severidad, sin ancla.
2. **Los `descarte` se imprimen en su propio subapartado** *«Vías exploradas sin
   resultado»*. No es relleno: es la objetividad que la guía exige (p. 125) — deja
   constancia de que la hipótesis se consideró y no se sostuvo.
3. **La procedencia sube a bloque `kv`** en lugar de la línea `meta` comprimida:
   `run_id` completo, `tool_id`, SHA-256 del artefacto completo, `observed_at`,
   `confidence`. Un perito contrario debe poder reejecutar; un hash truncado a 12
   caracteres no sirve para eso.
4. Nota de cabecera: un hallazgo es un **dato interpretado con procedencia**, no una
   conclusión (P1).

---

## §7 — Trabajos realizados

La sección más extensa (guía p. 120). **Origen:** `forensia.reports.works.tool_runs`.

Jerarquía en tres niveles, como la del ejemplo de la guía:

```
7    Trabajos realizados
7.1  Resumen de ejecuciones                    ← tabla de tool_usage (la de hoy)
7.2  Evidencia «disco-portatil.E01»
     7.2.1  Triaje y determinación del perfil de SO
     7.2.2  tsk_mmls — tabla de particiones
     7.2.3  tsk_fls — enumeración del sistema de ficheros
     7.2.4  bulk_extractor — extracción de artefactos
7.3  Evidencia «memoria.raw»
     7.3.1  volatility3 — …
```

Por cada ejecución, un bloque `kv` + un bloque `code` con el argv literal:

| Campo | Origen (`audit.jsonl`) |
| --- | --- |
| Identificador de ejecución (`run_id`) | `tool_run_start.run_id` |
| Herramienta y **versión** | `tool_id` + `tool_version` (manifiesto del maletín) |
| Evidencia y SHA-256 baseline | `evidence_id`, `baseline_sha256` |
| Inicio / fin (UTC) | `ts_utc` de start / finish |
| Código de salida | `tool_run_finish.exit_code` |
| SHA-256 de stdout / stderr | `stdout_sha256`, `stderr_sha256` |
| Ficheros de salida | `output_files_count` |
| Artefactos de entrada | `derived_inputs[]` (id, relpath, hash verificado) |
| Hallazgos derivados | `finding_ids` que citan ese `run_id` → referencia cruzada a §6 |

```
$ tsk_fls -m C:/ -r -o 2048 /evidence/<id>/original.E01
```

Reglas:

- **Las ejecuciones con `exit_code != 0` se imprimen igual**, con su `error_message`. Un
  informe que solo muestra lo que funcionó no es reproducible, y esos fallos alimentan
  las limitaciones de §9.
- El argv es el **literal auditado**, no una reconstrucción ni la intención declarada
  por el modelo (FORENSIC INVARIANT 4).
- Si `ficha.dispositivos[].procedencia == "adquirido"`, la subsección de esa evidencia
  abre con el proceso de adquisición (guía p. 120).
- Párrafo de cierre: cualquier tercero con la misma imagen, el mismo maletín y estos
  argv reproduce el análisis — que es la definición de reproducibilidad de la guía.

---

## §8 — Indicadores de compromiso (IOCs)

**Origen:** `IocStore` agregado por `(ioc_type, value)` + veredictos del perito.

Tabla, con las cuatro columnas de la guía (p. 122) más la trazabilidad que Agentopsy
puede dar y la guía no contempla:

| Tipo de IOC | Valor | Descripción / Contexto | Fuente del hallazgo | Procedencia | Veredicto |
| --- | --- | --- | --- | --- | --- |
| Hash (SHA-256) | `e3b0c442…1e46` | Ejecutable de malware (Backdoor X) | `C:\Users\Public\update.exe` | run `7e9f…` · §6.2 | Validado |
| IP maliciosa | `185.239.236[.]170` | Servidor de mando y control (C2) | Conexiones salientes | run `a13c…` · §6.4 | Sin dictaminar |

Reglas:

- **Valores de red *defanged*** en informe y UI (P5): `185.239.236[.]170`,
  `hxxp://dominio[.]tld`. El valor exacto va en el CSV de export, que es el canal máquina.
  Se indica en una nota al pie de la tabla para que nadie crea que el dato está alterado.
- Un IOC sin `run_id` no existe — el store lo rechaza.
- **Nota fija obligatoria:** *«La guía metodológica recomienda contrastar cada indicador
  con fuentes de Threat Intelligence actualizadas. Agentopsy no realiza llamadas de red
  propias (no lleva credenciales ni consulta servicios externos), de modo que ese
  contraste queda fuera del alcance de la herramienta y a cargo del perito. Los
  indicadores se presentan como observados en la evidencia, no como confirmados por
  inteligencia de amenazas.»*
- Sin IOCs: se dice, y se indica que el agente los registra con `record_ioc` durante el
  análisis.
- Pie: enlace al export CSV para SIEM/EDR/firewall.

---

## §9 — Conclusiones

**Cada conclusión, un bloque, con referencia cruzada obligatoria.** Se deriva de los
hallazgos, no de recuentos.

Formato por conclusión:

> **9.1** Se acredita la creación de un mecanismo de persistencia en el sistema
> analizado. *Se sostiene en:* §6.1 (`a1b2c3d4`, severidad alta, confianza 0,90),
> §6.3 (`f5e6d7c8`). *Técnica ATT&CK asociada:* T1053.003, **confirmada** por dictamen
> pericial.

Reglas de generación:

- Se emite una conclusión por **grupo de hallazgos que sostienen una misma técnica
  confirmada**, y una por cada hallazgo `critical`/`high` no cubierto por ninguna.
- Un hallazgo con `confidence < 0.5` **no genera conclusión firme**: se enuncia como
  indicio y se remite a §6. La guía es explícita: *«no todo hallazgo permite una
  conclusión firme»*.
- Sin hallazgos, se conserva el texto honesto de hoy.

### 9.x Limitaciones del análisis

Subapartado **obligatorio** (guía p. 123), derivado — no redactado a mano:

| Limitación | Cómo se detecta |
| --- | --- |
| Herramientas que fallaron | ejecuciones con `exit_code != 0` en §7 |
| Evidencias sin perfil de SO determinado con confianza | `os_profile_source`, triaje `unknown` / baja confianza |
| Hallazgos sin anclaje temporal | `observed_at` nulo |
| Hallazgos sin procedencia de artefacto | `artifact_sha256` nulo |
| Super-timeline no generado | ninguna evidencia con timeline persistido |
| IOCs sin contraste de Threat Intelligence | siempre (RULE 7) |
| Fiabilidad de las marcas temporales | siempre: dependen del reloj del sistema de origen y son manipulables |
| Alcance post-mortem | siempre: sin análisis en vivo ni adquisición desde el equipo original |
| Campos de la ficha pericial sin cumplimentar | `ficha.*` vacíos |

Cierre fijo: el documento nace en **BORRADOR** y adquiere validez pericial al firmarse,
acto registrado en el audit hash-encadenado.

---

## §10 — Recomendaciones y plan de acción

**Origen:** `ficha.recomendaciones[]`, ordenadas por prioridad (`alta` → `media` → `baja`).

Un `h3` por prioridad; dentro, un `kv` por recomendación:

| Campo | Contenido |
| --- | --- |
| Recomendación | `texto` |
| Justificación | referencia cruzada a los hallazgos de `finding_ids` (§6.x) |
| Plazo estimado | `plazo` |
| Recursos necesarios | `recursos` |
| Cómo se medirá el éxito | `metrica` |

Reglas:

- **Una recomendación sin `finding_ids` no se imprime en la tabla principal**: va a
  *«Recomendaciones generales no vinculadas a un hallazgo concreto»*. La guía lo exige
  (p. 124: *«cada recomendación esté claramente vinculada a los hallazgos que la
  justifican»*), y mantiene la separación conclusión ≠ acción.
- Sección vacía: *«No se han registrado recomendaciones en la ficha pericial del caso.
  Las recomendaciones son un acto del perito, no un resultado del análisis
  automatizado.»* — que es exactamente la distinción de la guía entre conclusiones
  (qué ocurrió) y recomendaciones (qué hacer).

---

## Anexo A — Traza de la investigación

`build_investigation_timeline` completo: qué hizo el analista y cuándo. Va a anexo, no
al cuerpo: es trazabilidad del trabajo, no del incidente (P1).

## Anexo B — Verificación de integridad

- SHA-256 del contenido del documento y cómo recomputarlo.
- Estado de la cadena hash del audit del caso (`hash_chain_verified`).
- Baseline de cada evidencia y el resultado de la reverificación al cierre.

---

## Numeración final

| # | Sección | ¿Nueva? |
| --- | --- | --- |
| — | Portada · índice · índice de ilustraciones | ampliada |
| 1 | Control de versiones | **nueva** |
| 2 | Resumen ejecutivo | reescrita |
| 3 | Línea de tiempo del incidente | **nueva** |
| 4 | MITRE ATT&CK TTPs | conservada + figura |
| 5 | Descripción del incidente, alcance y dispositivos | **nueva** (absorbe la custodia actual) |
| 6 | Hallazgos | conservada + numeración y procedencia completa |
| 7 | Trabajos realizados | **reescrita a fondo** |
| 8 | Indicadores de compromiso | **nueva** |
| 9 | Conclusiones y limitaciones | reescrita |
| 10 | Recomendaciones y plan de acción | **nueva** |
| A | Traza de la investigación | **nueva** |
| B | Verificación de integridad | **nueva** |

El orden sigue el de la guía (p. 115), que a su vez sigue la lógica que ella misma pide
(p. 111): contexto → metodología → hallazgos → análisis → conclusiones →
recomendaciones. La única desviación es subir la línea de tiempo y las TTPs por delante
de la descripción del incidente: es el orden de la propia guía, y responde a que un
lector técnico escanea primero cronología y TTPs.
