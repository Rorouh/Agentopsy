# Rediseño de informes — 2026-07

> **Estado:** diseño aprobado en alcance, pendiente de implementar.
> **Rama:** `tools`.
> **Fuente normativa:** UCM · Máster en Ciberseguridad · *Introducción a la práctica
> forense* v1.2.0, TEMA IV «Presentación de resultados», apartado **«Cómo documentar
> la investigación»** (pp. 109-126). En adelante, **la guía**.
> **Normas que la guía invoca:** ISO/IEC 27037:2016 (identificación, recolección,
> adquisición y preservación de evidencia digital) y **UNE 197010:2015** (elaboración
> de informes periciales sobre TIC).

Este directorio contiene:

| Fichero | Qué es |
| --- | --- |
| `README.md` (este) | Diagnóstico, principios y el mapeo **dato → origen** |
| [`plantilla-informe.md`](plantilla-informe.md) | La plantilla de las 10 secciones, bloque a bloque |
| [`plan-migracion.md`](plan-migracion.md) | Fases, ficheros tocados, tests y gates de CI |

---

## 1. El problema

El informe que Agentopsy genera hoy (`forensia.reports.generator.build_pericial_report`)
tiene **7 secciones**:

```
1. Resumen ejecutivo          5. Hallazgos
2. Datos del informe y del perito   6. Correlación MITRE ATT&CK
3. Cadena de custodia         7. Conclusiones
4. Metodología y herramientas empleadas
```

La guía fija **10 secciones esenciales** (p. 115) más los requisitos de forma y de
calidad de las pp. 109-114 y 123-126. El desajuste no es cosmético:

### 1.1 Faltan cinco secciones enteras

| Sección de la guía | Estado hoy |
| --- | --- |
| Control de versiones | **No existe.** Hay un campo `version` suelto en el documento, sin histórico ni trazabilidad entre revisiones |
| Línea de tiempo | **No entra en el informe.** `forensia.timeline` existe y tiene su vista, pero el informe no la incorpora |
| Descripción del incidente | **No existe.** El informe no dice qué se investigó, para quién, ni con qué marco temporal |
| IOCs | **No existe.** No hay modelo, ni almacén, ni herramienta del agente, ni tabla |
| Recomendaciones y plan de acción | **No existe** |

### 1.2 Y dos de las que existen incumplen el estándar

**«Metodología y herramientas empleadas» (§4) tira a la basura la trazabilidad que el
sistema ya tiene.** La guía es explícita (p. 112):

> «La descripción de las metodologías debe ser tan detallada que el análisis se pueda
> reproducir. Esto significa especificar las versiones del software, las configuraciones
> de hardware y cualquier ajuste personalizado que se haya hecho a las herramientas
> estándar.»

El informe muestra hoy una tabla de **recuentos**:

| Herramienta | Ejecuciones | Correctas | Con error |
| --- | --- | --- | --- |
| `tsk_fls` | 3 | 3 | 0 |

Mientras tanto, `audit.jsonl` ya guarda, por cada ejecución y de forma
hash-encadenada (FORENSIC INVARIANT 4):

`run_id` · `tool_id` · **`argv` literal** · `params` · **`tool_version` autoritativa
del manifiesto del maletín** · `evidence_id` · `baseline_sha256` · `derived_inputs[]`
· `exit_code` · `stdout_sha256` · `stderr_sha256` · `output_files_count`.

Es decir: **Agentopsy ya cumple el requisito de reproducibilidad de la guía a nivel de
dato, y lo pierde a nivel de informe.** Ese es el peor defecto del subsistema actual, y
el más barato de arreglar — el dato está ahí, hay que dejar de agregarlo a un número.

La guía además llama a esta sección *«probablemente la más extensa de nuestro informe»*
(p. 120) y la organiza jerárquicamente por artefacto analizado. Hoy son cuatro columnas.

**«Conclusiones» (§7) es estadística, no pericia.** Hoy redacta *«el análisis ha
permitido documentar N hallazgos, con M técnicas confirmadas»*. La guía (p. 123):

> «Cada conclusión debe estar ligada a una prueba concreta del informe, y cualquier
> limitación o incertidumbre debe comunicarse con transparencia.»

No hay referencias cruzadas ni apartado de limitaciones.

### 1.3 Tres defectos de forma

1. **El índice no lleva números de página** (`pdf._toc` lista títulos). La guía los pide
   expresamente para informes que van a usarse como prueba (p. 112).
2. **No hay índice de ilustraciones** — la guía lo exige junto al índice (p. 111) — ni
   ilustraciones que indexar: el PDF no dibuja ni la línea de tiempo ni la matriz ATT&CK,
   pese a que la guía las muestra como las dos figuras canónicas del informe.
3. **`pdf._s()` degrada el contenido a latin-1** (`.encode("latin-1", "replace")`). Un
   nombre de fichero cirílico, griego o CJK **procedente de la evidencia** se convierte
   en `?` en el informe. Eso no es un defecto tipográfico: es **corrupción silenciosa de
   un dato probatorio**, y contradice la propia RULE 2. Ver `plan-migracion.md` §F4.

---

## 2. Principios del rediseño

Cinco reglas que gobiernan todas las decisiones de abajo.

### P1 — Los tres niveles no se mezclan

La guía lo dice en las conclusiones (p. 123) y es la columna vertebral del rediseño:

> «Es importante diferenciar claramente entre los **datos observados**, los **hallazgos
> relevantes** y las **conclusiones extraídas**. No todo dato constituye un hallazgo, y
> no todo hallazgo permite una conclusión firme.»

Se materializa en la estructura del informe:

| Nivel | Qué es en Agentopsy | Dónde vive en el informe |
| --- | --- | --- |
| **Dato observado** | Salida de un `ArtifactRun` (argv + exit + hash) | §7 Trabajos realizados |
| **Hallazgo** | `Finding` con procedencia (`run_id`) | §6 Hallazgos |
| **Conclusión** | Síntesis, con referencia cruzada al hallazgo que la sostiene | §9 Conclusiones |

Una conclusión sin hallazgo que la ancle **no se escribe**. Un hallazgo sin `run_id` ya
lo rechaza `FindingStore` (salvo `finding_kind="descarte"`).

### P2 — Nada se inventa; lo que falta se declara «no consta» (RULE 2)

La guía prohíbe suposiciones (p. 107: *«sin suposiciones ni interpretaciones
subjetivas»*). RULE 2 dice lo mismo desde la ingeniería. Consecuencia operativa: **una
sección sin dato no se omite y no se rellena** — se imprime con una nota explícita de
qué falta y quién debe aportarlo. Un informe que dice «no consta el marco temporal del
incidente» es honesto; uno que se lo inventa o que calla la sección, no.

### P3 — Dos ejes que nunca se funden

Ya vigente para MITRE (propuesta del agente ≠ veredicto del perito) y se extiende a los
IOCs. El agente **propone**; el perito **dictamina**. Un IOC propuesto y no validado no
se presenta como confirmado. Agentopsy no hace llamadas a la nube (RULE 7), así que **no
puede contrastar un IOC contra Threat Intelligence** — la guía lo pide (p. 122) y el
informe debe decir explícitamente que ese contraste queda fuera del alcance de la
herramienta y a cargo del perito.

### P4 — Lo derivable se deriva; lo que exige contexto humano lo firma el perito

La evidencia no contiene el encargo, ni quién entregó el disco, ni qué debe hacer la
organización a continuación. Eso lo aporta el perito en una **ficha pericial** del caso
(§3.2). Todo lo demás sale de los almacenes que ya existen.

### P5 — La evidencia es dato hostil, también en el informe

Los valores de IOC (dominios, URLs, rutas) y los nombres de fichero vienen de la
evidencia y pueden ser payloads. En la UI se renderizan con `textContent`
(SECURITY INVARIANT 8) y **nunca como enlace**; en informe y UI, los indicadores de red
van **defanged** (`hxxp://`, `dominio[.]tld`, `192.168.0[.]1`) para que copiar el
informe no arme una petición. El valor exacto se conserva en `iocs.jsonl` y en el CSV
de export, que es el canal máquina.

---

## 3. Mapeo dato → origen

La tabla que gobierna la implementación. **«Origen»** es de dónde sale el dato en
tiempo de generación del informe.

### 3.1 Lo que ya existe en el caso

| Dato | Origen | Sección del informe |
| --- | --- | --- |
| Nombre, examinador, estado, fechas del caso | `Case` (`case.json`) | §2, portada |
| `os_profile` + `os_profile_source` | `Case` (determinado por `forensia.triage`) | §2, §5 |
| SHA-256 baseline, tamaño, segmentos EWF, nivel de solo-lectura | `build_custody_act` / `baseline.json` | §5 |
| `register_entry_hash`, `hash_chain_verified` | `AuditLog` | §5 |
| SO y tipo detectados por triaje | `EvidenceHandle` (`detected_os`, `detected_kind`) | §5 |
| **argv literal, `tool_version`, `exit_code`, hashes de salida, `derived_inputs`** | `audit.jsonl` (`tool_run_start` / `tool_run_finish`) | **§7** |
| Hallazgos: título, resumen, severidad, `confidence`, `observed_at`, `run_id`, `artifact_sha256`, `finding_kind` | `FindingStore` | §6 |
| Técnicas propuestas / veredicto / rationale | `CoverageStore` | §4 |
| Catálogo ATT&CK Enterprise (nombre, táctica) | `forensia.mitre.catalog` | §4 |
| Eventos MACB relevantes del super-timeline | `forensia.timeline` + `relevance.select_relevant_events` | §3 |
| Revisiones anteriores del informe | `DocumentStore.list` (documentos `type="pericial"`) | **§1** |
| Versión de la herramienta | `forensia.__version__` | §2 |

Dos derivaciones no obvias, que son las que hacen barata la implementación:

- **§1 Control de versiones no necesita campo nuevo.** El histórico de revisiones *es*
  la lista de documentos periciales previos del caso, cada uno con su `version`,
  `created_at`, `author`, `status` (`draft`/`final`) y su **SHA-256 de contenido**. Eso
  es un control de versiones con integridad criptográfica, mejor que la tabla manual que
  describe la guía.
- **§3 Línea de tiempo del incidente ≠ timeline de investigación.** La guía pide los
  *hitos del incidente* (p. 116), no el registro de lo que hizo el analista. Por tanto:
  - **§3** se construye con los `observed_at` de los hallazgos (cuándo ocurrió el hecho
    *en la evidencia*) + los eventos MACB relevantes del super-timeline persistido.
  - El timeline de investigación (`build_investigation_timeline`: ejecuciones + registro
    de hallazgos) es **trazabilidad del trabajo** y va a §7 / anexo.
  - Un hallazgo sin `observed_at` **no se coloca en la línea temporal** (no se usa
    `created_at` como sustituto — sería fechar el incidente con la hora del análisis).
    Se listan aparte como «hallazgos sin anclaje temporal».

### 3.2 Lo que hay que crear

| Dato | Mecanismo nuevo | Sección |
| --- | --- | --- |
| Encargo, solicitante, alcance, marco temporal, limitaciones declaradas | **Ficha pericial** — `<case_dir>/ficha.json` (`FichaStore`) | §5 |
| Procedencia de cada dispositivo (adquirido por el perito vs. proporcionado, quién y cuándo lo entregó) | **Ficha pericial**, por `evidence_id` | §5 |
| Recomendaciones priorizadas, ligadas a hallazgos | **Ficha pericial** | §10 |
| Indicadores de compromiso | **`IocStore`** (`<case_dir>/iocs.jsonl`) + herramienta `record_ioc` + veredicto del perito | §8 |
| Ilustraciones (línea de tiempo, matriz ATT&CK) | Render en `forensia.reports.pdf` (fpdf2 nativo, sin dependencia nueva) | §3, §4 |

---

## 4. Contratos nuevos

### 4.1 `FichaStore` — la ficha pericial del caso

Vive en `<case_dir>/ficha.json`, gestionada por `backend/forensia/ficha/store.py`. **No
va en `case.json`**: ese fichero es el registro de identidad y enrutado del caso y debe
seguir siendo pequeño; la ficha es contenido pericial voluminoso y editable.

```jsonc
{
  "encargo":        "",   // objeto del encargo: qué se pide investigar
  "solicitante":    "",   // quién lo encarga
  "alcance":        "",   // qué entra y qué NO entra en el análisis
  "incidente":      "",   // descripción del incidente conocida ANTES del análisis
  "marco_temporal": { "inicio": null, "fin": null },   // ISO-8601 con zona explícita
  "limitaciones":   "",   // limitaciones declaradas por el perito
  "dispositivos": [
    {
      "evidence_id":  "…uuid4…",       // debe existir en el caso; si no, se rechaza
      "procedencia":  "proporcionado", // "adquirido" | "proporcionado"
      "entregado_por": "",
      "entregado_el":  null,           // ISO-8601 con zona
      "descripcion":   "",             // marca, modelo, nº de serie, precintos
      "observaciones": ""
    }
  ],
  "recomendaciones": [
    {
      "id":        "…uuid4…",
      "texto":     "",
      "prioridad": "alta",             // "alta" | "media" | "baja"
      "finding_ids": ["…"],            // los hallazgos que la justifican
      "plazo":     "",
      "recursos":  "",
      "metrica":   ""                  // cómo se medirá el éxito (guía p. 124)
    }
  ]
}
```

**Reglas.** Todos los campos son opcionales y arrancan vacíos; un campo vacío se imprime
como «no consta» con la nota de quién debe aportarlo (P2). `evidence_id` y `finding_ids`
se validan contra los almacenes reales: un id inexistente **rechaza la escritura**, no se
guarda silenciosamente (RULE 2). Toda edición se audita (`ficha_updated`) porque entra en
un documento pericial. Superficie: `GET`/`PUT /api/cases/{id}/ficha` (adaptador fino,
RULE 3) y un formulario en la UI.

### 4.2 `IocStore` + `record_ioc`

`<case_dir>/iocs.jsonl`, append-only, espejo exacto de `FindingStore`.

```python
@dataclass(frozen=True)
class Ioc:
    id: str                      # uuid4
    case_id: str
    ioc_type: str                # enum CERRADA (abajo)
    value: str                   # normalizado y validado según el tipo
    context: str                 # «Descripción/Contexto» de la tabla de la guía
    source: str                  # «Fuente del hallazgo»: ruta, clave, tabla concreta
    evidence_id: str | None
    tool_id: str | None
    run_id: str | None           # OBLIGATORIO — misma regla que un hallazgo afirmativo
    finding_id: str | None       # el hallazgo del que cuelga, si cuelga de uno
    artifact_sha256: str | None
    observed_at: str | None
    confidence: float | None
    created_at: str
```

**Tipos (enum cerrada).** `hash_md5` · `hash_sha1` · `hash_sha256` · `ip` · `dominio` ·
`url` · `email` · `ruta_archivo` · `nombre_archivo` · `clave_registro` · `proceso` ·
`servicio` · `tarea_programada` · `cuenta_usuario` · `mutex` · `user_agent` ·
`certificado`. Un tipo fuera de la enum rechaza el registro, igual que un `mitre_hints`
fuera de la semilla.

**Validación por tipo (RULE 2 — un IOC mal formado es ruido en un SIEM).** `hash_sha256`
exige 64 hex; `hash_md5`, 32; `hash_sha1`, 40; `ip` debe parsear con `ipaddress`;
`dominio` y `url` contra un patrón estricto. El valor se guarda **crudo y exacto**; el
*defanging* es una transformación de presentación (P5), nunca de almacenamiento.

**Procedencia obligatoria.** Un IOC es una afirmación sobre la evidencia: sin `run_id`
que lo sostenga es indistinguible de una alucinación. Se rechaza sin él — no hay
equivalente de `finding_kind="descarte"` para un IOC.

**Deduplicación en lectura, no en escritura.** El almacén es append-only y tonto (como
findings); el informe agrega por `(ioc_type, value)` y lista todas las apariciones. Así
un mismo hash visto en tres runs conserva las tres procedencias.

**Veredicto del perito (P3).** Eje separado en `ioc_adjudications.jsonl`:
`validado` / `descartado` / sin dictaminar, con `rationale` obligatorio y entrada en el
audit (`ioc_adjudicated`). Espejo de `mitre_proposals` / `mitre_adjudicated`.

**`record_ioc`** es una herramienta en proceso del agente (side-channel, como
`record_finding` y `annotate_mitre`), no una tool del catálogo: no ejecuta nada, escribe
en el almacén del caso. Schema en `agent/tool_schemas.py`, `additionalProperties: false`,
con los mismos avisos anti-alucinación que `record_finding`.

**Export.** `GET /api/cases/{id}/iocs/export.csv` — columnas exactas de la guía (p. 122):
`Tipo de IOC | Valor | Descripción/Contexto | Fuente del hallazgo`, más
`run_id | evidence_id | observed_at | veredicto` para la trazabilidad que la guía no
contempla y Agentopsy sí puede dar. STIX/MISP queda fuera de alcance (nota en
`plan-migracion.md` §G).

### 4.3 `forensia.reports.works` — «Trabajos realizados»

Módulo nuevo que reensambla el audit log en la unidad que le importa al perito: **la
ejecución**, no el recuento.

```python
def tool_runs(case_id: str) -> list[dict[str, Any]]:
    """Una entrada por ArtifactRun, en orden cronológico, con TODO lo auditado:
    run_id, tool_id, tool_version, argv literal, params, evidence_id,
    baseline_sha256, started_at, finished_at, exit_code, status,
    stdout_sha256, stderr_sha256, output_files_count, derived_inputs[],
    y los finding_ids que citan ese run_id."""
```

`toolkit.usage.tool_usage` **se conserva** — es la vista del panel «Tools» de la UI y
sigue valiendo como tabla resumen de cabecera de §7. Lo que cambia es que deja de ser lo
*único* que ve el lector del informe.

---

## 5. Trazabilidad con la guía

Cada requisito del apartado «Cómo documentar la investigación», y dónde queda cubierto.

| Requisito de la guía | Página | Dónde se cumple |
| --- | --- | --- |
| Objetivo, preciso, completo, claro, reproducible | 108 | P1, P2 y §7 (argv + versiones) |
| Cadena de custodia meticulosa: quién, cuándo, qué | 112 | §5 (ya cubierto; se añade procedencia del dispositivo) |
| Integridad verificada con hash en varios momentos | 112 | §5 — `baseline` + `verify` + cadena del audit |
| Metadatos preservados y documentados | 113 | §6 (`observed_at`, `artifact_sha256`) y §3 |
| Versiones de software y parámetros exactos | 110, 112 | **§7** — `tool_version` + `argv` |
| Fechas, horas y **zonas horarias** de todo | 109 | Todo el informe en UTC explícito (`TIMEZONE`), nunca hora local implícita |
| Correlación entre evidencias | 113 | §4 (ATT&CK) + el grafo `forensia.knowledge` |
| Portada, índice, índice de ilustraciones, paginación, referencias cruzadas | 111-112 | `pdf.py` — ver `plan-migracion.md` fase F |
| Control de versiones | 115 | §1, derivado del `DocumentStore` |
| Resumen ejecutivo ≤ 2 páginas, no técnico | 115 | §2 con cota dura |
| Línea de tiempo de hitos | 116 | §3 |
| MITRE ATT&CK TTPs | 118 | §4 (ya cubierto) |
| Descripción del incidente y marco temporal | 119 | §5 ← ficha pericial |
| Dispositivos: adquiridos vs. proporcionados | 119 | §5 ← ficha pericial |
| Trabajos realizados, jerárquico por artefacto | 120 | §7 |
| IOCs en tabla accionable | 121-122 | §8 + export CSV |
| Conclusiones ligadas a prueba concreta; limitaciones transparentes | 123 | §9 con referencias cruzadas y subapartado de limitaciones |
| Recomendaciones priorizadas con recursos, plazos y métrica | 124 | §10 ← ficha pericial |
| Objetividad; explicaciones alternativas consideradas | 125 | §9 — hallazgos `descarte` y técnicas `descartada` se imprimen, no se ocultan |

**Un requisito que NO se puede cumplir y hay que declarar:** contrastar los IOCs contra
Threat Intelligence actualizada (p. 122). Agentopsy no hace llamadas a la nube por sí
mismo (RULE 7 / SECURITY INVARIANT 7). El informe lo dice en §8 en vez de simularlo.

---

## 6. Qué NO cambia

- El modelo de bloques del `Document` (`p`, `h3`, `quote`, `list`, `code`, `kv`, `table`,
  `finding`) es suficiente para las 10 secciones. **No se añaden tipos de bloque** salvo
  los dos de figura de la fase F (`figure_timeline`, `figure_mitre`), que se validan igual.
- El `sha256` de contenido y la semántica `draft` → `final` (firmar no altera el
  contenido; un `final` no se borra). Un informe con más secciones sigue siendo un
  documento con integridad verificable.
- `generate_draft_report` y el ancla `AUTO_DRAFT_TITLE` (refresco sin apilar, nunca toca
  un firmado).
- Las invariantes forenses y de seguridad. El rediseño **solo lee** de los almacenes
  existentes; no toca `EvidenceManager`, ni el dispatcher, ni la puerta de hash.
