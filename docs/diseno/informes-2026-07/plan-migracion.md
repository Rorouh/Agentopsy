# Plan de migración — informes 2026-07

> ⚠️ **SUPERADO (2026-07-30) por [`redaccion-integra.md`](redaccion-integra.md).**
> Estas siete fases describían cómo enriquecer `generator.py` sección a sección;
> ese fichero ya no existe. De todo el plan solo se conservó la **Fase A**, y
> transformada: `forensia/reports/works.py` reensambla las ejecuciones del audit
> con su argv literal, pero ya no para imprimir §7 — para dárselo al modelo como
> material y para VALIDAR que ningún comando citado en el informe se haya
> reescrito. Se mantiene el documento como registro de las decisiones y de los
> orígenes de dato que se identificaron.
>
> Siete fases, ordenadas para que **cada una deje el árbol verde y el informe mejor que
> antes**. Ninguna depende de que la siguiente exista. Las fases A-C son las de mayor
> retorno (arreglan lo que ya está roto sin contratos nuevos); D-E añaden los almacenes;
> F es el PDF; G queda fuera de alcance.

Convenciones: los ficheros son relativos a la raíz del repo. Cada fase lista sus
**gates de CI** (RULE 6) y su **documentación a actualizar** (RULE 4) — ambos son
precondición del push, no un paso posterior.

---

## Fase A — «Trabajos realizados» con argv, versiones y hashes

**Por qué primero.** Es el defecto más grave (`README.md` §1.2) y el más barato: el dato
ya está auditado, solo hay que dejar de agregarlo a un número. No necesita ningún
contrato nuevo, ni ficha, ni IOCs.

**Ficheros**

- `backend/forensia/reports/works.py` — **nuevo**. `tool_runs(case_id)` reensambla
  `audit.jsonl` por `run_id`, emparejando `tool_run_start` con su `tool_run_finish` y
  cruzando los `finding_ids` que citan cada run. Lógica pura (RULE 3): sin `print`, sin
  red, sin `sys.exit`.
- `backend/forensia/reports/generator.py` — `_metodologia` → `_trabajos_realizados`, con
  la jerarquía evidencia → herramienta → ejecución de `plantilla-informe.md` §7.
- `backend/forensia/toolkit/usage.py` — **sin cambios**. Sigue sirviendo al panel «Tools»
  y pasa a ser la tabla resumen de §7.1.

**Tests** (`backend/tests/test_reports_works.py`)

1. Un caso con 2 runs (uno `exit 0`, otro `exit 1`) produce 2 entradas, ambas presentes.
2. El `argv` del informe es **token a token** el `argv` de `tool_run_start` — nunca una
   reconstrucción.
3. `tool_version` viaja al informe; un run sin versión en el audit no inventa `"unknown"`.
4. Un `run_id` sin `finish` (fallo de transporte) aparece con estado incompleto, no se
   descarta.
5. Los `finding_ids` cruzados son exactamente los que citan ese `run_id`.

**Gates:** `ruff check .` + `pytest -q` desde `backend/`.
**Docs:** `CLAUDE.md` §Status; `tools/graph/CONTEXT.md` (módulo nuevo).

---

## Fase B — Conclusiones trazadas y limitaciones

**Ficheros**

- `backend/forensia/reports/generator.py` — `_conclusiones` reescrita según
  `plantilla-informe.md` §9: una conclusión por grupo de hallazgos que sostiene una
  técnica confirmada, referencia cruzada obligatoria, y el subapartado de limitaciones
  **derivado** (no redactado a mano).

**Tests** (`backend/tests/test_reports_conclusiones.py`)

1. Ninguna conclusión sin al menos un `finding_id` citado.
2. Un hallazgo con `confidence < 0.5` no genera conclusión firme.
3. Un run con `exit_code != 0` aparece en limitaciones.
4. Un hallazgo sin `observed_at` aparece en limitaciones.
5. Las limitaciones que son siempre ciertas (post-mortem, sin TI, fiabilidad de marcas)
   están presentes aunque el caso esté impoluto.

**Gates:** backend.
**Docs:** `CLAUDE.md` §Status.

---

## Fase C — Numeración, referencias cruzadas y línea de tiempo del incidente

**Ficheros**

- `backend/forensia/reports/generator.py` — numeración estable de hallazgos (§6.x),
  sección §3 nueva a partir de `observed_at` + `select_relevant_events`, §1 control de
  versiones derivado de `DocumentStore.list`, y reordenación a la numeración final.
- `backend/forensia/reports/store.py` — **sin cambios de schema**. El modelo de bloques
  actual basta.

**Tests** (`backend/tests/test_reports_estructura.py`)

1. Un hallazgo sin `observed_at` **no** aparece en §3 (regresión: no usar `created_at`).
2. Toda marca temporal de §3 acaba en `Z`.
3. §1 lista las revisiones previas del caso con su SHA-256, y la actual.
4. Los `num` de sección son únicos y en orden.
5. Toda referencia cruzada emitida apunta a una sección que existe.

**Gates:** backend.
**Docs:** `CLAUDE.md` §Status (la síntesis del informe desde los hallazgos deja de estar
pendiente); `docs/agentes/contrato-paquetes.md`, tabla «La telaraña del caso vive en las
stores por caso» — la fila «Entregables (informe) → `documents/`».

---

## Fase D — Ficha pericial del caso

**Ficheros**

- `backend/forensia/ficha/__init__.py`, `backend/forensia/ficha/store.py` — **nuevos**.
  `FichaStore` sobre `<case_dir>/ficha.json`, con el schema de `README.md` §4.1.
  Validación estricta: `evidence_id` y `finding_ids` contra los almacenes reales; ISO-8601
  con zona explícita en las fechas; cotas de longitud como en `cases.manager`. Toda
  escritura audita `ficha_updated`.
- `backend/forensia/routers/ficha.py` — **nuevo**. `GET /api/cases/{case_id}/ficha` +
  `POST /api/cases/{case_id}/ficha`, adaptador fino (RULE 3), con
  `dependencies=[Depends(require_token)]`. **`POST`, no `PUT`**: es la convención del
  repo — todas las mutaciones son `POST /api/cases/{id}/<acción>` (`close`, `reopen`,
  `update`, `delete`); el único `DELETE` del árbol está en `documents.py`.
- `backend/forensia/server.py` — `app.include_router(ficha.router)` en `create_app`
  (los routers se registran ahí, no en `routers/__init__.py`, que solo lleva docstring).
- `backend/forensia/reports/generator.py` — §5 y §10 leen la ficha; campos vacíos → «no
  consta» (P2).
- `web/src/pages/…` — formulario de ficha. Ubicación natural: la escalera de fases del
  sidebar, junto a la gestión del caso. `web/src/api/client.ts` gana los dos métodos.

**Tests** (`backend/tests/test_ficha_store.py`, `backend/tests/test_routers_ficha.py`)

1. Un `evidence_id` inexistente en `dispositivos[]` **rechaza** el `PUT` (no se guarda
   parcialmente).
2. Un `finding_id` inexistente en una recomendación lo rechaza igual.
3. `procedencia` fuera de `{adquirido, proporcionado}` lo rechaza.
4. Una fecha sin zona horaria lo rechaza.
5. Ficha vacía → el informe imprime «no consta» en §5 y §10, y **no omite** las secciones.
6. El `PUT` deja entrada `ficha_updated` en el audit y la cadena sigue verificando.
7. `case_id` malformado → 422, no traversal (SECURITY INVARIANT 6).

**Gates:** backend + web (`npm ci`, `npm run typecheck`, `npm run build`).
**Docs:** `CLAUDE.md` §Status; `tools/graph/CONTEXT.md`; `docs/operacion/` (flujo del
perito).

---

## Fase E — IOCs

**Ficheros**

- `backend/forensia/iocs/__init__.py`, `backend/forensia/iocs/store.py` — **nuevos**.
  `IocStore` (append-only `iocs.jsonl`) + `IocAdjudicationStore`
  (`ioc_adjudications.jsonl`), con el contrato de `README.md` §4.2.
- `backend/forensia/iocs/defang.py` — **nuevo**. Transformación de **presentación**
  (`defang(value, ioc_type)`), pura y sin estado. Nunca se aplica al almacenar.
- `backend/forensia/agent/tool_schemas.py` — schema de `record_ioc`,
  `additionalProperties: false`, con los avisos anti-alucinación de `record_finding`.
- `backend/forensia/agent/agent.py` — despacho en proceso de `record_ioc`, junto a
  `record_finding` y `annotate_mitre` (~línea 490).
- `agentes/agent.md` — sección nueva: cuándo registrar un IOC y la exigencia de `run_id`.
  Es **el único fichero de comportamiento** que lee el agente.
- `backend/forensia/routers/iocs.py` — **nuevo**. `GET` lista, `POST …/adjudicate`
  (rationale obligatorio), `GET …/export.csv` (espejo de `timeline/export.csv`).
  Registrar en `server.py`, como en la fase D.
- `backend/forensia/reports/generator.py` — §8.
- `web/src/pages/…` — vista de IOCs con veredicto del perito; valores **defanged** y
  renderizados con `textContent`, **nunca** como `<a href>` (SECURITY INVARIANT 8, P5).

**Tests** (`backend/tests/test_iocs_store.py`, `…_iocs.py`, `…_defang.py`)

1. Un IOC sin `run_id` se rechaza.
2. `ioc_type` fuera de la enum se rechaza.
3. `hash_sha256` con 63 hex se rechaza; una IP no parseable se rechaza.
4. El valor se almacena **crudo**; `defang` solo actúa en la salida.
5. El mismo `(tipo, valor)` en dos runs → una fila agregada con **dos** procedencias.
6. Un veredicto sin `rationale` se rechaza; queda en el audit (`ioc_adjudicated`).
7. Propuesta y veredicto no se funden: un IOC propuesto y no dictaminado no se presenta
   como validado.
8. El CSV lleva las cuatro columnas de la guía + trazabilidad, y escapa comas/comillas.
9. **Regresión de inyección:** un valor de IOC con `<script>` o `=cmd|…` no se
   interpreta ni en la UI ni en el CSV.
10. La nota fija de «sin contraste de Threat Intelligence» aparece siempre en §8.

**Gates:** backend + web.
**Docs:** `CLAUDE.md` §Status y §Trained-agent packages; `agentes/README.md`;
`docs/agentes/contrato-paquetes.md`; `tools/graph/CONTEXT.md`.

---

## Fase F — El PDF a la altura del estándar

Cuatro trabajos independientes; F4 es un arreglo de fidelidad probatoria, no cosmética.

### F1 — Índice con números de página
`pdf._toc` lista títulos sin página. fpdf2 resuelve con `insert_toc_placeholder` (render
en dos pasadas) o con una pasada previa que registre `page_no()` por sección. La guía lo
exige para documentos que van a usarse como prueba (p. 112).

### F2 — Figuras + índice de ilustraciones
Dos bloques nuevos, validados como el resto en `store._BLOCK_TYPES`:

- `figure_timeline` — línea temporal dibujada (§3), al estilo de la ilustración de la
  guía (p. 117).
- `figure_mitre` — matriz de tácticas con las técnicas tocadas, distinguiendo propuesta
  de confirmada (p. 118).

Se dibujan con las primitivas nativas de fpdf2 (`rect`, `line`, `text`): **sin
dependencia nueva** — matplotlib no entra (RULE 1: todo viaja en la imagen `api`, y una
dependencia gráfica pesada por dos figuras no lo justifica).

Con las figuras aparece el **índice de ilustraciones** tras el de contenidos.

### F3 — Estado del documento en portada
`BORRADOR` / `FIRMADO` en grande. Hoy solo se lee al pie. Un borrador que parece
definitivo es un riesgo real.

### F4 — Unicode, no latin-1  ⚠️ **fidelidad probatoria**

`pdf._s()` hace `.encode("latin-1", "replace")`: un nombre de fichero cirílico, griego o
CJK **procedente de la evidencia** se imprime como `?`. Eso no es un problema
tipográfico, es **corrupción silenciosa de un dato probatorio** — y contradice RULE 2 en
el sitio donde más caro sale, el documento que se firma.

Arreglo: embeber una TTF Unicode (DejaVuSans / DejaVuSansMono, licencia libre) con
`pdf.add_font(..., uni=True)` y eliminar la normalización destructiva. La fuente se
vendoriza bajo `backend/forensia/reports/fonts/` y viaja en la imagen `api` (RULE 1: el
usuario no instala nada).

**Tests** (`backend/tests/test_reports_pdf.py`)

1. Un documento con un nombre de fichero en cirílico conserva los caracteres en el PDF
   (regresión de F4).
2. El PDF se genera sin excepción con las 10 secciones y las dos figuras.
3. El índice lleva números de página coherentes con las secciones.
4. Un documento `draft` marca `BORRADOR` en portada.

**Gates:** backend + compose (`docker compose config --quiet`, `docker compose build api`)
— F4 toca el contenido de la imagen `api`.
**Docs:** `CLAUDE.md` §Status; `docs/operacion/`.

---

---

## Hallazgo colateral — la comprobación Origin/Referer no está implementada

Al mapear las superficies nuevas de las fases D y E salió algo que **no pertenece a este
rediseño pero conviene no perder**:

`CLAUDE.md` (SECURITY INVARIANT 3) afirma que *«los endpoints con efecto secundario
exigen comprobación de Origin/Referer **y** el token de sesión»*. En el árbol,
`backend/forensia/security.py` implementa `new_session_token`, `allowed_hosts`,
`HostHeaderMiddleware` (anti DNS-rebinding) y `require_token` — pero **no hay ninguna
comprobación de Origin/Referer**, y ningún router la usa: todas las mutaciones se
protegen solo con `require_token`.

Los endpoints nuevos de D y E seguirán la convención vigente (`require_token`) para no
introducir un patrón divergente. Cerrar la brecha es un trabajo aparte —
`require_same_origin` como dependencia en `security.py` + su gate en `backend/tests/` —
que merece su propia rama y su propia decisión. Anotado aquí para que quede registrado;
no se aborda en estas siete fases.

---

## Fase G — Fuera de alcance (registrado, no planificado)

- **Export STIX 2.1 / MISP** de los IOCs. El CSV cubre el caso de uso de la guía
  («usados directamente por SIEMs, EDRs, firewalls»); STIX es un contrato mucho mayor.
- **Contraste automático contra Threat Intelligence.** Imposible por RULE 7 y SECURITY
  INVARIANT 7 sin romper el modelo de «cero llamadas de red propias». El informe declara
  la limitación (§8) en vez de simular la capacidad.
- **Firma criptográfica del PDF** (PAdES). El documento ya lleva SHA-256 de contenido
  verificable; una firma con validez legal exige certificado cualificado, que un TFM
  académico no tiene («sin validez legal certificada»).
- **Plantillas de informe intercambiables** (técnico / investigativo / ejecutivo, guía
  p. 110). Interesante, pero primero conviene tener una plantilla buena.

---

## Orden recomendado y coste

| Fase | Retorno | Contratos nuevos | Toca web | Toca imagen |
| --- | --- | --- | --- | --- |
| **A** Trabajos realizados | **Muy alto** | ninguno | no | no |
| **B** Conclusiones y limitaciones | Alto | ninguno | no | no |
| **C** Estructura y línea de tiempo | Alto | ninguno | no | no |
| **D** Ficha pericial | Alto | `FichaStore` | sí | no |
| **E** IOCs | Alto | `IocStore`, `record_ioc` | sí | no |
| **F** PDF | Medio (F4: alto) | 2 bloques de figura | no | sí (F4) |

A-B-C no introducen ningún contrato ni tocan el frontend: son tres PRs de backend puro
que ya dejan el informe muy por encima del actual. D y E son las que exigen superficie
nueva. F puede ir en paralelo a partir de C.

---

## Checklist antes de cada push (RULE 6)

```bash
# backend — los MISMOS extras que usa CI (el extra mcp no es opcional)
cd backend && pip install -e ".[dev,mcp]" && ruff check . && pytest -q

# web — solo si la fase toca web/
cd web && npm ci && npm run typecheck && npm run build

# compose — solo si la fase toca una imagen (F4)
docker compose config --quiet && docker compose build api web
```

Y antes: `git pull` en `tools` (RULE 5), documentación en sintonía (RULE 4), y
verificar en Actions que el run quedó verde en remoto — un push no está hecho hasta que
CI está verde.
