# 01 — El flujo que se ejecutó

> Reconstruido de `projects/cases/f575846e…/audit.jsonl`, `baseline.json`,
> `verification.json` y el registro de jobs. Marcas de tiempo reales, UTC.
> Índice: [`README.md`](README.md).

## Cronología

| Hora (UTC) | Paso | Quién lo ejecuta |
|---|---|---|
| `12:18:31.551` | **Caso creado** — «Prueba 188k tokens», examinador Daniel Ramos, nota *«Investigacion caso UCM»*. Sin `os_profile` todavía | Operador (UI) |
| *(sin marca)* | **Subida a la bandeja** de `IE11-Win7-VMWare-disk1.vmdk` a `./evidence` | Operador (drag-and-drop → `POST /api/evidence/upload`) |
| `12:24:33.303` | **Job de registro asíncrono creado** para `/evidence/windows7-x64-ram-dump/ram.raw` | `forensia.evidence_jobs` |
| `12:24:33` → `12:24:54` | **Hash gate** (21,5 s): hash del origen → copia inmutable → re-hash. `bytes_total = 16 106 127 360` = **3 × 5 GiB**, los tres barridos del gate | `EvidenceManager` |
| `12:24:54.759` | **Evidencia registrada** — `a35686e4…`, SHA-256 `a0ad93b2…b240`, 5 368 709 120 B. Evento `evidence_register` en el audit | `EvidenceManager` |
| `12:24:54.768` | **Triage + enrutado automático** → `os_profile = windows`. Evento `os_profile_routed`, `decision: auto_set` | `forensia.triage` |
| `12:25:48.897` | **Re-verificación**: hash actual == baseline → `verified: true`. Evento `evidence_verify` | `EvidenceManager` |
| — | **Análisis del agente** | **NUNCA OCURRIÓ** |

Total desde crear el caso hasta tener evidencia verificada y perfil anclado:
**7 min 17 s**, de los cuales 21,5 s son el hash gate real.

## Paso a paso, con lo que importa de cada uno

### 1. Ingesta (bandeja `./evidence`)

El fichero llega a `./evidence` en el host. La bandeja se monta **`rw` para el
`api`** (es el camino de escritura del perito: subir desde el navegador) y
**`ro` para los maletines y el agente** (cadena de custodia: nunca mutan la
imagen). La subida solo deposita el fichero; valida nombre y formato, rechaza
traversal y no sobrescribe nunca.

**El hash gate NO corre aquí.** Corre al registrar.

### 2. Registro asíncrono

`POST /api/cases/{id}/evidence/async` devolvió un `job_id` de inmediato y el
trabajo siguió en segundo plano. Es la mecánica que evita que cerrar la pestaña
aborte un registro de varios GB (y que nginx dé 504).

El job reporta `phase ∈ {hashing, copying, verifying}` y `bytes_done/bytes_total`.
Aquí terminó en `state: done`, `phase: verifying`, `16 106 127 360 /
16 106 127 360`.

El registro es **atómico**: se construye en un directorio oculto
`evidence/.registrando-<eid>` y se publica con un único `os.rename`. Una
interrupción no puede dejar una evidencia truncada y sin baseline.

### 3. Hash gate (FORENSIC INVARIANT 2)

Orden estricto, y se cumplió:

```
hash del origen → copia inmutable → re-hash → baseline.json → handle read-only
```

Los `bytes_total` triples (3 × 5 GiB) son la prueba de que los tres barridos se
hicieron sobre los bytes, no una estimación.

Resultado: `sha256 = a0ad93b20cd9294f9d49947e87675c12159e3d96ae0d3c5a547f232630b0b240`.

**Nada llega a una herramienta o a un agente antes de que exista ese baseline.**

### 4. Triage y enrutado

`forensia.triage` leyó el contenido del fichero (no el nombre, no el host) y
determinó:

```json
{
  "detected_kind": "memory",
  "detected_os":   "windows",
  "triage_confidence": "markers",
  "triage_signals": ["pe_scatter=6", "rsds_pdb=3", "page0_zero"]
}
```

Tres señales: dispersión de cabeceras PE, firmas de PDB `RSDS`, y página 0 a
ceros — la firma típica de un volcado de memoria física de Windows. Con eso el
enrutado fue **automático** (`decision: auto_set`), sin preguntar al operador,
y el caso pasó de no tener perfil a `os_profile: windows` con
`os_profile_source: derived`.

Esto quedó en el audit log como evento propio (`os_profile_routed`) con familia,
confianza y señales — es auditable en el informe.

> **Aquí es donde muerde la objeción del perito.** El enrutado fue correcto en
> este caso, pero fue **automático y vinculante**: al agente se le habría
> entregado el perfil ya decidido, el bloque «Ruta del playbook — MEMORY DUMP»
> inyectado, y la rama de disco del playbook **recortada del prompt** por
> `select_playbook_section`. Ver [`02-decisiones.md`](02-decisiones.md) y
> `docs/agentes/INTERNO-revision-flujo-y-autonomia.md` §1.

### 5. Re-verificación

Un minuto después, `evidence_verify`: hash actual idéntico al baseline,
`verified: true`. El playbook exige `verified=true` antes de tocar ninguna
herramienta, así que la evidencia estaba lista para analizar.

### 6. Análisis — no ocurrió

`chats/` vacío, `artifacts/` vacío, ningún evento `agent_run_start` en el audit.
El flujo **se detuvo aquí**, con la evidencia lista y sin usar.

## El segundo fichero: se quedó fuera

`IE11-Win7-VMWare-disk1.vmdk` está en `./evidence` (subido hoy) pero:

- no tiene entrada en `GET /api/cases/{id}/evidence`,
- no tiene `baseline.json` ni directorio bajo `evidence/<uuid>/`,
- no hay job de registro para él (el único job del caso es el del RAM dump),
- no aparece en el audit log.

Está **en la bandeja, no en el caso**. Para `EvidenceManager` no existe, y ninguna
herramienta puede tocarlo.

Es un dato interesante de por sí: **subir ≠ registrar**, y la UI no lo hace
evidente. Ver [`05-notas-perito.md`](05-notas-perito.md).

## Diagrama del flujo real

```
   ./evidence (bandeja, rw para api / ro para maletines)
        │
        │  [ram.raw]                    [IE11-…vmdk]  ──► se quedó aquí
        ▼
   POST /evidence/async ──► job b585a042 (21,5 s)
        │
        ▼
   HASH GATE: hash origen → copia → re-hash   (3 × 5 GiB)
        │
        ▼
   baseline.json  +  evidence_register (audit)
        │
        ▼
   TRIAGE: memory / windows / markers / 3 señales
        │
        ▼
   os_profile_routed: auto_set → windows   (audit)
        │
        ▼
   evidence_verify: verified=true          (audit)
        │
        ▼
   ┌──────────────────────────────┐
   │  AGENTE  —  no se ejecutó    │
   └──────────────────────────────┘
```
