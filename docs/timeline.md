# Timeline forense del caso

FORENSIA ofrece **dos capas** de línea temporal, ambas deterministas y con marcas de
tiempo en **UTC explícito** (ISO-8601 con `Z`; la UI etiqueta la zona y nunca convierte a
hora local — hallazgo F). La lógica vive en `backend/forensia/timeline/` (RULE 3) y se
expone por el router fino `backend/forensia/routers/timeline.py`; la UI la consume en
`web/src/pages/TimelinePage.tsx`.

## Capa 1 — Timeline de investigación (siempre disponible)

Ensambla eventos a partir de lo que el caso **ya** contiene, sin ejecutar herramientas
nuevas:

- **Ejecuciones de herramienta** del audit log append-only y hash-encadenado
  (`audit.jsonl`): un evento `tool_run` por cada `tool_run_start`, enriquecido con su
  `tool_run_finish` emparejado (`exit`, `status`, sha256 de stdout/stderr, nº de
  artefactos).
- **Hallazgos** (`forensia.findings.store.Finding`): un evento `finding` por hallazgo.

Ordenados cronológicamente por su `ts` UTC. Un evento con timestamp no parseable se
ordena al final pero **nunca se descarta** (RULE 2).

```
GET /api/cases/{case_id}/timeline
→ 200 { "case_id", "timezone": "UTC", "events": [
    { "kind": "tool_run", "ts": "2026-07-15T10:00:05.000Z", "tool_id": "tsk_fls",
      "run_id": "...", "argv": ["fls","-m","/","original.raw"], "exit": 0,
      "status": "finished", "evidence_id": "...",
      "artifacts": [{ "relpath": "stdout.txt", "sha256": "..." }],
      "output_files_count": 0 },
    { "kind": "finding", "ts": "2026-07-15T10:03:00.000Z", "finding_id": "...",
      "title": "...", "summary": "...", "severity": "high", "tool_id": "tsk_fls",
      "evidence_id": "...", "mitre_hints": ["T1547.001"] }
  ] }
```

### Export CSV (hallazgo D)

La capa 1 se lleva fuera de FORENSIA como CSV. Reusa el **mismo builder**
(`build_investigation_timeline`) — no reconstruye nada ni ejecuta herramientas — y el
formateo vive en `backend/forensia/timeline/export.py` (`timeline_to_csv`, RULE 3). Un
caso sin actividad devuelve un CSV con **sólo la cabecera** (0 filas, honesto), nunca un
error.

```
GET /api/cases/{case_id}/timeline/export.csv
→ 200  Content-Type: text/csv; charset=utf-8
       Content-Disposition: attachment; filename="timeline-{case_id}.csv"

ts_utc,kind,tool_id,argv,exit,status,title,severity,evidence_id,mitre_hints
2026-07-15T10:00:05.000Z,tool_run,tsk_fls,fls -m / img.raw,0,finished,,,e1,
2026-07-15T11:00:00.000Z,finding,RegRipper,,,,Persistencia detectada,high,e1,T1547.001
```

Una fila por evento: `tool_run` rellena `tool_id`/`argv`/`exit`/`status`; `finding`
rellena `title`/`severity`/`mitre_hints` (separados por `;`). Un `ts` no parseable llega
como cadena vacía pero la fila **no se descarta** (RULE 2). La UI lo descarga desde el
botón **«Exportar CSV»** de la pestaña *Investigación* (`api.cases.exportTimelineCsv`,
blob mismo-origen con el token en cabecera).

## Capa 2 — Super-timeline del sistema de ficheros (bajo demanda)

Dispara el paso forense `tsk_fls -m -r` sobre la **evidencia seleccionada** a través del
dispatcher/maletín (argv arrays, shell-free, auditado y con artefacto hasheado — nunca un
subprocess reimplementado; SECURITY INVARIANTS 4-5). El *bodyfile* TSK resultante se
expande a eventos **MACB** (`kind: "fs"`), que es exactamente la transformación
determinista que aplica `mactime`.

Como puede tardar minutos en una imagen real, corre como **job asíncrono**
(`forensia.agent.jobs.JobRegistry`): la request devuelve un `job_id` al instante y no se
bloquea; una desconexión no aborta el análisis. La validación (evidencia seleccionada,
`os_profile` resuelto) ocurre **síncrona** antes de encolar, para fallar rápido.

```
POST /api/cases/{case_id}/timeline/filesystem   { "evidence_id": "..." }
→ 200 { "job_id", "status": "running", "case_id", "kind": "fs_timeline",
        "evidence_id", "os_profile", ... }

# Sin evidence_id → 422 (RULE 2: FORENSIA no asume "la única" ni "la última").
# os_profile no resoluble (unknown / baja confianza / conflicto) → 409: el operador ancla.

GET /api/cases/{case_id}/timeline/filesystem/jobs/{job_id}?since=0
→ 200 { "status": "running" | "done" | "error",
        "events": [{ "type": "status", "stage": "fls|mactime|done", "message": "..." }],
        "result": {                      // presente cuando status == "done"
          "timezone": "UTC", "evidence_id", "os_profile", "fls_run_id",
          "total_events", "returned", "truncated",
          "events": [{ "kind": "fs", "ts": "1970-01-01T00:00:00Z", "path": "/etc/passwd",
                       "macb": "m.c.", "size": 4096, "inode": "128-1-1" }] } }
```

Un `exit != 0` de `tsk_fls` hace **fallar el job en alto** con el stderr de la
herramienta; nunca se construye una super-timeline parcial (RULE 2). Los eventos se
recortan a `DEFAULT_FS_EVENT_LIMIT` (5000) y el recorte se reporta (`total_events` /
`truncated`), nunca se oculta.

### Supuesto de implementación (mactime)

El *bodyfile* de `fls -m` se emite por **stdout**, que el store persiste como
`artifacts/<run_id>/stdout.txt` (fuera de `out/`). El contrato de `tsk_mactime` exige su
`bodyfile_path` como **ArtifactRef** resuelto bajo `out/` de un run previo, así que el
relevo `fls → mactime` a través del dispatcher no está cableado hoy. Por eso la expansión
MACB (la parte determinista que hace `mactime`) se realiza **en proceso** dentro de
`forensia.timeline.builder.bodyfile_to_fs_events`, alimentada por el bodyfile real que
`tsk_fls` produjo. Si en el futuro un wrapper de `fls` escribe el bodyfile a `out/`, el
paso `mactime` podría encadenarse por ArtifactRef sin tocar esta capa.
