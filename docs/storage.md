# FORENSIA — Sistema de almacenamiento

Capa de persistencia del lado del backend (servicio `api`). No hay base de datos pesada: todo en filesystem
+ JSON / JSONL. Es exactamente lo que la práctica forense pide — un caso es una carpeta
que se puede archivar, hashear, transferir y peritar sin necesidad de levantar servicios
auxiliares.

> **Por qué no hay base de datos relacional**
>
> Una BD relacional añade un proceso más, un esquema versionable y una superficie de
> corrupción adicional. Un caso forense necesita ser **autosuficiente** y **portable**:
> meterlo en un USB, mandarlo por correo, ingestarlo en otra máquina. Una carpeta con
> JSON / JSONL cumple esto sin ceremonia. SQLite queda **opcional** y exclusivamente como
> índice de listado rápido en `~/.forensia/index.db`; si se borra, el filesystem manda y
> el índice se reconstruye con un scan.

## Layout en disco

```
~/.forensia/
├── config.json                    # ya existe (operador)
├── index.db                       # SQLite opcional para listar casos rápido (3-4 columnas)
└── cases/
    └── <case-id-uuid>/
        ├── case.json              # { id, name, examiner, created_at, os_profile, status, notes }
        ├── evidence/
        │   └── <evidence-id>/
        │       ├── original.<ext> # copia inmutable (chmod 0444 mínimo; block-RO en Linux real)
        │       └── baseline.json  # { sha256, blake3, size, registered_at, source_path }
        ├── artifacts/
        │   └── <run-id>/          # cada invocación de tool produce un run
        │       ├── manifest.json  # { tool_id, argv, evidence_id, timestamps, sha256 por archivo }
        │       ├── stdout.txt
        │       ├── stderr.txt
        │       └── out/           # los ficheros que generó la tool (CSVs, body files, etc.)
        ├── chats/
        │   └── <session-id>.jsonl # 1 línea por mensaje { role, content, ts, tool_calls? }
        ├── audit.jsonl            # AuditLog real anclado AQUÍ (uno por caso)
        └── reports/
            └── <report-id>.{md,pdf}
```

> **Raíz alternativa**: el entorno `FORENSIA_HOME` sobreescribe `~/.forensia/` para tests
> e integración (ver `backend/forensia/config.py`).

> **En el despliegue compose**: la raíz de datos del servicio `api` se monta en
> `./projects/` del repo (vía `FORENSIA_HOME`), de modo que los casos viven en la máquina
> del usuario como carpetas normales bajo `./projects/` — archivables y peritables sin
> entrar al contenedor. Las evidencias de origen se dejan en `./evidence/`, que los
> servicios montan en **solo lectura**; los maletines ven el volumen de trabajo como
> `/cases`. El layout de arriba es idéntico: solo cambia dónde está anclada la raíz.

## Módulos que materializan el layout

| Path | Módulo | Responsabilidad |
|---|---|---|
| `cases/<case-id>/case.json` | `forensia.cases.manager` (`CaseManager`) | Crear / listar / cargar / cerrar casos. UUID4 obligatorio; `os_profile` opcional/nullable — derivado del contenido de la evidencia (triage) o anclado por el operador; validado `in {unix, windows}` solo cuando está presente (+ `os_profile_source ∈ {derived, operator, conflict}`); subdirectorios (`evidence/`, `artifacts/`, `chats/`, `reports/`) materializados al crear. |
| `cases/<case-id>/evidence/<id>/` | `forensia.evidence` (`EvidenceManager`) | Hash gate estricto: stream SHA-256 de la fuente → `shutil.copy2` → re-hash de la copia (abort + cleanup si mismatch) → `chmod 0o444` → `baseline.json`. La fuente nunca se modifica; el handle devuelto apunta SIEMPRE a la copia inmutable. |
| `cases/<case-id>/artifacts/<run>/` | `forensia.artifacts.store` (`ArtifactStore`) | `start_run` reserva `run_id` (UUID4) y abre `manifest.json` en estado `running`; `set_run_argv` fija después el argv literal ya resuelto. `finalize_run` cierra una ejecución que devolvió código como `finished`; `fail_run` cierra una invocación sin código como `error`. Ambos escriben y hashean `stdout.txt`/`stderr.txt` (también si son parciales), hashean recursivamente `out/` en chunks de 1 MiB y reemplazan el manifest atómicamente. `resolve_output_file` resuelve un fichero de `out/` de una corrida a su ruta on-disk **confinada** (rechaza absoluta / `..` / escape por symlink) y lo **re-hashea** contra el SHA-256 del manifiesto — la puerta de custodia de un input derivado (`ArtifactIntegrityError` si los bytes ya no coinciden). |
| `cases/<case-id>/chats/<session>.jsonl` | `forensia.chats.store` (`ChatStore`) | Append-only line-buffered JSONL. `session_id` UUID4 o slug `^[a-zA-Z0-9_-]{1,64}$`. Roles validados contra `{user, assistant, system, tool}`. Lectura tolera última línea truncada (warning). |
| `cases/<case-id>/audit.jsonl` | `forensia.audit.log` (`AuditLog`) | Append-only encadenado por hash. Una instancia por caso: el dispatcher la crea con `AuditLog(case_dir / "audit.jsonl")` por cada ejecución. La cadena `prev_hash → entry_hash` se verifica con `audit_log.verify()`. |
| `cases/<case-id>/reports/<id>.{md,pdf}` | (pendiente — `forensia.reports`) | Pendiente para el slice de generación de informes. El layout está reservado. |

Todos los módulos exponen un singleton de conveniencia (`case_manager`, `evidence_manager`,
`artifact_store`, `chat_store`) ligado a `CONFIG_DIR / "cases"`. Los tests inyectan una
raíz alternativa pasando `FORENSIA_HOME` al entorno.

## Flujo end-to-end: una ejecución de herramienta anclada a un caso

```
agente / panel toolkit-tester
   │
   ▼
dispatcher.execute(tool_id, params, case_id="…")
   │
   ├─ gate central Tool.path_parameters (ANTES de reservar run o auditar start)
   │     · EVIDENCE_INPUT → case_dir/evidence del caso activo
   │     · CASE_INPUT → case_dir del caso activo; nunca otro caso
   │     · DERIVED_INPUT → ArtifactRef {run_id, relpath, sha256?, size?}, sin extras;
   │                       resolve_output_file + re-hash autoritativo
   │     · RUN_OUTPUT del caller → rechazo; bundled/runtime → id exacto allowlisted
   │
   ├─ resolver inputs derivados (tools con input_artifact_params): cada param cuyo valor
   │  sea un ArtifactRef → artifact_store.resolve_output_file(…)
   │     · re-hashea el fichero contra el manifiesto de la corrida productora (custodia
   │       del derivado, INVARIANTS 1-2); mismatch/ausente → ToolExecutionError (RULE 2)
   │     · sustituye la ref por la ruta RO resuelta (el wrapper ve una ruta normal)
   │     · acumula el enlace de derivación para el audit
   │
   ├─ artifact_store.start_run(case_id, tool_id, argv=[])      → (run_id, out_dir)
   │     · crea cases/<id>/artifacts/<run_id>/{manifest.json, out/}
   │     · manifest.json en estado "running"
   │
   ├─ generar todos los RUN_OUTPUT declarados bajo out_dir
   │     · normalmente `output_dir` = out/; bulk_extractor recibe el subdirectorio
   │       todavía inexistente out/bulk_extractor; ficheros concretos quedan debajo
   │     · nunca se preserva un output_path/output_dir aportado por el caller
   │
   ├─ build_argv(params) → argv_tail
   ├─ resolve binario local o seleccionar un único maletín por os_profile
   ├─ artifact_store.set_run_argv(…)         → persiste el argv literal
   │
   ├─ audit.append({ action: "tool_run_start", argv literal, run_id, case_id, params,
   │                 evidence_id, baseline_sha256, derived_inputs? })
   │                                      · evidence_id + baseline_sha256 = el EvidenceContext
   │                                        verificado que la superficie (agente/MCP) hila desde
   │                                        EvidenceManager; ancla la acción a la evidencia
   │                                        (INVARIANT 4). El dispatcher NO lo re-deriva de una
   │                                        ruta/param (RULE 2); una tool que LEE evidencia en un
   │                                        run anclado sin contexto falla fuerte antes del start.
   │                                      · derived_inputs lista {param, source_run_id,
   │                                        relpath, sha256, size} — el enlace de derivación
   │
   ├─ run_argv(argv, shell=False) o POST /exec al maletín seleccionado
   │
   ├─ si el runner devuelve un exit code (0 o distinto de 0):
   │     artifact_store.finalize_run(…)      → status "finished", exit_code literal
   │
   ├─ si el runner/transporte lanza sin devolver código:
   │     artifact_store.fail_run(…)          → status "error", exit_code null,
   │                                           error_type + error_message
   │     · conserva stdout/stderr parciales cuando la excepción los aporta
   │
   ├─ audit.append({ action: "tool_run_finish", run_id, status, exit_code,
   │                 hashes, evidence_id, baseline_sha256, error_type?, error_message? })
   │     · TODOS los caminos de cierre (exit 0, exit != 0, excepción del runner, fallo de
   │       finalize) conservan el MISMO evidence_id + baseline_sha256 que el start pareado
   │       (INVARIANT 4): ningún finish de error pierde el contexto forense
   │     · se intenta una sola vez; un fallo se propaga sin retry ni reejecución
   │
   └─ devuelve { tool_id, argv, exit_code, stdout_sample, stderr_sample, parsed,
                 case_id, run_id, artifact_run }
```

Si `case_id is None`, un parámetro case-scoped (`EVIDENCE_INPUT`, `CASE_INPUT`,
`DERIVED_INPUT`) o cualquier `RUN_OUTPUT` se rechaza antes del runner. Solo una tool sin
rutas de caso, o un identificador bundled/runtime exacto, podría usar el modo no anclado.

## Relevo derivado: encadenar herramientas con custodia

Una cadena multi-tool real (extraer un hive con TSK `icat`, y parsearlo con RegRipper)
necesita que la salida de una corrida sea el input de la siguiente **sin que el agente
invente rutas** ni se salte la verificación. Dos piezas simétricas lo hacen:

- **La salida remite al artefacto.** Una tool `binary_stdout` (icat) escribe sus bytes
  crudos a `out/stdout.bin` (hasheado, INVARIANT 4); su stdout de texto es `""`. El
  `parsed` del resultado **no** es `parse("")` (que diría `content_length: 0` y se leería
  como "no devolvió nada") sino una **referencia al artefacto**:
  `{"artifact": {run_id, relpath: "stdout.bin", sha256, size}}` — solo en exit 0.
- **La entrada acepta esa referencia.** Una tool que declara `input_artifact_params`
  (RegRipper → `("hive_path",)`) puede recibir, en ese param, el `ArtifactRef`
  compartido. `run_id` y `relpath` son obligatorios; `sha256` y `size` son
  opcionales porque el productor los emite; cualquier otra clave se rechaza. Antes de
  `build_argv`, el dispatcher la resuelve con
  `artifact_store.resolve_output_file`, que **confina** la ruta bajo `out/` y **re-hashea**
  el fichero contra el SHA-256 del manifiesto de la corrida productora (custodia del
  derivado — INVARIANTS 1-2). Nunca confía en el hash/tamaño aportado: si están presentes
  también deben coincidir con el valor re-hasheado/autoritativo del store. Coincide →
  sustituye la ref por la ruta RO resuelta y sigue.
  No coincide, falta o la ref es inválida → `ToolExecutionError` accionable y la tool **no
  se ejecuta** (RULE 2: nunca sobre un derivado sin verificar). Una ruta literal (`str`)
  bajo `artifacts/` no sustituye la referencia: se rechaza para impedir saltarse el re-hash.

La ref que produce icat es exactamente la que consume RegRipper, así que el agente encadena
`icat → RegRipper` pasando `result["parsed"]["artifact"]` como `hive_path`. El **enlace de
derivación** (qué artefacto de la corrida A alimentó la corrida B, con el hash re-verificado)
queda en `tool_run_start.derived_inputs` del `audit.jsonl` — INVARIANT 4. Sin `case_id` no
hay árbol de artefactos que resolver: una ref sin caso falla fuerte.

## API HTTP que materializa el storage

Todos los endpoints usan `Depends(require_token)` (ver `backend/forensia/security.py`).
`KeyError → 404`, `ValueError → 422`.

| Method | Path | Resultado |
|---|---|---|
| `POST`  | `/api/cases`                                                    | crea caso (`{name, examiner, os_profile, notes?}`) |
| `GET`   | `/api/cases`                                                    | lista casos (orden `created_at` desc) |
| `GET`   | `/api/cases/{case_id}`                                          | carga un caso |
| `POST`  | `/api/cases/{case_id}/close`                                    | marca `status="closed"`; audita `case_closed` |
| `POST`  | `/api/cases/{case_id}/reopen`                                   | marca `status="active"`; audita `case_reopened` (única forma de volver a registrar evidencia en un caso cerrado) |
| `POST`  | `/api/cases/{case_id}/update`                                   | edita `{name?, examiner?, notes?}`; audita `case_updated` con el before/after de cada campo cambiado |
| `POST`  | `/api/cases/{case_id}/evidence`                                 | registra evidencia (`{source_path}`); ejecuta el hash gate; rechaza con 422 si el caso está `closed` |
| `GET`   | `/api/cases/{case_id}/evidence`                                 | lista handles |
| `POST`  | `/api/cases/{case_id}/evidence/{evidence_id}/verify`            | re-hashea y compara a `baseline.json` |
| `GET`   | `/api/cases/{case_id}/artifacts`                                | lista manifests completos de runs |
| `GET`   | `/api/cases/{case_id}/artifacts/{run_id}`                       | manifest completo de un run |
| `GET`   | `/api/cases/{case_id}/chats`                                    | lista session_ids |
| `GET`   | `/api/cases/{case_id}/chats/{session_id}`                       | mensajes de la sesión |
| `POST`  | `/api/cases/{case_id}/chats/{session_id}/messages`              | append `{role, content, tool_calls?}` |

`audit.jsonl` **NO** se expone por HTTP — es un artefacto forense que se consulta desde
el filesystem por un perito autorizado, no por la app.

El contrato HTTP completo de cada `ArtifactRun` es:
`run_id`, `case_id`, `tool_id`, `argv`, `started_at`, `finished_at`,
`status` (`running | finished | error`), `exit_code`, `output_files`
(cada elemento contiene `relpath`, `sha256` y `size`), `stdout_sha256`,
`stderr_sha256`, `error_type` y `error_message`. En `running`,
`finished_at` y `exit_code` aún pueden ser `null`; en `error` por excepción
del runner/transporte, `finished_at` ya está fijado, `exit_code` es `null` y
los campos de error son accionables. Este manifest HTTP es más amplio que el
`artifact_run` embebido de compatibilidad que devuelve `dispatcher.execute()`
cuando una ejecución retorna normalmente.

## Invariantes que el layout fija

1. **Un caso es una carpeta.** Archivable, copiable a USB, hasheable como bundle. La
   forense pericial real ya funciona así.
2. **La evidencia se copia, no se referencia.** El handle apunta SIEMPRE a la copia
   bajo `cases/<id>/evidence/<eid>/original.<ext>`, nunca a la ruta original del
   analista. La ruta original queda registrada como `source_path` en `baseline.json`
   por trazabilidad, pero no es accionable desde el dispatcher.
3. **Read-only en filesystem (`chmod 0o444`) es el v1 mínimo.** El read-only a nivel de
   bloque (`losetup --read-only` + `blockdev --setro`) es Linux-only y se cablea en
   **Phase 2**; está documentado en `soundness-forense.md` §1.
4. **Hash gate en orden estricto.** SHA-256 del origen → copia → re-hash de la copia →
   `chmod` → `baseline.json` → handle expuesto. Cualquier paso fuera de orden invalida
   la cadena de custodia.
5. **El audit log es la verdad de la ejecución.** Encadenado por hash, registra el
   `argv` literal del proceso (no la "intención" del LLM). `audit_log.verify()` recorre
   el `prev_hash → entry_hash` y devuelve `False` si alguien manipuló cualquier entrada.
6. **JSONL para chats y audit** evita lock contention al hacer append concurrente; cada
   línea es un objeto JSON independiente que sobrevive a una última línea truncada.
7. **SQLite es índice opcional, no source-of-truth.** Si `index.db` se corrompe se
   reconstruye desde `cases/*/case.json`. Si el filesystem se corrompe, el caso se
   pierde — y eso lo cubre la política de backups del operador, no la app.
8. **`baseline.json` reserva un campo `blake3`** documentado en el diagrama; la
   implementación v1 lo deja en `null` y solo escribe `sha256`. BLAKE3 entra junto con
   el read-only a nivel de bloque (Phase 2).

## Lo que NO está en este layout (deliberado)

| Cosa | Por qué fuera |
|---|---|
| Multi-tenant / multi-operador | Es una herramienta autoalojada single-user (un despliegue compose por analista). Si la TFM crece, se modela `<raíz>/<operator>/cases/`. Hoy es ruido. |
| Reportes generados | Reservado en `cases/<id>/reports/` pero el módulo `forensia.reports` aún no existe — slice posterior. |
| Streaming SSE / WebSocket de chats | El JSONL ya soporta lectura tail-friendly; el endpoint de streaming entra cuando la UI lo necesite. |
| Compresión de stdout/stderr | Texto plano en v1. Compresión `zstd` cuando empiece a doler. |
| Política de retención / GC de artifacts | Decisión del operador, no del software. Los runs se acumulan en disco hasta que el operador purge. |
| Encriptación at rest | Fuera de scope. La política es del filesystem subyacente (FileVault / BitLocker / LUKS). |

## Tests

`backend/tests/` cubre el contrato de cada módulo: case create/list/load/close, evidence
hash gate completo (incluido mismatch durante la copia), ArtifactRun
`start_run`/`set_run_argv`/`finalize_run`/`fail_run` con ficheros vacíos,
parciales y árboles anidados, estados HTTP `running | finished | error`, chat
append/read con líneas truncadas, y la rama de dispatcher con `case_id` (audit +
manifest + integración con wrappers).
