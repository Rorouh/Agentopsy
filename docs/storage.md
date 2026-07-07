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
| `cases/<case-id>/artifacts/<run>/` | `forensia.artifacts.store` (`ArtifactStore`) | `start_run` reserva `run_id` (UUID4) y abre `manifest.json` en estado `running`. `finalize_run` escribe `stdout.txt`/`stderr.txt`, hashea recursivamente cada fichero en `out/` con chunks de 1 MiB, y cierra el manifest atómicamente (`os.replace`). |
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
   ├─ artifact_store.start_run(case_id, tool_id, argv=[])      → (run_id, out_dir)
   │     · crea cases/<id>/artifacts/<run_id>/{manifest.json, out/}
   │     · manifest.json en estado "running"
   │
   ├─ params["output_dir"] = str(out_dir)   (solo si el wrapper acepta output_dir)
   │
   ├─ build_argv(params) → argv_tail
   ├─ resolve binario   (bundled) o run_in_container (container)
   ├─ subprocess.run(argv, shell=False)
   │
   ├─ audit.append({ action: "tool_run_start", argv literal, run_id, case_id, params })
   │
   ├─ artifact_store.finalize_run(…)        → ArtifactRun
   │     · escribe stdout.txt / stderr.txt (con SHA-256 propio)
   │     · hashea recursivamente cada fichero en out/  (1 MiB blocks)
   │     · manifest.json en estado "finished" + lista completa de output_files
   │
   ├─ audit.append({ action: "tool_run_finish", run_id, exit_code,
   │                 stdout_sha256, stderr_sha256, output_files_count })
   │
   └─ devuelve { tool_id, argv, exit_code, stdout_sample, stderr_sample, parsed,
                 case_id, run_id, artifact_run }
```

Si `case_id is None`, el dispatcher salta toda la rama de persistencia: no se reserva
`ArtifactRun`, no se toca `audit.jsonl`, y el resultado no incluye `case_id`/`run_id`.
Eso es el modo "legacy" / "panel dev" — útil para probar wrappers sin un caso abierto,
pero **inaceptable** para uso forense real.

## API HTTP que materializa el storage

Todos los endpoints usan `Depends(require_token)` (ver `backend/forensia/security.py`).
`KeyError → 404`, `ValueError → 422`.

| Method | Path | Resultado |
|---|---|---|
| `POST`  | `/api/cases`                                                    | crea caso (`{name, examiner, os_profile, notes?}`) |
| `GET`   | `/api/cases`                                                    | lista casos (orden `created_at` desc) |
| `GET`   | `/api/cases/{case_id}`                                          | carga un caso |
| `POST`  | `/api/cases/{case_id}/close`                                    | marca `status="closed"` |
| `POST`  | `/api/cases/{case_id}/evidence`                                 | registra evidencia (`{source_path}`); ejecuta el hash gate |
| `GET`   | `/api/cases/{case_id}/evidence`                                 | lista handles |
| `POST`  | `/api/cases/{case_id}/evidence/{evidence_id}/verify`            | re-hashea y compara a `baseline.json` |
| `GET`   | `/api/cases/{case_id}/artifacts`                                | lista runs |
| `GET`   | `/api/cases/{case_id}/artifacts/{run_id}`                       | manifest completo de un run |
| `GET`   | `/api/cases/{case_id}/chats`                                    | lista session_ids |
| `GET`   | `/api/cases/{case_id}/chats/{session_id}`                       | mensajes de la sesión |
| `POST`  | `/api/cases/{case_id}/chats/{session_id}/messages`              | append `{role, content, tool_calls?}` |

`audit.jsonl` **NO** se expone por HTTP — es un artefacto forense que se consulta desde
el filesystem por un perito autorizado, no por la app.

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
hash gate completo (incluido mismatch durante la copia), artifact start/finalize con
ficheros vacíos y con árboles anidados, chat append/read con líneas truncadas, y la rama
de dispatcher con `case_id` (audit + manifest + integración con wrappers). El conjunto
total que debe estar verde antes de mergear ronda los 172+ asserts.
