# FORENSIA — Soundness forense (cadena de custodia)

Resumen de la revisión DFIR de la fase de planificación. El riesgo número uno **no** es la
tecnología: es asumir que `mount -o ro` equivale a integridad. No lo es.

## 1. Read-only de verdad: a nivel de BLOQUE, no solo de filesystem

- Montar un FS "sucio" (EXT3/4, NTFS) en solo-lectura **puede disparar journal replay** y
  **escribir** en el dispositivo subyacente → altera la evidencia → rompe el hash.
- La barrera dura es a nivel de **dispositivo de bloque**: loop device read-only
  (`losetup --read-only`) + `blockdev --setro`. El `mount -o ro,noload,noatime` es
  secundario.
- **Prioriza herramientas que NO montan FS**: TSK (`fls/icat/mmls`) y Volatility3 trabajan
  sobre la imagen raw directamente. Con eso, el grueso del análisis trata la evidencia como
  **fichero raw read-only** y se esquiva por completo el riesgo de journal-replay. El montaje
  de FS queda como ruta de excepción, documentada por caso.

## 2. Orden de operaciones (el `EvidenceManager` lo impone)

```
ingest(path)
  → baseline hash  (SHA-256 + un segundo algoritmo, p.ej. BLAKE3)   [ANTES de nada]
  → set read-only a nivel de bloque
  → append `evidence_register` al audit  (id, sha256 baseline, origen, tamaño)
  → expose handle                                                    [recién aquí]
  ... análisis (herramientas y agente solo reciben el handle) ...
  → verify()  (re-hash y comparación) → append `evidence_verify`     [al cerrar sesión]
```

Ninguna herramienta ni agente recibe la ruta cruda: solo un `Handle`. El hash baseline
existe **antes** de cualquier exposición y **alcanza el audit log en la ingesta**
(`evidence_register`), no solo al verificar. Se re-verifica al final (`evidence_verify`)
para demostrar que el flujo no alteró la evidencia. Ambos eventos van a la cadena
hash-chained del caso (forensic invariant 4).

## 3. Audit log: trazabilidad de cada acción del agente

Un agente IA introduce no-determinismo. Forensemente hay que poder responder: *¿qué comando
exacto, con qué argv, sobre qué evidencia, a qué hora, con qué versión de herramienta,
produjo este artefacto?* Por eso el log es **append-only y encadenado por hash**
(tamper-evident) y registra el **comando literal ejecutado**, no la "intención" del LLM.

Esquema por entrada:
```
{ seq, ts_utc, prev_hash, evidence_id, evidence_sha256,
  tool_id, tool_version, argv[], exit_code,
  stdout_sha256, stderr_sha256, artifact_sha256, consent_ref?, entry_hash }
```

El límite del runner distingue dos resultados que no son intercambiables. Si el
proceso devuelve un código —cero o distinto de cero— la ejecución terminó y se
registra ese `exit_code` literal con `status: "finished"`. Si el transporte,
el timeout o el runner lanzan antes de devolver un código, no existe un código
que registrar: el `ArtifactRun` se cierra con `status: "error"`,
`exit_code: null`, el tipo/mensaje real y los streams parciales disponibles.
Para que ese intento sea trazable, `tool_run_start` con el argv exacto debe
haber quedado durable en el AuditLog **antes** de cruzar el límite del runner.
Si no se puede persistir el start, la herramienta se rechaza sin ejecutar.
Tras un start se intenta como máximo un finish, sin retry ambiguo: el pareado
depende de que ArtifactStore y AuditLog continúen escribibles. Un fallo del
append final se propaga sin reejecutar la herramienta y conserva la causa
primaria cuando existe.

El timeout local (`subprocess.TimeoutExpired`) pertenece al segundo caso y queda
`error/null`. El timeout interno del exec-agent remoto todavía responde
`timed_out=true` con `exit=124`; el cliente actual lo trata como retorno normal y
queda `finished/124`. Esta diferencia es un gap pendiente de decisión, no una
equivalencia forense.

Además del **comando literal por tool run** (lo escribe el dispatcher), el loop del agente
añade eventos de nivel-agente que el dispatcher no puede ver, encadenados en la misma
`audit.jsonl`: `agent_run_start` (caso, evidencia + hash, backend, modelo), `agent_cloud_egress`
(uno por salida a cloud: `consent_ref`, `redacted_payload_sha256`, `message_count`) y
`agent_finding` (`finding_id`). Nunca registran bytes crudos, sólo hashes/metadatos.

**Concurrencia** (sprint S1, rama `mcp`): el `AuditLog` ahora puede recibir appends de
múltiples procesos en paralelo (el servicio HTTP `api` que consume la UI web + el servidor
MCP standalone `python -m forensia.mcp`, que el cliente externo spawnea). `AuditLog.append`
usa un `filelock` cross-platform (POSIX `fcntl` / Windows `msvcrt`) sobre un fichero
`.lock` adyacente durante la región crítica leer-prev → calcular hash → escribir
nueva entrada. Sin esto, dos appends concurrentes leían el mismo `prev_hash` y la cadena
se bifurcaba silenciosamente. Test: `backend/tests/test_audit_lock.py` con
`multiprocessing` (4 procesos × 50 entradas) verifica que `AuditLog.verify()` sigue
devolviendo `True` tras la mezcla.

**MCP transparency** (L1 del servidor MCP): el adaptador MCP **NO** escribe en
`audit.jsonl` directamente — solo el `dispatcher.execute()` lo hace. Una llamada
`tools/call` por MCP que alcanza el runner produce una entrada `tool_run_start` e
intenta emitir como máximo un `tool_run_finish`; el pareado requiere que el
AuditLog siga escribible. Las únicas
entradas adicionales que escribe la capa MCP son las del
ciclo de sesión: `mcp_session_open` (al arrancar el servidor, con `consent_ref` y
`redaction_mode`), `mcp_session_select_case` (al seleccionar caso, con `consent_ref` y
`agent_package`), y `mcp_session_close` (al apagar). El argv literal sigue siendo lo que
queda registrado por cada ejecución de tool — no la intención del LLM ni el wire JSON-RPC
del MCP.

## 4. Separación de volúmenes

- **Evidencia**: solo-lectura (block-level RO). Nunca se escribe aquí.
- **Trabajo (outputs)**: volumen RW separado para artefactos, cachés de símbolos de
  Volatility, ficheros `.plaso`. Cada artefacto se hashea al producirse y se enlaza en el log.

### 4.1 Política central de rutas de tools (P0.5-2)

Cada `Tool` declara explícitamente sus parámetros filesystem; no se detectan por sufijos.
`forensia.path_policy` define roles cerrados y el dispatcher los aplica **antes** de
reservar `ArtifactRun`, escribir `tool_run_start` o cruzar el runner:

- `EVIDENCE_INPUT`: path inyectado desde el handle, existente y confinado a
  `case_dir/evidence` del caso activo.
- `CASE_INPUT`: auxiliar RO existente y confinado al `case_dir` activo; otro caso,
  traversal, escape por symlink y directorios sensibles se rechazan.
- `DERIVED_INPUT`: solo el contrato compartido `ArtifactRef`: `run_id` y `relpath`
  obligatorios, `sha256` y `size` opcionales, sin claves adicionales.
  `ArtifactStore.resolve_output_file` confina y re-hashea siempre. Si los metadatos
  opcionales no coinciden con ese valor autoritativo, falla antes del runner. Una ruta
  literal bajo `artifacts/` se rechaza.
- `RUN_OUTPUT`: el caller no lo puede suministrar. El dispatcher lo genera exclusivamente
  bajo `artifacts/<run_actual>/out`; no puede apuntar a `case.json`, `baseline.json`,
  `audit.jsonl`, manifests ni otro run. `bulk_extractor` recibe específicamente
  `out/bulk_extractor`, todavía inexistente al cruzar el runner porque su CLI exige crear
  el directorio; ArtifactStore descubre y hashea después todos sus ficheros.
- `BUNDLED_RULESET` / `RUNTIME_DEVICE`: el modelo aporta un id de enum exacta y el backend
  lo mapea a una única ruta allowlisted por tool. No existe una allowlist amplia de `/opt`
  o `/dev`.

Sin `case_id`, cualquier rol case-scoped o `RUN_OUTPUT` falla fuerte. MCP y el agente
consumen el mismo contrato del catálogo; una llamada directa al dispatcher recibe el
mismo gate.

`qemu_nbd` conserva el identificador cerrado `nbd0` → `/dev/nbd0` y emite `-r`
incondicionalmente. No publica ni acepta un modo escribible.

## 5. Frontera de egreso de datos (nube)

La herramienta **no llama a APIs cloud por sí misma ni usa API keys**. El egreso solo puede
ocurrir a través del **ejecutor** que el operador haya elegido para la investigación: con
**Ollama** (servicio local del compose) nada sale de la máquina; con un ejecutor respaldado
por cloud (**Claude Code**, **Codex CLI**, **Gemini CLI** — autenticados con la cuenta del
propio operador) el contenido derivado del caso fluye al proveedor del CLI. Elegir un
ejecutor cloud exige **advertencia explícita + consentimiento registrado en el audit log**,
con **redacción/minimización** previa (enviar metadatos/artefactos derivados, no bytes
crudos de evidencia). Sin ejecutor seleccionado no hay análisis (RULE 2). Aunque el TFM use
datos sintéticos/públicos, el diseño **impide técnicamente** que la evidencia cruda salga
sin esa decisión consciente y registrada — no lo deja a la política.

**Implementado (la frontera es código, no política).** El egreso a un backend no-local pasa
por un único punto en `ForensicAgent.run`:

1. **Redacción.** Antes de cada `model.next_action`, si `model.capabilities().is_local ==
   False`, se aplican TODAS las `redaction_patterns` del paquete activo
   (`forensia.agent.redaction.redact_messages`) sobre una copia de la conversación entera
   —system (con el nombre de la evidencia inyectado), user y resultados de tool—; la
   conversación canónica que conserva el loop sigue en claro para replay, sólo se redacta el
   payload que sale. Con backend local no se redacta porque nada cruza el host.
2. **Consentimiento por caso.** `CaseManager` persiste `cloud_consent {granted, granted_at,
   by, ref}` en `case.json` (`grant_cloud_consent` / `POST /api/cases/{id}/consent`). Sin
   consentimiento, `/api/agent/query` devuelve `consent_required` y **no instancia el
   backend**: cero bytes salen (THREAT_MODEL gate 9). Además `run` rechaza con error
   cualquier egreso cloud sin `consent_ref` (RULE 2, defensa en profundidad).
3. **Auditoría del egreso.** Cada salida queda encadenada en `audit.jsonl` con el SHA-256 del
   payload **redactado** (nunca los bytes), `consent_ref` y `message_count` (ver §3).

**MCP server con cliente cloud** (sprint S1, rama `mcp`): cuando un cliente MCP cloud como
Claude Desktop consume el servidor `mcp-toolkit`, los outputs de cada tool fluyen al
proveedor del cliente en el siguiente turno del LLM — es la misma frontera de egreso. Las
protecciones:

- **`FORENSIA_CLOUD_CONSENT=<client>` obligatorio** para arrancar el servidor; sin el flag,
  exit 2. El `consent_ref` se registra como entrada `mcp_session_open` en el audit del primer
  caso seleccionado.
- **`FORENSIA_REDACTION_MODE`** controla la agresividad: `strict` (default — todo) redacta
  IPs, emails, MACs, SIDs, AWS keys, JWTs, private keys. `relaxed` preserva los IoCs
  forenses (red, identidades) pero sigue redactando credenciales y material criptográfico.
  `off` no aplica nada (solo apropiado para tests in-process; queda registrado en el audit).
- La redacción se aplica **antes del wire MCP**, sobre `stdout_sample` y `stderr_sample`,
  con los patrones de `agentes/<id>/policy/redaction.yaml` del paquete activo. Cada patrón
  declara `apply_in` con los modos en los que aplica.
- Schemas Pydantic `extra='forbid'` rechazan que el cliente MCP envíe paths crudos a
  evidencia (`image_path`, `dump_path`, etc.); el dispatcher los inyecta desde
  `EvidenceManager`. Los paths auxiliares (YARA `rules_path`, jq `input_path`, Chainsaw
  `sigma_dir`/`rules_dir`) pasan por la política compartida y quedan confinados al
  **caso activo**, no al árbol global de casos.

## 6. Manifiesto del caso (reproducibilidad)

Cada caso registra versiones/builds de cada herramienta y del backend (`api`), hashes
baseline y de verificación, y la cadena del audit log. Sin esto no hay informe defendible.

## 7. Contenedores y evidencia

En el modelo compose **todas** las herramientas corren dentro de los maletines
(`toolkit-windows`, `toolkit-unix`), y la evidencia les llega como **bind-mount de solo
lectura** (`/evidence:ro`) gobernado por `EvidenceManager`. La regla dura se conserva
intacta: **ningún contenedor monta la imagen raw como filesystem**. Las herramientas
prioritarias (TSK `fls/icat/mmls`, Volatility3) leen los bytes de la imagen directamente
como fichero — sin montar FS no hay journal replay posible (§1); el montaje de FS queda
como ruta de excepción documentada por caso, siempre tras el read-only a nivel de bloque.

El motivo de mantener la prohibición es el mismo que justifica la sección §1, agravado por
el runtime: en Mac y Windows el runtime de contenedores (Docker Desktop) proxifica los
volúmenes a través de una VM intermedia — Virtualization.framework en macOS, WSL2 en
Windows — que tiene su propio journaling y políticas de montaje. Un `guestmount`/`qemu-nbd`
de la imagen dentro del contenedor puede disparar journal replay o escrituras de metadatos
en el dispositivo subyacente, romper el hash baseline y, con él, la cadena de custodia. El
usuario no lo ve; el `verify()` final sí.

Disciplina de los wrappers que consumen artefactos extraídos (`evtxecmd`, `mftecmd`,
`regripper`): **se pre-extrae el artefacto** necesario con TSK (`icat` desde un inodo
conocido) o equivalente — siempre a través del `Handle` read-only de `EvidenceManager` — y
el parser opera solo sobre ese fichero derivado, materializado en el volumen de trabajo
(`/cases`). El parser ve un EVTX, un hive de registro o un `$MFT` aislado; nunca necesita
la imagen entera como entrada.

Defensa en profundidad: `backend/forensia/toolkit/container.py:_validate_mount_paths` rechaza
que una imagen de evidencia entre como montaje puntual de un run: cualquier ruta cuyo sufijo
coincida con la lista prohibida (`.raw`, `.dd`, `.img`, `.vmdk`, `.vmem`, `.E01`, `.aff`,
`.lime`, `.ad1`) se rechaza, independientemente de qué wrapper la haya construido. Es
belt-and-suspenders frente a un wrapper mal escrito o una herramienta nueva que un
colaborador añada sin leer esta sección.

Networking del contenedor: `--network none` por defecto, sin excepción implícita. Una
herramienta forense que necesite red es una bandera roja — egress significa exfiltración
potencial de bytes de evidencia y una superficie de SSRF a través de prompt injection.
Habilitarla exige una decisión consciente del operador, queda registrada en el audit log
junto con el motivo, y nunca se concede de forma persistente para la herramienta entera.
