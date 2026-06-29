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
  → expose handle                                                    [recién aquí]
  ... análisis (herramientas y agente solo reciben el handle) ...
  → verify()  (re-hash y comparación)                                [al cerrar sesión]
```

Ninguna herramienta ni agente recibe la ruta cruda: solo un `Handle`. El hash baseline
existe **antes** de cualquier exposición. Se re-verifica al final para demostrar que el
flujo no alteró la evidencia.

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

Además del **comando literal por tool run** (lo escribe el dispatcher), el loop del agente
añade eventos de nivel-agente que el dispatcher no puede ver, encadenados en la misma
`audit.jsonl`: `agent_run_start` (caso, evidencia + hash, backend, modelo), `agent_cloud_egress`
(uno por salida a cloud: `consent_ref`, `redacted_payload_sha256`, `message_count`) y
`agent_finding` (`finding_id`). Nunca registran bytes crudos, sólo hashes/metadatos.

## 4. Separación de volúmenes

- **Evidencia**: solo-lectura (block-level RO). Nunca se escribe aquí.
- **Trabajo (outputs)**: volumen RW separado para artefactos, cachés de símbolos de
  Volatility, ficheros `.plaso`. Cada artefacto se hashea al producirse y se enlaza en el log.

## 5. Frontera de egreso de datos (nube)

`local` por defecto. El modo `cloud` es opt-in por caso, con consentimiento registrado en el
audit log, **redacción/minimización** previa (enviar metadatos/artefactos derivados, no
bytes crudos de evidencia) y preview de lo que sale. Aunque el TFM use datos
sintéticos/públicos, el diseño **impide técnicamente** que la evidencia cruda salga por
defecto, no lo deja a la política.

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

## 6. Manifiesto del caso (reproducibilidad)

Cada caso registra versiones/builds de cada herramienta y del sidecar, hashes baseline y de
verificación, y la cadena del audit log. Sin esto no hay informe defendible.

## 7. Contenedores y evidencia

Regla dura: **un contenedor nunca monta la imagen raw**. Extensiones prohibidas como volumen
de entrada a cualquier contenedor: `.raw`, `.dd`, `.img`, `.vmdk`, `.vmem`, `.E01`, `.aff`,
`.lime`, `.ad1`.

El motivo es el mismo que justifica la sección §1, agravado por el runtime: en Mac y Windows
el OCI runtime (Docker Desktop, Podman Desktop) proxifica los volúmenes a través de una VM
intermedia — HyperKit/Virtualization.framework en macOS, WSL2 en Windows — que tiene su
propio journaling y políticas de montaje. Montar la imagen raw allí puede disparar journal
replay o escrituras de metadatos en el dispositivo subyacente, romper el hash baseline y, con
él, la cadena de custodia. El usuario no lo ve; el `verify()` final sí.

Disciplina de los wrappers `container` (`evtxecmd`, `mftecmd`, `regripper`): **se
pre-extrae el artefacto** necesario en el host con TSK (`icat` desde un inodo conocido) o
equivalente — siempre a través del `Handle` read-only de `EvidenceManager` — y solo ese
fichero derivado se monta read-only dentro del contenedor (típicamente en `/in/<artifact>`).
El contenedor ve un EVTX, un hive de registro o un `$MFT` aislado; nunca la imagen entera.

Defensa en profundidad: `backend/forensia/toolkit/container.py:_validate_mount_paths` rechaza
cualquier ruta cuyo sufijo coincida con la lista prohibida, independientemente de qué
wrapper la haya construido. Es belt-and-suspenders frente a un wrapper mal escrito o una
herramienta nueva que un colaborador añada sin leer esta sección.

Networking del contenedor: `--network none` por defecto, sin excepción implícita. Una
herramienta forense que necesite red es una bandera roja — egress significa exfiltración
potencial de bytes de evidencia y una superficie de SSRF a través de prompt injection.
Habilitarla exige una decisión consciente del operador, queda registrada en el audit log
junto con el motivo, y nunca se concede de forma persistente para la herramienta entera.
