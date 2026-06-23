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

## 6. Manifiesto del caso (reproducibilidad)

Cada caso registra versiones/builds de cada herramienta y del sidecar, hashes baseline y de
verificación, y la cadena del audit log. Sin esto no hay informe defendible.
