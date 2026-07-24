# Runbook manual — cadena forense E2E sobre un `.E01` (docker compose)

Pasos exactos para ejercer la **cadena completa por el camino producto** sobre una imagen
**EWF real** (`.E01`), levantando el stack con `docker compose`. Es un paso del **operador**,
no de CI: la cadena abre el `.E01` con `ewfmount` (FUSE, RO — P0.3), y el runner de CI no
tiene `/dev/fuse`. La contraparte automatizada **sin Docker ni FUSE** vive en
[`backend/tests/test_e2e_chain.py`](../../backend/tests/test_e2e_chain.py) (exec-agent por
loopback, binarios sustituidos por stand-ins POSIX): ese test cubre en CI todo excepto el
montaje EWF real, que se valida aquí.

La cadena es: **`mmls` → `fls` → `icat` (→ `out/stdout.bin` hasheado) → RegRipper** que
consume ese artefacto como input derivado (re-verificado por SHA-256 antes de correr).

## 0. Prerrequisitos

- **Docker** con el plugin `compose` (único prerequisito documentado de la app, RULE 1).
- Un **`.E01`** de un disco (idealmente Windows, para RegRipper). Si es un set segmentado,
  incluye también `.E02`, `.E03`, … (o `.Ex01`, …) junto al primero.
- FUSE en el host: el compose ya concede a los maletines `cap_add:[SYS_ADMIN]` y
  `devices:[/dev/fuse]` para `ewfmount` (ver [`docker-compose.yml`](../../docker-compose.yml)
  `x-toolkit-common`). No los comentes: sin ellos el `.E01` no se puede procesar (RULE 2).

## 1. Colocar la evidencia y levantar el stack

```bash
# Deja el .E01 (y sus segmentos) en la bandeja de evidencias del repo:
cp /ruta/a/caso.E01 ./evidence/          # + caso.E02, caso.E03, … si es segmentado

docker compose up --build                # levanta web, api, ollama y los dos maletines
# Abre la UI en el navegador:
#   http://127.0.0.1:5173
```

Comprobación rápida de que el maletín trae `ewfmount` y su exec-agent responde:

```bash
docker compose exec toolkit-unix sh -lc 'command -v ewfmount && \
  python3 -c "import urllib.request;print(urllib.request.urlopen(\"http://127.0.0.1:8666/health\").read())"'
```

## 2. Crear el caso y registrar la evidencia (hash gate)

En la UI:

1. **Crear caso** (nombre, examinador). El `os_profile` lo determina el triage por el
   contenido, o lo ancla el operador (Windows para un disco NTFS) — nunca por el host (RULE 2).
2. **Registrar evidencia** desde la bandeja (`Registrar evidencia` → elige `caso.E01`).
   Registrar el **primer segmento** (`.E01` / `.Ex01`) **ingiere el SET COMPLETO como UNA
   evidencia**: el backend descubre sus hermanos co-localizados (`.E02`, `.E03`, … según la
   convención libewf) en el **mismo directorio** de origen y aplica el **hash gate en orden,
   por segmento** (SHA-256 del origen → copia inmutable → re-hash → `chmod 0444`). Las copias
   quedan bajo un **stem común** para que `ewfmount` reensamble desde la primera:

   ```
   ./projects/cases/<case-id>/evidence/<evidence-id>/
     original.E01   original.E02   …   original.E0N
     baseline.json  ← sha256 primario = el del .E01; segments:[{name,sha256,size}, …] (N entradas)
   ```

   - **Set incompleto → rechazo (RULE 2):** si la secuencia tiene un hueco (hay `.E01` y
     `.E03` pero falta `.E02`) el registro **falla fuerte** y **no** deja evidencia a medias;
     coloca el segmento que falta y reintenta. Un `.E01` **sin hermanos** es válido (segmento
     único). Registrar un segmento intermedio (`.E02`…) por sí solo se rechaza: registra el
     `.E01`.
   - Un fichero único (`.raw` / `.dd` / `.vmdk` / `.mem`) se registra exactamente igual que
     antes (sin `segments`).

> El agente y las tools **nunca** tocan la ruta original: siempre la copia inmutable
> (FORENSIC INVARIANTS 1-2). Ningún segmento `.E0x` se modifica en ningún paso. **Verificar**
> (Evidencia → Verificar) re-hashea **todos** los segmentos: si cualquiera cambia, la
> verificación falla nombrando el segmento afectado.

## 3. Ejecutar la cadena (por el agente / chat)

`dispatcher.execute` lo dirige el **agente** (chat de la UI) o el servidor **MCP** — no hay
endpoint REST de ejecución arbitraria de tools (SECURITY INVARIANT 5: el LLM emite id de tool
+ params tipados, el backend resuelve el argv del allowlist). Con un **ejecutor
seleccionado** (Claude Code / Codex / Gemini / Ollama — el operador lo elige explícitamente,
RULE 2), pide al agente la cadena anclada al caso. Las tools y params que el agente invoca:

| Paso | Tool | Params (típicos) | Qué produce |
|------|------|------------------|-------------|
| 1 | `tsk_mmls` | `{image_path: …/original.E01}` | tabla de particiones (offset de la partición del SO) |
| 2 | `tsk_fls`  | `{image_path: …/original.E01, partition_offset: <sectores>, recursive: true}` | árbol de ficheros → localiza el inodo del hive (p. ej. `SOFTWARE`) |
| 3 | `tsk_icat` | `{image_path: …/original.E01, inode: <n>, partition_offset: <sectores>}` | extrae el hive **byte-exacto** a `out/stdout.bin` (hasheado) |
| 4 | `regripper`| `{hive_path: {run_id: <run de icat>, relpath: "stdout.bin"}, plugin: <plugin>}` | parsea el hive extraído |

Notas de soundness de la cadena:

- **EWF automático (P0.3):** como `image_path` termina en `.E01`, el dispatcher pasa
  `ewf_image` al exec-agent; el maletín monta con `ewfmount` (FUSE, **RO** — bloque raw
  `ewf1`, **sin** montar el sistema de ficheros, INVARIANT 3), reescribe el token del argv al
  raw, ejecuta la tool y **desmonta siempre**. TSK lee el disco sin montar el FS. Ver
  [`exec-agent.md`](exec-agent.md) § *Routing EWF*.
- **Relevo derivado (paso 4):** RegRipper recibe la **referencia** al artefacto de `icat`
  (`{run_id, "stdout.bin"}`), no una ruta inventada; el dispatcher la resuelve a la ruta RO
  del caso y **re-hashea** contra el manifiesto antes de ejecutar (custodia del derivado,
  INVARIANTS 1-2). Ver [`storage.md`](../storage.md) § *Relevo derivado*.
- Si `ewfmount`/FUSE no está → el exec-agent responde `424` nombrando la dependencia y la
  tool falla fuerte; **jamás** se trata el `.E01` como raw (RULE 2).

> **Alternativa MCP:** desde un cliente MCP, `select_case` (obligatorio, RULE 2) y luego las
> mismas tools con los mismos params. Mismo dispatcher, mismo audit.

## 4. Qué comprobar en el audit (custodia end-to-end)

El log vive **en disco**, no se expone por HTTP:
`./projects/cases/<case-id>/audit.jsonl`. Para cada una de las 4 corridas debe haber:

- un **`tool_run_start`** con el **argv literal** (con la ruta **`.E01`** — la identidad
  estable de la evidencia, no el `ewf1` efímero) y los `params`;
- un **`tool_run_finish`** con el **exit code literal** y los **SHA-256** de stdout/artefactos
  (INVARIANT 4);
- en la corrida de RegRipper, un **`derived_inputs`** que enlaza el artefacto de `icat`
  (`source_run_id`, `relpath: "stdout.bin"`, `sha256` re-verificado) con esa corrida.

Verificaciones:

```bash
CASE=./projects/cases/<case-id>

# La cadena de hash del audit es íntegra (tamper-evident):
docker compose exec api python -c \
  "from forensia.audit.log import AuditLog; print(AuditLog('/cases/cases/<case-id>/audit.jsonl').verify())"
# → True

# El SHA-256 del stdout.bin de icat coincide con el que RegRipper re-verificó:
grep -E '"action":"tool_run_(start|finish)"' "$CASE/audit.jsonl" | tail -8

# La evidencia no se modificó (baseline intacto): re-verifica el handle desde la UI
# (Evidencia → Verificar) o compara baseline.json con un re-hash del original.E01.
```

Criterio de éxito: `verify()` = `True`, el `sha256` del `stdout.bin` en el `finish` de `icat`
es idéntico al `sha256` del `derived_inputs` de RegRipper, y el `baseline.json` de la
evidencia no cambia (el `.E01` se abrió **RO** vía `ewfmount`).

## 5. Cierre

```bash
docker compose down                      # detiene el stack (conserva ./projects y ./evidence)
# Revocar además las sesiones de los CLIs (y modelos de ollama):
# docker compose down -v
```

## Referencias

- Camino api→maletín y routing EWF: [`exec-agent.md`](exec-agent.md).
- Artefactos, relevo derivado y custodia: [`storage.md`](../storage.md).
- Contraparte automatizada sin Docker/FUSE (CI): `backend/tests/test_e2e_chain.py`
  (cadena por loopback), `test_ewf_routing.py` (routing EWF), `test_derived_handoff.py`
  (relevo derivado), `test_binary_stdout_channel.py` (canal binario de `icat`).
- Ingesta del set multi-segmento (copia de `.E01`…`.E0N`, `segments[]`, rechazo de huecos,
  `verify` de todos los segmentos): `backend/tests/test_evidence_ewf_segments.py`.
