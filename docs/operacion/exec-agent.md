# Canal api→maletín: el exec-agent (§B)

Cómo el servicio `api` consulta y ejecuta herramientas forenses que viven
dentro de los maletines (`toolkit-unix` / `toolkit-windows`), **sin** el socket de Docker
del host. Es el cableado elegido en `proximos-pasos.md` §B.bis.

## El problema

Cada herramienta forense (Sleuthkit, Volatility3, plaso, hayabusa, chainsaw, RegRipper…)
vive en la imagen de un maletín, no en la del `api` (RULE 1: el `api` no empaqueta
ninguna). Para saber si una tool está disponible —y para ejecutarla— el `api` necesita un
canal hacia el maletín. Había dos opciones:

- **§A — socket de Docker en el `api`**: montar `/var/run/docker.sock` y usar `docker exec`.
  Directo, pero le da al `api` (que procesa **evidencia hostil**) control del daemon de
  Docker del **host** en cada despliegue — escalada de privilegios equivalente a root en el
  host. `:ro` sobre el socket no es una frontera real. Descartada como default del repo.
- **§B — exec-agent** (esta): un servicio HTTP mínimo dentro de cada maletín, en la red
  interna del compose. El `api` le habla por HTTP, igual que hace con `ollama`. **Sin
  socket, sin cliente docker en el `api`.** Elegida.

## Arquitectura

```
api  ──HTTP (red interna del compose)──▶  exec-agent  ──subprocess (shell=False)──▶  fls / vol / plaso …
                                          (dentro del maletín, sin puerto publicado)
```

- **Servidor**: `docker/docker/forensic-toolkit/exec_agent.py` (solo stdlib de Python, que
  el maletín ya trae). Los maletines lo arrancan con `command: ["python3",
  "/opt/forensia/exec_agent.py"]` en `docker-compose.yml`.
- **Cliente**: `forensia.toolkit.maletin` (`_request`, `probe_service`, `probe_binaries`).
  `capabilities` consume su `snapshot`.
- **Direccionamiento**: el `api` recibe por env las URLs de red interna:
  `FORENSIA_TOOLKIT_UNIX_URL=http://toolkit-unix:8666` y
  `FORENSIA_TOOLKIT_WINDOWS_URL=http://toolkit-windows:8666`. Sin esas URLs (p. ej. `api`
  standalone fuera del compose), el sondeo reporta cada maletín como *no consultable* con
  razón accionable — nunca adivina disponibilidad (RULE 2).

## API del exec-agent

| Método | Ruta | Cuerpo | Respuesta |
|--------|------|--------|-----------|
| `GET`  | `/health` | — | `{"ok": true, "stage": "unix"\|"windows"}` |
| `GET`  | `/versions` | — | `{"stage": …, "versions": {binario: versión}}` — el manifiesto **inmutable** horneado en el build (`/opt/forensia/versions.json`); ausente/corrupto → `500` accionable |
| `POST` | `/which`  | `{"binaries": ["fls","vol",…]}` | `{"present": ["fls",…]}` (subconjunto en PATH) |
| `POST` | `/exec`   | `{"argv": ["fls","-r","/evidence/…"], "timeout": 300}` | `{"exit": int, "stdout": str, "stderr": str, "timed_out": bool, "executed_argv": [str]}` |
| `POST` | `/exec` (binario) | `{"argv": ["icat",…], "timeout": 300, "stdout_path": "/cases/…/out/stdout.bin"}` | `{"exit": int, "stdout_file": str, "stdout_sha256": str, "stdout_size": int, "stderr": str, "timed_out": bool, "executed_argv": [str]}` |
| `POST` | `/exec` (EWF)     | `{"argv": ["mmls",…,"/cases/…/original.E01"], "timeout": 300, "ewf_image": "/cases/…/original.E01"}` | igual que `/exec` (o el binario si además va `stdout_path`); en fallo de montaje: `424 {"error": "…ewfmount…"}` |

El campo `timeout` acepta `null` (el api no impone timeout): entonces el exec-agent aplica
su techo duro `_MAX_TIMEOUT_S` como timeout efectivo — **nunca** corre sin límite (ver
*Semántica del cierre* → timeouts). Un número se acota a `min(t, techo)`; un no-positivo es
`400`.

**Canal binario-seguro (`stdout_path`).** Algunas tools (TSK `icat`) emiten **bytes crudos**
por stdout (hives, EVTX, `$MFT`, ejecutables). Decodificarlos como texto los corrompe
irreversiblemente (cada byte no-UTF-8 → `U+FFFD`). Cuando el api pasa `stdout_path` —una
ruta dentro del volumen `/cases` compartido, derivada del `ArtifactRun` (nunca la elige el
LLM)— el exec-agent conecta el stdout del hijo **directamente a ese fichero** (`shell=False`,
sin decodificar) y responde con su `stdout_sha256`/`stdout_size` en vez del texto; stderr
sigue como texto (diagnóstico). El catálogo marca esas tools con `binary_stdout=True`; el
dispatcher exige que corran ancladas a un caso (si no, error accionable) y el `ArtifactStore`
re-hashea `out/stdout.bin` (defensa en profundidad, FORENSIC INVARIANT 4).

**Routing EWF (`ewf_image`).** TSK no lee `.E01` nativo (`mmls -i ewf` → *"Unsupported
image type"*). Cuando una tool declara `image_param` (TSK `mmls`/`fls`/`icat` → `"image_path"`)
y ese path es un contenedor EWF (`.E01`/`.ExNN`), el **dispatcher** (que tiene el allowlist y
el param) pasa `ewf_image` con el **token exacto** del argv. El exec-agent lo monta con
`ewfmount` (FUSE, **solo lectura** — expone la imagen como bloque raw `ewf1`, **no** monta el
sistema de ficheros de la evidencia, FORENSIC INVARIANT 3), reescribe ese token del argv al
raw `ewf1`, ejecuta la tool y **desmonta siempre** (incl. en error). El `.E01` se abre RO, así
que no se modifica (el hash baseline no cambia). Compone con `stdout_path` (icat sobre `.E01`).
El maletín necesita `ewfmount` (paquete `ewf-tools`/libewf) y FUSE (`docker-compose.yml`:
`devices:[/dev/fuse]`, `cap_add:[SYS_ADMIN]`); si falta, el agente responde `424` nombrando la
dependencia y el dispatcher falla fuerte — **nunca** trata el `.E01` como raw (RULE 2). La
decisión de si es EWF es del api; el mecanismo (mount/rewrite/unmount) vive en el maletín,
donde corre la tool.

El argv que se **audita** (paso 2 abajo) es el que construye el api, con la ruta **`.E01`** —
la identidad estable y reproducible de la evidencia (ligada a su SHA-256 baseline), **no** el
bloque raw `ewf1`. La reescritura al `ewf1` es un detalle de transporte RO **efímero**
(mountpoint aleatorio, inexistente tras la corrida) y determinista, resuelto por el backend
dentro del maletín; por eso el registro cita la evidencia y no el mount temporal — coherente
con FORENSIC INVARIANT 4 (se audita el argv literal que fija el api, no la intención del LLM,
que además nunca elige el mountpoint).

**El argv ejecutado se VERIFICA, no se presume (P0.5-4).** Toda respuesta 200 de `/exec`
incluye `executed_argv`: la lista literal que el exec-agent pasó a `subprocess.run` (también
en exit 127/timeout). `forensia.toolkit.maletin.run_argv_in_maletin` la compara token a
token contra el argv auditado: sin `ewf_image` deben ser idénticos; con `ewf_image`, cada
posición cuyo token solicitado era el `.E01` debe estar reescrita — todas al MISMO bloque
raw absoluto con basename `ewf1` — y el resto intacto. Cualquier otra cosa (campo ausente
→ imagen anterior al contrato, reconstruye el maletín; longitud distinta; token alterado;
token EWF sin reescribir; reescritura que no es el bloque raw) es `MaletinExecError`
("custodia rota"): el dispatcher cierra el run como error con su contexto forense y el
resultado **no se acepta** (RULE 2 — nunca "probablemente hizo lo correcto"). Tests:
`backend/tests/test_ewf_routing.py` §4.

El **dispatcher** (`toolkit/dispatcher.py`) ejecuta las tools sobre este canal:
resuelve el argv desde el allowlist, elige el maletín por el `os_profile` del caso
(`_select_maletin`, sin fallback entre maletines — RULE 2) y lanza `POST /exec` vía
`forensia.toolkit.maletin.run_argv_in_maletin`. El mismo canal alimenta el sondeo de
`capabilities` (`/health` + `/which`).

Para una ejecución anclada a caso, el límite auditable está antes del transporte:

1. el dispatcher valida el **`EvidenceContext`** contra `EvidenceManager` (contexto
   obligatorio en toda ejecución anclada; falsificado/de otro caso → rechazo), aplica el
   gate de rutas (incl. la procedencia de los `ArtifactRef` derivados), resuelve la única
   ubicación de ejecución y la **versión autoritativa** de la tool en ese maletín
   (`GET /versions`; irresoluble → la tool no se ejecuta, sin fallback);
2. abre el `ArtifactRun` (el manifiesto persiste `evidence_id` + baseline +
   `tool_version`), construye el argv literal, lo persiste y añade `tool_run_start`
   (con contexto + versión) al `audit.jsonl` hash-encadenado;
3. solo después invoca `run_argv` local o `POST /exec` en el maletín seleccionado;
4. cuando el runner devuelve —también con exit code distinto de cero— finaliza el
   `ArtifactRun` e intenta añadir como máximo un `tool_run_finish` con el exit code
   literal, hashes y el mismo contexto + versión del start.

Si el transporte, el timeout local o la invocación lanzan una excepción después del start,
el `ArtifactRun` se cierra con `status: "error"`, `exit_code: null` y el
tipo/mensaje de la excepción. El dispatcher intenta emitir como máximo un
`tool_run_finish` de error con esos datos; no se inventa un exit code ni se reintenta
en otro maletín. Un
rechazo anterior a disponer de un argv ejecutable (tool desconocida, params inválidos o
selección imposible) no genera un `tool_run_start` que afirme una ejecución inexistente.

El pareado start/finish depende de que `ArtifactStore` y `AuditLog` sigan escribibles;
no se promete frente a `kill -9`, caída de máquina, corrupción irrecuperable o fallo
del append final. Cada cierre se intenta **una sola vez**, porque un error de
flush/fsync deja incierto si la línea llegó a disco y un retry podría duplicarla. El
dispatcher propaga ese fallo como `ToolExecutionError` accionable, conserva como causa
la excepción primaria cuando existe y no reejecuta la herramienta. Si falla el append
del `tool_run_start`, la tool se rechaza sin ejecutar, no se intenta un finish sin start
y el `ArtifactRun` reservado se cierra como `error`.

Hay dos timeouts con semántica distinta:

- `subprocess.TimeoutExpired` del runner local cruza el dispatcher como excepción:
  `ArtifactRun.status="error"` y `exit_code=null`, con streams parciales.
- El timeout interno del exec-agent remoto se serializa como
  `{"timed_out": true, "exit": 124, ...}`. `maletin.py` devuelve ese `124` como un
  resultado normal, por lo que el dispatcher registra `status="finished"` y
  `exit_code=124`.

**Toda corrida está SIEMPRE acotada (custodia del hash, INVARIANT 4).** El agente/MCP
llaman al dispatcher sin timeout, así que baja `timeout=null` hasta el exec-agent. El
exec-agent **nunca** ejecuta con timeout efectivo `None`: si llega `null`, aplica el
techo duro `_MAX_TIMEOUT_S` (1800 s) como timeout efectivo; un número se acota a
`min(t, techo)` y un no-positivo es un `400` accionable (RULE 2). `subprocess.run` **mata
y recolecta** el hijo al expirar, así que cuando el exec-agent hashea `out/stdout.bin` el
proceso ya está muerto y el fichero no cambia. En el lado del `api`, `maletin.py`
dimensiona el timeout de lectura HTTP **estrictamente por encima** del techo efectivo del
exec-agent (`_EXEC_AGENT_MAX_TIMEOUT`, espejo del techo del exec-agent, `+
_HTTP_TIMEOUT_MARGIN`), de modo que el exec-agent **siempre** termina (mata + hashea +
responde) antes de que el transporte se rinda: el dispatcher jamás cierra ni hashea un run
con el proceso del maletín aún vivo escribiendo (evita el SHA-256 sobre bytes que mutan).

Unificar o distinguir formalmente la semántica del `124` remoto vs. la excepción local
sigue siendo un gap pendiente de una decisión separada.

## Seguridad

- **Shell-free**: `subprocess.run(argv, shell=False)`; `argv` debe ser `list[str]` no vacía
  (SECURITY INVARIANT 4). El agente rechaza cualquier otra cosa.
- **`/versions` es un endpoint cerrado**: sin parámetros, sin paths del caller, sin
  ejecutar comandos — solo lee el `versions.json` inmutable de la imagen (horneado por
  `gen_versions.py`; el build falla si una tool declarada no tiene versión determinista).
  Nunca sirve un placeholder (RULE 2). La ruta del manifiesto admite el override
  `FORENSIA_VERSIONS_MANIFEST` — existe **solo** para que los tests loopback sirvan un
  manifiesto real desde `tmp`; el compose no lo define y fijarlo en despliegue rompería
  la identidad de build (no lo hagas).
- **Allowlist en el `api`, no aquí**: el LLM emite un id de tool + params tipados y el
  backend resuelve el argv real desde el allowlist (SECURITY INVARIANT 5). El exec-agent
  solo ejecuta el argv ya resuelto — no interpreta, no expande, no usa shell.
- **Sin exposición al host**: el maletín no declara `ports:`, así que el bind a
  `0.0.0.0:8666` es alcanzable **solo** en la red interna del compose, nunca desde el host
  (SECURITY INVARIANT 1). Idéntico a `ollama`.
- **Token opcional**: si defines `FORENSIA_EXEC_AGENT_TOKEN` en el `api` y en ambos
  maletines, el agente exige la cabecera `X-Forensia-Exec-Token`. Por defecto va sin auth,
  apoyándose en el aislamiento de red interna.
- **Evidencia read-only**: el compose monta `./evidence:/evidence:ro` también en los
  maletines; un `POST /exec` que lea `/evidence/…` respeta la cadena de custodia. Las
  herramientas TSK/Volatility leen la imagen sin montar el sistema de ficheros
  (soundness-forense.md).

## Operación

```bash
# Salud del exec-agent de un maletín (desde el host, vía el propio maletín):
docker compose exec toolkit-unix python3 -c \
  "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8666/health').read())"

# Presencia de binarios / estado real de tools: lo reporta la UI (Estado del Sistema) y
# GET /api/capabilities (campos `toolkits` y `tools`).
```

Endurecer con token:

```yaml
# docker-compose.override.yml (local)
services:
  api:            { environment: { FORENSIA_EXEC_AGENT_TOKEN: "<secreto>" } }
  toolkit-unix:   { environment: { FORENSIA_EXEC_AGENT_TOKEN: "<secreto>" } }
  toolkit-windows:{ environment: { FORENSIA_EXEC_AGENT_TOKEN: "<secreto>" } }
```
