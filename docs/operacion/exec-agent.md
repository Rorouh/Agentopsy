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
| `POST` | `/which`  | `{"binaries": ["fls","vol",…]}` | `{"present": ["fls",…]}` (subconjunto en PATH) |
| `POST` | `/exec`   | `{"argv": ["fls","-r","/evidence/…"], "timeout": 300}` | `{"exit": int, "stdout": str, "stderr": str, "timed_out": bool}` |

El **dispatcher** (`toolkit/dispatcher.py`) ejecuta las tools sobre este canal:
resuelve el argv desde el allowlist, elige el maletín por el `os_profile` del caso
(`_select_maletin`, sin fallback entre maletines — RULE 2) y lanza `POST /exec` vía
`forensia.toolkit.maletin.run_argv_in_maletin`. El mismo canal alimenta el sondeo de
`capabilities` (`/health` + `/which`).

Para una ejecución anclada a caso, el límite auditable está antes del transporte:

1. el dispatcher valida la tool y sus params, abre el `ArtifactRun`, construye el argv
   literal y resuelve una única ubicación de ejecución;
2. persiste ese argv en el manifiesto y añade `tool_run_start` al `audit.jsonl`
   hash-encadenado;
3. solo después invoca `run_argv` local o `POST /exec` en el maletín seleccionado;
4. cuando el runner devuelve —también con exit code distinto de cero— finaliza el
   `ArtifactRun` e intenta añadir como máximo un `tool_run_finish` con el exit code
   literal y hashes.

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

Hay dos timeouts con semántica actual distinta:

- `subprocess.TimeoutExpired` del runner local cruza el dispatcher como excepción:
  `ArtifactRun.status="error"` y `exit_code=null`, con streams parciales.
- El timeout interno del exec-agent remoto se serializa hoy como
  `{"timed_out": true, "exit": 124, ...}`. `maletin.py` devuelve ese `124` como un
  resultado normal, por lo que el dispatcher registra `status="finished"` y
  `exit_code=124`.

Unificar o distinguir formalmente esa segunda semántica es un gap pendiente de una
decisión separada; este cambio no modifica `maletin.py` ni el exec-agent.

## Seguridad

- **Shell-free**: `subprocess.run(argv, shell=False)`; `argv` debe ser `list[str]` no vacía
  (SECURITY INVARIANT 4). El agente rechaza cualquier otra cosa.
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
