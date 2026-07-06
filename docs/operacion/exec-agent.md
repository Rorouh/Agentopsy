# Canal api→maletín: el exec-agent (§B)

Cómo el servicio `api` consulta y (a futuro) ejecuta herramientas forenses que viven
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

`/exec` está implementado en el agente pero el **dispatcher** (`toolkit/dispatcher.py`) aún
no lo usa (Parte 2 pendiente): hoy el canal alimenta el sondeo de `capabilities`; que el
agente ejecute tools end-to-end requiere realinear el dispatcher sobre `POST /exec`.

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
