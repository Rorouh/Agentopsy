# 00 — Estado de la plataforma

> Leído de `/api/capabilities` en vivo el **2026-07-28**, con la stack levantada
> por `docker compose up --build`. Índice: [`README.md`](README.md).

## Host y runtime

| Campo | Valor |
|---|---|
| Plataforma del contenedor `api` | `linux` / `aarch64` |
| Runtime de contenedores detectado | sí |
| Host real | macOS (Darwin 25.5.0), Apple Silicon |

> Los maletines están fijados a `linux/amd64` (el PPA GIFT no publica arm64), así
> que en este host **corren emulados**. Es un coste de rendimiento conocido y
> documentado, no un fallo.

## Servicios

Los cinco arrancan y los tres con healthcheck lo pasan antes de que arranque el
que depende de ellos.

| Servicio | Estado | Puerto publicado |
|---|---|---|
| `web` | up | `127.0.0.1:5173` → 80 |
| `api` | up (healthy) | `127.0.0.1:8000` |
| `ollama` | up | ninguno (red interna) |
| `toolkit-unix` | up (healthy) | ninguno (`http://toolkit-unix:8666`) |
| `toolkit-windows` | up (healthy) | ninguno (`http://toolkit-windows:8666`) |

Ambos maletines responden al sondeo del exec-agent (`running: true`, sin razón de
degradación). Todos los puertos publicados bindean `127.0.0.1` — SECURITY
INVARIANT 1 se cumple.

## Herramientas del catálogo: 31/31 disponibles

**Ninguna degradada.** El api alcanza los dos maletines y encuentra el binario de
cada herramienta, con su versión.

```
amcacheparser, appcompatcacheparser, bulk_extractor, chainsaw, evtxecmd, ewf_info,
file_info, foremost, ftkimager, hashdeep, hayabusa, jlecmd, jq, lecmd, mftecmd,
plaso_log2timeline, plaso_psort, qemu_nbd, rbcmd, recmd, regripper, sbecmd,
strings_head, tsk_fls, tsk_icat, tsk_mactime, tsk_mmls, volatility3, wxtcmd,
xxd_head, yara
```

Es un dato relevante para §4 ([`04-resultados.md`](04-resultados.md)): **que no
haya resultados no se explica por herramientas faltantes**. Estaban todas.

## Ejecutores: 3 de 4 disponibles

| Ejecutor | Local | Disponible | Razón |
|---|---|---|---|
| Claude Code | no | **sí** | — |
| Codex CLI | no | **sí** | — |
| Ollama | **sí** | **sí** | — |
| Gemini CLI | no | **no** | Sin sesión: no existe `~/.gemini/oauth_creds.json` en el volumen `forensia-cli-auth` |

El mensaje de Gemini nombra el comando exacto para arreglarlo
(`docker compose exec -it -e NO_BROWSER=true api gemini`) — es el patrón de RULE 2:
degradar nombrando la dependencia que falta, sin sustituir por otro ejecutor.

Recordatorio: **no hay ejecutor por defecto**. Si el operador no elige uno, la
petición al agente es un 503, nunca una ejecución silenciosa contra Ollama.

## Paquetes de agente cargados: 2

| Paquete | `os_profile` | Herramientas permitidas | `max_iterations` | Modelo declarado |
|---|---|---|---|---|
| `forensia-unix` | `unix` | 16 | 12 | `llama3.1:8b` |
| `forensia-windows` | `windows` | 28 | 12 | `llama3.1:8b` |

Sin errores de carga. Raíz montada en el contenedor: `/opt/forensia/agentes`.

Notas sobre estos números:

- El **allowlist** del paquete es un subconjunto del catálogo: `forensia-windows`
  puede invocar 28 de las 31; `forensia-unix`, 16. El dispatcher rechaza cualquier
  `tool_id` fuera de esa lista aunque el modelo lo emita.
- `max_iterations: 12` se bajó de 18 por el bug de consumo de tokens (Bug 008). Es
  uno de los puntos que el perito quiere revisar con criterio forense y no solo de
  coste — ver `docs/agentes/INTERNO-revision-flujo-y-autonomia.md` §3.
- El `model.name` del `agent.yaml` (`llama3.1:8b`) es la base local de la
  comparativa; **el ejecutor real lo elige el operador** en cada petición y puede
  no ser Ollama.
- `agentes/_orchestrator/` **no aparece** en esta lista, y es correcto: la registry
  salta los directorios con prefijo `_`. No es un agente cargable.

## Qué se puede concluir de esta sección

La plataforma estaba **entera** en el momento de la prueba: cinco servicios
sanos, las 31 herramientas alcanzables, tres ejecutores utilizables y los dos
paquetes de agente cargados. Cualquier cosa que no ocurrió en este caso
(→ [`04-resultados.md`](04-resultados.md)) no se puede achacar a la
infraestructura.
