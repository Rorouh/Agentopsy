# Agentopsy — Maletín forense contenedorizado

Maletín de herramientas forenses CLI empaquetado en Docker, en dos imágenes:
**`toolkit-windows`** (artefactos de Windows) y **`toolkit-unix`** (artefactos
Unix-like). Es la base sobre la que los agentes de IA hacen *tool-calling*
(sección «Cómo lo consulta la IA»).

Los dos maletines son parte del compose raíz del repo (`docker-compose.yml`,
cinco servicios: `web`, `api`, `ollama` y los dos maletines). Este directorio
contiene los Dockerfiles de los servicios (`api/`, `web/`,
`docker/forensic-toolkit/`) y este README documenta los maletines en concreto.

> **Aclaración importante.** Son contenedores **Linux** que contienen las
> herramientas para analizar evidencias de Windows y de Unix. No es un contenedor
> con sistema operativo Windows: RegRipper, hayabusa, chainsaw, TSK, Volatility y
> plaso son ejecutables sobre Linux, y es lo que permite que `docker compose up`
> dé el mismo entorno en los tres sistemas operativos anfitriones. Si en algún momento
> necesitas un binario que SOLO exista para Windows, ese caso se trataría aparte
> con un contenedor Windows real (requiere host Windows en modo *Windows
> containers*).

## Requisitos

- Docker Engine 24+ y Docker Compose v2 (`docker compose`, no `docker-compose`).
- Conexión a Internet en el primer build (descarga paquetes, hayabusa, chainsaw,
  el runtime .NET, las EZ Tools de Eric Zimmerman y el FTK Imager CLI).
- Linux o Windows/macOS con Docker Desktop. En Windows usa WSL2 como backend.

> **Arquitectura: los maletines son `linux/amd64`.** El compose fija
> `platform: linux/amd64` en `toolkit-windows` y `toolkit-unix` porque el PPA GIFT
> (plaso, sleuthkit, libyal, bulk-extractor) **no publica paquetes arm64**: sin ese
> pin, el build falla en Apple Silicon. Con el pin, en un host arm64 (Mac M-series)
> los maletines corren **bajo emulación** (Rosetta/QEMU vía binfmt) — idénticos a x86
> pero con build y análisis pesados más lentos. En un host x86_64 el pin coincide con
> la plataforma nativa, sin coste. Docker Desktop trae la emulación activada por
> defecto; en Linux arm64 puro instala `qemu-user-static` + `binfmt` si no la tienes.

> **En Linux usa el Docker Engine nativo** (contexto `default`), no Docker
> Desktop. Docker Desktop —también en Linux— ejecuta los contenedores dentro de
> una VM y los bind-mounts pasan por su capa de compartición de ficheros: eso
> rompe el invariante de soundness para montar evidencia y además su file-sharing
> no cubre rutas fuera de `$HOME` (p. ej. `/mnt`). Si tienes ambos instalados:
> `docker context use default` o prefija los comandos con
> `docker --context default …`.

## Estructura

```
Agentopsy/                          # raíz del repo
├── docker-compose.yml              # el compose raíz: los CINCO servicios
├── evidence/                       # <- coloca aquí las evidencias (.raw/.vmdk/.E01)
├── projects/                       # <- salidas, casos e informes
└── docker/
    ├── api/                        # imagen del backend + CLIs de ejecución
    ├── web/                        # imagen del frontend: build de web/ + nginx (proxy /api)
    ├── docker/forensic-toolkit/
    │   ├── Dockerfile              # multi-stage: base + windows + unix
    │   ├── requirements-windows.txt# parsers Python de artefactos Windows
    │   ├── tool-binaries.json      # binarios y versiones fijadas del maletín
    │   └── .dockerignore
```

## Construir y levantar (un solo comando)

Desde la **raíz del repo**:

```bash
cd Agentopsy
docker compose up --build
```

Comprobar que el maletín está listo:

```bash
docker compose exec toolkit-windows agentopsy-info
docker compose exec toolkit-unix    agentopsy-info
```

Debería listar cada herramienta con su ruta. El primer build tarda (compila e
instala plaso y descarga ~150 MB de binarios: hayabusa, chainsaw, runtime .NET
y EZ Tools); los siguientes usan caché.

## Carpeta de evidencia configurable

La aplicación final centraliza todas las evidencias del caso en **una única
carpeta que elige el usuario**. El compose refleja ese diseño: la carpeta que
se monta en `/evidence` (solo lectura) se configura con la variable
`AGENTOPSY_EVIDENCE_DIR`, y la de salidas (`/cases`) con `AGENTOPSY_CASES_DIR`.
Sin variables definidas se usan `./evidence` y `./projects` (defaults de
diseño, relativos a la raíz del repo, donde vive `docker-compose.yml`). Nunca
escribas rutas absolutas de tu host en los ficheros versionados.

```bash
# Opción A: variable de entorno puntual
AGENTOPSY_EVIDENCE_DIR=/ruta/al/caso/evidencia docker compose up -d

# Opción B: fichero .env junto al docker-compose.yml de la raíz (ignorado por git)
echo 'AGENTOPSY_EVIDENCE_DIR=/ruta/al/caso/evidencia' > .env
docker compose up -d
```

## Uso básico

1. Apunta `AGENTOPSY_EVIDENCE_DIR` a la carpeta de evidencia del caso (o copia
   la evidencia a `./evidence/`; desde la web también puedes ARRASTRARLA/subirla).
   Se monta en `/evidence` en **solo lectura** para los maletines/agente; el
   servicio `api` la monta en lectura-escritura (camino de subida del perito —
   ver soundness-forense.md §7).
2. Verifica integridad (cadena de custodia):

   ```bash
   docker compose exec toolkit-windows agentopsy-hash /evidence/disco.raw
   ```
3. Lanza herramientas; las salidas van a `./projects` (`/cases` dentro):

   ```bash
   docker compose exec toolkit-windows fls -r -p /evidence/disco.raw
   docker compose exec toolkit-unix    log2timeline.py /cases/out.plaso /evidence/linux.raw
   ```

Catálogo completo de herramientas de cada maletín: `docker compose exec toolkit-unix agentopsy-info` (o `toolkit-windows`); las versiones fijadas viven en [`docker/forensic-toolkit/tool-binaries.json`](docker/forensic-toolkit/tool-binaries.json).

## Cómo lo consulta la IA (tool-calling)

El maletín queda **habilitado para que el `api` lo consulte** así:

- Cada contenedor corre el **exec-agent** (`python3 /opt/agentopsy/exec_agent.py`) con
  todas las herramientas en el `PATH`, las evidencias en `/evidence:ro` y las salidas en
  `/cases`. El exec-agent es un HTTP mínimo en la red interna del compose (`:8666`, **sin
  puerto publicado**) — es el canal api→maletín, sin socket de Docker. El código
  del agente vive en [`docker/forensic-toolkit/exec_agent.py`](docker/forensic-toolkit/exec_agent.py).
- El `api` consulta presencia de tools (`GET /health`, `POST /which`) por HTTP a
  `http://toolkit-unix:8666` / `http://toolkit-windows:8666` — es lo que reporta
  `capabilities` — y ejecuta las tools del agente por el mismo canal (`POST /exec`):
  el dispatcher resuelve el argv desde el allowlist y lo lanza en el maletín del
  `os_profile` del caso.
- **Versiones autoritativas:** durante el build de cada stage,
  `gen_versions.py` hornea el manifiesto **inmutable** `/opt/agentopsy/versions.json`
  (una fuente designada por binario: paquete dpkg, `importlib.metadata` para
  volatility3, el ARG pinneado para hayabusa/chainsaw, el commit git del clone de
  RegRipper, y la versión auto-reportada + SHA-256 del zip para las EZ Tools). La lista
  de binarios declarados vive en `docker/forensic-toolkit/tool-binaries.json` (espejo
  del catálogo del backend, verificado por test); **si una tool declarada no tiene
  versión determinista, el build falla** — nunca existe un "unknown". El exec-agent lo
  sirve por `GET /versions` y el dispatcher lo consulta ANTES de cada `tool_run_start`
  (FORENSIC INVARIANT 4).
- A mano, para depurar, también puedes ejecutar directamente dentro del contenedor:

  ```bash
  docker compose exec toolkit-windows <herramienta> <args...>
  ```

  El agente Windows apunta a `toolkit-windows` y el Unix-like a `toolkit-unix`.

## Privacidad y cadena de custodia

- Evidencias montadas en **solo lectura**; se trabaja sobre copias y se verifica
  hash SHA-256 antes y después.
- El ejecutor de IA lo **elige explícitamente el operador** (RULE 2: sin
  selección no hay análisis, nunca un default silencioso). **Ollama** es la
  opción 100 % local; si se elige un ejecutor respaldado por cloud (Claude
  Code, Codex CLI, Gemini CLI), la herramienta advierte de que contenido
  derivado del caso sale a ese proveedor y lo registra en el audit log.
- **Qué Ollama**, también lo elige el operador. El compose fija
  `OLLAMA_HOST=http://ollama:11434` en el servicio `api` como línea base del
  despliegue (su propio servicio `ollama`, sin puerto publicado), y lo que el
  perito guarde en *Ajustes* gana sobre esa variable
  (`backend/agentopsy/config.py`: primero `config.json`, después el entorno).
  Escribiendo `http://localhost:11434` se usa el Ollama que corre en el equipo
  del perito, con sus modelos y su GPU. Dentro del contenedor esa URL apuntaría
  al propio contenedor, así que se resuelve al nombre por el que se alcanza la
  máquina anfitriona, declarado por el despliegue en `AGENTOPSY_HOST_GATEWAY`
  junto al `extra_hosts: host.docker.internal:host-gateway` que lo hace resolver
  también en Linux. Sin esa declaración no se reescribe nada (RULE 2: no se
  inventa una pasarela). La reescritura viaja en el motivo de
  `/api/capabilities` y en el evento de auditoría, junto a lo que el perito
  escribió. Del lado del host, con Docker Desktop (macOS y Windows) el reenvío
  llega hasta la loopback del anfitrión y no hay nada que tocar; en Linux
  `host.docker.internal` resuelve a la IP del puente, así que Ollama tiene que
  escuchar fuera de loopback (`OLLAMA_HOST=0.0.0.0 ollama serve`, o *Expose
  Ollama to the network* en la app). Es exactamente lo que dice el motivo cuando
  falla. Esto no publica nada nuevo hacia fuera: los puertos del compose siguen
  atados a `127.0.0.1` (SECURITY INVARIANT 1).
- **El límite de tiempo acota solo a los ejecutores en nube.** El selector de
  *Ajustes* (60 s, 120 s, 300 s, y `AGENTOPSY_EXECUTOR_TIMEOUT` como variable de
  despliegue, 300 s por defecto) se aplica a Claude Code, Codex CLI y Gemini
  CLI: su turno sale de la máquina, lo factura un proveedor y un CLI colgado no
  puede retener el análisis. **Ollama corre sin límite**: un prompt, una
  extracción de grafo o la redacción del informe pericial esperan a que el
  modelo local termine. Nada sale de la máquina y nadie factura por segundo, y
  un modelo grande en la GPU del perito tarda de sobra más que cualquiera de
  esas cotas, así que cortarlo solo tiraba el trabajo ya hecho. Cada arranque de
  turno deja la cota en el audit log (`executor_run_start.timeout_s`, nula
  cuando no la hay). Lo declara el propio ejecutor en `enforces_timeout`, nunca
  se deduce del contexto (RULE 2); ver `PromptExecutor.timeout_for` en
  `backend/agentopsy/executors/base.py`.

## Notas de seguridad del contenedor

`docker-compose.yml` añade `SYS_ADMIN` + `/dev/fuse` para permitir montar
imágenes con `guestmount`/`qemu-nbd` **dentro** del contenedor. Es un privilegio
elevado: si prefieres montar las imágenes en el host y pasar solo la carpeta
montada, comenta `cap_add`, `devices` y `security_opt` en el compose.

## Versiones

Las versiones fijadas de cada binario viven en [`docker/forensic-toolkit/tool-binaries.json`](docker/forensic-toolkit/tool-binaries.json) y en los `ARG *_SHA256` del `Dockerfile`.
Los binarios descargados (hayabusa, chainsaw) se verifican por SHA-256 durante
el build.
