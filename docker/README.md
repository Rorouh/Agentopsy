# FORENSIA — Maletín forense contenedorizado

Maletín de herramientas forenses CLI empaquetado en Docker, en dos imágenes:
**`toolkit-windows`** (artefactos de Windows) y **`toolkit-unix`** (artefactos
Unix-like). Es la base sobre la que los agentes de IA harán *tool-calling*
(sección «Cómo lo consulta la IA»).

Los dos maletines son parte del compose raíz del repo (`docker-compose.yml`,
cinco servicios: `web`, `api`, `ollama` y los dos maletines). Este directorio
contiene los Dockerfiles de los servicios (`api/`, `web/`,
`docker/forensic-toolkit/`) y este README documenta los maletines en concreto.

> **Aclaración importante.** Son contenedores **Linux** que contienen las
> herramientas para analizar evidencias de Windows y de Unix. No es un contenedor
> con sistema operativo Windows: RegRipper, hayabusa, chainsaw, TSK, Volatility y
> plaso son ejecutables sobre Linux y es el enfoque que el documento de alcance
> asume (`docker compose up` en localhost, multiplataforma). Si en algún momento
> necesitas un binario que SOLO exista para Windows, ese caso se trataría aparte
> con un contenedor Windows real (requiere host Windows en modo *Windows
> containers*).

## Requisitos

- Docker Engine 24+ y Docker Compose v2 (`docker compose`, no `docker-compose`).
- Conexión a Internet en el primer build (descarga paquetes, hayabusa, chainsaw,
  el runtime .NET y las EZ Tools de Eric Zimmerman).
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
> rompe el invariante de soundness para montar evidencia (ver
> `docs/soundness-forense.md` del repo raíz) y además su file-sharing no cubre
> rutas fuera de `$HOME` (p. ej. `/mnt`). Si tienes ambos instalados:
> `docker context use default` o prefija los comandos con
> `docker --context default …`.

## Estructura

```
Forensia-AI/                        # raíz del repo
├── docker-compose.yml              # el compose raíz: los CINCO servicios
├── evidence/                       # <- coloca aquí las evidencias (.raw/.vmdk/.E01)
├── projects/                       # <- salidas, casos e informes
└── docker/
    ├── api/                        # imagen del backend + CLIs de ejecución
    ├── web/                        # imagen del frontend: build de web/ + nginx (proxy /api)
    ├── docker/forensic-toolkit/
    │   ├── Dockerfile              # multi-stage: base + windows + unix
    │   ├── requirements-windows.txt# parsers Python de artefactos Windows
    │   └── .dockerignore
    └── docs/CATALOGO_MALETIN.md    # catálogo de herramientas y comandos
```

## Construir y levantar (un solo comando)

Desde la **raíz del repo**:

```bash
cd Forensia-AI
docker compose up --build
```

Comprobar que el maletín está listo:

```bash
docker compose exec toolkit-windows forensia-info
docker compose exec toolkit-unix    forensia-info
```

Debería listar cada herramienta con su ruta. El primer build tarda (compila e
instala plaso y descarga ~150 MB de binarios: hayabusa, chainsaw, runtime .NET
y EZ Tools); los siguientes usan caché.

## Carpeta de evidencia configurable

La aplicación final centraliza todas las evidencias del caso en **una única
carpeta que elige el usuario**. El compose refleja ese diseño: la carpeta que
se monta en `/evidence` (solo lectura) se configura con la variable
`FORENSIA_EVIDENCE_DIR`, y la de salidas (`/cases`) con `FORENSIA_CASES_DIR`.
Sin variables definidas se usan `./evidence` y `./projects` (defaults de
diseño, relativos a la raíz del repo, donde vive `docker-compose.yml`). Nunca
escribas rutas absolutas de tu host en los ficheros versionados.

```bash
# Opción A: variable de entorno puntual
FORENSIA_EVIDENCE_DIR=/ruta/al/caso/evidencia docker compose up -d

# Opción B: fichero .env junto al docker-compose.yml de la raíz (ignorado por git)
echo 'FORENSIA_EVIDENCE_DIR=/ruta/al/caso/evidencia' > .env
docker compose up -d
```

## Uso básico

1. Apunta `FORENSIA_EVIDENCE_DIR` a la carpeta de evidencia del caso (o copia
   la evidencia a `./evidence/`; desde la web también puedes ARRASTRARLA/subirla).
   Se monta en `/evidence` en **solo lectura** para los maletines/agente; el
   servicio `api` la monta en lectura-escritura (camino de subida del perito —
   ver soundness-forense.md §7).
2. Verifica integridad (cadena de custodia):

   ```bash
   docker compose exec toolkit-windows forensia-hash /evidence/disco.raw
   ```
3. Lanza herramientas; las salidas van a `./projects` (`/cases` dentro):

   ```bash
   docker compose exec toolkit-windows fls -r -p /evidence/disco.raw
   docker compose exec toolkit-unix    log2timeline.py /cases/out.plaso /evidence/linux.raw
   ```

Catálogo completo de herramientas y ejemplos: [`docs/CATALOGO_MALETIN.md`](docs/CATALOGO_MALETIN.md).

## Cómo lo consulta la IA (tool-calling)

El maletín queda **habilitado para que el `api` lo consulte** así:

- Cada contenedor corre el **exec-agent** (`python3 /opt/forensia/exec_agent.py`) con
  todas las herramientas en el `PATH`, las evidencias en `/evidence:ro` y las salidas en
  `/cases`. El exec-agent es un HTTP mínimo en la red interna del compose (`:8666`, **sin
  puerto publicado**) — es el canal api→maletín §B, sin socket de Docker. Ver
  [`docs/operacion/exec-agent.md`](../docs/operacion/exec-agent.md).
- El `api` consulta presencia de tools (`GET /health`, `POST /which`) por HTTP a
  `http://toolkit-unix:8666` / `http://toolkit-windows:8666` — es lo que reporta
  `capabilities` — y ejecuta las tools del agente por el mismo canal (`POST /exec`):
  el dispatcher resuelve el argv desde el allowlist y lo lanza en el maletín del
  `os_profile` del caso (`proximos-pasos.md` §B.bis, HECHO).
- **Versiones autoritativas (P0.5-3):** durante el build de cada stage,
  `gen_versions.py` hornea el manifiesto **inmutable** `/opt/forensia/versions.json`
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
- Este es el «contrato CLI→JSON» del documento. La capa de *wrappers* que
  formaliza ese contrato y los *system prompts* de cada agente se implementan en
  la siguiente fase (no incluidos en esta entrega, que cubre Dockerfile + compose).

## Privacidad y cadena de custodia

- Evidencias montadas en **solo lectura**; se trabaja sobre copias y se verifica
  hash SHA-256 antes y después.
- El ejecutor de IA lo **elige explícitamente el operador** (RULE 2: sin
  selección no hay análisis, nunca un default silencioso). **Ollama** es la
  opción 100 % local; si se elige un ejecutor respaldado por cloud (Claude
  Code, Codex CLI, Gemini CLI), la herramienta advierte de que contenido
  derivado del caso sale a ese proveedor y lo registra en el audit log.

## Notas de seguridad del contenedor

`docker-compose.yml` añade `SYS_ADMIN` + `/dev/fuse` para permitir montar
imágenes con `guestmount`/`qemu-nbd` **dentro** del contenedor. Es un privilegio
elevado: si prefieres montar las imágenes en el host y pasar solo la carpeta
montada, comenta `cap_add`, `devices` y `security_opt` en el compose.

## Versiones

Ver tabla de versiones fijadas en [`docs/CATALOGO_MALETIN.md`](docs/CATALOGO_MALETIN.md).
Los binarios descargados (hayabusa, chainsaw) se verifican por SHA-256 durante
el build.
