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
- Conexión a Internet en el primer build (descarga paquetes, hayabusa y chainsaw).
- Linux o Windows/macOS con Docker Desktop. En Windows usa WSL2 como backend.

> **Arquitectura: los maletines son `linux/amd64`.** El compose fija
> `platform: linux/amd64` en `toolkit-windows` y `toolkit-unix` porque el PPA GIFT
> (plaso, sleuthkit, libyal, bulk-extractor) **no publica paquetes arm64**: sin ese
> pin, el build falla en Apple Silicon. Con el pin, en un host arm64 (Mac M-series)
> los maletines corren **bajo emulación** (Rosetta/QEMU vía binfmt) — idénticos a x86
> pero con build y análisis pesados más lentos. En un host x86_64 el pin coincide con
> la plataforma nativa, sin coste. Docker Desktop trae la emulación activada por
> defecto; en Linux arm64 puro instala `qemu-user-static` + `binfmt` si no la tienes.

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
instala plaso y descarga ~50 MB de binarios); los siguientes usan caché.

## Uso básico

1. Copia la evidencia a `./evidence/` (se monta en `/evidence` en **solo
   lectura**).
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

El maletín queda **habilitado para que el agente lo consulte** así:

- Cada contenedor se mantiene vivo (`sleep infinity`) con todas las herramientas
  en el `PATH`, las evidencias en `/evidence:ro` y las salidas en `/cases`.
- El orquestador de IA expone cada herramienta CLI como una función invocable y,
  cuando el modelo decide usarla, ejecuta el comando dentro del contenedor:

  ```bash
  docker exec forensia-toolkit-windows <herramienta> <args...>
  ```

  La salida (stdout/stderr/JSON) se devuelve al modelo como resultado de la
  llamada. El agente Windows apunta a `toolkit-windows` y el Unix-like a
  `toolkit-unix`.
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
