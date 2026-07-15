# FORENSIA

[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Ollama](https://img.shields.io/badge/Ollama-Local%20AI-FF6F00?logo=ollama&logoColor=white)](https://ollama.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Herramienta de análisis forense **post-mortem** asistida por IA, **autoalojada**: se despliega con `git clone` + `docker compose up --build` y se usa desde el navegador. Sin instaladores nativos y **sin API keys**.

> **Trabajo Final de Máster · Entrega: 7 de septiembre de 2026.**  
> Documento maestro de alcance y planificación: [`FORENSIA_Alcance_y_Planificacion.md`](FORENSIA_Alcance_y_Planificacion.md).

---

## Qué es

Un investigador carga evidencias ya extraídas (`.E01` / `.raw` / `.vmdk` / volcado), conduce el análisis mediante prompts contra dos **sub-agentes** especializados (Windows y Unix-like) coordinados por un **agente orquestador**, y obtiene un informe forense estructurado, su línea temporal y la correlación con MITRE ATT&CK.

**Principios**

- **Un solo comando.** `git clone` + `docker compose up --build` levantan la interfaz web, el backend, el modelo local y los maletines forenses. Sin instalador nativo, sin auto-update, sin pasos por herramienta.
- **Sin API keys.** Los prompts de la sección *Investigación* se ejecutan con el **ejecutor** que elija el usuario: **Claude Code** (`claude -p`), **Codex CLI** (`codex exec`), **Gemini CLI** (`gemini -p`) u **Ollama** (servicio del propio compose). Los CLIs consumen la suscripción del propio usuario mediante la sesión guardada en un volumen local del stack (`forensia-cli-auth`), *seeded* una única vez desde las credenciales del host o creada con un login directo en el contenedor; ninguna clave de proveedor existe en el proyecto, y las sesiones nunca salen de tu máquina, no se escriben en logs ni se exponen por la API.
- **Privacidad explícita.** Ollama es la opción 100 % local. Si el usuario elige un ejecutor respaldado por cloud (Claude Code, Codex, Gemini), la aplicación lo advierte y lo registra en el audit log. Sin ejecutor seleccionado no hay análisis — nunca un default silencioso (RULE 2).
- **Cadena de custodia.** Lectura a nivel de bloque en solo lectura, hash SHA-256 baseline en la ingesta, audit log encadenado por hash, comando literal (argv) registrado por cada ejecución.
- **Maletín completo en el compose.** Las herramientas forenses viajan en las imágenes `toolkit-windows` y `toolkit-unix` que construye el propio compose (RULE 1).

## Instalación

Prerequisitos:

1. **Docker con el plugin Compose** (Docker Desktop en Windows/macOS; `docker-ce` + `docker-compose-plugin` en Linux).
2. **Un ejecutor de IA**, a tu elección:
   - **Ollama** — no requiere nada más: el propio compose levanta el servicio (100 % local).
   - **Claude Code**, **Codex CLI** o **Gemini CLI** — tu propia suscripción/cuenta (los CLIs ya vienen instalados en la imagen `api`; solo falta la sesión, ver abajo).

```bash
git clone https://github.com/Rorouh/Forensia-AI.git
cd Forensia-AI
docker compose up --build
```

Abre <http://127.0.0.1:5173> en el navegador. Todos los puertos se publican únicamente en `127.0.0.1`: nada queda expuesto fuera de tu máquina.

> **Apple Silicon / arm64.** Los dos maletines se fijan a `platform: linux/amd64` en el compose: el PPA GIFT (plaso, sleuthkit, libyal, bulk-extractor) no publica paquetes arm64, así que en Mac ARM se construyen y ejecutan **bajo emulación** (Rosetta/QEMU) — funcionan igual que en x86 pero su build y sus análisis pesados van más lentos. En un host x86_64 esto coincide con la plataforma nativa: sin coste. Detalle en [`docker/README.md`](docker/README.md).

### Sesión de los CLIs (solo si usas un ejecutor cloud)

El HOME del servicio `api` vive en el volumen `forensia-cli-auth`. En el primer arranque, el entrypoint **seedea** a ese volumen las credenciales que ya existan en tu host (`~/.claude`, `~/.claude.json`, `~/.codex`, `~/.gemini`, montadas en solo lectura como staging); desde entonces los CLIs leen y **refrescan sus tokens solo en el volumen**, nunca en tus ficheros.

**Conectar desde la web (recomendado).** Si un ejecutor aparece *No disponible* en *Ajustes → Ejecutores / IA* (o en el selector de proveedor del chat), pulsa **«Conectar»**: FORENSIA lanza el login del propio CLI dentro del contenedor y te muestra en un diálogo la **URL** a abrir y el **código** del flujo *device*/OAuth, sin abrir una terminal. La sesión se guarda en el volumen `forensia-cli-auth` igual que el login manual.

- **Codex** (`codex login --device-auth`): abre la URL e **introduce el código en el navegador**; el diálogo pasa a *Disponible* solo cuando terminas.
- **Claude Code** (`claude auth login`): abre la URL, autoriza y **pega de vuelta** en el diálogo el código que te da el navegador.
- **Gemini**: el login individual lo rechaza Google en el servidor (`IneligibleTierError`), así que no puede relayarse; el diálogo degrada al comando manual exacto + un botón **«Comprobar»** (RULE 2 — nunca un spinner infinito).

**Login manual** (o si prefieres la terminal / no había nada que seedear — p. ej. Claude Code en macOS guarda la sesión en el Keychain), **una única vez dentro del contenedor**:

```bash
docker compose exec -it api claude auth login          # Claude Code
docker compose exec -it api codex login --device-auth  # Codex CLI (flujo device-code)
docker compose exec -it -e NO_BROWSER=true api gemini  # Gemini CLI (imprime URL; pega el código)
```

La sesión persiste entre reinicios. Comprueba el estado en *Ajustes → Ejecutores* (o `GET /api/capabilities`). Para **revocar/limpiar**: `docker compose down -v` elimina el volumen de sesiones (y los modelos de Ollama descargados).

> **Aviso**: si el proveedor rota el *refresh token* al renovarlo dentro del volumen, la sesión de tu host podría invalidarse; en ese caso mantén sesiones separadas (login dentro del contenedor) en vez de seedear.

> **Windows**: el compose usa la variable `HOME` para localizar el staging de credenciales. Si tu shell no la define (PowerShell/cmd fuera de WSL), copia [`.env.example`](.env.example) a `.env` y apunta `HOME` a tu perfil de usuario — o sáltate el seeding e inicia sesión dentro del contenedor.

## Arquitectura

```text
                      navegador → http://127.0.0.1:5173
                                    │
┌─ docker compose (puertos SOLO en 127.0.0.1) ─────────────────────────────┐
│                                   ▼                                      │
│  web            frontend React servido por su contenedor                 │
│    │  HTTP (red interna del compose)                                     │
│    ▼                                                                     │
│  api            FastAPI — backend/forensia, el núcleo completo:          │
│                 · dispatcher (resolver, shell=False, argv literal)       │
│                 · EvidenceManager (hash gate, read-only a nivel bloque)  │
│                 · ArtifactStore (manifest + sha256 por run)              │
│                 · AuditLog (append-only, encadenado por hash)            │
│    │                                                                     │
│    ├──► CAPA DE EJECUCIÓN — a elección del usuario (sin default):        │
│    │      claude -p · codex exec · gemini -p                             │
│    │      (CLIs instalados en la imagen api; sesión en el volumen        │
│    │       forensia-cli-auth — seeded del host o login en contenedor)    │
│    │      ollama ──HTTP──► servicio ollama (100 % local)                 │
│    ▼                                                                     │
│  toolkit-windows · toolkit-unix                                          │
│                 maletines forenses — imágenes construidas por el         │
│                 compose; evidencias montadas en SOLO LECTURA             │
└──────────────────────────────────────────────────────────────────────────┘
```

Documentación técnica:

- [Arquitectura](docs/arquitectura.md) — capas, transporte, decisiones bloqueadas.
- [Modelo de amenazas](docs/modelo-amenazas.md) — superficie MCP incluida.
- [Cadena de custodia](docs/soundness-forense.md) — read-only a nivel de bloque, audit log.
- [Maletín contenedorizado](docker/README.md) — los dos toolkits, uso y seguridad del contenedor.
- [Contrato de paquetes de agente](docs/agentes/contrato-paquetes.md)
- [Inventario de servidores MCP](docs/maletin/inventario-mcps.md) — 13 candidatos priorizados P0–P3.
- [Plan del MCP toolkit (S1 cerrado)](docs/maletin/mcp-toolkit-s1.md)
- Índice completo: [`docs/README.md`](docs/README.md).

## Desarrollo local

Sección para contribuidores del proyecto. **El usuario final solo necesita la sección Instalación.**

Requisitos:

- Docker con el plugin Compose.
- Python 3.12 (para la suite de tests en venv; la suite no necesita Docker).

```bash
# Stack completo
docker compose up --build

# Reconstruir un servicio concreto
docker compose build api

# Tests del backend (venv local)
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest

# Backend standalone para depurar (imprime url 127.0.0.1 + token)
python -m forensia.server
```

### Servidor MCP standalone

El maletín se expone también como servidor MCP estándar para clientes externos (Claude Desktop, Continue, Cline). Detalle en [`docs/maletin/mcp-toolkit-s1.md`](docs/maletin/mcp-toolkit-s1.md).

```bash
cd backend
source .venv/bin/activate
pip install -e ".[mcp]"
FORENSIA_CLOUD_CONSENT=manual_test python -m forensia.mcp
```

## Estado del proyecto

Estado actualizado, deuda técnica y próximos pasos: [`docs/operacion/proximos-pasos.md`](docs/operacion/proximos-pasos.md).

## Equipo

Enrique · Daniel · Santiago · Luis · Diego · Miguel Ángel

## Licencia

Ver [`LICENSE`](LICENSE).
