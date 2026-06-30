# FORENSIA

[![Electron](https://img.shields.io/badge/Electron-30-47848F?logo=electron&logoColor=white)](https://www.electronjs.org/)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-5-646CFF?logo=vite&logoColor=white)](https://vite.dev/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Ollama](https://img.shields.io/badge/Ollama-Local%20AI-FF6F00?logo=ollama&logoColor=white)](https://ollama.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Herramienta de análisis forense **post-mortem** asistida por IA, distribuida como **aplicación de escritorio universal** (Windows / macOS / Linux) instalable con un único comando.

> **Trabajo Final de Máster · Entrega: 7 de septiembre de 2026.**  
> Documento maestro de alcance y planificación: [`FORENSIA_Alcance_y_Planificacion.md`](FORENSIA_Alcance_y_Planificacion.md).

---

## Qué es

Un investigador carga evidencias ya extraídas (`.E01` / `.raw` / `.vmdk` / volcado), conduce el análisis mediante prompts contra dos **sub-agentes** especializados (Windows y Unix-like) coordinados por un **agente orquestador**, y obtiene un informe forense estructurado, su línea temporal y la correlación con MITRE ATT&CK.

**Principios**

- **Instalación en una línea.** No `git clone`, no `docker compose up` — un instalador nativo por SO.
- **Privacidad por defecto.** Modelo local (Ollama) recomendado. Cloud (Claude / GPT) es opt-in por caso, con consentimiento registrado en el audit log.
- **Cadena de custodia.** Lectura a nivel de bloque en solo lectura, hash SHA-256 baseline en la ingesta, audit log encadenado por hash, comando literal (argv) registrado por cada ejecución.
- **Maletín completo en la app.** Las herramientas forenses viajan con el instalador como binarios nativos vendoreados o como imágenes OCI pre-cargadas (RULE 1).

## Instalación

```bash
# Linux / macOS
curl -fsSL https://forensia.dev/install.sh | bash

# Windows
# Instalador .exe firmado.
```

Docker o Podman es un **prerequisito del instalador**; FORENSIA lo usa internamente para ejecutar herramientas sin build nativa cross-OS (RegRipper en macOS, plaso en Windows, etc.). El investigador no escribe `docker` jamás.

## Arquitectura

```text
                                    +----------------------------------+
                                    | Cliente MCP externo              |
                                    |  (Claude Desktop, Continue, ...) |
                                    +-----------------+----------------+
                                                      | (stdio MCP)
+-------------------------------------------------+   |
|         INSTALABLE NATIVO (Electron)            |   |
|  - Renderer Chromium hardened                   |   |
|  - Main process: ciclo de vida del sidecar      |   |
|  - IPC seguro (contextIsolation + sandbox)      |   |
+----------------------+--------------------------+   |
                       | (loopback + token de sesión) |
                       v                              v
+-------------------------+    +-------------------------------------+
| Sidecar FastAPI (Python)|    | Servidor MCP standalone             |
| `python -m forensia     |    | `python -m forensia.mcp`            |
|   .server`              |    | stdio puro, patrón Jira             |
+-----------+-------------+    +---------------+---------------------+
            |                                  |
            +----------------+-----------------+
                             | mismo núcleo
                             v
+-------------------------------------------------------------+
| backend/forensia/  =  núcleo compartido                     |
|  - dispatcher (resolver, shell=False, argv literal)         |
|  - EvidenceManager (hash gate, read-only)                   |
|  - ArtifactStore (manifest + sha256 por run)                |
|  - AuditLog (hash-chained + fcntl.flock concurrencia)       |
+----------------------+--------------------------------------+
                       | (subprocess shell=False, argv arrays)
                       v
+-------------------------------------------------------------+
|             MALETÍN FORENSE EMPAQUETADO                     |
|  - vendor/<tool>/<os>-<arch>/      (RULE 1 — bundled)       |
|  - imágenes OCI per-tool           (RULE 1 — container)     |
+-------------------------------------------------------------+
```

Documentación técnica:

- [Arquitectura](docs/arquitectura.md) — capas, transporte, decisiones bloqueadas.
- [Modelo de amenazas](docs/modelo-amenazas.md) — superficie MCP incluida.
- [Cadena de custodia](docs/soundness-forense.md) — read-only a nivel de bloque, audit log.
- [Contrato de paquetes de agente](docs/agentes/contrato-paquetes.md)
- [Inventario de servidores MCP](docs/maletin/inventario-mcps.md) — 13 candidatos priorizados P0–P3.
- [Plan del MCP toolkit (S1 cerrado)](docs/maletin/mcp-toolkit-s1.md)
- Índice completo: [`docs/README.md`](docs/README.md).

## Desarrollo local

Sección para contribuidores del proyecto. **El usuario final no necesita nada de esto** — usa el instalador.

Requisitos:

- Node.js v20 o superior.
- Python 3.12.
- Docker o Podman (para tools containerizadas durante el desarrollo).

```bash
# Sidecar Python
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Levantarlo en standalone (debug)
python -m forensia.server

# Interfaz Electron en modo hot-reload
cd ../desktop
npm install
npm run dev
```

### Servidor MCP standalone

El maletín se expone también como servidor MCP estándar para clientes externos (Claude Desktop, Continue, Cline). Detalle en [`docs/maletin/mcp-toolkit-s1.md`](docs/maletin/mcp-toolkit-s1.md).

```bash
cd backend
source .venv/bin/activate
pip install -e ".[mcp]"
FORENSIA_CLOUD_CONSENT=manual_test python -m forensia.mcp
```

### Empaquetado de producción

```bash
cd desktop
npm run dist
```

Genera el instalador nativo para el SO actual.

## Estado del proyecto

Estado actualizado, deuda técnica y próximos pasos: [`docs/operacion/proximos-pasos.md`](docs/operacion/proximos-pasos.md).

## Equipo

Enrique · Daniel · Santiago · Luis · Diego · Miguel Ángel

## Licencia

Ver [`LICENSE`](LICENSE).
