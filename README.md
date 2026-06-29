# FORENSIA

[![Vite](https://img.shields.io/badge/Vite-5.2.0-646CFF?style=for-the-badge&logo=vite&logoColor=white)](https://vite.dev/)
[![React](https://img.shields.io/badge/React-18.3.0-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![Electron](https://img.shields.io/badge/Electron-30.0.0-47848F?style=for-the-badge&logo=electron&logoColor=white)](https://www.electronjs.org/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Ollama](https://img.shields.io/badge/Ollama-Local_AI-FF6F00?style=for-the-badge&logo=ollama&logoColor=white)](https://ollama.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

```text
 ______   ______   ______   ______   __   __   ______   __   ______    
/\  ___\ /\  __ \ /\  == \ /\  ___\ /\ "-.\ \ /\  ___\ /\ \ /\  __ \   
\ \  __\ \ \ \/\ \\ \  __< \ \  __\ \ \ \-.  \\ \___  \\ \ \\ \  __ \  
 \ \_\    \ \_____\\ \_\ \_\\ \_____\\ \_\\""_\\/\_____\\ \_\\ \_\ \_\ 
  \/_/     \/_____/ \/_/ /_/ \/_____/ \/_/ \/_/ \/_____/ \/_/ \/_/\/_/ 
                                                                       
 [BUILD STATUS: STABLE]  [DEPENDENCIES: BUNDLED]  [PRIVACY: LOCAL-FIRST]
```

> **WARNING:** Herramienta de análisis forense post-mortem asistida por IA local de grado profesional.
> Diseñada para correr en local, sin telemetría, sin nubes comerciales obligatorias, y sin dependencias externas.

---

## 💾 EL MANIFIESTO (Principios del Proyecto)

*   **Instalación Zero-Config:** Nada de `pip install`, nada de `docker pull`, y nada de pelearse con configuraciones de PATH. Todo el maletín de herramientas forenses nativas y el sidecar de Python viajan empaquetados dentro del binario compilado.
*   **Privacidad Absoluta u Offline-First:** Las evidencias contienen secretos. Por defecto, FORENSIA habla con motores de inferencia locales (Ollama/Llama3 sobre tu propia CPU/GPU). No enviamos tus dumps de memoria RAM a servidores remotos para ser leídos por terceros.
*   **Rigor a Nivel de Bloque:** Tratamos la evidencia como sagrada. La lectura se realiza a nivel de bloque en modo estrictamente de solo lectura (`read-only`), calculando hashes baseline SHA-256 en la ingesta y encadenando criptográficamente cada comando en un registro de auditoría (`audit log`) inmutable.
*   **Aparato de Escritorio Único:** Sin servidores web expuestos, sin APIs públicas en la nube. La aplicación levanta un socket loopback local (`127.0.0.1`) en un puerto efímero con tokens de un solo uso.

---

## 🛠️ ARQUITECTURA DEL COCKPIT

El sistema desacopla la GUI del motor de cómputo forense mediante una arquitectura de sidecar local. Desde la rama `mcp`, el maletín además se expone como servidor MCP estándar para clientes externos (Claude Desktop, Continue, Cline, agentes custom):

```text
                                    +----------------------------------+
                                    | Cliente MCP externo              |
                                    |  (Claude Desktop, Continue, ...) |
                                    +-----------------+----------------+
                                                      | (stdio MCP)
+-------------------------------------------------+   |
|         ELECTRON HARNESS (desktop/)             |   |
|  - Proceso principal de Chromium hardened       |   |
|  - Controla el ciclo de vida del sidecar         |   |
|  - IPC Bridge seguro (ContextIsolation+Sandbox)  |   |
+----------------------+--------------------------+   |
                       | (Local Loopback + Auth Token)|
                       v                              v
+-------------------------+    +-------------------------------------+
| FastAPI sidecar         |    | MCP server (mcp-toolkit, S1)        |
| `python -m forensia     |    | `python -m forensia.mcp`            |
|   .server`              |    | stdio puro, sin sockets de red      |
| Para la UI Electron     |    | Patrón Jira para selección de caso  |
+-----------+-------------+    +---------------+---------------------+
            |                                  |
            +----------------+-----------------+
                             | ambos delegan en el mismo dispatcher
                             v
+-------------------------------------------------------------+
| backend/forensia/  =  NÚCLEO COMPARTIDO                     |
|  - dispatcher (resolver, shell=False, argv literal)         |
|  - EvidenceManager (hash gate, read-only)                   |
|  - ArtifactStore (manifest + sha256 por run)                |
|  - AuditLog (hash-chained + fcntl.flock concurrencia)       |
+----------------------+--------------------------------------+
                       | (Subprocess calls, shell=False)
                       v
+-------------------------------------------------------------+
|             MALETÍN DE HERRAMIENTAS VENDORED                |
|  - Binarios compilados bajo vendor/<tool>/<os>-<arch>/      |
|  - Volatility3, plaso, Sleuth Kit, bulk_extractor, etc.     |
+-------------------------------------------------------------+
```

Documentación adicional para hackers y desarrolladores:
*   [Especificaciones de Arquitectura](docs/ARCHITECTURE.md)
*   [Modelo de Amenazas y Seguridad](docs/THREAT_MODEL.md) — incluye superficie MCP (sección E + gates 13–18).
*   [Preservación Criptográfica y Cadena de Custodia](docs/FORENSIC_SOUNDNESS.md)
*   [Inventario de servidores MCP](docs/MCP_INVENTORY.md) — los 13 MCPs candidatos priorizados P0–P3.
*   [Plan de implementación del MCP toolkit](docs/MCP_TOOLKIT_PLAN.md) — sprint S1 cerrado, decisiones D1–D7 + líneas rojas L1–L6.

---

## ⌨️ CÓMO COMPILAR Y COMPARTIR EL CÓDIGO (Hacking)

### Requisitos del Sistema
*   Node.js v20 o superior.
*   Python v3.12 (para desarrollo del sidecar).
*   Un editor de texto (Vim/Emacs/VSCode).
*   Monitor CRT (opcional, pero mejora el estilo retro pixel).

### Preparando el entorno local

```bash
# 1. Clonar el repositorio y configurar el sidecar de Python
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# 2. Levantar el sidecar en modo standalone (para debugging)
python -m forensia.server

# 3. Lanzar la interfaz en modo hot-reload de desarrollo
cd ../desktop
npm install
npm run dev
```

### Servidor MCP — exponer el maletín a Claude Desktop / clientes externos

```bash
# Instalar el extra MCP (mcp SDK + jsonref)
cd backend
source .venv/bin/activate
pip install -e ".[mcp]"

# Arrancar el servidor MCP standalone (stdio puro)
FORENSIA_CLOUD_CONSENT=manual_test python -m forensia.mcp
```

Para conectarlo a Claude Desktop, edita
`~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "forensia": {
      "command": "/ruta/absoluta/al/repo/backend/.venv/bin/python",
      "args": ["-m", "forensia.mcp"],
      "env": {
        "FORENSIA_CLOUD_CONSENT": "claude_desktop",
        "FORENSIA_REDACTION_MODE": "strict"
      }
    }
  }
}
```

Reinicia Claude Desktop (Cmd-Q completo). En un nuevo Chat aparecerán las
tools `list_cases` / `select_case` / `list_evidence` / `select_evidence` + 16
forenses una vez selecciones el caso. Detalle en
[`docs/MCP_TOOLKIT_PLAN.md`](docs/MCP_TOOLKIT_PLAN.md).

### Empaquetado de producción (Production Bundling)

```bash
# Compilar los assets del renderizador y generar el instalador nativo
npm run dist
```

---

## 🚀 ESTADO DEL PROYECTO

*   **GUI & Ventana:** Operativa con un tema RPG Pixel Art personalizado y panel de control de estado integrado.
*   **Sidecar Bridge:** En funcionamiento. Conexión IPC fluida mediante handshake de puerto efímero.
*   **Paquetes de Agente:** El loop del agente carga su persona, prompts y allowlist de tools desde una carpeta declarativa `agentes/<id>/` que entrega el equipo de entrenamiento (ver [`agentes/README.md`](agentes/README.md) y [`docs/AGENTS.md`](docs/AGENTS.md)). El loader, la registry y el endpoint `/api/agents` están operativos; los paquetes reales `forensia-unix` y `forensia-windows` viajan en `agentes/`, junto al pack de síntesis `_orchestrator/` (ignorado por la registry por su prefijo `_`, consumido por la futura capa `forensia.reports`).
*   **Agente Local:** Capas de auditoría e ingesta de evidencias implementadas; algoritmos de inferencia y wrappers específicos de CLI en fase de desarrollo.
*   **Servidor MCP (rama `mcp`):** Sprint S1 cerrado. El maletín forense se expone como servidor MCP estándar — verificado E2E con Claude Desktop sobre un memdump real Windows 7 SP1 de 5 GiB. Patrón Jira para selección de caso + evidencia, 16 tools forenses, ResourceLinks `artifact://`, redaction por modos, líneas rojas L1–L6 verificadas por panel de expertos. Ver [`docs/MCP_INVENTORY.md`](docs/MCP_INVENTORY.md) y [`docs/MCP_TOOLKIT_PLAN.md`](docs/MCP_TOOLKIT_PLAN.md).

---

## 👥 LA COFRADÍA (El Equipo)

Enrique · Daniel · Santiago · Luis · Diego · Miguel Ángel

---

## 📄 LICENCIA

Consulte el archivo [LICENSE](file:///Users/menciagonzalez/workspace/Forensia-AI/LICENSE) para más detalles.
