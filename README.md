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

El sistema desacopla la GUI del motor de cómputo forense mediante una arquitectura de sidecar local:

```text
+-------------------------------------------------------------+
|               ELECTRON HARNESS (desktop/)                   |
|  - Proceso principal de Chromium hardened                   |
|  - Controla el ciclo de vida del sidecar (spawns/kills)      |
|  - IPC Bridge seguro (ContextIsolation + Sandboxing)        |
+-------------------------------------------------------------+
                              | (Local Loopback + Auth Token)
                              v
+-------------------------------------------------------------+
|             PYTHON FASTAPI SIDECAR (backend/)              |
|  - Compilado via PyInstaller en modo 'onedir'               |
|  - Expone endpoints JSON para orquestación                  |
+-------------------------------------------------------------+
                              | (Subprocess calls, shell=False)
                              v
+-------------------------------------------------------------+
|             MALETÍN DE HERRAMIENTAS VENDORED                |
|  - Binarios compilados bajo vendor/<tool>/<os>-<arch>/       |
|  - Volatility3, plaso, Sleuth Kit, bulk_extractor, etc.     |
+-------------------------------------------------------------+
```

Documentación adicional para hackers y desarrolladores:
*   [Especificaciones de Arquitectura](file:///Users/menciagonzalez/workspace/Forensia-AI/docs/ARCHITECTURE.md)
*   [Modelo de Amenazas y Seguridad](file:///Users/menciagonzalez/workspace/Forensia-AI/docs/THREAT_MODEL.md)
*   [Preservación Criptográfica y Cadena de Custodia](file:///Users/menciagonzalez/workspace/Forensia-AI/docs/FORENSIC_SOUNDNESS.md)

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

### Empaquetado de producción (Production Bundling)

```bash
# Compilar los assets del renderizador y generar el instalador nativo
npm run dist
```

---

## 🚀 ESTADO DEL PROYECTO

*   **GUI & Ventana:** Operativa con un tema RPG Pixel Art personalizado y panel de control de estado integrado.
*   **Sidecar Bridge:** En funcionamiento. Conexión IPC fluida mediante handshake de puerto efímero.
*   **Paquetes de Agente:** El loop del agente carga su persona, prompts y allowlist de tools desde una carpeta declarativa `agentes/<id>/` que entrega el equipo de entrenamiento (ver [`agentes/README.md`](agentes/README.md) y [`docs/AGENTS.md`](docs/AGENTS.md)). El loader, la registry y el endpoint `/api/agents` están operativos; los samples `sample-unix` y `sample-windows` viajan en el repo para desarrollo.
*   **Agente Local:** Capas de auditoría e ingesta de evidencias implementadas; algoritmos de inferencia y wrappers específicos de CLI en fase de desarrollo.

---

## 👥 LA COFRADÍA (El Equipo)

Enrique · Daniel · Santiago · Luis · Diego · Miguel Ángel

---

## 📄 LICENCIA

Consulte el archivo [LICENSE](file:///Users/menciagonzalez/workspace/Forensia-AI/LICENSE) para más detalles.
