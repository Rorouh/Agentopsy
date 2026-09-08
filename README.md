# Agentopsy

[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Ollama](https://img.shields.io/badge/Ollama-Local%20AI-FF6F00?logo=ollama&logoColor=white)](https://ollama.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Herramienta de análisis forense **post-mortem** asistida por IA. Se autoaloja: un `git clone`, un `docker compose up --build`, y trabajas desde el navegador. Sin instaladores nativos y sin API keys.

---

## Qué es

Cargas la evidencia que ya tienes extraída y conduces el análisis conversando. Vale la imagen de un sistema entero (`.E01`, `.raw`, `.vmdk`, un volcado de RAM) y valen los ficheros sueltos con los que suele llegar un encargo: un PDF, un Word, una foto, un correo, un log exportado, un `.evtx` sin su disco, una muestra.

Detrás, un agente orquestador reparte el trabajo entre dos sub-agentes especializados, uno en artefactos Windows y otro en Unix-like, que manejan un maletín de herramientas forenses de línea de comandos. De ahí salen un informe pericial, la línea temporal del incidente y la correlación con MITRE ATT&CK.

Todo lo que entra pasa por el mismo hash-gate y la misma cadena de custodia, venga de un disco de 500 GB o de un PDF.

## Principios

- **Un solo comando.** `docker compose up --build` levanta la interfaz, el backend, el modelo local y los dos maletines. No hay instalador, ni auto-update, ni un paso de instalación por herramienta.
- **Sin API keys.** Tú eliges quién ejecuta los prompts: Claude Code, Codex CLI, Gemini CLI u Ollama. Los tres CLIs corren con tu propia suscripción, a partir de una sesión guardada en un volumen del stack. En el proyecto no existe ninguna clave de proveedor, y esas sesiones no salen de tu máquina, no se escriben en los logs ni se exponen por la API.
- **Privacidad explícita.** Ollama es la opción 100 % local. Si eliges un ejecutor de nube, la aplicación te avisa de que sale contenido derivado del caso y lo deja anotado en el audit log. Y sin ejecutor elegido no hay análisis: nunca se escoge uno por ti.
- **Cadena de custodia.** Lectura en solo lectura a nivel de bloque, SHA-256 baseline en la ingesta, audit log encadenado por hash y el comando literal, el argv, registrado en cada ejecución.
- **En inglés o en castellano.** La interfaz, los mensajes del backend, el informe con sus anexos y lo que escribe el agente salen en el idioma que elijas (*Configuración → Apariencia → Idioma*; por defecto, inglés). El contenido del caso no se traduce nunca: el nombre que le pusiste, el título de un hallazgo o el resumen que redactó el agente viajan tal cual, porque traducir un dato del expediente sería inventarlo.
- **El maletín viaja en el compose.** Las herramientas forenses van dentro de las imágenes `toolkit-windows` y `toolkit-unix`, que construye el propio compose. No hay nada que compilar ni configurar aparte.
- **Un modo para equipos de 8 GB sin GPU.** El servicio `local-fit-llm` es un segundo motor (dos agentes, investigador y revisor, con un prompt pequeño por paso) que convive con el `api` y usa los mismos maletines y casos. Se elige en el chat como ejecutor «Local fit LLM» y la cabecera muestra en todo momento qué backend atiende. Detalle: [`agentopsy-local-fit-llm/README.md`](agentopsy-local-fit-llm/README.md).

## Instalación

Necesitas dos cosas:

1. **Docker con el plugin Compose.** Docker Desktop en Windows y macOS; `docker-ce` más `docker-compose-plugin` en Linux.
2. **Un ejecutor de IA.** Ollama no requiere nada más, porque lo levanta el propio compose. Si prefieres Claude Code, Codex CLI o Gemini CLI, los binarios ya vienen en la imagen `api` y solo falta iniciar sesión con tu cuenta.

```bash
git clone https://github.com/Rorouh/Agentopsy.git
cd Agentopsy
docker compose up --build
```

Abre <http://127.0.0.1:5173> en el navegador. Todos los puertos se publican solo en `127.0.0.1`, así que nada queda expuesto fuera de tu máquina.

> **Apple Silicon.** Los dos maletines se fijan a `linux/amd64` porque el PPA GIFT (plaso, sleuthkit, libyal, bulk-extractor) no publica paquetes arm64. En un Mac ARM funcionan igual, pero bajo emulación: el build y los análisis pesados tardan más. En un host x86_64 no cuesta nada. Más detalle en [`docker/README.md`](docker/README.md).

### Iniciar sesión en un ejecutor de nube

Sáltate este apartado si vas a usar Ollama.

El HOME del servicio `api` es el volumen `agentopsy-cli-auth`. Si en el primer arranque ya tenías sesión abierta en tu host (`~/.claude`, `~/.claude.json`, `~/.codex`, `~/.gemini`), el entrypoint la copia ahí dentro. A partir de ese momento los CLIs leen y renuevan sus tokens solo en el volumen, nunca en tus ficheros.

**Desde la web, que es lo cómodo.** Si un ejecutor aparece como *No disponible* en *Ajustes → Ejecutores / IA*, pulsa «Conectar»: Agentopsy lanza el login del CLI dentro del contenedor y te enseña la URL y el código en un diálogo, sin pasar por la terminal.

- **Codex.** Abre la URL e introduce el código en el navegador. El diálogo pasa a *Disponible* cuando terminas.
- **Claude Code.** Abre la URL, autoriza y pega de vuelta en el diálogo el código que te dé el navegador.
- **Gemini.** Google rechaza este login en el servidor (`IneligibleTierError`), así que no se puede relayar. El diálogo te da el comando manual exacto y un botón «Comprobar», en lugar de dejarte ante un spinner que no acaba nunca.

**Desde la terminal**, si lo prefieres o si no había nada que copiar (Claude Code en macOS, por ejemplo, guarda la sesión en el Keychain). Una sola vez:

```bash
docker compose exec -it api claude auth login          # Claude Code
docker compose exec -it api codex login --device-auth  # Codex CLI (flujo device-code)
docker compose exec -it -e NO_BROWSER=true api gemini  # Gemini CLI (imprime URL; pega el código)
```

La sesión sobrevive a los reinicios. Puedes comprobarla en *Ajustes → Ejecutores* o con `GET /api/capabilities`. Para revocarla, `docker compose down -v` borra el volumen de sesiones, y con él los modelos que hubiera descargado Ollama.

> **Cuidado con el token de refresco.** Si tu proveedor lo rota al renovarlo dentro del volumen, la sesión de tu host puede quedar invalidada. Si eso te importa, no copies nada: inicia sesión directamente en el contenedor y mantén las dos sesiones separadas.

> **Windows.** El compose usa la variable `HOME` para localizar las credenciales del host. Si tu shell no la define (PowerShell o cmd fuera de WSL), copia [`.env.example`](.env.example) a `.env` y apúntala a tu perfil de usuario. O sáltate la copia e inicia sesión dentro del contenedor.

## Documentación

- [`docker/README.md`](docker/README.md) — los dos maletines: qué traen, cómo se usan y qué privilegios piden.
- [`agentes/README.md`](agentes/README.md) — cómo se configura el agente, con sus dos ficheros de comportamiento: [`agent.md`](agentes/agent.md) en castellano y [`agent.en.md`](agentes/agent.en.md) en inglés.
- [`CLAUDE.md`](CLAUDE.md) — la arquitectura y los invariantes forenses y de seguridad que el proyecto no rompe.

## Equipo

Enrique · Daniel · Santiago · Luis · Diego · Miguel Ángel

## Licencia

Ver [`LICENSE`](LICENSE).
