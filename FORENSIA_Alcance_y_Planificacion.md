# Agentopsy — Alcance y Diseño del TFM

**Herramienta con integración de IA para la práctica forense**

Trabajo Final de Máster · Documento de alcance, diseño y planificación

| | |
| :--- | :--- |
| Equipo | Enrique · Daniel · Santiago · Luis · Diego · Miguel Ángel |
| Fecha de entrega | 7 de septiembre de 2026 |
| Versión | v1.2 · 2 de julio de 2026 |

---

## 1. Resumen ejecutivo

Agentopsy es una herramienta de análisis forense **post-mortem** asistida por IA, **autoalojada y desplegada con Docker Compose**: el usuario clona el repositorio, ejecuta `docker compose up --build` y trabaja desde el navegador (`http://127.0.0.1:5173`), en Windows, macOS o Linux por igual. El compose levanta cinco servicios: la interfaz web (`web`, React), el backend (`api`, FastAPI — con el agente orquestador y los dos sub-agentes de IA especializados por sistema operativo), el modelo local (`ollama`) y los dos maletines forenses contenedorizados (`toolkit-windows`, `toolkit-unix`). Los prompts de la investigación se ejecutan mediante el **ejecutor** que el usuario elija — Claude Code, Codex CLI o Gemini CLI, autenticados con su propia cuenta, u Ollama, 100 % local — **sin API keys de ningún proveedor**.

El usuario carga evidencias ya extraídas (`.E01` / `.raw` / `.vmdk` / volcado), conduce la investigación mediante prompts y obtiene un informe forense estructurado, su línea temporal y la correlación con MITRE ATT&CK.

El plan cubre **11 semanas**, del 29 de junio al 7 de septiembre. La planificación prioriza un MVP estricto en las primeras 6–7 semanas y reserva las últimas para validación, cierre de la memoria académica y preparación de la defensa.

---

## 2. Modelo de entrega y arquitectura

### 2.1. Despliegue: `git clone` + `docker compose up --build`

La herramienta se entrega como **repositorio autodesplegable con Docker Compose**. Dos comandos:

```bash
git clone https://github.com/Rorouh/Forensia-AI.git && cd Forensia-AI
docker compose up --build
```

La interfaz se usa desde el navegador en `http://127.0.0.1:5173`. No hay instalador nativo, ni Electron, ni PyInstaller, ni `curl | bash`, ni auto-update. El único prerequisito es Docker con el plugin Compose (más, opcionalmente, el CLI de IA que el usuario quiera usar como ejecutor — véase §5). El espíritu de empaquetado *"todo viaja con la herramienta"* se preserva: las imágenes que construye el compose contienen la interfaz web, el backend, el maletín forense completo y el runtime del modelo local.

### 2.2. Topología en runtime

```
┌─ docker compose (puertos publicados SOLO en 127.0.0.1) ────────────────────┐
│                                                                            │
│  web — frontend React            navegador → http://127.0.0.1:5173         │
│    ↕  HTTP por la red interna del compose                                  │
│  api — FastAPI (backend/forensia): orquestador + sub-agentes,              │
│        EvidenceManager (hash gate, read-only), dispatcher shell=False,     │
│        AuditLog encadenado por hash                                        │
│    │                                                                       │
│    ├─► CAPA DE EJECUCIÓN (a elección del usuario — sin default, RULE 2):   │
│    │     claude -p · codex exec · gemini -p   (CLIs en la imagen api;      │
│    │     sesión en el volumen forensia-cli-auth, seeded del host o login   │
│    │     en el contenedor)                                                 │
│    │     ollama → HTTP al servicio ollama del compose (100 % local)        │
│    ▼                                                                       │
│  toolkit-windows · toolkit-unix — maletines forenses (imágenes construidas │
│        por el compose; evidencias montadas en solo lectura)                │
└────────────────────────────────────────────────────────────────────────────┘
```

- La **UI** es idéntica en los tres SOs: es el navegador del usuario contra `127.0.0.1`. Los cinco servicios son contenedores Linux, de modo que el entorno de ejecución es exactamente el mismo en Windows, macOS y Linux.
- Ningún servicio expone puertos fuera del host: el compose publica únicamente en `127.0.0.1` y los servicios se comunican por su red interna.
- Cada herramienta del maletín declara en el catálogo qué maletín la transporta (`toolkit-windows` o `toolkit-unix`); las imágenes se construyen desde el repo con versiones pineadas.
- Las sesiones de los CLIs viven en un **volumen local del stack** (`forensia-cli-auth`, el HOME del servicio `api`): el entrypoint las *seedea* una única vez desde las credenciales del host (montadas en solo lectura como staging) o el operador inicia sesión directamente en el contenedor. El refresh de tokens ocurre en el volumen — nunca en los ficheros del host —, las sesiones no salen de la máquina, no se loguean ni se exponen por la API, y `docker compose down -v` las revoca. La herramienta no pide claves de ningún proveedor.

### 2.3. Por qué Docker Compose es el modelo de entrega

- **Reproducibilidad.** Las imágenes se construyen desde el repositorio con versiones pineadas: cada despliegue produce el mismo maletín, idéntico y auditable — exactamente lo que la práctica forense exige del entorno de análisis.
- **Un solo comando.** `docker compose up --build` levanta interfaz, backend, modelo local y maletines de una vez. No hay instalación por herramienta ni configuración manual de entorno.
- **Mismo entorno en los tres SOs.** Todo corre en contenedores Linux, así que Windows, macOS y Linux ejecutan exactamente el mismo stack: desaparecen las builds nativas por SO/arch, la firma de instaladores y la matriz de empaquetado.

La complejidad de distribución se concentra así en los Dockerfiles del propio repositorio, versionados y revisables como cualquier otro código del proyecto.

---

## 3. La aplicación

La aplicación expone seis secciones, accesibles tras crear o seleccionar un caso:

- **Guía** — guía de uso y especificaciones técnicas; catálogo de soluciones desplegadas, comandos y prompts detallados, para facilitar los primeros pasos y para maximizar el rendimiento de la plataforma.
- **Casos y evidencias** — creación de proyectos/casos y carga de evidencias ya extraídas (`.E01` / `.raw` / `.vmdk` / volcado). Montaje en solo lectura a nivel de bloque y hashing SHA-256 baseline en la ingesta (cadena de custodia).
- **Investigación** — análisis vía prompts contra los sub-agentes (ej.: *"Recopila toda la información de navegación web del usuario entre los días 01/01/2025 y 30/01/2025"*). El prompt `[proceed-to-report]` cierra la investigación y dispara la redacción del informe.
- **Timeline** — selección de un informe y visualización de su línea temporal.
- **Documents / reporte** — previsualización del informe generado y exportación a PDF.
- **Mitre Attack** — correlación de las evidencias del informe con la matriz MITRE ATT&CK; identificación de técnicas, tácticas y posibles grupos / APTs involucrados.

---

## 4. Fase 1 — Selección y empaquetado del maletín forense

Selección de las herramientas forenses CLI (todas gratuitas) para los sistemas operativos en los que trabaja Agentopsy (Windows y Unix-like). Se priorizan herramientas de línea de comandos por encima de GUIs por su control determinista y su mejor integración con LLMs.

Cada herramienta se cataloga en uno de los dos maletines contenedorizados que construye el compose:

- **`toolkit-windows`** — herramientas para artefactos de sistemas Windows (RegRipper, hayabusa, chainsaw, plaso, Volatility3, …).
- **`toolkit-unix`** — herramientas para sistemas Unix-like.

No hay binarios vendoreados por SO/arch: los maletines son imágenes **Linux**, idénticas en las tres plataformas, con la versión de cada herramienta pineada en el Dockerfile.

Para las herramientas que funcionen mejor con el protocolo MCP, se expone su capacidad como servidor MCP que la aplicación consume internamente.

El listado de herramientas candidatas se detalla en el **Anexo**. La selección definitiva se cierra dentro de esta misma fase.

---

## 5. Fase 2 — Agente y sub-agentes de IA

El esquema es de un **agente orquestador** que media entre el investigador y dos **sub-agentes** especializados por SO:

- **`forensia-windows`** — sub-agente Windows.
- **`forensia-unix`** — sub-agente Unix-like.

El orquestador llama al sub-agente correspondiente para cada tarea, recopila y organiza la información que extraigan, redacta el informe, construye la timeline y correlaciona la actividad con MITRE ATT&CK. Los sub-agentes ejecutan herramientas del maletín o las acciones que consideren necesarias y devuelven la información estructurada al orquestador.

Cada agente se entrega como un **paquete declarativo** (`agentes/<id>/`) con su `agent.yaml`, sus prompts (identidad, sistema, playbook), su policy de herramientas y su política de redacción. El servicio `api` los descubre al arrancar y los indexa por `os_profile`.

**Capa de ejecución**: los prompts de la sección *Investigación* se ejecutan mediante uno de **cuatro ejecutores**, a elección del usuario: **Claude Code** (`claude -p`), **Codex CLI** (`codex exec`), **Gemini CLI** (`gemini -p`) u **Ollama** (HTTP contra el servicio `ollama` del compose). Los tres CLIs van instalados en la imagen del servicio `api` y se autentican con la sesión del volumen `forensia-cli-auth` (seeded una vez desde las credenciales del host, o creada con un login único dentro del contenedor: `claude auth login`, `codex login --device-auth`, `gemini` con `NO_BROWSER=true`), de modo que cada CLI consume la suscripción/cuenta del propio usuario. **La herramienta no usa API keys de ningún proveedor.** La capa abstrae los cuatro ejecutores tras una interfaz común; si el usuario no ha seleccionado ejecutor, la API devuelve un error accionable — nunca un default silencioso (RULE 2). Ollama es la opción 100 % local; al elegir un ejecutor respaldado por cloud (Claude Code, Codex, Gemini), la aplicación advierte explícitamente de que contenido derivado del caso saldrá al proveedor y registra la elección en el audit log.

Esta fase arranca en cuanto el maletín está listo y es la última en cerrarse: el conocimiento de los agentes se enriquece de forma incremental, lo que se traduce en **análisis más preciso**, **mejor consumo de tokens** y **mejor redacción de informes**.

---

## 6. Fase 3 — Desarrollo de la aplicación

Implementación de las seis secciones descritas en la sección 3. La superficie es **única**: la **interfaz web** que sirve el compose (servicio `web`), usada desde el navegador en `127.0.0.1`. No hay aplicación de escritorio, ni web pública/SaaS, ni CLI alternativa para el usuario final; sí utilidades CLI internas para el equipo durante el desarrollo.

---

## 7. Fase 4 — Test y correcciones

Probamos contra **todos los escenarios posibles** para evitar fallos en la ejecución y pulir el resultado final del análisis.

Los tests no esperan a la versión final del proyecto: empiezan antes de que los agentes estén plenamente entrenados y antes de que la interfaz sea estéticamente final. Lo importante es validar cuanto antes el flujo extremo-a-extremo y el catálogo de tools.

**Datos de prueba**: combinación de datasets públicos (CFReDS de NIST, Digital Corpora, Forensic Focus) y **máquinas virtuales propias** con actividad guionizada, que aportan ground truth para validar objetivamente los hallazgos.

---

## 8. Modo de empleo

- **Despliegue** — `git clone` del repositorio y `docker compose up --build`; la herramienta se usa desde el navegador en `http://127.0.0.1:5173`.
- **Iniciar proyecto** — crear nuevo caso y subir las evidencias (`.E01` / `.raw` / `.vmdk` / volcado). Hash SHA-256 baseline en la ingesta.
- **Elegir ejecutor** — seleccionar el ejecutor de IA (Claude Code, Codex CLI, Gemini CLI u Ollama). Sin selección explícita no hay análisis (RULE 2); si el ejecutor es cloud, la herramienta lo advierte y lo registra en el audit log.
- **Investigación** — sesión de prompts contra los sub-agentes en la sección *Investigación*.
- **Redacción** — `[proceed-to-report]` genera el informe forense y su línea temporal.
- **Revisión** — previsualización y exportación a PDF del informe y de la timeline desde la sección *Documents / reporte*.
- En caso de no estar conforme con el resultado, el prompt `[back-to-analysis]` devuelve al investigador a la sección *Investigación*.

---

## 9. Fuera de alcance

- **Adquisición o extracción de evidencias** del equipo original — se asume que las evidencias llegan ya extraídas.
- **Live forensics o respuesta a incidentes en tiempo real** — el foco es exclusivamente post-mortem.
- **Validez legal o pericial certificada** — el proyecto es académico y de demostración; preservamos rigor (chain of custody, integridad, reproducibilidad) pero no se persigue acreditación.

---

## 10. Cronograma (29 jun → 7 sep)

| Sem. | Fechas | Foco principal | Hitos / entregables |
| :--- | :--- | :--- | :--- |
| 1 | 29 jun – 5 jul | Fundaciones: esqueleto del compose (maletines + backend); api FastAPI operativo; CI; inventario inicial del maletín; elegir dataset público y arrancar VMs propias. | Esqueleto desplegable con `docker compose up --build`; lista de herramientas v0; dataset elegido. |
| 2 | 6 – 12 jul | Maletín v1: contenedorización de las herramientas core en los dos maletines; montaje read-only de `.raw`/`.vmdk` + hashing SHA-256; contrato de wrappers CLI→JSON. | Maletín v1; evidencias con cadena de custodia. |
| 3 | 13 – 19 jul | Capa de ejecución bajo interfaz común (Claude Code, Codex CLI, Gemini CLI, Ollama — sin API keys); prompts base y RAG inicial. UI web: creación de casos y subida de evidencias. | Capa de ejecución operativa; alta de casos en la UI. |
| 4 | 20 – 26 jul | **Vertical slice E2E** sobre una imagen pequeña: prompt → sub-agente → herramienta → hallazgo. Informe básico vía `[proceed-to-report]`. | Demo E2E mínima funcionando. |
| 5 | 27 jul – 2 ago | Segundo sub-agente operativo (Windows y Unix-like al mismo nivel). Timeline (plaso/psort) integrada en la UI web. Exportación a PDF. | Dos sub-agentes; timeline visible; export PDF. |
| 6 | 3 – 9 ago | Consolidación: **MVP feature-complete**. Flujo completo Investigación → Documents → `[back-to-analysis]`. Sección MITRE ATT&CK v1. | MVP funcional completo. |
| 7 | 10 – 16 ago | Hardening: batería de escenarios y casos límite; validación contra ground truth de las VMs propias. Robustez del despliegue con compose. | Suite de pruebas; `docker compose up --build` limpio en los 3 SOs. |
| 8 | 17 – 23 ago | Pulido de UI, guía de usuario y especificaciones técnicas. Extras opcionales (MCPs adicionales, fine-tuning) sólo si MVP es estable. Memoria: redacción de resultados. | Guía de usuario; UI presentable. |
| 9 | 24 – 30 ago | **Feature freeze**: sólo correcciones. Pruebas de despliegue desde cero con `docker compose up --build` en máquinas limpias (Windows / macOS / Linux). Memoria: borrador completo. | Feature freeze; borrador de memoria para revisión. |
| 10 | 31 ago – 6 sep | Validación final E2E con datasets públicos y propios. Cierre de la memoria (revisión cruzada, formato, bibliografía). Preparación de la defensa (guion de demo, slides). | Memoria casi final; materiales de defensa. |
| 11 | 7 sep | Buffer y cierre. Revisión final del repo (README, licencia, versión etiquetada). Ensayo de defensa y grabación de demo de respaldo. | **Entrega del TFM.** |

> Riesgos identificados (alcance, datos de prueba, integración tardía) se mitigan con MVP estricto, ground truth temprano y feature freeze en la semana 9.

---

## 11. Equipo y metodología

Equipo de seis personas, con reparto por módulos y responsabilidades transversales (memoria y testeo) compartidas:

| Módulo | Responsabilidad |
| :--- | :--- |
| DevOps / Integración | Docker Compose (imágenes y orquestación de los cinco servicios), CI/CD, integración entre módulos, compilación de la memoria. |
| Maletín + Sub-agente Windows | Selección y empaquetado de herramientas Windows; prompts y RAG del sub-agente Windows. |
| Maletín + Sub-agente Unix-like | Selección y empaquetado de herramientas Unix-like; prompts y RAG del sub-agente Unix-like. |
| Orquestación IA / Capa de ejecución | Interfaz común de los cuatro ejecutores (Claude Code, Codex CLI, Gemini CLI, Ollama), tool-calling, pipeline RAG, optimización de tokens, generación de informes. |
| Frontend | UI web (React) servida por el compose, sección de casos, repositorio de informes, timeline, export PDF, sección Mitre. |
| Datos / QA | Datasets, VMs con ground truth, escenarios de prueba, validación contra hallazgos esperados. |

**Metodología**:

- Git con ramas por funcionalidad, pull requests con revisión cruzada, tablero de tareas.
- Sprints semanales: una reunión de planificación y una de revisión.
- Integración continua para evitar choques de última hora.
- Integración temprana: vertical slice E2E en la semana 4, mejorado de forma incremental.

---

## Anexo · Herramientas candidatas

Repositorio del proyecto: <https://github.com/Rorouh/Forensia-AI/tree/tools>.

Listado-fuente; las inclusiones definitivas se acuerdan en Fase 1 en función del valor forense y de la viabilidad de integración en las imágenes del maletín.

### 1. Adquisición, procesamiento de imágenes de disco y sistemas de archivos

- `tsk_loaddb` (The Sleuth Kit)
- `fls` (The Sleuth Kit)
- `icat` (The Sleuth Kit)
- `ils` (The Sleuth Kit)
- `img_stat` (The Sleuth Kit)
- `istat` (The Sleuth Kit)
- `mmstat` (The Sleuth Kit)
- `blkcalc` / `blkls` / `blkcat` (The Sleuth Kit)
- `guestfish` (libguestfs)
- `guestmount` (libguestfs)
- `ewfinfo` (libewf)
- `ewfexport` (libewf)
- `ewfverify` (libewf)
- `vmdkinfo` (libvmdk)
- `vmdkmount` (libvmdk)
- `affuse` (afflib)
- `affstats` (afflib)
- `bulk_extractor`
- `bitlocker-dump` / `dislocker-find`
- `7z` (p7zip)
- `hfsutils` (para artefactos heredados de macOS)

### 2. Artefactos, registros y telemetría de Windows (offline / parsers)

- `log2timeline.py` (Plaso)
- `psort.py` (Plaso)
- `image_export.py` (Plaso)
- `hayabusa-cli` (versión Rust multi-arch)
- `chainsaw` (versión Rust multi-arch)
- `rip.pl` (RegRipper 3.0)
- `EvtxECmd` (Suite de Eric Zimmerman — vía .NET Core en Linux)
- `MFTECmd` (Suite de Eric Zimmerman — vía .NET Core en Linux)
- `RECmd` (Suite de Eric Zimmerman — vía .NET Core en Linux)
- `AmcacheParser` (Suite de Eric Zimmerman — vía .NET Core en Linux)
- `LECmd` (Suite de Eric Zimmerman — vía .NET Core en Linux)
- `JLECmd` (Suite de Eric Zimmerman — vía .NET Core en Linux)
- `ShellBagsExplorer` (versión CLI — vía .NET Core en Linux)
- `fred` (Forensic Registry Editor CLI)
- `hivexget` / `hivexml` / `hivexsh` (libhivex)
- `evtx_dump` (Rust-evtx)
- `python-registry` (Reglookup)
- `srch_strings`
- `prefetch-parser` (Python/Rust equivalents)
- `srum-parser`
- `scca` (Shim Cache Parser)

### 3. Artefactos, logs y auditoría de sistemas Unix-like (Linux/macOS)

- `uac` (Unix Artifact Collector)
- `ausearch` (Auditd)
- `aureport` (Auditd)
- `utmpdump` (análisis de `wtmp`/`btmp`)
- `journalctl` (para entornos con Systemd montados)
- `logcheck`
- `logwatch`
- `linenum.sh` (scripts de enumeración)
- `lynis` (módulo de auditoría forense)
- `chkrootkit`
- `rkhunter`
- `dumpe2fs`
- `debugfs`
- `find` / `stat` / `file` (comandos nativos coreutils con flags forenses)
- `maclookup` (para análisis de direcciones MAC históricas)
- `stat` (extracción forense de marcas de tiempo birth/access/modify/change)

### 4. Análisis de memoria RAM volátil

- `vol` (Volatility 3 Framework)
- `vol.py` (Volatility 2 — entorno Python 2 legacy heredado)
- `dwarf2json` (generador de firmas ISF para kernels Linux)
- `rekall` (herramienta CLI de análisis de memoria alternativa)
- `lime-res` (parser de estructuras LiME)
- `vmem_parse`

### 5. Análisis de malware, ingeniería inversa estática y firmas

- `yara` (CLI con soporte multiplataforma)
- `capa` (FLARE Capability Analytics)
- `floss` (FLARE Obfuscated String Solver)
- `clamscan` (ClamAV Engine CLI)
- `pecheck`
- `readelf`
- `ldd`
- `objdump`
- `signcheck` (equivalentes en Python/Go para verificar firmas digitales)
- `trid` (identificador de formato de archivos CLI)
- `ssdeep` (fuzzy hashing)
- `tlsh` (Trend Micro Locality Sensitive Hash)

### 6. Correlación de datos, líneas de tiempo y helpers para la IA

- `sqlite3` (manipulación directa de BDs de Plaso, TSK, navegadores)
- `jq` (filtrado ultra-preciso de JSONs procedentes de Hayabusa/Volatility antes de enviar al LLM)
- `csvkit` (`csvlook`, `csvformat`, `csvgrep` para procesar outputs masivos de Zimmerman)
- `timesketch-cli`
- `grep` / `egrep` / `fgrep`
- `awk`
- `sed`
- `datamash`
- `diff` / `colordiff` (para comparar estados del registro o del sistema de archivos)

---

## Documentación de referencia

Documentación técnica que sostiene cada bloque de este plan. Índice completo en [`docs/README.md`](docs/README.md).

| Sección de este documento | Documento técnico |
| :--- | :--- |
| §2 Modelo de entrega y arquitectura | [`docs/arquitectura.md`](docs/arquitectura.md) · [`docs/modelo-amenazas.md`](docs/modelo-amenazas.md) |
| §2.2 Topología en runtime · cadena de custodia | [`docs/soundness-forense.md`](docs/soundness-forense.md) · [`docs/storage.md`](docs/storage.md) |
| §4 Fase 1 — Maletín | [`docs/maletin/inventario-tools.md`](docs/maletin/inventario-tools.md) · [`docs/maletin/inventario-mcps.md`](docs/maletin/inventario-mcps.md) · [`docs/maletin/mcp-toolkit-s1.md`](docs/maletin/mcp-toolkit-s1.md) |
| §5 Fase 2 — Agentes | [`docs/agentes/contrato-paquetes.md`](docs/agentes/contrato-paquetes.md) · [`docs/agentes/diseno-fase2.md`](docs/agentes/diseno-fase2.md) |
| §6 Fase 3 — Aplicación | [`docs/ai-context/frontend.md`](docs/ai-context/frontend.md) · [`docs/operacion/frontend-journal.md`](docs/operacion/frontend-journal.md) |
| §10 Cronograma · deuda técnica | [`docs/operacion/proximos-pasos.md`](docs/operacion/proximos-pasos.md) |
