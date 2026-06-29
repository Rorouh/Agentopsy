# FORENSIA — Alcance y Diseño del TFM

**Herramienta con integración de IA para la práctica forense**

Trabajo Final de Máster · Documento de alcance, diseño y planificación

| | |
| :--- | :--- |
| Equipo | Enrique · Daniel · Santiago · Luis · Diego · Miguel Ángel |
| Fecha de entrega | 7 de septiembre de 2026 |
| Versión | v1.1 · 29 de junio de 2026 |

---

## 1. Resumen ejecutivo

FORENSIA es una herramienta de análisis forense **post-mortem** asistida por IA, distribuida como **aplicación de escritorio universal** (Windows / macOS / Linux) instalable con un único comando. La aplicación empaqueta dentro de sí la interfaz gráfica, un sidecar de backend en Python, un maletín de herramientas forenses CLI y dos sub-agentes de IA especializados por sistema operativo, gobernados por un agente orquestador. Cuando alguna herramienta del maletín no dispone de binario nativo viable en el SO del usuario, la aplicación la ejecuta dentro de un contenedor Docker que despliega de forma transparente; Docker es **capa interna**, no es lo que el usuario instala ni invoca.

El usuario carga evidencias ya extraídas (`.E01` / `.raw` / `.vmdk` / volcado), conduce la investigación mediante prompts y obtiene un informe forense estructurado, su línea temporal y la correlación con MITRE ATT&CK.

De hoy (29 de junio) al 7 de septiembre quedan **11 semanas**. La planificación prioriza un MVP estricto en las primeras 6–7 semanas y reserva las últimas para validación, cierre de la memoria académica y preparación de la defensa.

---

## 2. Modelo de entrega y arquitectura

### 2.1. Instalación: una sola línea

La aplicación se entrega como **instalable nativo por SO**, no como un repositorio que el usuario clona y arranca con Docker Compose. Una sola línea por plataforma:

```bash
# Linux / macOS
curl -fsSL https://forensia.dev/install.sh | bash

# Windows
# Instalador .exe firmado.
```

Esto sustituye al flujo `git clone + cp .env.example .env + docker compose up --build`, más frágil y expuesto a fricciones de entorno. El espíritu de empaquetado *"todo viaja con la app"* se preserva: dentro del instalador van la GUI, el sidecar de Python, los binarios forenses nativos compilados por SO/arch y, cuando aplica, las imágenes OCI pre-construidas que sustituyen a las herramientas que no compilan de forma cross-OS.

### 2.2. Topología en runtime

```
┌─ APLICACIÓN INSTALADA (Electron) ──────────────────────────┐
│  Renderer (UI única en los 3 SOs)                          │
│     ↕  IPC seguro (contextIsolation + sandbox)             │
│  Main process — controla ciclo de vida del sidecar         │
│     ↕  127.0.0.1:<puerto efímero> + token de sesión         │
│  Sidecar Python (FastAPI) — orquestador + agentes          │
│     ↓                            ↓                          │
│  Binarios nativos vendoreados    Docker / Podman (host)     │
│  (vendor/<tool>/<os>-<arch>/)    ↓                          │
│                                  Imágenes OCI pre-cargadas  │
│                                  para tools no nativas      │
└─────────────────────────────────────────────────────────────┘
```

- La **GUI** es idéntica en los tres SOs (Chromium dentro de Electron).
- El **sidecar** habla con la GUI por `127.0.0.1` en puerto efímero, autenticado por token de sesión; nunca expone `0.0.0.0`.
- Cada herramienta del maletín declara su mecanismo de ejecución: **bundled** (binario nativo dentro del instalador) o **container** (imagen OCI que la app levanta on-demand).
- Docker o Podman es un **prerequisito documentado del instalador**; el primer arranque lo verifica. Si no está presente, las herramientas en modo *container* se reportan como no disponibles y el resto de la aplicación sigue funcionando.

### 2.3. Por qué Docker deja de ser la distribución

Docker Compose siempre cumplió la función de empaquetado, pero la cumple **peor** que un instalador nativo desde el punto de vista del investigador:

| Aspecto | `docker compose up --build` | Instalador nativo |
| :--- | :--- | :--- |
| Pasos del usuario | `git clone` + `.env` + `compose` | Una línea (curl o doble click) |
| Conocimiento exigido | Docker, redes, volúmenes | Ninguno |
| Interfaz | Browser apuntando a `localhost` | Ventana nativa |
| Cadena de custodia | Idéntica | Idéntica |
| Actualizaciones | `git pull` + rebuild | Auto-update firmado |
| Universalidad | Igual | Igual (gracias a fallback container interno) |

Docker se queda **dentro** del modelo, no fuera: lo usa la aplicación para garantizar que el catálogo de tools es el mismo en Windows, macOS y Linux sin pedirle al investigador que entienda contenedores.

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

Selección de las herramientas forenses CLI (todas gratuitas) para los sistemas operativos en los que trabaja FORENSIA (Windows y Unix-like). Se priorizan herramientas de línea de comandos por encima de GUIs por su control determinista y su mejor integración con LLMs.

Cada herramienta se cataloga con uno de dos mecanismos de entrega:

- **Bundled** — binario nativo compilado por SO/arch y embebido directamente en el instalador.
- **Container** — imagen OCI pre-construida que la aplicación levanta on-demand. Es la vía para herramientas sin build nativa viable cross-OS (RegRipper en Perl, plaso en Windows, etc.).

Para las herramientas que funcionen mejor con el protocolo MCP, se expone su capacidad como servidor MCP que la aplicación consume internamente.

El listado de herramientas candidatas se detalla en el **Anexo**. La selección definitiva se cierra dentro de esta misma fase.

---

## 5. Fase 2 — Agente y sub-agentes de IA

El esquema es de un **agente orquestador** que media entre el investigador y dos **sub-agentes** especializados por SO:

- **`forensia-windows`** — sub-agente Windows.
- **`forensia-unix`** — sub-agente Unix-like.

El orquestador llama al sub-agente correspondiente para cada tarea, recopila y organiza la información que extraigan, redacta el informe, construye la timeline y correlaciona la actividad con MITRE ATT&CK. Los sub-agentes ejecutan herramientas del maletín o las acciones que consideren necesarias y devuelven la información estructurada al orquestador.

Cada agente se entrega como un **paquete declarativo** (`agentes/<id>/`) con su `agent.yaml`, sus prompts (identidad, sistema, playbook), su policy de herramientas y su política de redacción. El sidecar los descubre al arrancar y los indexa por `os_profile`.

**Capa de modelos**: el usuario elige modelo **local** (Ollama, recomendado por defecto por la sensibilidad de la evidencia) o **cloud** (Claude, GPT). La capa abstrae al proveedor tras una interfaz común; al elegir cloud, la aplicación advierte explícitamente de que las evidencias saldrán a una API externa.

Esta fase arranca en cuanto el maletín está listo y es la última en cerrarse: el conocimiento de los agentes se enriquece de forma incremental, lo que se traduce en **análisis más preciso**, **mejor consumo de tokens** y **mejor redacción de informes**.

---

## 6. Fase 3 — Desarrollo de la aplicación

Implementación de las seis secciones descritas en la sección 3. La superficie es **única**: la aplicación de escritorio. No hay aplicación web pública, ni CLI alternativa para el usuario final; sí utilidades CLI internas para el equipo durante el desarrollo.

---

## 7. Fase 4 — Test y correcciones

Probamos contra **todos los escenarios posibles** para evitar fallos en la ejecución y pulir el resultado final del análisis.

Los tests no esperan a la versión final del proyecto: empiezan antes de que los agentes estén plenamente entrenados y antes de que la interfaz sea estéticamente final. Lo importante es validar cuanto antes el flujo extremo-a-extremo y el catálogo de tools.

**Datos de prueba**: combinación de datasets públicos (CFReDS de NIST, Digital Corpora, Forensic Focus) y **máquinas virtuales propias** con actividad guionizada, que aportan ground truth para validar objetivamente los hallazgos.

---

## 8. Modo de empleo

- **Instalación** — una sola línea o un instalador, según SO.
- **Iniciar proyecto** — crear nuevo caso y subir las evidencias (`.E01` / `.raw` / `.vmdk` / volcado). Hash SHA-256 baseline en la ingesta.
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
| 1 | 29 jun – 5 jul | Fundaciones: esqueleto del instalable; sidecar Python operativo; CI por SO; inventario inicial del maletín; elegir dataset público y arrancar VMs propias. | Esqueleto desplegable; lista de herramientas v0; dataset elegido. |
| 2 | 6 – 12 jul | Maletín v1: contenedorización / vendoring de las herramientas core; montaje read-only de `.raw`/`.vmdk` + hashing SHA-256; contrato de wrappers CLI→JSON. | Maletín v1; evidencias con cadena de custodia. |
| 3 | 13 – 19 jul | Capa de modelos local/cloud bajo interfaz común; prompts base y RAG inicial. UI: creación de casos y subida de evidencias. | Capa de modelos operativa; alta de casos en la UI. |
| 4 | 20 – 26 jul | **Vertical slice E2E** sobre una imagen pequeña: prompt → sub-agente → herramienta → hallazgo. Informe básico vía `[proceed-to-report]`. | Demo E2E mínima funcionando. |
| 5 | 27 jul – 2 ago | Segundo sub-agente operativo (Windows y Unix-like al mismo nivel). Timeline (plaso/psort) integrada en la GUI. Exportación a PDF. | Dos sub-agentes; timeline visible; export PDF. |
| 6 | 3 – 9 ago | Consolidación: **MVP feature-complete**. Flujo completo Investigación → Documents → `[back-to-analysis]`. Sección MITRE ATT&CK v1. | MVP funcional completo. |
| 7 | 10 – 16 ago | Hardening: batería de escenarios y casos límite; validación contra ground truth de las VMs propias. Robustez del instalador por SO. | Suite de pruebas; instalador limpio en los 3 SOs. |
| 8 | 17 – 23 ago | Pulido de UI, guía de usuario y especificaciones técnicas. Extras opcionales (MCPs adicionales, fine-tuning) sólo si MVP es estable. Memoria: redacción de resultados. | Guía de usuario; UI presentable. |
| 9 | 24 – 30 ago | **Feature freeze**: sólo correcciones. Pruebas de instalación desde cero en máquinas limpias (Windows / macOS / Linux). Memoria: borrador completo. | Feature freeze; borrador de memoria para revisión. |
| 10 | 31 ago – 6 sep | Validación final E2E con datasets públicos y propios. Cierre de la memoria (revisión cruzada, formato, bibliografía). Preparación de la defensa (guion de demo, slides). | Memoria casi final; materiales de defensa. |
| 11 | 7 sep | Buffer y cierre. Revisión final del repo (README, licencia, versión etiquetada). Ensayo de defensa y grabación de demo de respaldo. | **Entrega del TFM.** |

> Riesgos identificados (alcance, datos de prueba, integración tardía) se mitigan con MVP estricto, ground truth temprano y feature freeze en la semana 9.

---

## 11. Equipo y metodología

Equipo de seis personas, con reparto por módulos y responsabilidades transversales (memoria y testeo) compartidas:

| Módulo | Responsabilidad |
| :--- | :--- |
| DevOps / Integración | Instalador, CI/CD por SO, integración entre módulos, compilación de la memoria. |
| Maletín + Sub-agente Windows | Selección y empaquetado de herramientas Windows; prompts y RAG del sub-agente Windows. |
| Maletín + Sub-agente Unix-like | Selección y empaquetado de herramientas Unix-like; prompts y RAG del sub-agente Unix-like. |
| Orquestación IA / Capa de modelos | Interfaz común local/cloud, tool-calling, pipeline RAG, optimización de tokens, generación de informes. |
| Frontend | UI Electron, sección de casos, repositorio de informes, timeline, export PDF, sección Mitre. |
| Datos / QA | Datasets, VMs con ground truth, escenarios de prueba, validación contra hallazgos esperados. |

**Metodología**:

- Git con ramas por funcionalidad, pull requests con revisión cruzada, tablero de tareas.
- Sprints semanales: una reunión de planificación y una de revisión.
- Integración continua para evitar choques de última hora.
- Integración temprana: vertical slice E2E en la semana 4, mejorado de forma incremental.

---

## Anexo · Herramientas candidatas

Repositorio del proyecto: <https://github.com/Rorouh/Forensia-AI/tree/tools>.

Listado-fuente; las inclusiones definitivas se acuerdan en Fase 1 en función del valor forense y de la viabilidad técnica (build nativa o imagen container).

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
