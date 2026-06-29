# Propuesta TFM

## Herramienta con integración de IA para la Práctica Forense

El proyecto consiste en el desarrollo de una herramienta forense que permita la integración de IA para realizar análisis post-mortem con un nivel alto de precisión y automatización.

Dicha herramienta se desplegará mediante Docker, el contenido de esta será:

- Una aplicación con las siguientes secciones/funcionalidades:
  - Acceso a la guía de uso y especificaciones de la herramienta.
  - Creación de nuevos proyectos/investigaciones y carga de los archivos ya extraídos del equipo a analizar.
  - Investigación mediante prompts.
  - Visualización del contenido generado (informe, línea temporal, correlación con Mitre Attack).
- Un maletín forense compuesto por todas las herramientas (open source o gratuitas) necesarias para realizar un análisis forense exhaustivo en distintos sistemas operativos.
- Agente y sub-agentes de IA pre-entrenados en análisis forense de distintos entornos.

## Fase 1: Selección del maletín forense

Selección de las herramientas (todas ellas gratuitas) para los distintos sistemas operativos en los que trabaja la herramienta principal (Windows, Unix-like).

Con el objetivo de facilitar la integración de estas con la IA, utilizaremos herramientas que funcionen mediante CLI e implementaremos/crearemos MCPs para aquellas herramientas del maletín que funcionen mejor con este protocolo.

## Fase 2: Creación del agente de IA

El esquema será el siguiente: crearemos un agente orquestador que haga de intermediario entre la información volcada por el investigador en la herramienta y dos sub-agentes. Crearemos un sub-agente para sistemas Windows y otro para Unix-like.

El agente orquestador se encargará de llamar al sub-agente correspondiente para cada tarea, recopilar y organizar la información que éstos extraigan, redactar el informe, crear la timeline y correlacionar la actividad con la matriz Mitre Att&ck.

Los sub-agentes serán los encargados de recopilar la información mediante el uso de las herramientas del maletín o las acciones que estos consideren necesarias. Los sub-agentes estructurarán la información recopilada para que el agente orquestador pueda tener visibilidad de todas las evidencias recopiladas por los sub-agentes.

Esta fase arrancará en cuanto el maletín de herramientas esté listo; a medida que avance el proyecto iremos progresando en el entrenamiento de los agentes. De este modo maximizamos el aprendizaje de estos, lo que resultará en: un **análisis más preciso**, **optimización del consumo de tokens** y una **mejor redacción de informes**.

## Fase 3: Desarrollo de la aplicación

La aplicación **se desplegará vía Docker** (junto a todo lo demás). Tiene las siguientes funciones/secciones:

- **Sección "Guía"**: esta sección contendrá la guía de usuario y especificaciones técnicas. Este documento incluye un catálogo de las soluciones desplegadas, así como instrucciones, comandos y prompts detallados, diseñados tanto para facilitar los primeros pasos como para maximizar el rendimiento de la plataforma.
- **Sección "Casos y evidencias"**: en esta sección se crearán nuevos proyectos/casos y se realizará la carga de las evidencias, las cuales estarán ya extraídas de los equipos a analizar. El formato de estas evidencias es variado (`.E01` / `.raw` / `.vmdk` / volcado, etc.).
- **Sección "Investigación"**: desde esta se realizará el análisis mediante prompts (ej.: *"Recopila toda la información de navegación web del usuario entre los días 01/01/2025 y 30/01/2025"*). Una vez se dé por cubierta la investigación se generará el informe mediante el prompt `[proceed-to-report]`.
- **Sección "Timeline"**: en esta sección se seleccionará un informe, se generará una timeline en base a este y se mostrará/visualizará la timeline del informe.
- **Sección "Documents/reporte"**: en esta sección se previsualizará el informe una vez generado. Para ello es necesario realizar antes una investigación y haber ejecutado el `[proceed-to-report]`.
- **Sección "Mitre Attack"**: en esta sección se seleccionará un informe ya completo y se realizará la correlación de las evidencias recopiladas con la matriz de Mitre, las técnicas/tácticas utilizadas y los posibles grupos maliciosos/APTs involucrados.

## Fase 4: Test y correcciones

En esta fase pondremos a prueba el desarrollo anterior. Planteamos **todos los posibles escenarios** para evitar fallos en el momento de la ejecución y pulir el resultado final de los análisis.

Para ello no esperaremos a la versión final del proyecto para testearlo. Empezaremos a probarlo antes de que los agentes estén plenamente entrenados y la interfaz web sea estéticamente atractiva.

## Nota sobre el modo de empleo

- **Descarga y despliegue**: el usuario hará un `git clone` del repositorio y desplegará la herramienta mediante `docker compose up --build`.
- **Iniciar proyecto**: se creará un nuevo proyecto (para el caso en concreto) donde se subirán todas las evidencias recopiladas (archivos `.vmdk` y `.raw`).
- **Redacción**: al ejecutar el prompt `[proceed-to-report]` se genera el informe forense y su línea temporal.
- **Revisión**: se realizará mediante la interfaz web; además, permitirá realizar la previsualización y descarga en formato `.pdf` del informe y la timeline.
- En caso de no estar conforme con la versión final el usuario introducirá el prompt `[back-to-analysis]`, que devolverá al usuario a la sección de análisis.

## Anexo

El repositorio de GitHub ya está creado: <https://github.com/Rorouh/Forensia-AI/tree/tools>. Clonado en local en la ruta: `/Users/enrique/Documents/GitHub`. Puedes acceder a este para obtener más contexto. De momento es un boceto; cualquier cosa puede ser modificada.

El listado de herramientas se detalla a continuación; puedes eliminar cualquier herramienta que consideres innecesaria o añadir alguna si la echas en falta.

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
