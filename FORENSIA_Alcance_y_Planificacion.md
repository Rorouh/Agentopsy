**FORENSIA**  
Herramienta con integración de IA para la Práctica Forense

**Trabajo Final de Máster — Documento de Alcance y Planificación**

Versión 1.0  ·  20 de junio de 2026

Equipo: Enrique · Daniel · Santiago · Luis · Diego · Miguel Ángel

**Entrega: 7 de septiembre de 2026**

# **Índice**

*(Para actualizar el índice en Word: clic derecho sobre él → «Actualizar campos».)*

# **1\. Resumen ejecutivo**

FORENSIA es una herramienta de análisis forense post-mortem asistida por IA, desplegable con Docker, que combina un maletín de herramientas forenses de línea de comandos, dos agentes de IA especializados por sistema operativo (Windows y Unix-like), una aplicación web para gestionar evidencias e informes, y una aplicación de terminal para conducir la investigación mediante prompts. El objetivo del TFM es entregar, el 7 de septiembre de 2026, una herramienta funcional junto con la memoria académica y preparar su defensa.

De hoy (20 de junio) al 7 de septiembre hay **11 semanas**. El alcance de la propuesta es ambicioso, por lo que este documento prioriza un **MVP estricto** (lo imprescindible para una demostración y defensa sólidas) y relega a «extras» lo opcional (MCPs, fine-tuning). La estrategia central es construir cuanto antes un flujo extremo-a-extremo mínimo y mejorarlo de forma incremental, reservando las últimas semanas para validación, cierre de la memoria y preparación de la defensa.

# **2\. Decisiones de base acordadas**

Estas decisiones, acordadas en la sesión inicial de definición, condicionan toda la planificación:

| Tema | Decisión |
| :---- | :---- |
| Agentes de IA | Enfoque por orquestación de LLMs existentes (prompts especializados \+ RAG \+ contexto forense y tool-calling sobre las herramientas CLI). El fine-tuning de modelos open source queda como extra final, solo si el MVP es estable. |
| Modelos de IA | Capa configurable: el usuario elige modelo local (p. ej. Ollama) o cloud (p. ej. Claude/GPT). Por la sensibilidad de las evidencias, el modelo local es la opción por defecto recomendada. |
| Entregables | TFM completo: memoria académica \+ herramienta funcional \+ defensa oral. La memoria se redacta de forma continua, no solo al final. |
| Datos de prueba | No se dispone de imágenes suficientes. Se combinarán datasets públicos (CFReDS, Digital Corpora) con máquinas virtuales propias que aporten «ground truth» para validar a los agentes. |
| Equipo y stack | 6 personas con reparto por módulos (ver sección 7). Stack propuesto: Python/FastAPI, React, Docker Compose y una capa de IA propia (ver sección 6). |
| Disponibilidad | Ritmo de trabajo normal durante todo el verano, incluido agosto. |

# **3\. Alcance del proyecto**

## **3.1. MVP — imprescindible**

El MVP es la versión mínima que demuestra el valor del proyecto de extremo a extremo y que debe estar terminada antes de la congelación de funcionalidades:

* Despliegue reproducible con un único comando (git clone \+ docker compose up \--build) que levante todos los servicios en localhost.

* Maletín forense contenedorizado: conjunto curado de herramientas CLI gratuitas para Windows y Unix-like, con catálogo documentado.

* Carga de evidencias (.vmdk/.raw) en proyectos, con montaje en solo lectura y hashing de integridad (cadena de custodia).

* Dos agentes (Windows y Unix-like) por orquestación: system prompt especializado, base de conocimiento (RAG) y wrappers de las herramientas.

* Capa de modelos configurable con al menos un proveedor local y uno cloud bajo una interfaz común.

* Aplicación de terminal: menú de selección de proyecto, agente y modelo; sesión interactiva por prompts; generación de informe con \[proceed-to-report\] y retorno con \[back-to-analysis\].

* Aplicación web: creación de proyecto, subida de evidencias, repositorio de informes con previsualización y exportación a PDF, y vista de línea temporal.

* Generación de informe forense estructurado y su línea temporal.

## **3.2. Extras — opcionales (si el MVP es estable)**

* Servidores MCP que envuelvan las herramientas forenses (mencionados como opcionales en la propuesta).

* Exploración de fine-tuning de modelos open source sobre datos forenses.

* Mayor cobertura de sistemas, herramientas adicionales y mejoras estéticas avanzadas de la interfaz.

## **3.3. Fuera de alcance**

* Adquisición/extracción de evidencias del equipo original (se asume que las evidencias llegan ya extraídas).

* Análisis en vivo (live forensics) o respuesta a incidentes en tiempo real; el foco es post-mortem.

* Validez legal/pericial certificada; el proyecto es académico y de demostración.

# **4\. Arquitectura y decisiones técnicas**

## **4.1. Visión general**

La herramienta se organiza como un conjunto de servicios orquestados por Docker Compose: (1) un frontend web; (2) una API/backend que gestiona proyectos, evidencias e informes; (3) un orquestador de agentes que conecta el modelo de IA con las herramientas forenses mediante tool-calling; (4) el maletín de herramientas contenedorizado; (5) un ejecutor de modelos local (Ollama) y conectores a modelos cloud; y (6) almacenamiento de proyectos e informes. La aplicación de terminal abre una sesión del modelo elegido con el contexto del agente cargado y en la ruta del proyecto.

## **4.2. Capa de modelos y privacidad de las evidencias**

Dado que las evidencias forenses son datos sensibles, la capa de modelos abstrae el proveedor tras una interfaz común y prioriza el procesamiento local por defecto. Cuando se seleccione un modelo cloud, la herramienta advertirá de que las evidencias saldrán a una API externa. Se trabajará siempre sobre copias montadas en solo lectura y con verificación de hash, preservando la integridad de la evidencia original.

## **4.3. Maletín forense**

Selección inicial de herramientas (todas gratuitas y de uso CLI) que se afinará en la Fase 1\. Se partirá también del maletín facilitado por el Prof. Jesús Angosto.

| Categoría | Herramientas (CLI) | Sistema |
| :---- | :---- | :---- |
| Imagen y montaje | libewf/ewf-tools, qemu-nbd, guestmount; OSFMount | Cross |
| Integridad / hashing | sha256sum, hashdeep | Cross |
| Sistema de ficheros y carving | The Sleuth Kit (fls, icat, mmls, mactime), bulk\_extractor, foremost/scalpel | Cross |
| Línea temporal | plaso / log2timeline \+ psort | Cross |
| Memoria RAM | Volatility 3 | Cross |
| Artefactos Windows | RegRipper (registro), hayabusa y chainsaw (Sigma sobre EVTX), parsers de Prefetch/LNK/navegadores | Windows |
| Artefactos Unix-like | Análisis de /var/log, journald, bash history; TSK sobre EXT/XFS | Unix-like |

## **4.4. Agentes de IA**

Cada agente combina un system prompt especializado en su sistema operativo, una base de conocimiento forense recuperable por RAG (incluido el catálogo de herramientas con sus comandos) y un conjunto de wrappers que exponen las herramientas CLI como funciones invocables. Esta fase arranca en cuanto el maletín está listo y es la última en cerrarse: el conocimiento de los agentes se enriquece de forma incremental, lo que mejora la precisión, optimiza el consumo de tokens y la redacción de informes.

## **4.5. Aplicaciones web y de terminal e informes**

La web cubre la interacción previa y posterior al análisis (guía de uso, subida de evidencias, repositorio de informes con previsualización y exportación PDF, y vista de timeline). La terminal conduce el análisis por prompts y dispara la redacción del informe y su línea temporal. El informe se genera a partir de los hallazgos recopilados por el agente más una línea temporal derivada de plaso/psort.

## **4.6. Stack tecnológico propuesto**

| Capa | Tecnologías propuestas |
| :---- | :---- |
| Backend / API | Python 3.12, FastAPI, Pydantic, Uvicorn |
| Orquestación de IA | Conectores a proveedores (Anthropic/OpenAI) \+ Ollama local bajo interfaz común; tool-calling; framework ligero de agentes; MCP como extra |
| Conocimiento / RAG | Embeddings \+ almacén vectorial (p. ej. Chroma o FAISS) |
| Frontend | React \+ Vite \+ Tailwind; visualización de timeline (vis-timeline o similar) |
| Informes / PDF | Plantillas (Jinja2) → exportación a PDF (WeasyPrint o equivalente) |
| Almacenamiento | Sistema de ficheros \+ SQLite (metadatos de proyectos e índice de informes) |
| Maletín forense | TSK, Volatility 3, plaso, bulk\_extractor, RegRipper, hayabusa/chainsaw, ewf-tools… |
| Despliegue | Docker \+ Docker Compose (versiones fijadas) |
| Control de versiones | Git \+ GitHub/GitLab (issues, project board, PRs, CI) |

# **5\. Estrategia de datos de prueba**

Como el equipo no dispone de imágenes suficientes, se trabajará en dos frentes desde la primera semana: descargar datasets públicos bien documentados y construir máquinas virtuales propias con actividad guionizada que aporten «ground truth» (verdad conocida) para validar objetivamente los hallazgos de los agentes.

| Fuente | Qué aporta | Uso |
| :---- | :---- | :---- |
| CFReDS (NIST) | Conjuntos de referencia documentados para validar herramientas | Validación / pruebas |
| Digital Corpora | Escenarios completos (p. ej. M57-Patents, M57-Jean) con imágenes de disco | Desarrollo y demos |
| Forensic Focus — challenges | Imágenes y retos de la comunidad | Escenarios extra |
| VMs propias | Windows 10 (eval) y Linux con actividad guionizada → exportar .vmdk y adquirir .raw | Ground truth y demos controladas |

# **6\. Organización del equipo**

Propuesta de seis roles alineados con los módulos del sistema; la asignación de nombres es orientativa y la ajustáis según preferencias y habilidades. La memoria y las pruebas son responsabilidades transversales: cada persona documenta su módulo y participa en el testeo.

| Rol / módulo | Responsabilidades |  |
| :---- | :---- | :---- |
| DevOps / Integración | Docker Compose, repositorio y CI, integración entre módulos, compilación de la memoria | Daniel |
| Maletín \+ Agen te Windows | Selección y contenedorización de herramientas Windows; prompts y RAG del agente Windows |  |
| Maletín \+ Agente Unix-like | Ídem para Unix-like; artefactos de logs y journald | Enrique |
| Orquestación IA / capa de modelos | Interfaz común local/cloud, tool-calling, pipeline RAG, optimización de tokens, generación de informes | Luis |
| Frontend | Frontend, subida de evidencias, repositorio de informes, timeline, export PDF | SantIAgo |
| Aplicación terminal \+ Datos/QA | Menú CLI, lanzador de sesión, \[proceed-to-report\]/\[back-to-analysis\], datasets y escenarios de prueba |  |

## **6.1. Metodología de trabajo**

* Repositorio Git con ramas por funcionalidad, pull requests y revisión cruzada; tablero de tareas (issues/Kanban).

* Sprints semanales con una reunión de planificación y una de revisión; integración continua para evitar choques de última hora.

* Integración temprana: un flujo extremo-a-extremo mínimo en la semana 4, mejorado de forma incremental.

# **7\. Cronograma (20 jun → 7 sep)**

Plan semana a semana alineado con las cinco fases de la propuesta y con tres líneas transversales (DevOps, memoria y datos de prueba). Las pruebas (Fase 5\) comienzan antes de tener la versión final, tal y como indica la propuesta.

| Sem. | Fechas | Foco principal | Hitos / entregables |
| :---- | :---- | :---- | :---- |
| 0 | 20–21 jun | Kickoff: aterrizar alcance (este documento), confirmar requisitos del tutor, crear repo y tablero, asignar roles y preparar entornos. | Repo y tablero creados; roles asignados; rúbrica y fecha de defensa confirmadas. |
| 1 | 22–28 jun | Fundaciones: esqueleto de monorepo y Docker Compose. Fase 1: inventario de herramientas (CLI-first). Elegir dataset público y planificar VMs. Memoria: índice \+ estado del arte. | Esqueleto desplegable; lista de herramientas v0; dataset elegido. |
| 2 | 29 jun–5 jul | Fase 1: contenedorizar herramientas núcleo; montaje en solo lectura de .vmdk/.raw \+ hashing. Definir contrato de wrappers CLI→JSON. Andamiaje de web, terminal y API. | Maletín v1 contenedorizado; evidencias montables con integridad. |
| 3 | 6–12 jul | Cierre del maletín (catálogo documentado). Fase 2 arranca: capa de modelos local/cloud con interfaz común; prompts base \+ RAG. Web: crear proyecto y subir evidencias. Terminal: menú y lanzador. | Catálogo del maletín; capa de modelos operativa; subida de evidencias. |
| 4 | 13–19 jul | Primer flujo extremo-a-extremo (vertical slice) con un agente sobre una imagen pequeña: prompt→herramienta→hallazgo. Fase 5: primeros escenarios. Informe básico con \[proceed-to-report\]. | Demo E2E mínima funcionando; informe básico generado. |
| 5 | 20–26 jul | Agente Windows a la par del Unix-like; ampliar herramientas y prompts. Timeline con plaso/psort → web. Web: repositorio de informes (preview \+ export PDF). | Dos agentes operativos; timeline visible; export PDF. |
| 6 | 27 jul–2 ago | Consolidación (objetivo MVP feature-complete). Flujo completo análisis→informe→revisión→\[back-to-analysis\]. Optimización de tokens y redacción. Memoria: diseño e implementación. | MVP funcional completo; flujo cerrado. |
| 7 | 3–9 ago | Hardening. Fase 5 intensiva: batería de escenarios y casos límite; validación contra ground truth de las VMs. Robustez del despliegue. | Suite de pruebas; despliegue limpio reproducible. |
| 8 | 10–16 ago | Pulido de UI, guía de usuario y especificaciones técnicas (catálogo de soluciones). Extras opcionales (MCPs / fine-tuning) solo si el MVP es estable. Memoria: resultados. | Guía de usuario; UI presentable; extras (si procede). |
| 9 | 17–23 ago | Congelación de funcionalidades (feature freeze): solo correcciones. Pruebas de despliegue desde cero en máquinas limpias. Memoria: borrador completo. | Feature freeze; borrador de memoria para revisión. |
| 10 | 24–30 ago | Validación final E2E con datasets públicos y propios. Cierre de la memoria (revisión cruzada, formato, bibliografía). Preparar defensa (guion de demo, slides). | Memoria casi final; materiales de defensa. |
| 11 | 31 ago–6 sep | Buffer y cierre. Revisión final de memoria y repo (README, licencia, versión etiquetada). Ensayo de defensa y demo de respaldo grabada. | Todo listo para entregar. |

  **7 de septiembre de 2026 — ENTREGA del TFM (memoria \+ herramienta).**

# **8\. Hitos clave**

| Fecha | Hito |
| :---- | :---- |
| 28 jun | Fin de fundaciones: repo, Docker y herramientas v0. |
| 12 jul | Maletín forense v1 \+ capa de modelos operativa. |
| 19 jul | Primera demo extremo-a-extremo (vertical slice). |
| 2 ago | MVP funcional completo (feature-complete). |
| 9 ago | Suite de pruebas y despliegue reproducible. |
| 23 ago | Feature freeze \+ borrador completo de memoria. |
| 30 ago | Validación final y memoria casi cerrada. |
| 6 sep | Cierre total (repo \+ memoria \+ ensayo de defensa). |
| 7 sep | Entrega del TFM. |

# **9\. Riesgos y mitigaciones**

| Riesgo | Mitigación |
| :---- | :---- |
| Alcance ambicioso para el plazo | MVP estricto; extras opcionales; feature freeze en la semana 9\. |
| Datos de prueba insuficientes | Datasets públicos \+ VMs propias desde la semana 1, con ground truth. |
| Privacidad / cadena de custodia con cloud | Modelos locales por defecto; avisos al usar cloud; trabajo sobre copias en solo lectura \+ hashing. |
| Coste de tokens en cloud | Presupuesto, prompts eficientes, caché y preferencia por modelos locales. |
| Integración tardía entre módulos | Vertical slice E2E en la semana 4 e integración continua. |
| Dependencia de herramientas externas | Contenedorizar versiones fijadas; documentar en el catálogo. |
| Fine-tuning consume demasiado tiempo | Tratarlo como extra; solo si el MVP es estable. |
| Vacaciones / disponibilidad variable | Tablero claro, buffer en la semana 11 y reparto que evita cuellos de botella. |

# **10\. Próximos pasos inmediatos (esta semana)**

1. Confirmar la propuesta con los tutores.

2. Crear el repositorio, el tablero de tareas y un canal de comunicación del equipo.

3. Asignar los seis roles de la sección 6\.

4. Descargar un dataset público (Digital Corpora / CFReDS) y empezar a montar una VM propia.

5. Levantar el esqueleto de Docker Compose y la estructura del monorepo.

# **11\. Preguntas abiertas y dependencias**

Puntos a cerrar para afinar el plan; ninguno bloquea el arranque, pero conviene resolverlos pronto:

* Tutor: rúbrica y criterios de evaluación, formato y longitud esperada de la memoria, y fecha exacta de la defensa.

* Hardware disponible para modelos locales (GPU/RAM), que condiciona qué modelos open source son viables.

* Habilidades individuales del equipo, para confirmar la asignación de roles.

* Modelos cloud concretos y presupuesto de API, si se usan.

* Repositorio: GitHub o GitLab, y política de privacidad del repo.

* Confirmar que solo se usarán datos sintéticos/públicos (sin datos personales reales).

# **12\. Referencias**

The Sleuth Kit: [https://www.sleuthkit.org/](https://www.sleuthkit.org/)

Volatility 3: [https://github.com/volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3)

plaso / log2timeline: [https://github.com/log2timeline/plaso](https://github.com/log2timeline/plaso)

bulk\_extractor: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

Hayabusa (análisis de EVTX): [https://github.com/Yamato-Security/hayabusa](https://github.com/Yamato-Security/hayabusa)

Chainsaw (EVTX / Sigma): [https://github.com/WithSecureLabs/chainsaw](https://github.com/WithSecureLabs/chainsaw)

RegRipper: [https://github.com/keydet89/RegRipper3.0](https://github.com/keydet89/RegRipper3.0)

NIST CFReDS: [https://cfreds.nist.gov/](https://cfreds.nist.gov/)

Digital Corpora — Disk Images: [https://digitalcorpora.org/corpora/disk-images/](https://digitalcorpora.org/corpora/disk-images/)

Forensic Focus — Challenges & Images: [https://www.forensicfocus.com/challenges-and-images/](https://www.forensicfocus.com/challenges-and-images/)

Model Context Protocol (MCP): [https://modelcontextprotocol.io/](https://modelcontextprotocol.io/)

Ollama: [https://ollama.com/](https://ollama.com/)