// Catálogo CASTELLANO. El tipo `Record<MessageKey, string>` lo obliga a traer
// todas las claves de `en.ts` y el chequeo de propiedades sobrantes de
// TypeScript impide que traiga alguna que allí no exista, así que los dos
// catálogos no pueden divergir sin que `npm run typecheck` lo diga.
//
// Este es el texto que la aplicación ya tenía: aquí no se «traduce del inglés»,
// se conserva el castellano original, que es el que estaba escrito con cuidado.

import type { MessageKey } from "./en";

export const es: Record<MessageKey, string> = {
  "lang.en": "English",
  "lang.es": "Español",

  "settings.tab.executors": "Motor de análisis",
  "settings.tab.system": "Sistema y maletín",
  "settings.tab.appearance": "Apariencia",
  "settings.appearance.palette": "Paleta",
  "settings.appearance.paletteGroup": "Paleta de la interfaz",
  "settings.appearance.mode": "Modo",
  "settings.appearance.modeGroup": "Modo de la interfaz",
  "settings.appearance.light": "Claro",
  "settings.appearance.dark": "Oscuro",
  "settings.appearance.hint":
    "Paleta y modo se guardan en este navegador y se aplican a toda la aplicación.",

  "settings.language.title": "Idioma",
  "settings.language.group": "Idioma de la interfaz",
  "settings.language.hint":
    "Se guarda en este navegador. Se aplica a la interfaz, a los mensajes que devuelve el api y al informe pericial que se redacte a partir de ahora. Un informe ya firmado conserva el idioma con el que se firmó.",

  "palette.papel.name": "Papel",
  "palette.papel.desc": "Crema cálido y terracota. Expediente, archivo, papel.",
  "palette.acero.name": "Acero",
  "palette.acero.desc": "Gris frío y azul de instrumento. Sobria, de laboratorio.",

  // --- navegación y armazón ------------------------------------------------
  "nav.repository": "Evidencia",
  "nav.investigation": "Investigación",
  "nav.mitre": "Correlación ATT&CK",
  "nav.timeline": "Timeline",
  "nav.findings": "Hallazgos",
  "nav.graphs": "Grafos",
  "nav.report": "Informe pericial",
  "nav.settings": "Configuración",
  "nav.guide": "Guía",
  "shell.phaseOf": "Fase {n} de {total}",

  // --- barra lateral: caso y escalera de fases -----------------------------
  "sidebar.phases": "Fases del caso",
  "sidebar.newCase": "crear caso",
  "sidebar.pickCase": "Elige un caso",
  "sidebar.changeCase": "{name} · cambiar de caso",
  "case.status.active": "abierto",
  "case.status.closed": "cerrado",

  // --- cantidades del caso (plurales) --------------------------------------
  "count.files.one": "{count} fichero",
  "count.files.other": "{count} ficheros",
  "count.findings.one": "{count} hallazgo",
  "count.findings.other": "{count} hallazgos",
  "count.techniques.one": "{count} técnica",
  "count.techniques.other": "{count} técnicas",
  "count.events.one": "{count} evento",
  "count.events.other": "{count} eventos",
  "count.documents.one": "{count} documento",
  "count.documents.other": "{count} documentos",

  // --- metadatos de cada fase en la escalera -------------------------------
  "phase.evidence.none": "sin evidencia",
  "phase.evidence.verified": "{count} verificados",
  "phase.findings.none": "sin hallazgos",
  "phase.mitre.toCorrelate": "hallazgos por correlacionar",
  "phase.mitre.noVerdict": "sin dictaminar",
  "phase.mitre.withVerdict": "{count} con dictamen",
  "phase.timeline.noEvents": "sin eventos en el eje",
  "phase.timeline.allUndated": "{count} sin fecha situable",
  "phase.timeline.undated": "{count} sin fecha",
  "phase.graphs.none": "sin grafos",
  "phase.graphs.some": "{done} de {total} con grafo",
  "phase.documents.none": "sin documentos",

  // --- comunes -------------------------------------------------------------
  "common.na": "n/d",
  "common.retry": "Reintentar",
  "common.cancel": "Cancelar",
  "common.close": "Cerrar",
  "common.save": "Guardar",
  "common.delete": "Borrar",
  "common.loading": "Cargando",
  "common.noCase": "sin caso seleccionado",

  // --- naturaleza de la evidencia (detected_kind del triage) ---------------
  "kind.disk": "Imagen de disco",
  "kind.memory": "Volcado de memoria",
  "kind.container_disk": "Disco VM",
  "kind.document": "Fichero aportado",
  "kind.unknown": "Desconocido",

  // --- piezas de interfaz compartidas --------------------------------------
  "ui.connectionError": "Error de conexión:",
  "ui.loading": "Cargando…",
  "ui.prevPage": "Página anterior",
  "ui.nextPage": "Página siguiente",

  // --- tabla de evidencias -------------------------------------------------
  "evidenceTable.col.file": "Fichero",
  "evidenceTable.col.kind": "Tipo",
  "evidenceTable.col.size": "Tamaño",
  "evidenceTable.col.hash": "SHA-256",
  "evidenceTable.col.integrity": "Integridad",
  "evidenceTable.search": "Buscar por nombre de fichero…",
  "evidenceTable.noMatch": "Ningún fichero coincide con «{query}».",
  "evidenceTable.copyHash": "Clic para copiar el SHA-256 completo",
  "evidenceTable.copyHashLabel": "Copiar el SHA-256 completo",
  "evidenceTable.verifying": "verificando…",
  "evidenceTable.unverified": "sin verificar",
  "evidenceTable.verified": "verificada",
  "evidenceTable.mismatch": "hash mismatch",
  "evidenceTable.verifyingBtn": "Verificando…",
  "evidenceTable.reverify": "Re-verificar",
  "evidenceTable.verifyNow": "Verificar ahora",
  "evidenceTable.firstSegment": "{size} el primer segmento",
  "count.segments.one": "{count} segmento",
  "count.segments.other": "{count} segmentos",

  // --- alta de caso --------------------------------------------------------
  "newCase.eyebrow": "Fase 1 · antes de tocar evidencia",
  "newCase.title": "Abrir caso nuevo",
  "newCase.enterToSave": "enter para guardar",
  "newCase.saving": "Guardando…",
  "newCase.save": "Guardar caso",
  "newCase.name": "Nombre del caso",
  "newCase.namePlaceholder": "Nombre o referencia del caso",
  "newCase.examiner": "Examinador",
  "newCase.examinerPlaceholder": "Nombre completo",
  "newCase.examinerHint":
    "Responsable del caso. Figura en el acta de adquisición y en el informe pericial.",
  "newCase.notes": "Descripción · notas",
  "newCase.optional": "opcional",
  "newCase.notesPlaceholder": "Descripción breve del caso",
  "newCase.failed": "No se pudo crear el caso:",

  // --- buscador y gestión de casos -----------------------------------------
  "caseSearch.eyebrow.list": "Casos del servicio",
  "caseSearch.eyebrow.edit": "Caso activo",
  "caseSearch.eyebrow.delete": "Irreversible",
  "caseSearch.title.list": "Buscar casos",
  "caseSearch.title.edit": "Editar caso",
  "caseSearch.title.delete": "Eliminar caso",
  "caseSearch.hint.list": "esc cerrar · ↵ abrir",
  "caseSearch.hint.other": "esc cerrar",
  "caseSearch.label": "Buscar casos",
  "caseSearch.placeholder": "Buscar por nombre o examinador…",
  "caseSearch.filterGroup": "Filtrar casos por estado",
  "caseSearch.filter.all": "Todos",
  "caseSearch.filter.active": "Abiertos",
  "caseSearch.filter.closed": "Cerrados",
  "caseSearch.sortLabel": "Ordenar por",
  "caseSearch.sort.recent": "Más reciente",
  "caseSearch.sort.oldest": "Más antiguo",
  "caseSearch.sort.nameAsc": "Nombre A-Z",
  "caseSearch.sort.nameDesc": "Nombre Z-A",
  "caseSearch.emptyTitle": "Aún no hay casos",
  "caseSearch.emptyBody":
    "Pulsa «crear caso» en el lateral para abrir el primero. Sin caso no hay dónde registrar evidencia.",
  "caseSearch.noResults": "Sin resultados",
  "caseSearch.noMatchQuery": "Ningún caso coincide con «{query}».",
  "caseSearch.noMatchFilter": "Ningún caso coincide con el filtro.",
  "caseSearch.edit": "Editar",
  "caseSearch.close": "Cerrar",
  "caseSearch.reopen": "Reabrir",
  "caseSearch.saveChanges": "Guardar cambios",
  "caseSearch.deleting": "Eliminando…",
  "caseSearch.deleteForever": "Eliminar permanentemente",
  "caseSearch.actionFailed": "No se pudo completar la acción:",
  "caseSearch.saveFailed": "No se pudo guardar:",
  "caseSearch.deleteFailed": "No se pudo eliminar el caso:",
  "caseSearch.osNotEditable":
    "El perfil de sistema operativo no se edita aquí: lo deriva el orquestador del contenido de la evidencia registrada.",
  "caseSearch.dangerLead": "Esta acción es irreversible.",
  "caseSearch.dangerBody":
    "Se borrará de forma PERMANENTE todo el caso «{name}» y con él su cadena de custodia completa: las copias de evidencia registradas, el log de auditoría hash-encadenado, los hallazgos, los artefactos, los chats y los informes. No hay papelera ni deshacer.",
  "caseSearch.typeToConfirm": "Escribe «{name}» para confirmar",
  "count.cases.one": "{count} caso",
  "count.cases.other": "{count} casos",

  // --- bandeja de evidencias -----------------------------------------------
  "inbox.materialFormats":
    "documentos (pdf, word, hojas de cálculo, presentaciones, texto, logs), correo, imagen y audiovisual, archivos comprimidos, capturas de red, artefactos sueltos de Windows y muestras",
  "inbox.ewfHint":
    "Si la imagen es un EWF partido (.E01, .E02, …), suelta o selecciona TODOS sus segmentos: se registran desde el .E01 como una sola evidencia.",
  "inbox.caseClosed": "Este caso está cerrado",
  "inbox.caseClosedBody":
    "Reábrelo desde «cambiar caso» en el lateral para registrar más evidencia.",
  "inbox.droppedFolder":
    "Has soltado una carpeta. Suelta los FICHEROS de imagen forense, no el directorio que los contiene.",
  "inbox.noFiles": "No se ha recibido ningún fichero. Vuelve a intentarlo o usa «Examinar…».",
  "inbox.foldersIgnored":
    "Se han ignorado las carpetas del arrastre: suelta los ficheros de imagen forense directamente.",
  "inbox.rejected":
    "La bandeja no reconoce la extensión de {names}. Acepta imágenes y volcados ({images}), los segmentos de un EWF partido, ficheros sin extensión, y material aportado: {material}. Si aun así aporta al caso, cópialo a la carpeta ./evidence del repositorio: la bandeja lista todo lo que hay ahí y desde ahí se registra igual.",
  "inbox.dropTitle": "Arrastra aquí la evidencia del caso",
  "inbox.dropBody":
    "Agentopsy calcula el SHA-256 baseline y la deja en solo lectura antes de que ninguna herramienta la toque, sea una imagen de un sistema entero o un fichero que te han entregado.",
  "inbox.browse": "Examinar…",
  "inbox.searching": "Buscando…",
  "inbox.browseInbox": "Examinar bandeja",
  "inbox.imagesLabel": "Imágenes y volcados:",
  "inbox.materialLabel": "Material aportado:",
  "inbox.uploading": "Subiendo evidencia a la bandeja…",
  "inbox.noExtension": "sin extensión",
  "inbox.ewfContinuation": "segmento EWF · se registra desde el .E01",
  "inbox.selected": "seleccionada",
  "inbox.registering": "Registrando…",
  "inbox.registerNamed": "Registrar {name}",
  "inbox.register": "Registrar evidencia",
  "inbox.refresh": "Actualizar bandeja",
  "inbox.emptyBefore":
    "La bandeja está vacía. Arrastra la imagen forense arriba para subirla, o cópiala a",
  "inbox.emptyAfter": "en el host.",

  // --- conexión de un ejecutor cloud ---------------------------------------
  "execLogin.title": "Conectar {name}",
  "execLogin.starting": "Iniciando el login de {name}…",
  "execLogin.incomplete": "El login terminó sin completarse.",
  "execLogin.noSession": "Aún no hay sesión iniciada.",
  "execLogin.failed": "No se pudo completar el login.",
  "execLogin.notFromWebLead": "El login de {name} no puede completarse desde la web.",
  "execLogin.runCommand": "Ejecuta este comando en una terminal",
  "execLogin.copy": "Copiar",
  "execLogin.checking": "Comprobando…",
  "execLogin.check": "Comprobar",
  "execLogin.step1": "1 · Abre esta URL en tu navegador",
  "execLogin.step2code": "2 · Introduce este código EN EL NAVEGADOR",
  "execLogin.codeExpiry": "El código caduca en ~15 min. No lo compartas con nadie.",
  "execLogin.pasteStep": "{n} · Pega aquí el código que te da el navegador",
  "execLogin.codePlaceholder": "Código de la página de autorización",
  "execLogin.sending": "Enviando…",
  "execLogin.sendCode": "Enviar código",
  "execLogin.waiting": "Esperando a que completes el acceso en el navegador…",
  "execLogin.connectedBefore": "{name} conectado. La sesión persiste en el volumen",

  // --- registro de evidencia en segundo plano ------------------------------
  "register.stalled":
    "Sin contacto con el api mientras se sondeaba el registro ({seconds} s). El hash-gate corre en el servidor y sigue su curso; esto se reintenta solo.",
  "register.gaveUp":
    "No se ha podido contactar con el api en {seconds} s, así que se deja de sondear. El registro puede seguir corriendo en el servidor: comprueba el servicio (docker compose ps api) y vuelve a esta vista, que retoma el registro que siga vivo. Último fallo: {detail}",
  "register.jobLost":
    "El api ya no conoce este registro: se reinició mientras corría. El registro es atómico, así que no ha quedado nada a medias. Si la evidencia no aparece en la lista, vuelve a registrarla.",
  "register.errorNoDetail": "el registro terminó en error sin detalle",

  // --- fase 1: evidencia ---------------------------------------------------
  "evidence.kind.disk": "imagen de disco",
  "evidence.kind.container_disk": "imagen contenedor",
  "evidence.kind.memory": "volcado de memoria",
  "evidence.kind.document": "fichero aportado",
  "evidence.kind.unknown": "formato no identificado",
  "evidence.registeredPlain": "Evidencia registrada",
  "evidence.registeredSize": "Evidencia registrada: {size}",
  "evidence.registeredSet": "Evidencia registrada: {segments} segmentos, {size} en total",
  "evidence.uploadedOne": "{count} fichero subido a la bandeja",
  "evidence.uploadedMany": "{count} ficheros subidos a la bandeja",
  "evidence.alreadyOne":
    "{count} ya estaba en la bandeja ({names}); no se sobrescribe evidencia",
  "evidence.alreadyMany":
    "{count} ya estaban en la bandeja ({names}); no se sobrescribe evidencia",
  "evidence.goToInvestigation": "Pasar a Investigación",
  "evidence.needEvidenceFirst":
    "Registra primero una evidencia: el agente solo trabaja sobre un handle hash-verificado",
  "evidence.loadingCases": "Cargando casos…",
  "evidence.casesFailed": "no se pudo listar los casos",
  "evidence.noActiveCase": "Sin caso activo",
  "evidence.noActiveCaseBody":
    "Abre uno con «crear caso» o elige otro con «cambiar caso», en el lateral. La evidencia se registra siempre dentro de un caso: es lo que ancla la cadena de custodia.",
  "evidence.statRegistered": "Registradas",
  "evidence.statVerified": "Hash verificado",
  "evidence.statPending": "Pendientes",
  "evidence.statExaminer": "Examinador",
  "evidence.addSection": "Añadir evidencia",
  "evidence.inboxFailed": "No se pudo leer la bandeja: {detail}",
  "evidence.listSection": "Evidencias del caso",
  "evidence.listFailed": "No se pudo listar la evidencia del caso: {detail}",
  "evidence.verifyFailed": "No se pudo verificar la evidencia: {detail}",
  "evidence.kSize": "tamaño",
  "evidence.kIntegrity": "integridad",
  "evidence.kOs": "sistema operativo",
  "evidence.inSegments": "en {count} segmentos",
  "evidence.notReverified": "sin re-verificar",
  "evidence.reverified": "hash re-verificado",
  "evidence.osNotApplicable": "no aplica",
  "evidence.osNotApplicableNote":
    "un fichero aportado es material sobre el sistema investigado, no el sistema; aquí el perfil elige el maletín, no el SO",
  "evidence.osUndetermined": "sin determinar",
  "evidence.osRedetectTitle": "Volver a abrir la imagen y determinar su sistema operativo",
  "evidence.osDetermining": "Determinando…",
  "evidence.osFromContent": "determinado del contenido de la imagen, no del equipo anfitrión",
  "evidence.acquisitionRecord": "Acta de adquisición",
  "evidence.anchorOnlyMaterial":
    "Este caso sólo tiene ficheros aportados, y un fichero no es el sistema investigado: no hay sistema operativo que determinarle. Aun así el agente necesita un perfil, porque es lo que elige el maletín donde corren las herramientas. Las que leen un fichero suelto (file, strings, bulk_extractor, yara, hashdeep) están en los dos, así que para material aportado cualquiera de los dos sirve; elige el del sistema del que proceda el material si lo sabes:",
  "evidence.anchorUndetermined":
    "La determinación automática no ha podido cerrar el sistema operativo de este caso, o la imagen contiene señales de más de un SO, o el maletín que la abre no está disponible. El agente no se enruta hasta que haya un perfil, así que puedes anclarlo tú:",
  "evidence.anchoring": "Anclando…",
  "evidence.anchorFinal": "El anclaje es final y queda en el log de auditoría del caso.",
  "evidence.custodyEyebrow": "Cadena de custodia",
  "evidence.escToClose": "esc para cerrar",
  "evidence.downloadRecord": "Descargar acta (JSON)",
  "evidence.generatingRecord": "Generando acta…",
  "acta.case": "Caso",
  "acta.source": "Origen",
  "acta.baselineHash": "SHA-256 (baseline)",
  "acta.baselineNote": "cubre el primer segmento; cada uno tiene el suyo, abajo",
  "acta.size": "Tamaño",
  "acta.sizeNote":
    "{count} segmentos ingeridos como una sola evidencia; el primero pesa {size}",
  "acta.segments": "Segmentos ({count})",
  "acta.registered": "Registrada",
  "acta.readOnlyLevel": "Nivel de solo-lectura",
  "acta.chainVerified": "cadena verificada",
  "acta.chainNotVerified": "la cadena NO verifica",
  "acta.verification": "Verificación",
  "acta.verifiedAt": "Verificada {date}",
  "acta.hashMismatch": "Hash MISMATCH",
  "acta.unverified": "Sin verificar",
  "acta.tool": "Herramienta",
  "acta.bytes": "bytes",

  // --- severidad y naturaleza de un hallazgo -------------------------------
  "severity.low": "baja",
  "severity.medium": "media",
  "severity.high": "alta",
  "severity.critical": "crítica",
  "severity.all": "Todas",
  "findingKind.descarte": "descarte",
  "findingKind.afirmacion": "afirmación",

  // --- fase 5: hallazgos ---------------------------------------------------
  "findings.loadCaseFailed": "No se pudo cargar el caso activo:",
  "findings.noCase": "Sin caso abierto",
  "findings.noCaseBody":
    "Abre un caso en el lateral. Los hallazgos aparecen aquí a medida que el agente los registra durante la investigación.",
  "findings.goToEvidence": "Ir a Evidencia",
  "findings.goToReport": "Ir al informe pericial",
  "findings.nothingToReport": "Todavía no hay hallazgos que informar",
  "findings.section": "Hallazgos del caso",
  "findings.searchLabel": "Buscar hallazgo",
  "findings.searchPlaceholder": "Buscar por título, herramienta o técnica…",
  "findings.loading": "Cargando hallazgos…",
  "findings.empty":
    "Aún no hay hallazgos. El agente los registra en caliente durante la Investigación; en cuanto concluya algo (aunque sea un descarte), aparecerá aquí como tarjeta.",
  "findings.noMatch": "Ningún hallazgo coincide con la búsqueda o el filtro.",
  "findings.noneOpen": "Ningún hallazgo abierto",
  "findings.noneOpenBody":
    "Elige un hallazgo de la lista para leerlo completo, con su procedencia y su correlación ATT&CK.",
  "finding.severity": "Severidad",
  "finding.kind": "Tipo",
  "finding.tool": "Herramienta",
  "finding.run": "Run que lo sostiene",
  "finding.evidence": "Evidencia",
  "finding.observedAt": "Observado en la evidencia",
  "finding.recordedAt": "Registrado",
  "finding.confidence": "Confianza",
  "finding.artifactHash": "SHA-256 del artefacto",
  "finding.recordedOn": "registrado {date}",
  "finding.provenance": "Procedencia y custodia",
  "finding.attackCorrelation": "Correlación ATT&CK",
  "finding.noTechniques":
    "El agente no asoció ninguna técnica a este hallazgo. Puede anclarlas desde el chat («dame la correlación MITRE») o el perito adjudicarlas en la fase ATT&CK.",

  // --- guía de uso ---------------------------------------------------------
  "guide.title": "Guía de uso",
  "guide.state.done": "Hecho",
  "guide.state.now": "En curso",
  "guide.state.todo": "Pendiente",
  "guide.goToEvidence": "Ir a Evidencia",
  "guide.start": "Empezar: crear caso",
  "guide.workflow": "Flujo de trabajo",
  "guide.reflectsCase": "refleja el caso activo",
  "guide.noActiveCase": "sin caso activo",
  "guide.step1.title": "Crear caso / repositorio",
  "guide.step1.desc":
    "Registra un nuevo caso y define el examinador responsable antes de tocar evidencia.",
  "guide.step2.title": "Registrar evidencia",
  "guide.step2.desc":
    "Sube la imagen, el volcado o los ficheros que te hayan entregado; Agentopsy calcula el hash baseline y los deja en solo lectura.",
  "guide.step3.title": "Investigar con el agente",
  "guide.step3.desc":
    "Conversa con el agente, que ejecuta el maletín de herramientas forenses sobre la evidencia verificada.",
  "guide.step4.title": "Correlacionar con ATT&CK",
  "guide.step4.desc":
    "Vincula los hallazgos con tácticas y técnicas conocidas para dar contexto al informe final.",
  "guide.step5.title": "Revisar el timeline",
  "guide.step5.desc":
    "La capa de entrada, Hallazgos, es la línea de tiempo del incidente: qué pasó en el dispositivo investigado, un evento por hallazgo con la marca temporal del artefacto, y se exporta como imagen PNG para adjuntarla. Las otras tres reconstruyen la actividad de la investigación y del sistema de ficheros, y se leen como lista y se exportan como hoja de cálculo.",
  "guide.step6.title": "Extraer los grafos de relaciones",
  "guide.step6.desc":
    "El grafo responde a qué se conecta con qué: el modelo que elijas lee el texto de cada hallazgo y propone qué cuentas, ficheros, equipos, dominios e IP intervienen, y el grafo del caso los funde por entidad para enseñar lo que ata unos hallazgos con otros. Es una propuesta del modelo, no un hecho verificado, y así se etiqueta; la figura se exporta como PNG para adjuntarla al informe.",
  "guide.step7.title": "Finalizar la investigación y firmar el informe",
  "guide.step7.desc":
    "Pulsa «Finalizar investigación» y el modelo seleccionado redactará el informe pericial completo desde los hallazgos y las evidencias del caso. Verifica su integridad y fírmalo como versión final.",
  "guide.loginSection": "Iniciar sesión en un ejecutor",
  "guide.loginProseA": "Agentopsy no usa API keys.",
  "guide.loginProseB":
    "funciona sin nada más. Para un ejecutor cloud necesitas tu propia sesión: en el primer arranque el stack intenta reutilizar la del host y, si no la hay, inicias sesión una única vez dentro del contenedor. La sesión persiste en el volumen",
  "guide.loginNoteA": "Comprueba el estado en",
  "guide.loginNoteB": "Para revocar la sesión:",
  "guide.settingsPath": "Configuración → Motor de análisis",
  "guide.cmd.codex": "Codex CLI · device-code",
  "guide.cmd.gemini": "Gemini CLI · URL + código",
  "guide.notesSection": "Lo que debes saber",
  "guide.note1.title": "Ejecutor cloud y privacidad (RGPD)",
  "guide.note1.body":
    "Al elegir un ejecutor cloud los prompts incluyen contenido derivado de la evidencia (posibles datos personales reales) y sale a ese proveedor bajo tu propia suscripción. La alternativa 100 % local es Ollama, que nunca envía nada fuera del equipo.",
  "guide.note2.title": "Principios forenses",
  "guide.note2.body":
    "La evidencia nunca se toca directamente: todo acceso pasa por un handle hash-verificado y de solo lectura a nivel de bloque. Cada acción queda en un log de auditoría encadenado por hash.",
  "guide.note3.title": "Alcance de la herramienta",
  "guide.note3.body":
    "Agentopsy es post-mortem y autoalojada: no realiza forensia en vivo ni adquisición desde el equipo original. Sin validez legal certificada, pero con rigor forense real.",

  // --- fase 2: investigación -----------------------------------------------
  "inv.loadingContext": "Cargando contexto del caso…",
  "inv.goToAttack": "Pasar a ATT&CK",
  "inv.nothingToCorrelate": "Todavía no hay hallazgos que correlacionar",
  "inv.noCaseBody":
    "Abre uno con «crear caso» en el lateral y regístrale evidencia antes de investigar: el agente solo trabaja sobre un handle hash-verificado.",
  "inv.mismatchLead":
    "Desajuste de perfil: el agente activo no es el adecuado para alguna evidencia del caso.",
  "inv.mismatchBodyA": "El caso declara",
  "inv.mismatchBodyB": "pero la determinación sobre el contenido dice",
  "inv.mismatchBodyC": "El agente del caso",
  "inv.mismatchBodyD":
    "se negará a invocar herramientas sobre las evidencias en desacuerdo mientras dure. Resuélvelo en",
  "inv.mismatchPath": "Evidencia → Sistema operativo",
  "inv.mismatchBodyE":
    "al anclar el perfil, Agentopsy re-enruta solo al sub-agente que corresponde. No lo cambia por ti (RULE 2, un desacuerdo lo decide el operador, no el programa).",
  "inv.collapsePanel": "Plegar el panel de contexto",
  "inv.expandPanel": "Desplegar el panel de contexto",
  "inv.evidence": "Evidencia",
  "inv.evidences": "Evidencias",
  "inv.scopeNote":
    "El agente las analiza todas por igual. Para centrarte en una, pídelo en tu mensaje.",
  "inv.verified": "verificada",
  "inv.noneRegistered": "ninguna registrada",
  "inv.noFindings": "Sin hallazgos.",
  "inv.tools": "Herramientas",
  "inv.noneRun": "Ninguna ejecutada.",
  "count.failures.one": "{count} fallo",
  "count.failures.other": "{count} fallos",

  // --- fase 6: grafos de relaciones ----------------------------------------
  "graphs.title": "Grafos de relaciones",
  "graphs.meta": "{done} de {total} hallazgos con grafo",
  "graphs.loading": "Cargando los grafos del caso…",
  "graphs.loadFailed": "No se pudieron cargar los grafos:",
  "graphs.noCaseBody":
    "El grafo se extrae del texto de los hallazgos de un caso. Abre uno desde el lateral.",
  "graphs.extractingModel": "Modelo que extrae",

  // --- selección de ejecutor -----------------------------------------------
  "executor.pick": "Elige un ejecutor…",
  "executor.unavailable": "{name} (no disponible)",
  "executor.local": "local",
  "executor.notAvailable": "{name} no está disponible.",

  // --- vocabulario del grafo: nodos ----------------------------------------
  "graphNode.ip": "Dirección IP",
  "graphNode.domain": "Dominio",
  "graphNode.hostname": "Equipo",
  "graphNode.user": "Usuario",
  "graphNode.file": "Fichero",

  // --- vocabulario del grafo: relaciones -----------------------------------
  "graphEdge.connection": "Conexión",
  "graphEdge.process_spawn": "Creación de proceso",
  "graphEdge.network_connection": "Conexión de red",
  "graphEdge.lateral_move": "Movimiento lateral",
  "graphEdge.malware": "Código malicioso",
  "graphEdge.c2": "Mando y control",
  "graphEdge.exfiltration": "Exfiltración",
  "graphEdge.beacon": "Baliza",
  "graphEdge.persistence": "Persistencia",
  "graphEdge.priv_esc": "Escalada de privilegios",
  "graphEdge.rce": "Ejecución remota de código",
  "graphEdge.logon": "Inicio de sesión",
  "graphEdge.file_transfer": "Transferencia de ficheros",

  // --- figura del grafo ----------------------------------------------------
  "graph.figure": "Figura",
  "graph.selectLabel": "Figura",
  "graph.caseOption": "Grafo del caso (todos los hallazgos, fundidos)",
  "graph.optionCounts": "{nodes} nodos, {edges} aristas",
  "graph.optionNoGraph": "sin grafo",
  "graph.extracting": "Extrayendo…",
  "graph.extractMissing": "Extraer los {count} que faltan",
  "graph.reextractThis": "Volver a extraer este",
  "graph.extractThis": "Extraer este hallazgo",
  "graph.exportPng": "Exportar PNG",
  // FUNCIÓN «INVENTARIO» (grafos, en prueba 2026-09-04)
  "graph.inventoryBand":
    "{count} entidades que los hallazgos nombran sin afirmar ninguna relación entre ellas",
  "graph.inventoryTitle": "Entidades sin relación",
  "graph.inventoryNote":
    "Los hallazgos las nombran, pero ningún hallazgo les afirma una relación, así que no forman parte de la red. Viajan enteras dentro del PNG exportado.",
  "graph.inventoryCount": "{loose} de {total} entidades",
  // FUNCIÓN «VISTAS» (grafos, en prueba 2026-09-04)
  "graph.viewLabel": "Vista",
  "graph.viewWhole": "Caso entero",
  "graph.viewOption": "{label} ({count} hallazgos)",
  "graph.viewDeclared": "Vista: {label}. Corte sobre {count} hallazgos del caso.",
  "graph.viewEmptyNote":
    "Esta vista no cubre ningún hallazgo con grafo extraído. Elige otra o extrae los grafos que faltan.",
  "graph.viewAxis.tecnica": "Técnica ATT&CK",
  "graph.viewAxis.tactica": "Táctica ATT&CK",
  "graph.viewAxis.evidencia": "Evidencia",
  "graph.viewAxis.severidad": "Severidad",
  // FUNCIÓN «LOCALIZADOR» (grafos, en prueba 2026-09-04)
  "graph.searchLabel": "Localizar una entidad",
  "graph.searchPlaceholder": "IP, cuenta, fichero, dominio",
  "graph.searchNoMatch": "Ninguna entidad de esta figura contiene {query}.",
  "graph.searchInInventory":
    "{value} es una de las entidades sin relación: está en la lista de debajo de la figura, no en la red.",
  "graph.searchMatches": "{count} entidades coinciden. Se encuadra la primera.",
  "graph.focusDepth": "Vecindad",
  "graph.focusDepth1": "1 salto",
  "graph.focusDepth2": "2 saltos",
  "graph.exporting": "Exportando…",
  "graph.exportNotReady": "no se pudo componer la figura que se exporta",
  "graph.needExecutor":
    "El grafo lo extrae el modelo que selecciones. Elige uno en «Modelo que extrae», aquí arriba: Agentopsy no elige uno por ti.",
  "graph.extractingNth": "Extrayendo {n} de {total}: {title}",
  "graph.extractingAll": "Extrayendo los grafos…",
  "graph.backgroundNote":
    "Puedes cambiar de sección o cerrar la pestaña: la extracción corre en el servidor y al volver aquí se retoma su progreso.",
  "graph.batchResult": "{done} de {asked} hallazgos con grafo",
  "graph.extractedWith": "Extraído con {executor}",
  "graph.didNotFinish": "La extracción no llegó a terminar",
  "graph.caseTitle": "Grafo de relaciones del caso",
  "graph.findingTitle": "Grafo de relaciones del hallazgo",
  "graph.caseSubtitle": "{nodes} activos y {edges} conexiones, de {findings} hallazgos",
  "graph.findingSubtitle": "{nodes} activos y {edges} conexiones",
  "graph.emptyCase":
    "Todavía no se ha extraído ningún grafo en este caso. El grafo del caso funde los de los hallazgos, así que aparece en cuanto haya uno.",
  "graph.emptyFinding":
    "Este hallazgo no nombra ninguna entidad de los cinco tipos. Grafo vacío, que es un resultado legítimo.",
  "graph.proposedByModel": "Propuesto por el modelo",
  "graph.cardType": "Tipo",
  "graph.cardRelations": "Relaciones",
  "graph.relTowards": "{relation} hacia {target}",
  "graph.relFrom": "{relation} desde {source}",
  "graph.verifiedFromCase": "Verificado, del caso",
  "graph.cardFindings": "Hallazgos",
  "graph.cardFinding": "Hallazgo",
  "graph.cardTool": "Herramienta",
  "graph.cardArtifactHash": "SHA-256 del artefacto",
  "graph.cardObserved": "Observado",
  "graph.noGraphFinding": "Este hallazgo no tiene grafo",
  "graph.noGraphYet": "Sin grafo todavía",
  "graph.noFindingsBody":
    "El grafo se extrae del texto de los hallazgos, y este caso no tiene ninguno todavía.",
  "graph.pressExtract":
    "Pulsa «Extraer» y el modelo seleccionado leerá el texto del hallazgo para proponer qué entidades intervienen y con qué relación.",
  "graph.revisionMeta": "Revisión v{rev} de {total}",

  // --- exploración de la figura --------------------------------------------
  "graph.zoomIn": "Acercar",
  "graph.zoomOut": "Alejar",
  "graph.fitView": "Ajustar a la vista",
  "graph.zoomLevel": "{percent} %",
  "graph.viewportLabel": "Grafo, se arrastra y se acerca",
  "graph.viewportHint":
    "Arrastra para mover, rueda para acercar, pulsa un nodo para enfocarlo. El PNG exportado lleva siempre la geometría calculada.",
  "graph.layoutEnlarged":
    "La figura no cabía en el lienzo estándar: ampliado a {width} por {height}.",
  "graph.layoutRelaxed": "Hubo que separar {count} pares de nodos para que sus etiquetas no se pisaran.",

  "count.attempts.one": "{count} intento",
  "count.attempts.other": "{count} intentos",

  // --- figura del grafo: rótulos dentro del dibujo -------------------------
  "graph.svgCounts": "{nodes} nodos · {edges} aristas",
  "graph.legendNodes": "NODOS",
  "graph.legendEdges": "RELACIONES",
  "graph.provenance": "Caso: {case} · Exportado: {date} · {nodes} nodos, {edges} aristas",

  // --- configuración: motor de análisis y sistema --------------------------
  "settings.tabsLabel": "Secciones de configuración",
  "settings.lede": "Quién ejecuta el análisis. Elige uno: Agentopsy no lo hace por ti.",
  "settings.queryingCaps": "Consultando capacidades del servicio api…",
  "settings.modelDefault": "por defecto",
  "settings.connectArrow": "conectar",
  "settings.localNote": "No sale nada de tu máquina.",
  "settings.cloudNote": "Usa tu propia suscripción; el prompt sale a ese proveedor.",
  "settings.cliDefault": "Por defecto del CLI",
  "settings.modelIdFor": "Id de modelo para {name}",
  "settings.saved": "guardado",
  "settings.power": "Potencia",
  "settings.noEfforts": "El catálogo no declara niveles de razonamiento para {model}.",
  "settings.pickModelFirst": "Elige antes un modelo: los niveles disponibles dependen de él.",
  "settings.effortMismatchA": "El nivel guardado (",
  "settings.effortMismatchB":
    ") no lo admite {model}: el turno fallaría. Elige uno de los de arriba.",
  "settings.modelByCli": "El modelo lo gestiona el CLI de este proveedor.",
  "settings.saveHost": "Guardar host",
  "settings.ollamaHostHint":
    "Escribe http://localhost:11434 para usar el Ollama que corre en tu equipo, o http://ollama:11434 para el que levanta el compose. Si no lo alcanza, arráncalo escuchando en todas las interfaces: OLLAMA_HOST=0.0.0.0 ollama serve.",
  "settings.ollamaHostFromEnv":
    "Ahora mismo lo fija el despliegue. Lo que guardes aquí manda sobre esa variable.",
  "settings.isDefaultEngine": "es el motor por defecto",
  "settings.useAsDefault": "usar por defecto",
  "settings.renewSession": "Renovar sesión de {name}",
  "settings.connectName": "Conectar {name}",
  "settings.startOllama": "Levanta el servicio ollama del compose para usarlo.",
  "settings.timeout": "Tiempo máximo",
  "settings.saveFailed": "No se pudo guardar: {detail}",
  "settings.foot": "sin API keys · sesiones y ajustes solo en tu máquina",
  "settings.noApi": "Sin conexión con el servicio api",
  "settings.noApiBody":
    "No se pudo obtener el diagnóstico del stack. Comprueba que el compose está levantado.",
  "settings.toolkits": "Maletines",
  "settings.toolkitRunning": "en ejecución",
  "settings.toolkitStopped": "detenido / inaccesible",
  "settings.toolkitUnknown": "no consultable desde el api",
  "settings.catalogTools": "Herramientas del catálogo",

  // --- configuración: cabecera ---------------------------------------------
  "settings.refreshing": "Actualizando…",
  "settings.refresh": "Actualizar estado",

  // --- fase 3: matriz ATT&CK -----------------------------------------------
  "mitre.status.confirmada": "Confirmada",
  "mitre.status.sospechosa": "Sospechosa",
  "mitre.status.descartada": "Descartada",
  "mitre.exploreMeta": "exploración del catálogo · sin caso",
  "mitre.exporting": "Exportando…",
  "mitre.exportLayer": "Exportar layer",
  "mitre.loading": "Cargando la matriz…",
  "mitre.loadFailed": "No se pudo cargar la matriz:",
  "mitre.noSeed": "Falta la semilla ATT&CK",
  "mitre.noSeedBody":
    "El catálogo se deriva de la semilla del orquestador y no se ha podido cargar.",
  "mitre.viewMatrix": "Matriz",
  "mitre.viewTimeline": "Línea temporal",
  "mitre.searchLabel": "Buscar técnica o identificador ATT&CK",
  "mitre.searchPlaceholder": "Buscar técnica o ID (T1055)…",
  "mitre.subTechniques": "Sub-técnicas",
  "mitre.onlyCovered": "Solo cubiertas",
  "mitre.noCase": "Sin caso",
  "mitre.exportSheet": "Exportar hoja",
  "mitre.exportNavigator": "Exportar Navigator layer",
  "mitre.exportFailed": "No se pudo exportar: {detail}",
  "mitre.phaseTactics": "{count} tácticas",
  "mitre.summaryConfirmed": "Confirmadas",
  "mitre.summarySuspected": "Sospechosas",
  "mitre.summaryTactics": "Tácticas",
  "mitre.noMatches": "Sin coincidencias",
  "mitre.nothingToShow": "Nada que mostrar",
  "mitre.noTechniqueMatch": "Ninguna técnica coincide con «{query}».",
  "mitre.noCoverageYet":
    "Ninguna táctica tiene cobertura todavía. Desactiva «Solo cubiertas» para ver la matriz completa.",
  "mitre.colCovered": "{covered}/{total} cubiertas",
  "mitre.colDiscarded": "{count} descart.",
  "mitre.colTechniques": "{count} técnicas",
  "mitre.cellProposedBy": "{count} hallazgo(s) del agente citan esta técnica",
  "mitre.cellSub": "{count} sub",
  "mitre.legendConfirmed": "confirmada por el perito",
  "mitre.legendSuspected": "sospechosa",
  "mitre.legendDiscarded": "descartada por el perito",
  "mitre.legendProposed": "propuesta del agente, sin dictaminar",
  "mitre.legendNone": "no evaluada",
  "mitre.legendNote": "gris = no evaluada, nunca «ausente»",
  "mitre.tlNoCaseBody":
    "La línea temporal se construye con los hallazgos reales del caso. Desactiva «Sin caso» para volver al caso activo.",
  "mitre.tlEmpty": "Sin hallazgos correlacionados",
  "mitre.tlEmptyBody":
    "Ningún hallazgo del caso cita todavía una técnica ATT&CK. La línea temporal se construye con los hallazgos reales que el agente asocia a una técnica.",
  "mitre.detailOf": "Detalle de {id}",
  "mitre.subCount": "{count} sub-técnicas",
  "mitre.supportedBy": "Se sostiene con",
  "mitre.goBackToCase":
    "Vuelve al caso activo para registrar si esta técnica se ha confirmado, está en sospecha o se ha descartado en la investigación.",
  "mitre.agentProposal": "Propuesta del agente",
  "mitre.noAgentCitation":
    "Ningún hallazgo del agente cita esta técnica. Puedes dictaminarla igualmente si la evidencia que has revisado lo sostiene.",
  "mitre.examinerVerdict": "Dictamen del perito",
  "mitre.currently": "Actualmente:",
  "mitre.rationaleLabel": "Motivo · obligatorio, queda en el log de auditoría",
  "mitre.rationalePlaceholder": "Qué evidencia sostiene este veredicto…",
  "mitre.withdraw": "Retirar dictamen",
  "mitre.needRationale":
    "Un veredicto sin motivo no vale nada en un informe pericial: el backend lo rechaza.",

  // --- fase 4: timeline forense --------------------------------------------
  "tl.title": "Timeline forense",
  "tl.noDate": "sin fecha",
  "tl.sev.low": "Baja",
  "tl.sev.medium": "Media",
  "tl.sev.high": "Alta",
  "tl.sev.critical": "Crítica",
  "tl.cat.credenciales": "Credenciales",
  "tl.cat.ssh": "SSH",
  "tl.cat.historial": "Historial de shell",
  "tl.cat.persistencia": "Persistencia",
  "tl.cat.ejecutable_temporal": "Ejecutable en temporal",
  "tl.cat.web": "Artefacto web",
  "tl.cat.logs": "Logs",
  "tl.cat.binario_sistema": "Binario de sistema",
  "tl.pager": "Página {page} de {total} · {count} {noun}",
  "tl.nounEvents": "eventos",
  "tl.nounRelevant": "eventos relevantes",
  "tl.figureNotDrawn": "la figura todavía no está dibujada",
  "tl.loading": "Cargando la línea de tiempo…",
  "tl.loadFailed": "No se pudo cargar la línea de tiempo:",
  "tl.noCaseBody":
    "La línea de tiempo se construye con la actividad auditada y la evidencia del caso. Abre uno desde el lateral.",
  "tl.tabFindingsTitle":
    "Qué pasó en el dispositivo investigado, según los hallazgos con marca temporal del artefacto.",
  "tl.tabFs": "Sistema de ficheros (MACB)",
  "tl.tabRelevant": "Eventos relevantes",
  "tl.tabRelevantTitle":
    "Eventos del sistema de ficheros forensemente relevantes (credenciales, persistencia, historial, logs, ejecutables en temporales…)",
  "tl.allUtc": "Todas las horas en UTC",
  "tl.searchLabel": "Buscar en la línea de tiempo",
  "tl.searchInv": "Buscar por herramienta, argv, hallazgo o técnica…",
  "tl.searchRelevant": "Buscar por ruta, motivo, categoría, MACB o inode…",
  "tl.searchFs": "Buscar por ruta, MACB o inode…",
  "tl.metaCounts": "{runs} ejecuciones · {findings} hallazgos",
  "tl.evidenceSelect": "Evidencia de la super-timeline",
  "tl.pickEvidenceFirst": "Elige primero la evidencia.",
  "tl.generating": "Generando…",
  "tl.generate": "Generar super-timeline",
  "tl.exportSheet": "Exportar hoja",
  "tl.loadingIncident": "Cargando la línea de tiempo del incidente…",
  "tl.noPlaceable": "Sin eventos que situar en el tiempo",
  "tl.noActivity": "Sin actividad todavía",
  "tl.noActivityBody":
    "La línea de tiempo se llena con cada herramienta que se ejecuta y cada hallazgo que el agente registra, tomados del log de auditoría encadenado.",
  "tl.noEventMatch": "Ningún evento coincide con la búsqueda.",
  "tl.kindFinding": "Hallazgo",
  "tl.kindRun": "Ejecución",
  "tl.agent": "agente",
  "tl.noArgv": "(sin argv)",
  "count.artifacts.one": "{count} artefacto",
  "count.artifacts.other": "{count} artefactos",
  "tl.noEvidence": "Sin evidencia registrada",
  "tl.noEvidenceBody":
    "Registra una evidencia en el caso para construir la super-timeline del sistema de ficheros.",
  "tl.pickEvidence": "Elige la evidencia",
  "tl.pickEvidenceBody":
    "La super-timeline se construye sobre una evidencia concreta. Agentopsy no elige por ti cuál analizar.",
  "tl.runningFls": "Ejecutando tsk_fls -m sobre la evidencia…",
  "tl.asyncNote": "Es un trabajo asíncrono: puedes seguir investigando mientras corre.",
  "tl.analysisFailed": "El análisis falló.",
  "tl.notGenerated": "Super-timeline sin generar",
  "tl.notGeneratedA": "La línea temporal MACB se construye ejecutando",
  "tl.notGeneratedB":
    "sobre la evidencia seleccionada. Es un trabajo asíncrono: puedes seguir investigando mientras corre.",
  "tl.generatedAt":
    "Super-timeline generada el {date} a las {time} UTC · {count} eventos. Vuelve a pulsar «Generar super-timeline» para recalcularla.",
  "tl.truncated":
    "Mostrando {shown} de {total} eventos (recortado para acotar el tamaño). Afina con la búsqueda.",
  "tl.noFsEvents": "La evidencia no produjo eventos de sistema de ficheros.",
  "tl.colTime": "Hora (UTC)",
  "tl.colMacb": "MACB",
  "tl.colSize": "Tamaño",
  "tl.colInode": "Inodo",
  "tl.colPath": "Ruta",
  "tl.colDate": "Fecha (UTC)",
  "tl.colHour": "Hora",
  "tl.colCategory": "Categoría",
  "tl.colReason": "Motivo",
  "tl.oldSuperTimeline":
    "Esta super-timeline se generó con una versión anterior sin triage de relevancia. Vuelve a pulsar «Generar super-timeline» para calcular los eventos relevantes.",
  "tl.relevantTruncated":
    "Mostrando {shown} de {total} eventos relevantes (recortado). Afina con la búsqueda.",
  "tl.noRelevantMarked":
    "El triage no marcó ningún evento del sistema de ficheros como relevante.",
  "tl.noRelevantMatch": "Ningún evento relevante coincide con la búsqueda.",

  // --- figura de la línea de tiempo del incidente --------------------------
  "rail.noObservedAt":
    "{count} sin marca temporal del artefacto (no se sitúan en el eje: fecharlos con la hora del análisis falsearía el incidente)",
  "rail.unparseable": "{count} con una marca ilegible como fecha con zona",
  "rail.listTrimmed": " (lista recortada)",
  "rail.allPlaced": "Los {count} hallazgos del caso se sitúan en el eje.",
  "rail.ariaLabel": "Línea de tiempo del incidente: {count} eventos",
  "rail.title": "Línea de tiempo del incidente",
  "rail.case": "Caso: {name}",
  "rail.exported":
    "Exportado: {date} · {shown} eventos representados de {total} hallazgos del caso",

  // --- fase 7: informe pericial --------------------------------------------
  "doc.perito.name": "Perito",
  "doc.perito.colegiado": "Nº de colegiado",
  "doc.perito.colegiadoPh": "p. ej. COL-1234",
  "doc.perito.organization": "Organización",
  "doc.perito.organizationPh": "Laboratorio / empresa",
  "doc.perito.email": "Contacto",
  "doc.perito.emailPh": "correo@dominio",
  "doc.perito.version": "Versión",
  "doc.perito.versionPh": "se deriva de las revisiones",
  "doc.phase.material": "Reuniendo el material del caso…",
  "doc.phase.redactando": "El modelo está redactando el informe…",
  "doc.phase.validando": "Validando índice, referentes y comandos auditados…",
  "doc.phase.corrigiendo": "La validación rechazó el borrador: el modelo lo está corrigiendo…",
  "doc.phase.listo": "Informe redactado.",
  "doc.written":
    "Informe {version} redactado ({pages} pág.). Nace en BORRADOR: revísalo y fírmalo para darle validez pericial.",
  "doc.writeFailed": "La redacción del informe no pudo completarse.",
  "doc.signed": "Documento firmado y marcado como versión final.",
  "doc.blockNoExecutor":
    "Elige el modelo que redactará el informe: sin selección Agentopsy no llama a ninguno.",
  "doc.blockNoFindings":
    "El caso no tiene ningún hallazgo registrado: no hay investigación que informar. Analiza la evidencia en Investigación primero.",
  "doc.headerMeta": "{docs} · {signed} firmados",
  "count.signed.one": "{count} firmado",
  "count.signed.other": "{count} firmados",
  "doc.downloadPdf": "Descargar PDF",
  "doc.loading": "Cargando informes del caso…",
  "doc.loadFailed": "No se pudieron cargar los documentos:",
  "doc.noCaseBody":
    "Los informes se redactan y se firman dentro de un caso. Abre uno desde el lateral.",
  "doc.section": "Documentos del caso",
  "doc.searchLabel": "Buscar documento",
  "doc.searchPlaceholder": "Buscar por título, evidencia o hash…",
  "doc.filterAll": "Todos",
  "doc.statusDraft": "Borrador",
  "doc.statusFinal": "Final",
  "doc.groupLabel": "Agrupar documentos",
  "doc.groupEvidence": "por evidencia",
  "doc.groupType": "por tipo",
  "doc.groupNone": "sin agrupar",
  "doc.none": "Aún no hay ningún informe. Se emite al finalizar la investigación, aquí abajo.",
  "doc.noMatch": "Ningún documento coincide con la búsqueda o el filtro.",
  "doc.statusDraftLower": "borrador",
  "doc.statusFinalLower": "final",
  "doc.pagesShort": "pág.",
  "doc.finalize": "Finalizar investigación",
  "doc.finalizeBody":
    "El modelo que elijas redacta el informe pericial COMPLETO a partir de todos los hallazgos, evidencias, ejecuciones auditadas y veredictos ATT&CK del caso. Cada informe es único: solo el índice es común. Agentopsy valida que el índice esté entero, que ningún identificador ni hash sea inventado y que cada comando citado sea el argv literal del log de auditoría.",
  "doc.writingModel": "Modelo que redacta",
  "doc.peritoFields": "Datos del perito (opcionales)",
  "doc.backgroundNote":
    "Puedes cambiar de sección o cerrar la pestaña: la redacción corre en el servidor y al volver aquí se retoma su progreso.",
  "doc.notPublished": "La redacción no llegó a publicarse",
  "doc.notPublishedBody":
    "No se ha guardado ningún documento: el informe se publica entero o no se publica. Puedes volver a pulsar «Finalizar investigación».",
  "doc.writing": "Redactando informe…",
  "doc.noReportYet": "Sin informe todavía",
  "doc.noneOpen": "Ningún documento abierto",
  "doc.noReportYetBody":
    "El informe pericial se emite una sola vez, cuando la investigación termina: pulsa «Finalizar investigación» en el panel de la izquierda y el modelo seleccionado lo redactará de principio a fin desde los hallazgos y las evidencias del caso.",
  "doc.pickToRead":
    "Elige un documento de la lista para leerlo, verificar su integridad y descargarlo en PDF.",
  "doc.pages": "{count} páginas",
  "doc.verifyIntegrity": "Verificar integridad",
  "doc.signAsFinal": "Firmar y marcar final",
  "doc.deleteDraft": "Eliminar borrador",
  "doc.verifyOk":
    "Integridad verificada · el SHA-256 recalculado coincide con el de registro ({hash})",
  "doc.verifyBad":
    "El SHA-256 recalculado ({got}) NO coincide con el de registro ({want}). El documento ha cambiado desde que se registró.",
  "doc.footGenerated": "Generado por Agentopsy",
  "doc.footSigned": "Firmado",

  // --- chat de investigación -----------------------------------------------
  "chat.prompt1": "buscar persistencia",
  "chat.prompt2": "analizar conexiones de red",
  "chat.prompt3": "generar timeline del sistema de ficheros",
  "chat.toolchain": "Cadena de ejecución",
  "count.steps.one": "{count} paso",
  "count.steps.other": "{count} pasos",
  "chat.chainRunning": "en curso",
  "chat.chainDone": "registrada",
  "chat.background":
    "Analizando en segundo plano · puedes cambiar de sección o cerrar la pestaña: el análisis no se detiene y los hallazgos se guardan en caliente.",
  "chat.stoppedByOperator": "Análisis detenido por el operador.",
  "chat.jobFailed": "El análisis en segundo plano falló.",
  "chat.resuming": "Reanudando análisis en curso…",
  "chat.launching": "Lanzando análisis en segundo plano…",
  "chat.launchFailed": "No se pudo lanzar el análisis. ¿Está levantado el compose?",
  "chat.stopping": "Deteniendo el análisis…",
  "chat.startTitle": "¿Qué le pedimos al agente?",
  "chat.startBody":
    "Ejecuta el maletín forense sobre todas las evidencias verificadas del caso y deja cada comando en el log de auditoría encadenado. Para centrarte en una evidencia, dilo en el mensaje.",
  "chat.noEvidenceTitle": "Este caso todavía no tiene evidencia",
  "chat.noEvidenceBody":
    "El agente analiza las evidencias verificadas del caso, así que primero hay que registrar al menos una. Su hash baseline se calcula al hacerlo.",
  "chat.roleExaminer": "Perito",
  "chat.runningTool": "ejecutando {tool}",
  "chat.reasoning": "razonando",
  "chat.processing": "procesando resultado",
  "chat.recording": "registrando hallazgo",
  "chat.working": "trabajando",
  "chat.recorded": "registrado en el caso",
  "chat.jumpTitle": "Volver al final de la conversación",
  "chat.jump": "Ir al final",
  "chat.analysisRunning": "análisis en curso",
  "chat.placeholder": "Pide algo al agente",
  "chat.pickExecutor": "Elige ejecutor",
  "chat.executorTitle": "Ejecutor del análisis",
  "chat.executor": "Ejecutor",
  "chat.queryingCaps": "consultando capacidades…",
  "chat.modelTitle": "Modelo · {name}",
  "chat.loadingModels": "cargando modelos…",
  "chat.recommended": "recomendado",
  "chat.savedAs": "Se guarda como",
  "chat.noEfforts": "El catálogo no declara niveles para {model}.",
  "chat.pickModelFirst": "Elige antes un modelo: los niveles dependen de él.",
  "chat.effortMismatch":
    "{model} no admite «{effort}»: el turno fallaría. Elige uno de los de arriba.",
  "chat.enterSends": "Enter envía",
  "chat.stopTitle": "Detener el análisis en curso (conserva lo ya registrado)",
  "chat.stoppingBtn": "Deteniendo…",
  "chat.send": "Enviar",

  // --- bandeja: progreso del hash-gate y avisos ----------------------------
  "inbox.phase.hashing": "SHA-256 del origen",
  "inbox.phase.copying": "copiando a la carpeta del caso",
  "inbox.phase.verifying": "re-hash de la copia",
  "inbox.preparing": "Preparando el registro…",
  "inbox.segmentOf": "segmento {index}/{total}",
  "inbox.dontClose": "No cierres esta ventana hasta que termine.",
  "inbox.registeringName": "Registrando",
  "inbox.evidenceWord": "evidencia",
  "inbox.title": "Bandeja ./evidence",
  "inbox.uploadFailed": "No se pudo subir la evidencia:",
  "inbox.registerFailed": "No se pudo registrar la evidencia:",
  "evidenceTable.empty": "Sin evidencia registrada",
  "evidenceTable.emptyBody":
    "Arrastra la imagen forense a la zona de arriba o elígela de la bandeja. Nada llega a una herramienta antes de que exista su hash baseline.",

  // --- cliente HTTP: fallos de transporte ----------------------------------
  "http.gateway504": "HTTP 504: el api no respondió a tiempo a través del proxy.",
  "http.gateway":
    "HTTP {status}: el proxy no pudo hablar con el servicio api. Puede estar arrancando o reiniciándose (docker compose ps api).",
  "http.notJson": "HTTP {status}: respuesta no-JSON desde {source}.",
  "http.theApi": "el api",
  "http.badResponse": "Respuesta no válida del servidor.",
  "http.noStreamBody": "el api no devolvió cuerpo de streaming",

  // --- evidencia: rótulo suelto --------------------------------------------
  "evidence.verifyFailedLabel": "No se pudo verificar la evidencia:",

  // --- chat: selector de modelo --------------------------------------------
  "chat.modelPick": "modelo",
  "chat.modelPickTitle": "Modelo del proveedor",
  "chat.pickExecutorFirst": "Elige primero un ejecutor",
};
