// Catálogo INGLÉS y, a la vez, la fuente de verdad de las CLAVES: `MessageKey`
// se deriva de este objeto, así que `es.ts` está obligado por el tipo a traer
// exactamente las mismas, ni una menos ni una de más. Un hueco no se disimula
// en caliente cayendo al otro idioma (RULE 2): lo caza `npm run typecheck`, que
// es un gate de CI (RULE 6).
//
// REGLAS DE ESTILO (RULE 7, y aquí también en inglés):
//   - sin guion largo. En inglés es puntuación corriente, pero es regla de
//     PRODUCTO y vale para las dos lenguas: el inciso va entre comas,
//     paréntesis o dos puntos.
//   - sin el signo de sección: se escribe «section 6.2».
//   - sin emojis ni pictogramas: donde otro pondría un símbolo, va la palabra.
//   - el blanco de «sin dato» es `n/a` en inglés y `n/d` en castellano.
//
// GLOSARIO (fijado para que 800 mensajes no discutan entre sí):
//   informe pericial   -> expert report        perito/examinador -> examiner
//   caso               -> case                 evidencia         -> evidence
//   hallazgo           -> finding              maletín           -> toolkit
//   cadena de custodia -> chain of custody     acta              -> record
//   bandeja            -> inbox                registrar         -> register
//   ejecutor           -> executor             dictaminar        -> adjudicate
//   traza              -> trace                encargo           -> engagement
//   línea de tiempo    -> timeline             borrador          -> draft
//   fase               -> phase                firmar            -> sign
//
// CONVENCIÓN DE CLAVES: `dominio.asunto`. Un plural declara DOS claves,
// `base.one` y `base.other`, y se pide con `tn()`.
//
// Lo que NUNCA entra aquí: contenido del caso. El nombre que el perito puso al
// caso, el título de un hallazgo o el resumen que escribió el agente viajan tal
// cual. Traducir un dato del expediente sería inventarlo.

export const en = {
  // --- idiomas -------------------------------------------------------------
  // Cada idioma se nombra EN SÍ MISMO (endónimo) y por eso no se traduce: quien
  // no entiende la interfaz actual tiene que poder reconocer el suyo en la lista.
  "lang.en": "English",
  "lang.es": "Español",

  // --- configuración, apariencia e idioma ----------------------------------
  "settings.tab.executors": "Analysis engine",
  "settings.tab.system": "System and toolkit",
  "settings.tab.appearance": "Appearance",
  "settings.appearance.palette": "Palette",
  "settings.appearance.paletteGroup": "Interface palette",
  "settings.appearance.mode": "Mode",
  "settings.appearance.modeGroup": "Interface mode",
  "settings.appearance.light": "Light",
  "settings.appearance.dark": "Dark",
  "settings.appearance.hint":
    "Palette and mode are stored in this browser and apply to the whole application.",

  "settings.language.title": "Language",
  "settings.language.group": "Interface language",
  "settings.language.hint":
    "Stored in this browser. It applies to the interface, to the messages the api returns and to any expert report written from now on. A report that is already signed keeps the language it was signed in.",

  // --- paletas -------------------------------------------------------------
  "palette.papel.name": "Paper",
  "palette.papel.desc": "Warm cream and terracotta. Case file, archive, paper.",
  "palette.acero.name": "Steel",
  "palette.acero.desc": "Cool grey and instrument blue. Sober, laboratory.",

  // --- navegación y armazón ------------------------------------------------
  "nav.repository": "Evidence",
  "nav.investigation": "Investigation",
  "nav.mitre": "ATT&CK correlation",
  "nav.timeline": "Timeline",
  "nav.findings": "Findings",
  "nav.graphs": "Graphs",
  "nav.report": "Expert report",
  "nav.settings": "Settings",
  "nav.guide": "Guide",
  "shell.phaseOf": "Phase {n} of {total}",

  // --- barra lateral: caso y escalera de fases -----------------------------
  "sidebar.phases": "Case phases",
  "sidebar.newCase": "create case",
  "sidebar.pickCase": "Choose a case",
  "sidebar.changeCase": "{name}, switch case",
  "case.status.active": "open",
  "case.status.closed": "closed",

  // --- cantidades del caso (plurales) --------------------------------------
  "count.files.one": "{count} file",
  "count.files.other": "{count} files",
  "count.findings.one": "{count} finding",
  "count.findings.other": "{count} findings",
  "count.techniques.one": "{count} technique",
  "count.techniques.other": "{count} techniques",
  "count.events.one": "{count} event",
  "count.events.other": "{count} events",
  "count.documents.one": "{count} document",
  "count.documents.other": "{count} documents",

  // --- metadatos de cada fase en la escalera -------------------------------
  "phase.evidence.none": "no evidence",
  "phase.evidence.verified": "{count} verified",
  "phase.findings.none": "no findings",
  "phase.mitre.toCorrelate": "findings to correlate",
  "phase.mitre.noVerdict": "not adjudicated",
  "phase.mitre.withVerdict": "{count} adjudicated",
  "phase.timeline.noEvents": "no events on the axis",
  "phase.timeline.allUndated": "{count} with no placeable date",
  "phase.timeline.undated": "{count} undated",
  "phase.graphs.none": "no graphs",
  "phase.graphs.some": "{done} of {total} with a graph",
  "phase.documents.none": "no documents",

  // --- comunes -------------------------------------------------------------
  "common.na": "n/a",
  "common.retry": "Retry",
  "common.cancel": "Cancel",
  "common.close": "Close",
  "common.save": "Save",
  "common.delete": "Delete",
  "common.loading": "Loading",
  "common.noCase": "no case selected",

  // --- naturaleza de la evidencia (detected_kind del triage) ---------------
  "kind.disk": "Disk image",
  "kind.memory": "Memory dump",
  "kind.container_disk": "VM disk",
  "kind.document": "Supplied file",
  "kind.unknown": "Unknown",

  // --- piezas de interfaz compartidas --------------------------------------
  "ui.connectionError": "Connection error:",
  "ui.loading": "Loading…",
  "ui.prevPage": "Previous page",
  "ui.nextPage": "Next page",

  // --- tabla de evidencias -------------------------------------------------
  "evidenceTable.col.file": "File",
  "evidenceTable.col.kind": "Type",
  "evidenceTable.col.size": "Size",
  "evidenceTable.col.hash": "SHA-256",
  "evidenceTable.col.integrity": "Integrity",
  "evidenceTable.search": "Search by file name…",
  "evidenceTable.noMatch": "No file matches «{query}».",
  "evidenceTable.copyHash": "Click to copy the full SHA-256",
  "evidenceTable.copyHashLabel": "Copy the full SHA-256",
  "evidenceTable.verifying": "verifying…",
  "evidenceTable.unverified": "not verified",
  "evidenceTable.verified": "verified",
  "evidenceTable.mismatch": "hash mismatch",
  "evidenceTable.verifyingBtn": "Verifying…",
  "evidenceTable.reverify": "Re-verify",
  "evidenceTable.verifyNow": "Verify now",
  "evidenceTable.firstSegment": "{size} the first segment",
  "count.segments.one": "{count} segment",
  "count.segments.other": "{count} segments",

  // --- alta de caso --------------------------------------------------------
  "newCase.eyebrow": "Phase 1, before touching evidence",
  "newCase.title": "Open a new case",
  "newCase.enterToSave": "enter to save",
  "newCase.saving": "Saving…",
  "newCase.save": "Save case",
  "newCase.name": "Case name",
  "newCase.namePlaceholder": "Case name or reference",
  "newCase.examiner": "Examiner",
  "newCase.examinerPlaceholder": "Full name",
  "newCase.examinerHint":
    "Responsible for the case. Appears on the acquisition record and in the expert report.",
  "newCase.notes": "Description and notes",
  "newCase.optional": "optional",
  "newCase.notesPlaceholder": "Short description of the case",
  "newCase.failed": "The case could not be created:",

  // --- buscador y gestión de casos -----------------------------------------
  "caseSearch.eyebrow.list": "Service cases",
  "caseSearch.eyebrow.edit": "Active case",
  "caseSearch.eyebrow.delete": "Irreversible",
  "caseSearch.title.list": "Search cases",
  "caseSearch.title.edit": "Edit case",
  "caseSearch.title.delete": "Delete case",
  "caseSearch.hint.list": "esc close, enter open",
  "caseSearch.hint.other": "esc close",
  "caseSearch.label": "Search cases",
  "caseSearch.placeholder": "Search by name or examiner…",
  "caseSearch.filterGroup": "Filter cases by status",
  "caseSearch.filter.all": "All",
  "caseSearch.filter.active": "Open",
  "caseSearch.filter.closed": "Closed",
  "caseSearch.sortLabel": "Sort by",
  "caseSearch.sort.recent": "Most recent",
  "caseSearch.sort.oldest": "Oldest",
  "caseSearch.sort.nameAsc": "Name A-Z",
  "caseSearch.sort.nameDesc": "Name Z-A",
  "caseSearch.emptyTitle": "No cases yet",
  "caseSearch.emptyBody":
    "Press «create case» in the sidebar to open the first one. With no case there is nowhere to register evidence.",
  "caseSearch.noResults": "No results",
  "caseSearch.noMatchQuery": "No case matches «{query}».",
  "caseSearch.noMatchFilter": "No case matches the filter.",
  "caseSearch.edit": "Edit",
  "caseSearch.close": "Close",
  "caseSearch.reopen": "Reopen",
  "caseSearch.saveChanges": "Save changes",
  "caseSearch.deleting": "Deleting…",
  "caseSearch.deleteForever": "Delete permanently",
  "caseSearch.actionFailed": "The action could not be completed:",
  "caseSearch.saveFailed": "Could not save:",
  "caseSearch.deleteFailed": "The case could not be deleted:",
  "caseSearch.osNotEditable":
    "The operating system profile is not edited here: the orchestrator derives it from the content of the registered evidence.",
  "caseSearch.dangerLead": "This action cannot be undone.",
  "caseSearch.dangerBody":
    "The whole case «{name}» will be deleted PERMANENTLY, and with it its complete chain of custody: the registered evidence copies, the hash-chained audit log, the findings, the artifacts, the chats and the reports. There is no recycle bin and no undo.",
  "caseSearch.typeToConfirm": "Type «{name}» to confirm",
  "count.cases.one": "{count} case",
  "count.cases.other": "{count} cases",

  // --- bandeja de evidencias -----------------------------------------------
  "inbox.materialFormats":
    "documents (pdf, word, spreadsheets, presentations, text, logs), mail, still images and audiovisual, compressed archives, network captures, standalone Windows artifacts and samples",
  "inbox.ewfHint":
    "If the image is a split EWF (.E01, .E02, …), drop or select ALL of its segments: they are registered from the .E01 as a single piece of evidence.",
  "inbox.caseClosed": "This case is closed",
  "inbox.caseClosedBody":
    "Reopen it from «switch case» in the sidebar to register more evidence.",
  "inbox.droppedFolder":
    "You dropped a folder. Drop the FILES of the forensic image, not the directory that contains them.",
  "inbox.noFiles": "No file was received. Try again or use «Browse…».",
  "inbox.foldersIgnored":
    "The folders in the drop were ignored: drop the forensic image files directly.",
  "inbox.rejected":
    "The inbox does not recognise the extension of {names}. It accepts images and dumps ({images}), the segments of a split EWF, files with no extension, and supplied material: {material}. If it still contributes to the case, copy it to the ./evidence folder of the repository: the inbox lists everything there and it is registered from there just the same.",
  "inbox.dropTitle": "Drop the case evidence here",
  "inbox.dropBody":
    "Agentopsy computes the baseline SHA-256 and sets it read-only before any tool touches it, whether it is an image of a whole system or a file you were handed.",
  "inbox.browse": "Browse…",
  "inbox.searching": "Searching…",
  "inbox.browseInbox": "Browse inbox",
  "inbox.imagesLabel": "Images and dumps:",
  "inbox.materialLabel": "Supplied material:",
  "inbox.uploading": "Uploading evidence to the inbox…",
  "inbox.noExtension": "no extension",
  "inbox.ewfContinuation": "EWF segment, registered from the .E01",
  "inbox.selected": "selected",
  "inbox.registering": "Registering…",
  "inbox.registerNamed": "Register {name}",
  "inbox.register": "Register evidence",
  "inbox.refresh": "Refresh inbox",
  "inbox.emptyBefore":
    "The inbox is empty. Drop the forensic image above to upload it, or copy it to",
  "inbox.emptyAfter": "on the host.",

  // --- conexión de un ejecutor cloud ---------------------------------------
  "execLogin.title": "Connect {name}",
  "execLogin.starting": "Starting the {name} login…",
  "execLogin.incomplete": "The login ended without completing.",
  "execLogin.noSession": "There is still no session.",
  "execLogin.failed": "The login could not be completed.",
  "execLogin.notFromWebLead": "The {name} login cannot be completed from the web.",
  "execLogin.runCommand": "Run this command in a terminal",
  "execLogin.copy": "Copy",
  "execLogin.checking": "Checking…",
  "execLogin.check": "Check",
  "execLogin.step1": "1. Open this URL in your browser",
  "execLogin.step2code": "2. Enter this code IN THE BROWSER",
  "execLogin.codeExpiry": "The code expires in about 15 min. Do not share it with anyone.",
  "execLogin.pasteStep": "{n}. Paste here the code the browser gives you",
  "execLogin.codePlaceholder": "Code from the authorisation page",
  "execLogin.sending": "Sending…",
  "execLogin.sendCode": "Send code",
  "execLogin.waiting": "Waiting for you to complete the sign-in in the browser…",
  "execLogin.connectedBefore": "{name} connected. The session persists in the volume",

  // --- registro de evidencia en segundo plano ------------------------------
  "register.stalled":
    "No contact with the api while polling the registration ({seconds} s). The hash gate runs on the server and is still going; this retries on its own.",
  "register.gaveUp":
    "The api could not be contacted for {seconds} s, so polling stops. The registration may still be running on the server: check the service (docker compose ps api) and come back to this view, which picks up whichever registration is still alive. Last failure: {detail}",
  "register.jobLost":
    "The api no longer knows about this registration: it restarted while the registration was running. Registration is atomic, so nothing was left half done. If the evidence does not appear in the list, register it again.",
  "register.errorNoDetail": "the registration ended in error with no detail",

  // --- fase 1: evidencia ---------------------------------------------------
  "evidence.kind.disk": "disk image",
  "evidence.kind.container_disk": "container image",
  "evidence.kind.memory": "memory dump",
  "evidence.kind.document": "supplied file",
  "evidence.kind.unknown": "unidentified format",
  "evidence.registeredPlain": "Evidence registered",
  "evidence.registeredSize": "Evidence registered: {size}",
  "evidence.registeredSet": "Evidence registered: {segments} segments, {size} in total",
  "evidence.uploadedOne": "{count} file uploaded to the inbox",
  "evidence.uploadedMany": "{count} files uploaded to the inbox",
  "evidence.alreadyOne":
    "{count} was already in the inbox ({names}); evidence is never overwritten",
  "evidence.alreadyMany":
    "{count} were already in the inbox ({names}); evidence is never overwritten",
  "evidence.goToInvestigation": "Go to Investigation",
  "evidence.needEvidenceFirst":
    "Register a piece of evidence first: the agent only works on a hash-verified handle",
  "evidence.loadingCases": "Loading cases…",
  "evidence.casesFailed": "the cases could not be listed",
  "evidence.noActiveCase": "No active case",
  "evidence.noActiveCaseBody":
    "Open one with «create case» or pick another with «switch case», in the sidebar. Evidence is always registered inside a case: that is what anchors the chain of custody.",
  "evidence.statRegistered": "Registered",
  "evidence.statVerified": "Hash verified",
  "evidence.statPending": "Pending",
  "evidence.statExaminer": "Examiner",
  "evidence.addSection": "Add evidence",
  "evidence.inboxFailed": "The inbox could not be read: {detail}",
  "evidence.listSection": "Case evidence",
  "evidence.listFailed": "The case evidence could not be listed: {detail}",
  "evidence.verifyFailed": "The evidence could not be verified: {detail}",
  "evidence.kSize": "size",
  "evidence.kIntegrity": "integrity",
  "evidence.kOs": "operating system",
  "evidence.inSegments": "in {count} segments",
  "evidence.notReverified": "not re-verified",
  "evidence.reverified": "hash re-verified",
  "evidence.osNotApplicable": "not applicable",
  "evidence.osNotApplicableNote":
    "a supplied file is material about the system under investigation, not the system; here the profile picks the toolkit, not the OS",
  "evidence.osUndetermined": "undetermined",
  "evidence.osRedetectTitle": "Open the image again and determine its operating system",
  "evidence.osDetermining": "Determining…",
  "evidence.osFromContent": "determined from the image content, not from the host machine",
  "evidence.acquisitionRecord": "Acquisition record",
  "evidence.anchorOnlyMaterial":
    "This case only has supplied files, and a file is not the system under investigation: there is no operating system to determine for it. The agent still needs a profile, because that is what selects the toolkit the tools run in. The ones that read a standalone file (file, strings, bulk_extractor, yara, hashdeep) are in both, so for supplied material either one works; pick the one of the system the material came from if you know it:",
  "evidence.anchorUndetermined":
    "The automatic determination could not settle this case's operating system, or the image contains signals from more than one OS, or the toolkit that opens it is unavailable. The agent is not routed until there is a profile, so you can anchor it yourself:",
  "evidence.anchoring": "Anchoring…",
  "evidence.anchorFinal": "The anchor is final and is recorded in the case audit log.",
  "evidence.custodyEyebrow": "Chain of custody",
  "evidence.escToClose": "esc to close",
  "evidence.downloadRecord": "Download record (JSON)",
  "evidence.generatingRecord": "Generating record…",
  "acta.case": "Case",
  "acta.source": "Source",
  "acta.baselineHash": "SHA-256 (baseline)",
  "acta.baselineNote": "covers the first segment; each one has its own, below",
  "acta.size": "Size",
  "acta.sizeNote":
    "{count} segments ingested as a single piece of evidence; the first one is {size}",
  "acta.segments": "Segments ({count})",
  "acta.registered": "Registered",
  "acta.readOnlyLevel": "Read-only level",
  "acta.chainVerified": "chain verified",
  "acta.chainNotVerified": "the chain does NOT verify",
  "acta.verification": "Verification",
  "acta.verifiedAt": "Verified {date}",
  "acta.hashMismatch": "Hash MISMATCH",
  "acta.unverified": "Not verified",
  "acta.tool": "Tool",
  "acta.bytes": "bytes",

  // --- severidad y naturaleza de un hallazgo -------------------------------
  "severity.low": "low",
  "severity.medium": "medium",
  "severity.high": "high",
  "severity.critical": "critical",
  "severity.all": "All",
  "findingKind.descarte": "ruled out",
  "findingKind.afirmacion": "assertion",

  // --- fase 5: hallazgos ---------------------------------------------------
  "findings.loadCaseFailed": "The active case could not be loaded:",
  "findings.noCase": "No open case",
  "findings.noCaseBody":
    "Open a case in the sidebar. Findings appear here as the agent records them during the investigation.",
  "findings.goToEvidence": "Go to Evidence",
  "findings.goToReport": "Go to the expert report",
  "findings.nothingToReport": "There are no findings to report yet",
  "findings.section": "Case findings",
  "findings.searchLabel": "Search finding",
  "findings.searchPlaceholder": "Search by title, tool or technique…",
  "findings.loading": "Loading findings…",
  "findings.empty":
    "No findings yet. The agent records them as it goes during the Investigation; as soon as it concludes something (even a ruling out), it will appear here as a card.",
  "findings.noMatch": "No finding matches the search or the filter.",
  "findings.noneOpen": "No finding open",
  "findings.noneOpenBody":
    "Pick a finding from the list to read it in full, with its provenance and its ATT&CK correlation.",
  "finding.severity": "Severity",
  "finding.kind": "Type",
  "finding.tool": "Tool",
  "finding.run": "Run that supports it",
  "finding.evidence": "Evidence",
  "finding.observedAt": "Observed in the evidence",
  "finding.recordedAt": "Recorded",
  "finding.confidence": "Confidence",
  "finding.artifactHash": "Artifact SHA-256",
  "finding.recordedOn": "recorded {date}",
  "finding.provenance": "Provenance and custody",
  "finding.attackCorrelation": "ATT&CK correlation",
  "finding.noTechniques":
    "The agent did not associate any technique with this finding. It can anchor them from the chat («give me the MITRE correlation») or the examiner can adjudicate them in the ATT&CK phase.",

  // --- guía de uso ---------------------------------------------------------
  "guide.title": "How to use it",
  "guide.state.done": "Done",
  "guide.state.now": "In progress",
  "guide.state.todo": "Pending",
  "guide.goToEvidence": "Go to Evidence",
  "guide.start": "Start: create a case",
  "guide.workflow": "Workflow",
  "guide.reflectsCase": "reflects the active case",
  "guide.noActiveCase": "no active case",
  "guide.step1.title": "Create case and repository",
  "guide.step1.desc":
    "Register a new case and set the examiner in charge before touching evidence.",
  "guide.step2.title": "Register evidence",
  "guide.step2.desc":
    "Upload the image, the dump or the files you were handed; Agentopsy computes the baseline hash and sets them read-only.",
  "guide.step3.title": "Investigate with the agent",
  "guide.step3.desc":
    "Talk to the agent, which runs the forensic toolkit over the verified evidence.",
  "guide.step4.title": "Correlate with ATT&CK",
  "guide.step4.desc":
    "Link the findings to known tactics and techniques to give context to the final report.",
  "guide.step5.title": "Review the timeline",
  "guide.step5.desc":
    "The entry layer, Findings, is the timeline of the incident: what happened on the device under investigation, one event per finding with the artifact timestamp, exported as a PNG image to attach. The other three reconstruct the activity of the investigation and of the file system, and they are read as a list and exported as a spreadsheet.",
  "guide.step6.title": "Extract the relation graphs",
  "guide.step6.desc":
    "The graph answers what connects to what: the model you choose reads the text of each finding and proposes which accounts, files, hosts, domains and IPs take part, and the case graph merges them by entity to show what ties some findings to others. It is a proposal by the model, not a verified fact, and it is labelled as such; the figure is exported as a PNG to attach to the report.",
  "guide.step7.title": "Finish the investigation and sign the report",
  "guide.step7.desc":
    "Press «Finish investigation» and the selected model will write the complete expert report from the case findings and evidence. Agentopsy adds annex C with the incident timeline and the case relation graph, always on a white background: extract beforehand the graphs you want to see in it. Verify its integrity and sign it as the final version.",
  "guide.loginSection": "Sign in to an executor",
  "guide.loginProseA": "Agentopsy does not use API keys.",
  "guide.loginProseB":
    "works with nothing else. For a cloud executor you need your own session: on the first start-up the stack tries to reuse the host session and, if there is none, you sign in once inside the container. The session persists in the volume",
  "guide.loginNoteA": "Check the status in",
  "guide.loginNoteB": "To revoke the session:",
  "guide.settingsPath": "Settings, Analysis engine",
  "guide.cmd.codex": "Codex CLI, device code",
  "guide.cmd.gemini": "Gemini CLI, URL and code",
  "guide.notesSection": "What you should know",
  "guide.note1.title": "Cloud executor and privacy (GDPR)",
  "guide.note1.body":
    "When you choose a cloud executor, the prompts include content derived from the evidence (possibly real personal data) and it leaves for that provider under your own subscription. The 100 percent local alternative is Ollama, which never sends anything off the machine.",
  "guide.note2.title": "Forensic principles",
  "guide.note2.body":
    "Evidence is never touched directly: every access goes through a hash-verified handle that is read-only at block level. Every action is recorded in a hash-chained audit log.",
  "guide.note3.title": "Tool scope",
  "guide.note3.body":
    "Agentopsy is post-mortem and self-hosted: it does not perform live forensics or acquisition from the original machine. No certified legal validity, but real forensic rigor.",

  // --- fase 2: investigación -----------------------------------------------
  "inv.loadingContext": "Loading case context…",
  "inv.goToAttack": "Go to ATT&CK",
  "inv.nothingToCorrelate": "There are no findings to correlate yet",
  "inv.noCaseBody":
    "Open one with «create case» in the sidebar and register evidence for it before investigating: the agent only works on a hash-verified handle.",
  "inv.mismatchLead":
    "Profile mismatch: the active agent is not the right one for some evidence of the case.",
  "inv.mismatchBodyA": "The case declares",
  "inv.mismatchBodyB": "but the determination over the content says",
  "inv.mismatchBodyC": "The case agent",
  "inv.mismatchBodyD":
    "will refuse to invoke tools over the evidence in disagreement while it lasts. Resolve it in",
  "inv.mismatchPath": "Evidence, Operating system",
  "inv.mismatchBodyE":
    "when you anchor the profile, Agentopsy re-routes to the matching sub-agent on its own. It does not change it for you (RULE 2, a disagreement is decided by the operator, not by the program).",
  "inv.collapsePanel": "Collapse the context panel",
  "inv.expandPanel": "Expand the context panel",
  "inv.evidence": "Evidence",
  "inv.evidences": "Evidence",
  "inv.scopeNote":
    "The agent analyses all of it on equal terms. To focus on one piece, ask for it in your message.",
  "inv.verified": "verified",
  "inv.noneRegistered": "none registered",
  "inv.noFindings": "No findings.",
  "inv.tools": "Tools",
  "inv.noneRun": "None run.",
  "count.failures.one": "{count} failure",
  "count.failures.other": "{count} failures",

  // --- fase 6: grafos de relaciones ----------------------------------------
  "graphs.title": "Relation graphs",
  "graphs.meta": "{done} of {total} findings with a graph",
  "graphs.loading": "Loading the case graphs…",
  "graphs.loadFailed": "The graphs could not be loaded:",
  "graphs.noCaseBody":
    "The graph is extracted from the text of a case's findings. Open one from the sidebar.",
  "graphs.extractingModel": "Model that extracts",

  // --- selección de ejecutor -----------------------------------------------
  "executor.pick": "Choose an executor…",
  "executor.unavailable": "{name} (unavailable)",
  "executor.local": "local",
  "executor.notAvailable": "{name} is not available.",

  // --- vocabulario del grafo: nodos ----------------------------------------
  "graphNode.ip": "IP address",
  "graphNode.domain": "Domain",
  "graphNode.hostname": "Host",
  "graphNode.user": "User",
  "graphNode.file": "File",

  // --- vocabulario del grafo: relaciones -----------------------------------
  "graphEdge.connection": "Connection",
  "graphEdge.process_spawn": "Process creation",
  "graphEdge.network_connection": "Network connection",
  "graphEdge.lateral_move": "Lateral movement",
  "graphEdge.malware": "Malicious code",
  "graphEdge.c2": "Command and control",
  "graphEdge.exfiltration": "Exfiltration",
  "graphEdge.beacon": "Beacon",
  "graphEdge.persistence": "Persistence",
  "graphEdge.priv_esc": "Privilege escalation",
  "graphEdge.rce": "Remote code execution",
  "graphEdge.logon": "Logon",
  "graphEdge.file_transfer": "File transfer",

  // --- figura del grafo ----------------------------------------------------
  "graph.figure": "Figure",
  "graph.selectLabel": "Figure",
  "graph.caseOption": "Case graph (all findings, merged)",
  "graph.optionCounts": "{nodes} nodes, {edges} edges",
  "graph.optionNoGraph": "no graph",
  "graph.extracting": "Extracting…",
  "graph.extractMissing": "Extract the {count} missing",
  "graph.reextractThis": "Extract this one again",
  "graph.extractThis": "Extract this finding",
  "graph.exportPng": "Export PNG",
  // FUNCIÓN «INVENTARIO» (grafos, en prueba 2026-09-04)
  "graph.inventoryBand":
    "{count} entities named by the findings with no relation asserted between them",
  "graph.inventoryTitle": "Entities with no relation",
  "graph.inventoryNote":
    "The findings name them, but no finding asserts a relation for them, so they are not part of the network. They travel whole inside the exported PNG.",
  "graph.inventoryCount": "{loose} of {total} entities",
  // FUNCIÓN «VISTAS» (grafos, en prueba 2026-09-04)
  "graph.viewLabel": "View",
  "graph.viewWhole": "Whole case",
  "graph.viewOption": "{label} ({count} findings)",
  "graph.viewDeclared": "View: {label}. Cut over {count} of the case's findings.",
  "graph.viewEmptyNote":
    "This view covers no finding with a graph extracted. Pick another one or extract the missing graphs.",
  "graph.viewAxis.tecnica": "ATT&CK technique",
  "graph.viewAxis.tactica": "ATT&CK tactic",
  "graph.viewAxis.evidencia": "Evidence",
  "graph.viewAxis.severidad": "Severity",
  // FUNCIÓN «LOCALIZADOR» (grafos, en prueba 2026-09-04)
  "graph.searchLabel": "Find an entity",
  "graph.searchPlaceholder": "IP, account, file, domain",
  "graph.searchNoMatch": "No entity of this figure contains {query}.",
  "graph.searchInInventory":
    "{value} is one of the entities with no relation: it is in the list below the figure, not in the network.",
  "graph.searchMatches": "{count} entities match. The first one is framed.",
  "graph.focusDepth": "Neighbourhood",
  "graph.focusDepth1": "1 hop",
  "graph.focusDepth2": "2 hops",
  "graph.exporting": "Exporting…",
  "graph.exportNotReady": "the figure to export could not be composed",
  "graph.needExecutor":
    "The graph is extracted by the model you select. Choose one in «Model that extracts», above: Agentopsy does not choose one for you.",
  "graph.extractingNth": "Extracting {n} of {total}: {title}",
  "graph.extractingAll": "Extracting the graphs…",
  "graph.backgroundNote":
    "You can switch section or close the tab: the extraction runs on the server and its progress is picked up when you come back here.",
  "graph.batchResult": "{done} of {asked} findings with a graph",
  "graph.extractedWith": "Extracted with {executor}",
  "graph.didNotFinish": "The extraction did not finish",
  "graph.caseTitle": "Case relation graph",
  "graph.findingTitle": "Finding relation graph",
  "graph.caseSubtitle": "{nodes} entities and {edges} connections, from {findings} findings",
  "graph.findingSubtitle": "{nodes} entities and {edges} connections",
  "graph.emptyCase":
    "No graph has been extracted in this case yet. The case graph merges those of the findings, so it appears as soon as there is one.",
  "graph.emptyFinding":
    "This finding names no entity of the five types. Empty graph, which is a legitimate result.",
  "graph.proposedByModel": "Proposed by the model",
  "graph.cardType": "Type",
  "graph.cardRelations": "Relations",
  "graph.relTowards": "{relation} towards {target}",
  "graph.relFrom": "{relation} from {source}",
  "graph.verifiedFromCase": "Verified, from the case",
  "graph.cardFindings": "Findings",
  "graph.cardFinding": "Finding",
  "graph.cardTool": "Tool",
  "graph.cardArtifactHash": "Artifact SHA-256",
  "graph.cardObserved": "Observed",
  "graph.noGraphFinding": "This finding has no graph",
  "graph.noGraphYet": "No graph yet",
  "graph.noFindingsBody":
    "The graph is extracted from the text of the findings, and this case has none yet.",
  "graph.pressExtract":
    "Press «Extract» and the selected model will read the finding text to propose which entities take part and with what relation.",
  "graph.revisionMeta": "Revision v{rev} of {total}",

  // --- exploración de la figura --------------------------------------------
  // El zoom y el desplazamiento son de la VISTA: el PNG que se exporta lleva
  // siempre la geometría calculada, mire el perito donde mire en ese momento.
  "graph.zoomIn": "Zoom in",
  "graph.zoomOut": "Zoom out",
  "graph.fitView": "Fit to view",
  "graph.zoomLevel": "{percent}%",
  "graph.viewportLabel": "Graph, draggable and zoomable",
  "graph.viewportHint":
    "Drag to move, scroll to zoom, click a node to focus it. The exported PNG always carries the computed layout.",
  "graph.layoutEnlarged":
    "The figure did not fit the standard canvas: enlarged to {width} by {height}.",
  "graph.layoutRelaxed": "{count} node pairs had to be separated so their labels would not overlap.",

  "count.attempts.one": "{count} attempt",
  "count.attempts.other": "{count} attempts",

  // --- figura del grafo: rótulos dentro del dibujo -------------------------
  "graph.svgCounts": "{nodes} nodes · {edges} edges",
  "graph.legendNodes": "NODES",
  "graph.legendEdges": "RELATIONS",
  "graph.provenance": "Case: {case} · Exported: {date} · {nodes} nodes, {edges} edges",

  // --- configuración: motor de análisis y sistema --------------------------
  "settings.tabsLabel": "Settings sections",
  "settings.lede": "Who runs the analysis. Choose one: Agentopsy does not do it for you.",
  "settings.queryingCaps": "Querying the api service capabilities…",
  "settings.modelDefault": "default",
  "settings.connectArrow": "connect",
  "settings.localNote": "Nothing leaves your machine.",
  "settings.cloudNote": "Uses your own subscription; the prompt leaves for that provider.",
  "settings.cliDefault": "CLI default",
  "settings.modelIdFor": "Model id for {name}",
  "settings.saved": "saved",
  "settings.power": "Power",
  "settings.noEfforts": "The catalog declares no reasoning levels for {model}.",
  "settings.pickModelFirst": "Pick a model first: the available levels depend on it.",
  "settings.effortMismatchA": "The saved level (",
  "settings.effortMismatchB":
    ") is not accepted by {model}: the turn would fail. Pick one of the ones above.",
  "settings.modelByCli": "The model is managed by this provider's CLI.",
  "settings.saveHost": "Save host",
  "settings.ollamaHostHint":
    "Write http://localhost:11434 to use the Ollama running on your own machine, or http://ollama:11434 for the one the compose starts. If it cannot be reached, start it listening on every interface: OLLAMA_HOST=0.0.0.0 ollama serve.",
  "settings.ollamaHostFromEnv":
    "Right now the deployment sets it. What you save here wins over that variable.",
  "settings.isDefaultEngine": "is the default engine",
  "settings.useAsDefault": "use as default",
  "settings.renewSession": "Renew the {name} session",
  "settings.connectName": "Connect {name}",
  "settings.startOllama": "Start the compose ollama service to use it.",
  "settings.timeout": "Time limit",
  "settings.saveFailed": "Could not save: {detail}",
  "settings.foot": "no API keys · sessions and settings only on your machine",
  "settings.noApi": "No connection with the api service",
  "settings.noApiBody":
    "The stack diagnostics could not be obtained. Check that the compose is up.",
  "settings.toolkits": "Toolkits",
  "settings.toolkitRunning": "running",
  "settings.toolkitStopped": "stopped or unreachable",
  "settings.toolkitUnknown": "not queryable from the api",
  "settings.catalogTools": "Catalog tools",

  // --- configuración: cabecera ---------------------------------------------
  "settings.refreshing": "Refreshing…",
  "settings.refresh": "Refresh status",

  // --- fase 3: matriz ATT&CK -----------------------------------------------
  "mitre.status.confirmada": "Confirmed",
  "mitre.status.sospechosa": "Suspected",
  "mitre.status.descartada": "Ruled out",
  "mitre.exploreMeta": "catalog exploration, no case",
  "mitre.exporting": "Exporting…",
  "mitre.exportLayer": "Export layer",
  "mitre.loading": "Loading the matrix…",
  "mitre.loadFailed": "The matrix could not be loaded:",
  "mitre.noSeed": "The ATT&CK seed is missing",
  "mitre.noSeedBody":
    "The catalog is derived from the orchestrator seed and could not be loaded.",
  "mitre.viewMatrix": "Matrix",
  "mitre.viewTimeline": "Timeline",
  "mitre.searchLabel": "Search technique or ATT&CK identifier",
  "mitre.searchPlaceholder": "Search technique or ID (T1055)…",
  "mitre.subTechniques": "Sub-techniques",
  "mitre.onlyCovered": "Covered only",
  "mitre.noCase": "No case",
  "mitre.exportSheet": "Export sheet",
  "mitre.exportNavigator": "Export Navigator layer",
  "mitre.exportFailed": "Could not export: {detail}",
  "mitre.phaseTactics": "{count} tactics",
  "mitre.summaryConfirmed": "Confirmed",
  "mitre.summarySuspected": "Suspected",
  "mitre.summaryTactics": "Tactics",
  "mitre.noMatches": "No matches",
  "mitre.nothingToShow": "Nothing to show",
  "mitre.noTechniqueMatch": "No technique matches «{query}».",
  "mitre.noCoverageYet":
    "No tactic has coverage yet. Turn off «Covered only» to see the full matrix.",
  "mitre.colCovered": "{covered}/{total} covered",
  "mitre.colDiscarded": "{count} ruled out",
  "mitre.colTechniques": "{count} techniques",
  "mitre.cellProposedBy": "{count} agent finding(s) cite this technique",
  "mitre.cellSub": "{count} sub",
  "mitre.legendConfirmed": "confirmed by the examiner",
  "mitre.legendSuspected": "suspected",
  "mitre.legendDiscarded": "ruled out by the examiner",
  "mitre.legendProposed": "agent proposal, not adjudicated",
  "mitre.legendNone": "not evaluated",
  "mitre.legendNote": "grey = not evaluated, never «absent»",
  "mitre.tlNoCaseBody":
    "The timeline is built from the real findings of the case. Turn off «No case» to go back to the active case.",
  "mitre.tlEmpty": "No correlated findings",
  "mitre.tlEmptyBody":
    "No case finding cites an ATT&CK technique yet. The timeline is built from the real findings the agent associates with a technique.",
  "mitre.detailOf": "Detail of {id}",
  "mitre.subCount": "{count} sub-techniques",
  "mitre.supportedBy": "Supported by",
  "mitre.goBackToCase":
    "Go back to the active case to record whether this technique has been confirmed, is under suspicion or has been ruled out in the investigation.",
  "mitre.agentProposal": "Agent proposal",
  "mitre.noAgentCitation":
    "No agent finding cites this technique. You can adjudicate it anyway if the evidence you have reviewed supports it.",
  "mitre.examinerVerdict": "Examiner verdict",
  "mitre.currently": "Currently:",
  "mitre.rationaleLabel": "Reason, required, recorded in the audit log",
  "mitre.rationalePlaceholder": "What evidence supports this verdict…",
  "mitre.withdraw": "Withdraw verdict",
  "mitre.needRationale":
    "A verdict with no reason is worth nothing in an expert report: the backend rejects it.",

  // --- fase 4: timeline forense --------------------------------------------
  "tl.title": "Forensic timeline",
  "tl.noDate": "no date",
  "tl.sev.low": "Low",
  "tl.sev.medium": "Medium",
  "tl.sev.high": "High",
  "tl.sev.critical": "Critical",
  "tl.cat.credenciales": "Credentials",
  "tl.cat.ssh": "SSH",
  "tl.cat.historial": "Shell history",
  "tl.cat.persistencia": "Persistence",
  "tl.cat.ejecutable_temporal": "Executable in temp",
  "tl.cat.web": "Web artifact",
  "tl.cat.logs": "Logs",
  "tl.cat.binario_sistema": "System binary",
  "tl.pager": "Page {page} of {total} · {count} {noun}",
  "tl.nounEvents": "events",
  "tl.nounRelevant": "relevant events",
  "tl.figureNotDrawn": "the figure is not drawn yet",
  "tl.loading": "Loading the timeline…",
  "tl.loadFailed": "The timeline could not be loaded:",
  "tl.noCaseBody":
    "The timeline is built from the audited activity and the evidence of the case. Open one from the sidebar.",
  "tl.tabFindingsTitle":
    "What happened on the device under investigation, according to the findings with an artifact timestamp.",
  "tl.tabFs": "File system (MACB)",
  "tl.tabRelevant": "Relevant events",
  "tl.tabRelevantTitle":
    "Forensically relevant file system events (credentials, persistence, history, logs, executables in temp folders…)",
  "tl.allUtc": "All times in UTC",
  "tl.searchLabel": "Search the timeline",
  "tl.searchInv": "Search by tool, argv, finding or technique…",
  "tl.searchRelevant": "Search by path, reason, category, MACB or inode…",
  "tl.searchFs": "Search by path, MACB or inode…",
  "tl.metaCounts": "{runs} runs · {findings} findings",
  "tl.evidenceSelect": "Evidence for the super-timeline",
  "tl.pickEvidenceFirst": "Pick the evidence first.",
  "tl.generating": "Generating…",
  "tl.generate": "Generate super-timeline",
  "tl.exportSheet": "Export sheet",
  "tl.loadingIncident": "Loading the incident timeline…",
  "tl.noPlaceable": "No events to place in time",
  "tl.noActivity": "No activity yet",
  "tl.noActivityBody":
    "The timeline fills up with every tool that runs and every finding the agent records, taken from the hash-chained audit log.",
  "tl.noEventMatch": "No event matches the search.",
  "tl.kindFinding": "Finding",
  "tl.kindRun": "Run",
  "tl.agent": "agent",
  "tl.noArgv": "(no argv)",
  "count.artifacts.one": "{count} artifact",
  "count.artifacts.other": "{count} artifacts",
  "tl.noEvidence": "No evidence registered",
  "tl.noEvidenceBody": "Register evidence in the case to build the file system super-timeline.",
  "tl.pickEvidence": "Pick the evidence",
  "tl.pickEvidenceBody":
    "The super-timeline is built over a specific piece of evidence. Agentopsy does not choose which one to analyse for you.",
  "tl.runningFls": "Running tsk_fls -m over the evidence…",
  "tl.asyncNote": "It is an asynchronous job: you can keep investigating while it runs.",
  "tl.analysisFailed": "The analysis failed.",
  "tl.notGenerated": "Super-timeline not generated",
  "tl.notGeneratedA": "The MACB timeline is built by running",
  "tl.notGeneratedB":
    "over the selected evidence. It is an asynchronous job: you can keep investigating while it runs.",
  "tl.generatedAt":
    "Super-timeline generated on {date} at {time} UTC · {count} events. Press «Generate super-timeline» again to recompute it.",
  "tl.truncated":
    "Showing {shown} of {total} events (trimmed to bound the size). Narrow it down with the search.",
  "tl.noFsEvents": "The evidence produced no file system events.",
  "tl.colTime": "Time (UTC)",
  "tl.colMacb": "MACB",
  "tl.colSize": "Size",
  "tl.colInode": "Inode",
  "tl.colPath": "Path",
  "tl.colDate": "Date (UTC)",
  "tl.colHour": "Time",
  "tl.colCategory": "Category",
  "tl.colReason": "Reason",
  "tl.oldSuperTimeline":
    "This super-timeline was generated with an earlier version without relevance triage. Press «Generate super-timeline» again to compute the relevant events.",
  "tl.relevantTruncated":
    "Showing {shown} of {total} relevant events (trimmed). Narrow it down with the search.",
  "tl.noRelevantMarked": "The triage marked no file system event as relevant.",
  "tl.noRelevantMatch": "No relevant event matches the search.",

  // --- figura de la línea de tiempo del incidente --------------------------
  "rail.noObservedAt":
    "{count} with no artifact timestamp (they are not placed on the axis: dating them with the time of the analysis would falsify the incident)",
  "rail.unparseable": "{count} with a mark unreadable as a date with a time zone",
  "rail.listTrimmed": " (list trimmed)",
  "rail.allPlaced": "All {count} findings of the case are placed on the axis.",
  "rail.ariaLabel": "Incident timeline: {count} events",
  "rail.title": "Incident timeline",
  "rail.case": "Case: {name}",
  "rail.exported": "Exported: {date} · {shown} events shown of {total} case findings",

  // --- fase 7: informe pericial --------------------------------------------
  "doc.perito.name": "Examiner",
  "doc.perito.colegiado": "Registration number",
  "doc.perito.colegiadoPh": "e.g. COL-1234",
  "doc.perito.organization": "Organisation",
  "doc.perito.organizationPh": "Laboratory or company",
  "doc.perito.email": "Contact",
  "doc.perito.emailPh": "name@domain",
  "doc.perito.version": "Version",
  "doc.perito.versionPh": "derived from the revisions",
  "doc.phase.material": "Gathering the case material…",
  "doc.phase.redactando": "The model is writing the report…",
  "doc.phase.validando": "Validating index, referents and audited commands…",
  "doc.phase.corrigiendo": "Validation rejected the draft: the model is correcting it…",
  "doc.phase.listo": "Report written.",
  "doc.written":
    "Report {version} written ({pages} pp.). It is born a DRAFT: review it and sign it to give it expert validity.",
  "doc.writeFailed": "The report could not be completed.",
  "doc.signed": "Document signed and marked as the final version.",
  "doc.blockNoExecutor":
    "Choose the model that will write the report: with no selection Agentopsy calls none.",
  "doc.blockNoFindings":
    "The case has no recorded finding: there is no investigation to report on. Analyse the evidence in Investigation first.",
  "doc.headerMeta": "{docs} · {signed} signed",
  "count.signed.one": "{count} signed",
  "count.signed.other": "{count} signed",
  "doc.downloadPdf": "Download PDF",
  "doc.loading": "Loading the case reports…",
  "doc.loadFailed": "The documents could not be loaded:",
  "doc.noCaseBody": "Reports are written and signed inside a case. Open one from the sidebar.",
  "doc.section": "Case documents",
  "doc.searchLabel": "Search document",
  "doc.searchPlaceholder": "Search by title, evidence or hash…",
  "doc.filterAll": "All",
  "doc.statusDraft": "Draft",
  "doc.statusFinal": "Final",
  "doc.groupLabel": "Group documents",
  "doc.groupEvidence": "by evidence",
  "doc.groupType": "by type",
  "doc.groupNone": "ungrouped",
  "doc.none":
    "There is no report yet. It is issued when the investigation is finished, down below.",
  "doc.noMatch": "No document matches the search or the filter.",
  "doc.statusDraftLower": "draft",
  "doc.statusFinalLower": "final",
  "doc.pagesShort": "pp.",
  "doc.finalize": "Finish investigation",
  "doc.finalizeBody":
    "The model you choose writes the COMPLETE expert report from all the findings, evidence, audited runs and ATT&CK verdicts of the case. Every report is unique: only the index is common. Agentopsy validates that the index is whole, that no identifier or hash is made up and that every cited command is the literal argv from the audit log.",
  "doc.writingModel": "Model that writes",
  "doc.peritoFields": "Examiner details (optional)",
  "doc.backgroundNote":
    "You can switch section or close the tab: the writing runs on the server and its progress is picked up when you come back here.",
  "doc.notPublished": "The report was not published",
  "doc.notPublishedBody":
    "No document has been saved: the report is published whole or not at all. You can press «Finish investigation» again.",
  "doc.writing": "Writing report…",
  "doc.noReportYet": "No report yet",
  "doc.noneOpen": "No document open",
  "doc.noReportYetBody":
    "The expert report is issued once, when the investigation ends: press «Finish investigation» in the left-hand panel and the selected model will write it from start to finish from the case findings and evidence.",
  "doc.pickToRead":
    "Pick a document from the list to read it, verify its integrity and download it as a PDF.",
  "doc.pages": "{count} pages",
  "doc.verifyIntegrity": "Verify integrity",
  "doc.signAsFinal": "Sign and mark final",
  "doc.deleteDraft": "Delete draft",
  "doc.verifyOk":
    "Integrity verified · the recomputed SHA-256 matches the registered one ({hash})",
  "doc.verifyBad":
    "The recomputed SHA-256 ({got}) does NOT match the registered one ({want}). The document has changed since it was registered.",
  "doc.footGenerated": "Generated by Agentopsy",
  "doc.footSigned": "Signed",

  // --- chat de investigación -----------------------------------------------
  "chat.prompt1": "look for persistence",
  "chat.prompt2": "analyse network connections",
  "chat.prompt3": "generate a file system timeline",
  "chat.toolchain": "Execution chain",
  "count.steps.one": "{count} step",
  "count.steps.other": "{count} steps",
  "chat.chainRunning": "in progress",
  "chat.chainDone": "recorded",
  "chat.background":
    "Analysing in the background · you can switch section or close the tab: the analysis does not stop and the findings are saved as they are made.",
  "chat.stoppedByOperator": "Analysis stopped by the operator.",
  "chat.jobFailed": "The background analysis failed.",
  "chat.resuming": "Resuming the analysis in progress…",
  "chat.launching": "Launching the analysis in the background…",
  "chat.launchFailed": "The analysis could not be launched. Is the compose up?",
  "chat.stopping": "Stopping the analysis…",
  "chat.startTitle": "What do we ask the agent for?",
  "chat.startBody":
    "It runs the forensic toolkit over every verified piece of evidence of the case and leaves every command in the hash-chained audit log. To focus on one piece of evidence, say so in the message.",
  "chat.noEvidenceTitle": "This case has no evidence yet",
  "chat.noEvidenceBody":
    "The agent analyses the verified evidence of the case, so at least one piece has to be registered first. Its baseline hash is computed when you do.",
  "chat.roleExaminer": "Examiner",
  "chat.runningTool": "running {tool}",
  "chat.reasoning": "reasoning",
  "chat.processing": "processing result",
  "chat.recording": "recording finding",
  "chat.working": "working",
  "chat.recorded": "recorded in the case",
  "chat.jumpTitle": "Back to the end of the conversation",
  "chat.jump": "Go to the end",
  "chat.analysisRunning": "analysis running",
  "chat.placeholder": "Ask the agent for something",
  "chat.pickExecutor": "Pick an executor",
  "chat.executorTitle": "Analysis executor",
  "chat.executor": "Executor",
  "chat.queryingCaps": "querying capabilities…",
  "chat.modelTitle": "Model · {name}",
  "chat.loadingModels": "loading models…",
  "chat.recommended": "recommended",
  "chat.savedAs": "Saved as",
  "chat.noEfforts": "The catalog declares no levels for {model}.",
  "chat.pickModelFirst": "Pick a model first: the levels depend on it.",
  "chat.effortMismatch":
    "{model} does not accept «{effort}»: the turn would fail. Pick one of the ones above.",
  "chat.enterSends": "Enter sends",
  "chat.stopTitle": "Stop the running analysis (keeps what is already recorded)",
  "chat.stoppingBtn": "Stopping…",
  "chat.send": "Send",

  // --- bandeja: progreso del hash-gate y avisos ----------------------------
  "inbox.phase.hashing": "SHA-256 of the source",
  "inbox.phase.copying": "copying to the case folder",
  "inbox.phase.verifying": "re-hash of the copy",
  "inbox.preparing": "Preparing the registration…",
  "inbox.segmentOf": "segment {index}/{total}",
  "inbox.dontClose": "Do not close this window until it finishes.",
  "inbox.registeringName": "Registering",
  "inbox.evidenceWord": "evidence",
  "inbox.title": "Inbox ./evidence",
  "inbox.uploadFailed": "The evidence could not be uploaded:",
  "inbox.registerFailed": "The evidence could not be registered:",
  "evidenceTable.empty": "No evidence registered",
  "evidenceTable.emptyBody":
    "Drop the forensic image on the zone above or pick it from the inbox. Nothing reaches a tool before its baseline hash exists.",

  // --- cliente HTTP: fallos de transporte ----------------------------------
  "http.gateway504": "HTTP 504: the api did not answer in time through the proxy.",
  "http.gateway":
    "HTTP {status}: the proxy could not talk to the api service. It may be starting up or restarting (docker compose ps api).",
  "http.notJson": "HTTP {status}: non-JSON response from {source}.",
  "http.theApi": "the api",
  "http.badResponse": "Invalid response from the server.",
  "http.noStreamBody": "the api returned no streaming body",

  // --- evidencia: rótulo suelto --------------------------------------------
  "evidence.verifyFailedLabel": "The evidence could not be verified:",

  // --- chat: selector de modelo --------------------------------------------
  "chat.modelPick": "model",
  "chat.modelPickTitle": "Provider model",
  "chat.pickExecutorFirst": "Pick an executor first",
} as const;

//: La identidad de cada mensaje. Se deriva del catálogo inglés, nunca se
//: escribe a mano: así no puede quedar desalineada con lo que de verdad hay.
export type MessageKey = keyof typeof en;
