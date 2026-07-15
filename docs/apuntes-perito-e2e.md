# Apuntes de perito — prueba end-to-end de FORENSIA

> Cuaderno de campo escrito **desde la óptica de un perito forense** mientras uso
> FORENSIA de punta a punta sobre el caso **"Caso Con playwright"** con evidencia
> real. Anoto: lo que la herramienta **captura**, lo que **no**, lo **útil**, y lo
> que **falta** y sería necesario en un peritaje serio. Fecha: 2026-07-15.

## 0 · Contexto de la prueba

- **Caso:** "Caso Con playwright" (id `54e430ef…`), creado vacío por el operador.
- **Evidencia disponible en el inbox `./evidence`:**
  - `dvwa-container-rootfs/dvwa-disk.raw` — imagen de disco (~1,1 GB), Linux (DVWA).
  - `dvwa-installer-iso/DVWA-1.0.7.iso` — ISO instalador (~503 MB).
  - `hackable-secret-hacker/Hackable-Secret_Hacker.rar` — archivo comprimido (~2,5 GB).
  - `lab26-virtualbox/…` — VM VirtualBox.
  - `metasploitable2-linux/…` — VM Linux vulnerable.
- **Ejecutor IA:** Claude Code (opus) — CLI cloud, bajo la suscripción del operador.

---

## 1 · Registro de evidencia y cadena de custodia

Registré `dvwa-container-rootfs/dvwa-disk.raw` al caso.

**✔ Bien:**
- Se calcula un **SHA-256 baseline** en el ingreso (`d9d08eabe8008bccc…09f8f9`) —
  base de la cadena de custodia. Correcto: nada se analiza antes del hash.
- El **triage determina el `os_profile` de forma automática** desde el contenido
  (detectó `unix`), no del host. Muy útil: el perito no tiene que anclarlo a mano
  si la determinación es clara.
- La evidencia se copia a una ruta interna del caso
  (`/cases/cases/<caso>/evidence/<id>/original.raw`), separada del original.

**⚠ A mejorar (observado en la respuesta de registro):**
- Los campos `read_only` y `size_bytes` vuelven **`null`** en la respuesta de la
  API. Como perito quiero ver **explícitamente** el tamaño de la evidencia y una
  confirmación de que se abrió en **solo lectura a nivel de bloque** (no solo
  `mount -o ro`). Ahora mismo hay que confiar en que lo hace por dentro.
- No se muestra el **hash del original del inbox vs el de la copia de trabajo**
  por separado — un perito querría constatar que copia y original coinciden.
- No hay un **acta de adquisición** automática (operador, testigos, bloqueador de
  escritura, hora) como sí exige un peritaje formal.

## 2 · Análisis del agente (Chat Investigación)

Lancé al agente (Claude Code/opus) sobre `original.raw` (la imagen DVWA).

**✔ Bien — trabajo forense real y trazable:**
- El agente ejecuta herramientas de verdad del maletín unix: `tsk_mmls` (tabla de
  particiones), `tsk_fls` (listado de ficheros), `tsk_icat` (extracción), y
  `bulk_extractor` (carving). Detectó correctamente que la imagen **no tiene
  tabla de particiones** y es un **filesystem ext de contenedor** — conclusión
  forense acertada.
- **Cada ejecución queda como `artifact_run` en el audit hash-encadenado** (conté
  30 artifact_run en 12 iteraciones), con el argv literal, la herramienta, el hash
  de la evidencia y del artefacto de salida. Esto es **oro para el perito**:
  reproducibilidad total y cadena de custodia de cada paso.
- Registra el **egress cloud** (`agent_cloud_egress`) en el audit: queda constancia
  de qué salió al proveedor de IA (RGPD).

> **Dato medido:** con el timeout por iteración subido a 300s, un análisis
> *acotado* (pidiendo explícitamente registrar 3–5 hallazgos y ≤4 tools) corrió
> **más de 11 minutos sin terminar** (el cliente abortó a los 700s) y aun así
> produjo **1 hallazgo**. Las iteraciones de opus sobre las salidas de las tools
> son de 2–4 min cada una. **Conclusión: hoy no es práctico para un caso real sin
> ejecución asíncrona.**

**⚠ Carencia grave observada — análisis largo se corta:**
- Un análisis de disco real **tarda** (>7 min para una pasada superficial). El
  flujo por **streaming ata el turno del agente a la conexión del navegador**: al
  cerrarse el cliente (timeout, cierre de pestaña, corte de red) el turno se
  **aborta a mitad** y solo persiste lo ya registrado (en mi caso, 1 de los N
  hallazgos que iba a producir). **No hay análisis en segundo plano, ni
  reanudable, ni cola de trabajos.** Para un perito con evidencia de GB-TB esto es
  crítico: necesita lanzar el análisis y volver luego, con garantía de que
  termina y persiste.
- El agente hace **muchas iteraciones de exploración antes de registrar**
  hallazgos; si se corta, se pierde el razonamiento aunque los `artifact_run`
  queden. Sería mejor **persistir hallazgos incrementalmente** y poder continuar.
- No hay **límite de tiempo/coste visible** ni estimación previa del análisis; el
  perito no sabe cuánto va a tardar ni cuánto va a costar (tokens) antes de lanzar.

**⚠ Segunda carencia — timeout por iteración de 120s:**
- El ejecutor aborta una iteración si el CLI tarda >120s en responder
  (`ExecutorError: Claude Code superó el timeout de 120s`). En forense el modelo
  razona sobre salidas grandes de las herramientas y **supera ese límite con
  facilidad**, tumbando el análisis entero a mitad. El default (`DEFAULT_TIMEOUT_S
  = 120`, ajustable con `FORENSIA_EXECUTOR_TIMEOUT`) es **demasiado bajo** para
  este uso; lo subí a 300s para poder terminar. Debería venir más alto por defecto
  para cargas forenses, o adaptarse al tamaño de la salida.

**⚖ Sobre la "inteligencia" del agente con las herramientas (revisando el argv):**
- La **selección de herramientas y los argumentos son forense-correctos** y en
  orden lógico: `mmls` → `fls -o 0` → `fls -o 0 -r` → `fls -o 0 -m /` (body de
  mactime) → `bulk_extractor`. No inventa comandos ni flags; el allowlist cerrado
  del backend evita barbaridades. En elección de tool, **razonable**.
- El problema NO es la elección, sino:
  1. **Razonamiento lento por iteración** (el `claude -p` tarda 80–226s en decidir
     el siguiente paso). Cuello de botella = latencia del modelo, no las tools.
  2. **Explora mucho y sintetiza poco:** recopiló material bueno pero registró solo
     1 hallazgo. Caso claro: generó un **body file de mactime** (el insumo de una
     super-timeline) y **no lo procesó** (ni `mactime`, ni hallazgo). Recopila pero
     no cierra el bucle recopilar→analizar→registrar.
  3. **Redundancia leve** (dos `bulk_extractor`).
- Es más un problema de **orquestación/prompt** (forzar registrar tras cada tool,
  y encadenar `fls -m` → `mactime` → timeline) que de "inteligencia" del modelo.

**★ Útil:**
- El panel lateral del chat muestra en vivo las herramientas usadas (n OK / n
  fallos) y el **coste por ejecutor** (tokens · USD) — transparencia de coste.
- El **timeout por ejecutor es configurable** (`FORENSIA_EXECUTOR_TIMEOUT`), así
  que el perito puede subirlo — pero tiene que saber que existe.

## 3 · Timeline

**✔ Bien:** Renderiza los hallazgos reales en orden cronológico, agrupados por
día, con métricas por severidad (Críticos/Altos/Medios/Bajos), buscador, filtro
por severidad y por fuente (herramienta). Cada evento muestra hora, herramienta
(`tsk_fls`), severidad, id de evidencia y la descripción forense literal. Limpio
y útil para una vista rápida del caso.

**⚠ Carencia importante de concepto (perito):** este timeline es una **línea de
tiempo de HALLAZGOS** (ordena por `created_at`, es decir, *cuándo el agente
registró* la conclusión), NO una **super-timeline forense del sistema** (cuándo
ocurrieron los hechos en la evidencia: tiempos MACB de `$MFT`/ext, EVTX, prefetch,
etc.). Un peritaje real necesita la segunda: reconstruir la secuencia de eventos
del SISTEMA (p. ej. con `plaso`/`mactime`, que el maletín SÍ tiene) sobre una
línea temporal absoluta. Hoy FORENSIA ejecuta esas herramientas pero **no vuelca
su salida a esta vista**: el timeline muestra el momento del análisis, no el
momento del hecho. Sería la mejora de mayor valor pericial.

**⚠ Menor:** la fecha del evento usa la hora local del navegador; para un informe
conviene **UTC explícito** (como sí hace el resto del análisis).

## 4 · MITRE ATT&CK

**✔ Bien:** Pinta la **matriz ATT&CK Enterprise completa** (15 tácticas, ~240
técnicas, conteo de sub-técnicas). Dos ejes que no se funden: **propuesta del
agente** (derivada de los `mitre_hints` de hallazgos + correlación anclada) y
**dictamen del perito** (confirmada/sospechosa/descartada, con motivo obligatorio,
auditado y hash-encadenado). Gris = *no evaluada*, denominador honesto. La
correlación bajo demanda (`annotate_mitre`) persiste y puebla el tablero
(verificado esta sesión sobre otro caso).

**⚠ Carencias (perito):**
- El **agente solo puede proponer técnicas de la semilla curada** (~49), no de
  todo Enterprise. Si encuentra evidencia de una técnica fuera de la semilla, no
  se auto-propone (el perito sí puede dictaminarla a mano). Ampliar cobertura del
  agente = ampliar la semilla.
- La correlación es un **paso aparte** que hay que pedirle al agente; no se ancla
  automáticamente al registrar el hallazgo salvo que el modelo ponga el hint.
- No hay **exportación de la matriz** (a imagen/CSV/Navigator layer) para adjuntar
  al informe.

## 5 · Documentos / informe pericial

**✔ Bien:** Almacén real con **integridad SHA-256** por documento; verificar,
firmar (borrador→final, no se puede borrar un final — cadena de custodia),
eliminar, y **descarga en PDF pericial** (portada, metadata, índice, secciones
H2/H3, tablas, hallazgos con severidad, citas, cabecera/pie). Verificado
end-to-end esta sesión.

**⚠ Carencia mayor:** **no hay generador** — la capa de síntesis que redacta el
informe a partir de los hallazgos/audit/evidencia **no existe todavía**. Hoy los
documentos hay que crearlos vía API (o el agente, cuando tenga la tool). Para el
perito, poder pulsar "generar informe" y que ensamble los hallazgos + cadena de
custodia + cobertura MITRE en el formato pericial sería lo más valioso.

**⚠ Otras:**
- Los **datos del perito** (nombre, DNI, nº de colegiado, marco) que la portada
  pericial necesita no se capturan de forma estructurada (la pestaña *Operador y
  reportes* de Configuración es vista previa / deshabilitada).
- No hay **versionado/diff** entre borradores ni **exportar/compartir** real
  (coherente con "sin nube", pero un perito querría al menos exportar a un formato
  estándar firmado).

---

## ✔ Lo que la herramienta CAPTURA bien

- **Integridad y cadena de custodia:** SHA-256 baseline al ingresar, log de
  auditoría **append-only y hash-encadenado**, y cada ejecución de herramienta
  registrada como `artifact_run` con su **argv literal**, versión de tool, hash de
  evidencia y hash de la salida. Reproducibilidad total.
- **Triage automático del OS** desde el contenido de la evidencia (no del host),
  con enrutado al sub-agente correcto (unix/windows).
- **Ejecución de herramientas forenses reales** del maletín (TSK `mmls/fls/icat`,
  `bulk_extractor`, y disponibles Volatility3, plaso, RegRipper, EZ tools,
  hayabusa/chainsaw, yara, foremost, hashdeep…) sobre la evidencia, sin montar el
  filesystem cuando se puede (lee el raw directamente).
- **Razonamiento forense correcto:** en la prueba identificó bien que la imagen no
  estaba particionada y era la capa de un contenedor Docker (`.dockerenv`).
- **Transparencia del entorno:** Estado del Sistema muestra qué tools/ejecutores
  están vivos; el chat muestra coste por ejecutor (tokens · USD) y el egress cloud
  queda auditado (RGPD).
- **Dos ejes MITRE que no se funden** (propuesta del agente vs dictamen del perito)
  con denominador honesto, y **documentos con integridad + PDF pericial**.

## ✘ Lo que NO captura / limitaciones observadas

- **No hay super-timeline forense del SISTEMA** (MACB de `$MFT`/ext, EVTX,
  prefetch, plaso). El "Timeline" es de *hallazgos del agente*, no de los *hechos
  en la evidencia*. Es la carencia conceptual más grande.
- **No sintetiza informes**: no ensambla los hallazgos en el informe pericial; hay
  que crear los documentos a mano (o vía API). La capa `forensia.reports` es solo
  almacén, sin generador.
- **No captura los datos del perito** (nombre, DNI, colegiado, marco) de forma
  estructurada para la portada del informe.
- El **agente solo auto-propone técnicas MITRE de la semilla curada** (~49), no de
  todo Enterprise.

## ★ Útil para el perito

- Todo pasa por **una sola pantalla** (web local), con las 7 vistas coherentes.
- El **audit hash-encadenado** es directamente citable en un informe: cada
  conclusión tiene su procedencia (herramienta, argv, hashes).
- **Verificar integridad** de evidencia y de documentos re-calcula el hash y
  compara — un clic para constatar que nada se alteró.
- **Sin API keys y con aviso de egress**: el perito controla qué sale y a dónde.
- El **PDF pericial** ya tiene el formato legal (portada, custodia, hallazgos,
  cabecera/pie) — buena base para el entregable.

## ⚠ Carencias — lo que faltaría para un peritaje real (priorizado)

1. **Análisis en segundo plano / reanudable + cola de trabajos.** Hoy el turno se
   ata a la conexión; se corta si el cliente se desconecta, y las iteraciones de
   opus sobre salidas grandes son lentas (vi una de 226s). Para evidencia de GB-TB
   es imprescindible lanzar y volver, con persistencia y reanudación.
2. **Timeout por iteración más alto por defecto** (hoy 120s tumba análisis;
   configurable pero poco visible).
3. **Super-timeline forense del sistema** (plaso/mactime → una vista temporal
   absoluta de los hechos), no solo la de hallazgos.
4. **Generador de informe** (hallazgos + custodia + cobertura MITRE → PDF pericial
   con un clic), con captura estructurada de los datos del perito.
5. **Confirmación explícita de solo-lectura a nivel de bloque** y del tamaño en la
   UI/registro (hoy vuelven `null` por API), y **acta de adquisición** (operador,
   bloqueador de escritura, testigos, hora UTC).
6. **Exportaciones** para el informe: matriz MITRE (Navigator layer/CSV/imagen),
   super-timeline (CSV), y firma/versionado de documentos.
7. **Estimación previa de tiempo/coste** del análisis antes de lanzarlo.

---

## ✎ Mejoras ya aplicadas a raíz de esta prueba (2026-07-15)

1. **Registrar en caliente (carencia nº "explora pero no sintetiza")** — el motor
   ahora fuerza al agente a `record_finding` tras cada herramienta: prompt estricto
   + **recordatorio estructural en el loop** (si encadena ≥3 tools sin registrar,
   se le inyecta un aviso). Así, aunque el análisis se corte, lo concluido queda.
2. **Pipelines forenses fijos en los playbooks** (unix y windows): super-timeline
   `tsk_fls -m → tsk_mactime`, IOCs `bulk_extractor → jq → hallazgo por categoría`,
   eventos/registro en Windows. Con la regla "cierra el bucle: recopilar → analizar
   → registrar" (ataca el body de mactime huérfano que vi en la prueba).
3. **Ejecución asíncrona** — nuevo `POST /api/agent/analyze` que arranca el
   análisis en **segundo plano** (devuelve un `job_id` al instante) y
   `GET /api/agent/jobs/{id}` para consultar estado. Ya no lo mata una
   desconexión ni el timeout del cliente; los hallazgos persisten en caliente.

**Resultado medido tras las mejoras (mismo caso, mismo disco):**
- `POST /analyze` devolvió en **0,27s** (antes bloqueaba minutos) → async OK.
- El análisis en background pasó de **1 a 4 hallazgos** en poco tiempo, y son los
  que antes NO se registraban: contenedor Docker con DVWA, DVWA como app
  deliberadamente vulnerable, y sus credenciales por defecto. El nudge + los
  pipelines cierran el bucle *recopilar → analizar → registrar* que faltaba.
**Async llevado a la UI + probado robusto (2026-07-15):** el chat ya no usa
streaming; `send()` lanza `POST /api/agent/analyze` (vuelve al instante), sondea el
job con progreso ("Analizando en segundo plano · Ns · N hallazgos") y **reanuda**
al recargar si hay un job en curso. Test de dos sesiones con Playwright:
- Sesión 1 lanza el análisis y **cierra el navegador a mitad**.
- Verificado por API: el job seguía **`running`** tras el cierre (sobrevive a la
  desconexión) y los hallazgos seguían.
- Sesión 2 (navegador nuevo) **reanudó** el análisis en curso y mostró su
  progreso; el análisis **terminó** (job `done`) y los hallazgos pasaron de 4 a 5.
- **RESULT: ROBUSTO OK** — se cumple "lanzar y volver, con garantía de que termina
  y persiste".

Pendientes de las carencias: super-timeline del *sistema* volcada a la vista
Timeline, generador de informe, captura de datos del perito, y exportaciones.

---

*Prueba realizada de punta a punta conduciendo la app con Playwright como perito.
Evidencia real (`dvwa-disk.raw`), ejecutor Claude Code/opus. Todo lo funcional se
verificó en vivo; las carencias son observaciones directas del uso.*
