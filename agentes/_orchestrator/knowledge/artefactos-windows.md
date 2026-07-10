# Guía de interpretación de artefactos — Windows

Corpus recuperable (RAG, ver `diseno-fase2.md` §9.3) para la capa de síntesis. Cada
sección es una guía **artefacto → interpretación → técnica MITRE**. Sirve para
razonar sobre lo que un artefacto significa **sin confiarlo a la memoria del
modelo**, y para que la correlación MITRE respete la enum cerrada.

## Cómo usar esta guía (reglas heredadas)

- **Enum cerrada de MITRE.** Todo `technique_id` que aparece aquí existe en
  `mitre_attack_seed.md`. El orquestador (`mitre.md`) solo emite ids de esa semilla
  y **nunca** correlaciona una técnica sin `relatedFindingIds` no vacío: sin un
  finding con procedencia que la sostenga, la técnica queda `dismissed`/`pending`,
  jamás `correlated` (anti-alucinación, `diseno-fase2.md` §4.3).
- **Los `tool_id` son del catálogo.** Cada herramienta citada existe en
  `forensia.toolkit.catalog` y está en la allowlist del agente
  (`policy/tools.yaml`). El agente emite `{tool_id, params}`, nunca un comando.
- **Cadena de custodia (soundness §7).** Los artefactos de contenedor (registro,
  EVTX, `$MFT`) **no** se procesan sobre la imagen cruda: se **localizan** con
  `tsk_fls`, se **pre-extraen** con `tsk_icat` a través del handle read-only, y se
  procesa **solo el fichero derivado**. Ninguna guía induce a montar la imagen.
- **Un artefacto es una hipótesis; la correlación es la conclusión.** Sube la
  confianza solo cuando varias fuentes independientes coinciden en la misma ventana
  temporal.

Formato fijo por sección: **Qué es** · **Cómo se lee** · **Técnica(s) MITRE** ·
**Falsos positivos / cautelas**.

---

## Amcache (`Amcache.hve`)

**Qué es.** Hive del registro (`C:\Windows\AppCompat\Programs\Amcache.hve`) que
registra metadatos de ejecutables presentes/ejecutados: ruta, tamaño, SHA-1,
primera aparición. Evidencia de **presencia y ejecución** de binarios.

**Cómo se lee.** Es un hive: `tsk_fls` para localizarlo → `tsk_icat` para
extraerlo (handle read-only) → `regripper` con `plugin: amcache` sobre el fichero
derivado. Cruza el SHA-1 y la ruta con el `$MFT` (`mftecmd`) y con EVTX 4688
(`evtxecmd`) para fijar la hora de ejecución. Alternativa CSV: `amcacheparser` sobre el mismo hive derivado emite un CSV estructurado (mejor para timelining y cruce a escala); `regripper` `plugin: amcache` sigue siendo el triage rápido. Cita una sola fuente por hallazgo.

**Técnica(s) MITRE.** `T1059` (Command and Scripting Interpreter) / `T1059.003`
(Windows Command Shell) como evidencia de ejecución del binario. Si el binario
apunta a un servicio, **corrobora** `T1543.003` (Windows Service).

**Falsos positivos / cautelas.** Amcache lista binarios que existieron aunque no
se ejecutaran necesariamente; no es prueba directa de ejecución por sí solo (por
eso se cruza con 4688/Prefetch). Las marcas de tiempo internas no siempre son la
hora de ejecución. No confundir «primera aparición» con «primera ejecución».

---

## Prefetch (`C:\Windows\Prefetch\*.pf`)

**Qué es.** Ficheros de precarga que Windows genera al ejecutar un programa:
nombre del ejecutable, contador de ejecuciones y últimas marcas de ejecución.
Evidencia clásica de **ejecución**.

**Cómo se lee.** **No hay parser dedicado de Prefetch en la allowlist** (no existe
un `tool_id` tipo «PECmd» en `catalog.py`; RULE 2: no se inventa). Se corrobora por
otras vías: (a) super-timeline con `plaso_log2timeline` → `plaso_psort`, que sí
parsea Prefetch como fuente; (b) correlación con **Amcache** (`regripper`) y **EVTX
4688** (`evtxecmd`) del mismo binario; (c) ubicación del `.pf` en el árbol con
`tsk_fls` y de su binario en el `$MFT` (`mftecmd`). Si hace falta el contenido
crudo del `.pf`, se extrae con `tsk_icat`, pero **su interpretación queda a la
timeline/correlación**, no a un parser propio.

**Técnica(s) MITRE.** `T1059` / `T1059.003` (evidencia de ejecución). Se afirma
solo cuando la timeline o la correlación Amcache/4688 lo sostienen.

**Falsos positivos / cautelas.** Prefetch puede estar **deshabilitado** (SSD,
servidores) → su ausencia no prueba no-ejecución. El contador y las fechas se
sobrescriben; un borrado selectivo de `.pf` puede ser anti-forense (correlaciónalo
con `$MFT`/timeline). Sin parser dedicado, no cites un `tool_id` de Prefetch.

---

## ShimCache / AppCompatCache

**Qué es.** Caché de compatibilidad de aplicaciones en el hive `SYSTEM`
(`ControlSet\...\AppCompatCache`). Registra ruta, marca de tiempo del `$STANDARD_
INFORMATION` del binario y (según versión) un flag de ejecución. Evidencia de
**presencia** (y a veces ejecución) de binarios.

**Cómo se lee.** Hive `SYSTEM`: `tsk_fls` → `tsk_icat` → `regripper` con
`plugin: appcompatcache` sobre el hive derivado. Cruza el orden de la caché y las
rutas con Amcache y con la timeline (`tsk_mactime`). Alternativa CSV: `appcompatcacheparser` sobre el hive `SYSTEM` derivado → CSV estructurado; `regripper` `plugin: appcompatcache` para el triage rápido.

**Técnica(s) MITRE.** `T1059` / `T1059.003` (presencia/ejecución de un binario de
línea de comandos). Prefiere la sub-técnica solo si el binario lo justifica.

**Falsos positivos / cautelas.** En muchas versiones de Windows ShimCache prueba
**existencia/registro en la caché, no ejecución**: la marca es la del `$SI` del
binario, no la hora en que corrió. El orden de entradas es informativo pero no un
reloj. Corrobora siempre con Amcache/4688 antes de afirmar ejecución.

---

## ShellBags (`UsrClass.dat`, `NTUSER.DAT`)

**Qué es.** Estructuras del registro por usuario que guardan preferencias de vista
de carpetas del Explorador. Prueban que un usuario **navegó** a una carpeta
concreta, incluidas rutas de red, dispositivos extraíbles y carpetas ya borradas.

**Cómo se lee.** Hives de usuario (`UsrClass.dat`, `NTUSER.DAT`): `tsk_fls` →
`tsk_icat` → `regripper` con `plugin: shellbags`. Cruza las rutas con la timeline
(`tsk_mactime`) y con USBSTOR si aparecen letras de unidad extraíble. Alternativa CSV: `sbecmd` sobre el **directorio** de hives de usuario → CSV; `regripper` `plugin: shellbags` para el triage rápido.

**Técnica(s) MITRE.** `T1083` (File and Directory Discovery): evidencia de
navegación/descubrimiento de carpetas por parte del usuario o del atacante.

**Falsos positivos / cautelas.** Los ShellBags reflejan **navegación de la UI**, no
necesariamente intención maliciosa ni copia de datos: un usuario legítimo genera
muchos. La marca temporal es la del ShellBag, no la de creación de la carpeta.
Úsalos para *situar* actividad, no como prueba única de exfiltración.

---

## `$MFT` — `$STANDARD_INFORMATION` vs `$FILE_NAME` (timestomping)

**Qué es.** La Master File Table de NTFS mantiene dos juegos de marcas de tiempo
por fichero: `$STANDARD_INFORMATION` (`$SI`, modificable desde user-land) y
`$FILE_NAME` (`$FN`, actualizado por el kernel). Su incoherencia delata
**manipulación de marcas de tiempo (timestomping)**.

**Cómo se lee.** `$MFT`: `tsk_fls` → `tsk_icat` → `mftecmd` (CSV) sobre el `$MFT`
derivado. Señales: `$SI` **anterior** a `$FN`, subsegundos de `$SI` en cero, o
fechas que no cuadran con la timeline (`tsk_mactime`). Consulta el CSV con `jq`
por ruta/ventana; no vuelques el CSV entero.

**Técnica(s) MITRE.** `T1070` (Indicator Removal; el timestomp no tiene sub-técnica
en la semilla → técnica padre) y `T1036` (Masquerading, cuando las marcas se
falsean para imitar ficheros del sistema).

**Falsos positivos / cautelas.** Instaladores, procesos de copia y algunas
utilidades legítimas alteran `$SI`; una sola discrepancia no es prueba. Confírmalo
sobre binarios sospechosos y con contexto (ubicación en `%TEMP%`, falta de firma).
`$FN` puede faltar en ciertas entradas.

---

## USBSTOR / `MountedDevices` / `setupapi.dev.log`

**Qué es.** Claves del hive `SYSTEM`
(`...\Enum\USBSTOR`, `MountedDevices`) y el log `setupapi.dev.log` que registran
dispositivos de almacenamiento USB conectados: VID/PID, número de serie, primera y
última conexión, letra de unidad asignada.

**Cómo se lee.** Hive `SYSTEM`: `tsk_fls` → `tsk_icat` → `regripper` con
`plugin: usbstor` y `plugin: mountdev`. El `setupapi.dev.log` se localiza con
`tsk_fls` y se extrae con `tsk_icat`; **no tiene parser dedicado** (léelo como
texto con `strings_head`/`file_info`, sin inventar un `tool_id`). Cruza el número
de serie y las horas con ShellBags y con la timeline (`tsk_mactime`).

**Técnica(s) MITRE.** `T1052.001` (Exfiltration over USB) y su padre `T1052`
(Exfiltration Over Physical Medium), **solo como corroboración**: la conexión del
dispositivo apoya la hipótesis de exfiltración cuando se combina con evidencia de
copia (LNK, ShellBags, timeline).

**Falsos positivos / cautelas.** USBSTOR prueba **conexión de un dispositivo, no
exfiltración**: por sí solo no evidencia que se copiaran datos. Teclados/ratones y
cargadores no son USBSTOR (mass storage). Un mismo serie puede reconectarse muchas
veces; no confundas «primera conexión» con «única conexión».

---

## EVTX 4624 / 4625 — Inicio de sesión (`Security.evtx`)

**Qué es.** 4624 = inicio de sesión correcto; 4625 = inicio fallido. El campo
`LogonType` distingue el vector: 2 (interactivo), 3 (red/SMB), 10 (RDP).

**Cómo se lee.** `Security.evtx`: `tsk_fls` → `tsk_icat` → `evtxecmd` (CSV) para la
consulta puntual de IDs y `LogonType`; barrido de refuerzo con `hayabusa`
(`min_level: high`) y `chainsaw`. Filtra el CSV con `jq` por usuario/tipo/ventana.

**Técnica(s) MITRE.** `T1078` (Valid Accounts) para logons anómalos con cuenta
válida; `T1021.001` (Remote Desktop Protocol) para 4624 `LogonType: 10`. Una
**ráfaga de 4625** (fallos repetidos) sostiene `T1110` (Brute Force).

**Falsos positivos / cautelas.** Servicios y tareas programadas generan logons de
tipo 4/5 legítimos; los 4625 aislados son ruido normal (contraseñas mal tecleadas).
El `LogonType` importa: no todo 4624 es interactivo. Correlaciona la cuenta con su
uso habitual antes de marcar `T1078`.

---

## EVTX 4688 — Creación de proceso (`Security.evtx`)

**Qué es.** Registra la creación de un proceso: imagen, línea de comandos (si la
auditoría está activada), proceso padre. Núcleo de la evidencia de **ejecución**.

**Cómo se lee.** `Security.evtx`: `tsk_fls` → `tsk_icat` → `evtxecmd` (CSV). Busca
`cmd.exe`/`powershell.exe` y utilidades de reconocimiento (`whoami`, `net`,
`systeminfo`, `nltest`). Cruza con Amcache/Prefetch para confirmar y con el árbol
padre-hijo para la cadena.

**Técnica(s) MITRE.** `T1059.003` (Windows Command Shell). Una cadena de 4688 con
utilidades de enumeración **corrobora** `T1057` (Process Discovery).

**Falsos positivos / cautelas.** La captura de línea de comandos exige la política
de auditoría activada; si no, el evento es pobre. Administradores y scripts de
despliegue lanzan `cmd`/`powershell` legítimamente. La utilidad por sí sola no es
malicioso: pesa el contexto (usuario, hora, padre).

---

## EVTX 4720 — Creación de cuenta (`Security.evtx`)

**Qué es.** Se creó una cuenta de usuario. En un post-mortem, una cuenta nueva no
justificada es un mecanismo de **persistencia/acceso**.

**Cómo se lee.** `Security.evtx`: `tsk_fls` → `tsk_icat` → `evtxecmd` (CSV). Cruza
la cuenta con el hive `SAM` (`regripper` `plugin: samparse`) para ver si sigue
presente y con 4624 posteriores de esa cuenta.

**Técnica(s) MITRE.** `T1136` (Create Account).

**Falsos positivos / cautelas.** Altas legítimas (nuevo empleado, cuenta de
servicio provisionada por IT) generan 4720. Confírmalo con el contexto: quién la
creó (`SubjectUserName`), a qué hora, y si recibió privilegios (4728/4732).

---

## EVTX 7045 — Instalación de servicio (`System.evtx`)

**Qué es.** Se instaló un servicio nuevo: nombre, `ImagePath`, tipo de arranque.
Vector habitual de **persistencia** y de ejecución con privilegios.

**Cómo se lee.** `System.evtx`: `tsk_fls` → `tsk_icat` → `evtxecmd` (CSV). Cruza el
`ImagePath` con la clave `Services` del hive `SYSTEM` (`regripper`
`plugin: services`) y con Amcache/`$MFT` del binario. Refuerza con `hayabusa`.

**Técnica(s) MITRE.** `T1543.003` (Create or Modify System Process: Windows
Service).

**Falsos positivos / cautelas.** Instaladores de software y agentes de gestión
crean servicios legítimos. Señales de sospecha: `ImagePath` en `%TEMP%`/`%APPDATA%`,
binario sin firma, nombre que imita a uno del sistema (`svhost`, `lsass` fuera de
`System32` → ver `T1036`).

---

## EVTX 1102 — Borrado del log de auditoría (`Security.evtx`)

**Qué es.** Registra que **se limpió el log de seguridad**. Acción anti-forense de
alto valor: alguien con privilegios borró la pista.

**Cómo se lee.** `Security.evtx`: `tsk_fls` → `tsk_icat` → `evtxecmd` (CSV). El
1102 es evidencia directa; corrobóralo con un **hueco en la secuencia de
`RecordId`** (salto anómalo) y con la ausencia de eventos esperados en esa ventana.
Barrido de refuerzo con `hayabusa`/`chainsaw` (reglas Sigma de *log clear*).

**Técnica(s) MITRE.** `T1070.001` (Indicator Removal: Clear Windows Event Logs).

**Falsos positivos / cautelas.** Un 1102 puede provenir de mantenimiento/rotación
legítima en entornos concretos, pero es raro; siempre justifica el contexto. La
ausencia de logs no es solo por 1102: rotación por tamaño o reinstalación también
dejan huecos. El propio 1102 no puede borrarse sin dejar rastro posterior.

---

## EVTX 4698 — Creación de tarea programada (`Security.evtx` / TaskScheduler)

**Qué es.** Se registró una tarea programada. Junto con la clave `TaskCache` del
registro, es un vector de **persistencia** y de ejecución diferida.

**Cómo se lee.** `Security.evtx` (o el log operativo de TaskScheduler): `tsk_fls` →
`tsk_icat` → `evtxecmd` (CSV). Cruza con `TaskCache`
(`SOFTWARE\...\Schedule\TaskCache`, `regripper` sobre el hive `SOFTWARE`) y ubica el
binario/acción de la tarea en el `$MFT` (`mftecmd`) para fijar su creación.

**Técnica(s) MITRE.** `T1053.005` (Scheduled Task/Job: Scheduled Task).

**Falsos positivos / cautelas.** Windows y muchas aplicaciones crean tareas
legítimas (actualizadores, mantenimiento). Sospecha por: acción que lanza un
intérprete o un binario en ruta de usuario, disparador al inicio de sesión,
autor/usuario inesperado. Correlaciona 4698 (EVTX) con `TaskCache` (registro) antes
de concluir.

---

## Enumeración de procesos en RAM — PsList vs PsScan/PsXView

**Qué es.** Tres vías de enumerar procesos en un volcado: `windows.pslist.PsList`
recorre la lista enlazada del kernel (solo procesos enlazados y vivos),
`windows.psscan.PsScan` escanea estructuras `_EPROCESS` en el pool (ve también
desenlazados y terminados) y `windows.psxview.PsXView` cruza varias fuentes y
marca en cuáles aparece cada proceso. La **divergencia entre vías** es el
artefacto: su patrón distingue ocultación de limitación del volcado.

**Cómo se lee.** `volatility3` (el memdump se lee vía el handle read-only; no hay
contenedor). Primero `PsList`/`PsTree`; ante una enumeración pobre, `PsScan` y
`PsXView`. Interpreta el patrón: **ausencia parcial** (la lista enlazada funciona
y a un puñado solo lo ve el pool scan) frente a **vacío total** (`PsList` = 0
filas y `PsScan` recupera cientos). Diagnostica el vacío total con
`windows.info.Info` (build, capas de símbolos, anomalías tipo `PE TimeDateStamp`
incoherente). Las salidas son grandes: filtra con `jq`, no las vuelques.

**Técnica(s) MITRE.** `T1055` (Process Injection) **solo** para la ausencia
parcial corroborada (proceso desenlazado + `Malfind`/inyección que lo apoye). El
vacío total no mapea a técnica alguna: es una laguna de entorno.

**Falsos positivos / cautelas.** Un `PsList` totalmente vacío con `PsScan` lleno
NO es «ocultación masiva»: es símbolos/ISF parciales o un build raro — decláralo
como laguna de entorno y sigue el análisis sobre `PsScan`/`PsXView`. Procesos
terminados aparecen en `PsScan` legítimamente (no son ocultos). No ancles el
informe entero en la anomalía de enumeración sin haber declarado su causa
probable.

---

## Procesos de cliente cloud en memoria (sincronizadores y clientes S3)

**Qué es.** Procesos de sincronización o subida a almacenamiento cloud residentes
en el volcado: `Dropbox.exe`, `OneDrive.exe`, cliente de Google Drive, clientes
S3 (p.ej. S3 Browser), `rclone`. Señalan un **canal de salida de datos
disponible** en la ventana del volcado — el vector típico de exfiltración en
casos insider.

**Cómo se lee.** `volatility3`: `windows.pslist.PsList`/`windows.psscan.PsScan`
(nombre, PID/PPID, hora de creación y término del proceso) + `windows.netscan.
NetScan` (ESTABLISHED :443 hacia rangos del proveedor en la misma ventana; si el
socket no trae `Owner`, intenta `windows.netstat.NetStat` antes de darlo por no
atribuible) + `windows.filescan.FileScan`/`windows.dumpfiles.DumpFiles` para el
documento o la config del cliente (acotado por PID o `virtaddr`, nunca el volcado
completo). En el disco par, corrobora con la carpeta local del cliente, LNK y
ShellBags (`regripper`).

**Técnica(s) MITRE.** `T1567` (Exfiltration Over Web Service); `T1567.002`
(Exfiltration to Cloud Storage) cuando el cliente es de almacenamiento y hay un
fichero/documento identificado en la misma ventana. Con un solo eslabón (solo el
proceso, o solo la conexión), la técnica queda en hipótesis — no la correlaciones
como hecho.

**Falsos positivos / cautelas.** Estos clientes son software legítimo y
omnipresente: su mera presencia (o un autostart) no es exfiltración. Los sockets
sin `Owner` no atribuyen el tráfico al cliente — dilo en el hallazgo. La
severidad sube solo con la coincidencia temporal de proceso + conexión + fichero
(cadena «Exfiltración a nube (memoria)» del playbook); dos eslabones son una
hipótesis a seguir en el disco, no una conclusión.

---

## LNK / Accesos directos (`.lnk`)

**Qué es.** Ficheros de acceso directo que Windows crea al abrir documentos y al navegar
(carpeta `Recent`, escritorio, listas de recientes). Guardan la **ruta objetivo**, el
volumen y su número de serie (delata unidades extraíbles y de red) y las marcas de tiempo
del objetivo. Prueban **qué fichero se abrió y desde dónde**.

**Cómo se lee.** `tsk_fls` para localizar los `.lnk` → `tsk_icat` para extraerlos → `lecmd`
sobre el fichero o el directorio derivado → CSV. Cruza la ruta objetivo y el nº de serie
del volumen con USBSTOR (`regripper`), con ShellBags y con la timeline (`tsk_mactime`).

**Técnica(s) MITRE.** `T1083` (File and Directory Discovery): evidencia de acceso a
ficheros/carpetas. Como **corroboración** de una cadena: `T1052.001` (si el volumen es un
USB) o `T1074.001` (si la ruta apunta a una carpeta de staging) — nunca en solitario.

**Falsos positivos / cautelas.** Abrir un fichero es actividad normal; un LNK no prueba
copia ni intención. La marca del LNK es la de la última apertura, no la de creación del
objetivo. Un LNK a una unidad de red demuestra acceso, no exfiltración. Sitúa actividad;
concluye solo con la correlación temporal.

## Jump Lists (`AutomaticDestinations` / `CustomDestinations`)

**Qué es.** Estructuras por aplicación (barra de tareas / menú de saltos) que registran los
documentos y destinos recientes de cada programa. Complementan a los LNK con el **historial
de documentos por app**.

**Cómo se lee.** `tsk_fls` → `tsk_icat` (los ficheros de
`...\AutomaticDestinations-ms` / `CustomDestinations-ms` del perfil de usuario) → `jlecmd`
sobre el fichero o directorio derivado → CSV. Cruza los documentos y sus horas con LNK, con
la timeline (`tsk_mactime`) y con `wxtcmd`.

**Técnica(s) MITRE.** `T1083` (File and Directory Discovery): qué documentos manejó el
usuario. Como corroboración de una cadena de acceso/staging, ver `T1074.001`.

**Falsos positivos / cautelas.** Reflejan uso normal de aplicaciones; la mera presencia de
un documento en la Jump List no es maliciosa. El `AppId` identifica la app, no siempre de
forma evidente. Úsalas para reconstruir actividad, no como prueba única.

## Windows Timeline / ActivitiesCache (`ActivitiesCache.db`)

**Qué es.** Base de datos de la Línea de tiempo de Windows (Win10 1803+,
`...\ConnectedDevicesPlatform\...\ActivitiesCache.db`) que registra aplicaciones y
documentos usados con su marca temporal. Fuente de **actividad de usuario** correlacionable.

**Cómo se lee.** `tsk_fls` → `tsk_icat` (la `ActivitiesCache.db` del perfil) → `wxtcmd`
sobre el fichero derivado → CSV. Cruza app/documento y hora con LNK, Jump Lists y la
timeline (`tsk_mactime`).

**Técnica(s) MITRE.** Corrobora `T1083` (acceso/descubrimiento) dentro de una cadena; en
solitario suele quedar **«sin técnica de la semilla aplicable»** — es contexto temporal,
no una técnica por sí misma.

**Falsos positivos / cautelas.** Puede estar **deshabilitada** o vacía (política de grupo,
build anterior a 1803) → su ausencia no prueba inactividad. Registra uso legítimo
mayoritariamente; su valor es situar actividad en el tiempo, no imputar intención.

## Papelera de reciclaje (`$Recycle.Bin`, `$I` / `$R`)

**Qué es.** Por cada fichero enviado a la papelera, NTFS guarda un `$I` (metadatos: ruta
original y hora de borrado) y un `$R` (contenido). Evidencia de **qué se borró, cuándo y
desde dónde**.

**Cómo se lee.** `tsk_fls` para localizar `$Recycle.Bin` (por SID de usuario) → `tsk_icat`
para extraer los `$I` → `rbcmd` sobre el fichero o directorio derivado → CSV con ruta
original y hora de borrado. Para recuperar el contenido, ubica el `$R` correspondiente en
el árbol y extráelo con `tsk_icat`. Cruza con el `$MFT` (`mftecmd`) y la timeline.

**Técnica(s) MITRE.** `T1070` (Indicator Removal; la semilla no tiene subtécnica *File
Deletion* → técnica padre) cuando el borrado tenga carácter anti-forense. Si lo relevante
es **recuperar** documentos de interés (no el borrado en sí), trátalo como evidencia de
`T1005` (Data from Local System) / `T1074.001` (staging) o declara «sin técnica de la
semilla aplicable».

**Falsos positivos / cautelas.** Borrar ficheros es rutinario; la papelera llena no es
sospechosa por sí sola. Un `$I` sin su `$R` da la metadata pero no el contenido. Vaciar la
papelera elimina `$I`/`$R` (correlaciona con `$MFT`/`$UsnJrnl` y la timeline). La hora es la
del borrado, no la de creación del fichero.

> **Recordatorio de custodia:** ninguna guía de arriba procesa la imagen cruda con
> una herramienta de contenedor (`regripper`, `evtxecmd`, `mftecmd`, y los parsers EZ
> `amcacheparser`/`appcompatcacheparser`/`sbecmd`/`recmd`/`lecmd`/`jlecmd`/`wxtcmd`/`rbcmd`).
> El flujo es
> siempre `tsk_fls` → `tsk_icat` → procesar el artefacto derivado (soundness §7);
> los volcados de memoria se leen con `volatility3` a través del handle read-only.
> Los artefactos sin parser dedicado (Prefetch, `setupapi.dev.log`) se corroboran
> por timeline/correlación, nunca inventando un `tool_id` (RULE 2).
