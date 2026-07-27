# Playbook — Agentopsy-WIN

Heurística forense por tipo de evidencia. **No es un script**: es lo que un analista
humano probaría primero. El perito dirige; libertad en **qué** investigar, disciplina en
**cómo** ejecutar. Antes de cualquier herramienta, confirma que la evidencia está
**verificada** (`verified=true`).

> **Regla de oro de custodia:** las herramientas de contenedor (`regripper`,
> `evtxecmd`, `mftecmd`) **nunca** reciben la imagen cruda. Siempre:
> `tsk_fls` (localizar) → `tsk_icat` (extraer el artefacto vía handle read-only)
> → procesar **solo** ese fichero derivado.

## Disciplina de ejecución (OBLIGATORIO)

1. **Registra en caliente.** Tras CADA herramienta con salida útil, llama a
   `record_finding` (con `run_id` y `tool_id`) ANTES de la siguiente. Un descarte
   también cuenta. Nunca dejes los hallazgos "para el final": el análisis puede
   cortarse y se perdería.
2. **Cierra el bucle: recopilar → analizar → registrar.** Procesa cada artefacto
   intermedio (bodyfile, `.plaso`, salida de EVTX/registro); no lo dejes huérfano.
3. **Encadena entero un pipeline que empieces** (no a medias). Los de referencia:
   - **Super-timeline:** `tsk_fls` (`body_format: true`) → `tsk_mactime`; o
     `plaso_log2timeline` → `plaso_psort` cuando haya muchas fuentes. Una vez
     construida, **consúltala con `consultar_actividad`** (por fecha/categoría/ruta)
     en vez de re-lanzar fls.
   - **Eventos:** `evtxecmd` sobre los `.evtx` extraídos → correlaciona EIDs clave
     (4624/4625/4688/4720/7045…) y registra un hallazgo por patrón detectado.
   - **Registro:** `regripper` sobre los hives extraídos → persistencia, cuentas, USB.

## Objetivo → herramientas (elige según el caso, no las agotes todas)

- **Terreno / arranque:** `ewf_info` (si `.E01`), `tsk_mmls` (particiones/offsets).
- **Línea temporal:** `tsk_fls -m` → `tsk_mactime` (o `$MFT` con `mftecmd`); luego
  `consultar_actividad`.
- **Recuperar un fichero/hive/EVTX concreto:** `tsk_fls` → `tsk_icat` por inodo.
- **Registro:** `regripper` / `amcacheparser` sobre hives extraídos.
- **Eventos:** `evtxecmd`, o `hayabusa` / `chainsaw` (reglas Sigma priorizadas).
- **Actividad de usuario (LNK/JumpLists/ShellBags):** `lecmd` / `jlecmd` / `sbecmd`.
- **IOCs / firmas:** `bulk_extractor` + `jq`; `yara` sobre directorios extraídos.
- **Qué artefacto responde a qué pregunta:** `consultar_conocimiento("artefactos-windows")`.

---

## 0. Routing por tipo de evidencia (antes que nada)

Agentopsy te inyecta arriba, en «Contexto de evidencia», un `detected_kind`; cuando
hay señal clara, además te inyecta un bloque **«Ruta del playbook»** que ya decide
la sección. **Ese bloque manda**; esta tabla solo lo mapea a las secciones de abajo
para que no gastes iteraciones probando la sección equivocada:

| `detected_kind` | Sigue la sección | Qué NO hacer |
|---|---|---|
| `memory` | **B** (Volcado RAM) | No llames `tsk_mmls` / `tsk_fls` / `tsk_mactime` / `ewf_info`: fallan sobre un memdump. |
| `disk` | **A** (Imagen de disco) | No lances plugins `windows.*` de Volatility: no hay volcado de memoria física. |
| `container_disk` | **A** (Imagen de disco) | Igual que `disk`; TSK abre VMDK/VDI/QCOW/VHD/E01. No intentes Volatility. |
| `unknown` | un único probe diagnóstico (mismo conjunto que la regla 9) | En orden según la pista: `file_info` (tipo de fichero) → `strings_head` (banners), `volatility3` (`windows.info.Info` / `linux.banner.Banner`) si parece volcado, o `tsk_mmls` si parece disco. No encadenes tools a ciegas (regla 9). |

Coherente con lo que el motor ya inyecta: si el bloque «Ruta del playbook» está
presente, síguelo tal cual; esta sección no lo contradice, solo lo traduce a A/B.

---

## A. Imagen de disco Windows (`.raw`, `.E01`, `.vmdk`)

1. **Contenedor.** `ewf_info` si es `.E01` → metadatos de adquisición del contenedor
   (examiner, fechas, hashes internos). Es **informativo**: la verificación de
   integridad contra el baseline del caso la certifica `EvidenceManager`, no tú —
   **nunca** afirmes que «cuadra con el baseline» (no tienes el baseline).
2. **Particiones.** `tsk_mmls` → offsets y tipos. Apunta el `partition_offset` de
   la partición del sistema (NTFS).
3. **Sistema de ficheros (sin montar).**
   - **Paso 0 — huso horario (antes de la timeline).** Determina y **declara** el huso
     de la evidencia ANTES de construir cualquier línea temporal: extrae el hive
     `SYSTEM` (`tsk_fls`→`tsk_icat`) y córrelo con `regripper` `plugin: timezone`
     (clave `TimeZoneInformation`). Registra el huso hallado como dato de contexto. Sin
     esa declaración, las marcas MAC(b) son ambiguas.
   - `tsk_fls` con `recursive: true` → árbol completo, incluidos borrados.
   - `tsk_mactime` (bodyfile) → línea temporal MAC(b): tu columna vertebral. Pasa
     **siempre** `timezone: UTC` explícito para normalizar, y en cada marca del informe
     exige el offset o la referencia a UTC (nunca una hora «desnuda» sin huso).
4. **`$MFT`.** Localiza la `$MFT` con `tsk_fls`, extráela con `tsk_icat`, y
   procésala con `mftecmd` → CSV de creación/modificación/acceso. Cruza con la
   timeline para detectar *timestomping* (creación posterior a modificación, o
   `$STANDARD_INFORMATION` vs `$FILE_NAME` inconsistentes).
5. **Registro.** Extrae los hives (`SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`,
   `NTUSER.DAT`, `UsrClass.dat`) con `tsk_icat` y procésalos con `regripper`.
   Busca: persistencia (`Run`/`RunOnce`, `Services`, `Scheduled Tasks`), ejecución
   (`Amcache`, `ShimCache`/AppCompatCache), USB, cuentas (`SAM`), `ShellBags`.

   Para volcar esas mismas claves a **CSV estructurado** (timelining y correlación a
   escala) el maletín trae los parsers EZ dedicados sobre el **mismo hive pre-extraído**:
   `amcacheparser` (Amcache), `appcompatcacheparser` (ShimCache), `sbecmd` (ShellBags) y
   `recmd` (lote de varias claves con un batch tipo `Kroll_Batch.reb`). `regripper` sigue
   siendo el camino rápido de triage por clave; recurre al parser EZ cuando necesites el
   CSV completo para cruzarlo con la timeline. Una clave, una fuente citada por hallazgo
   (no mezcles regripper y el parser EZ en el mismo finding).
6. **Eventos (EVTX).** Extrae `Security.evtx`, `System.evtx`, `Application.evtx`,
   `Microsoft-Windows-Sysmon%4Operational.evtx` con `tsk_icat`. Procésalos con:
   - `evtxecmd` → CSV normalizado (consulta puntual de IDs: 4624/4625 logon,
     4688 process creation, 7045 service install, 4720 user created).
   - `hayabusa` y `chainsaw` → detecciones **Sigma** (barrido de amenazas).
7. **IOCs.** `bulk_extractor` sobre la imagen → emails, URLs, IPs, PII en
   no-asignado. Lento: anúncialo. Filtra con `jq`.
8. **Firmas / malware.** `yara` sobre directorios sospechosos extraídos
   (`%TEMP%`, `%APPDATA%`, `C:\Windows\Tasks`, perfiles de usuario).
9. **Super-timeline (opcional, pesado).** `plaso_log2timeline` → `.plaso`;
   `plaso_psort` para acotar por rango y exportar CSV.
10. **Acceso a ficheros y actividad de usuario (EZ Tools) — cuando la pregunta del caso
    pasa por *qué ficheros se abrieron o desde dónde*** (insider, acceso indebido,
    exfiltración; **no** en un barrido de persistencia/ejecución). Localiza y pre-extrae
    con `tsk_fls`→`tsk_icat`, procesa el artefacto derivado:
    - `lecmd` sobre los `.lnk` (`Recent`, escritorio) → CSV con ruta objetivo, volumen y
      número de serie (delata medios extraíbles) y marcas del objetivo.
    - `jlecmd` sobre las Jump Lists (`AutomaticDestinations`/`CustomDestinations`) → CSV con
      el historial de documentos por aplicación.
    - `wxtcmd` sobre `ActivitiesCache.db` (Windows Timeline, Win10 1803+) → CSV con
      app/documento y su marca temporal.
    Cruza las rutas con la timeline (`tsk_mactime`), con ShellBags y con USBSTOR.
    `mitre_hints`: `T1083`; si apuntan a medio extraíble o a una carpeta de staging,
    corrobora `T1052.001` / `T1074.001` (nunca en solitario).
11. **Borrado / papelera.** `rbcmd` sobre `$Recycle.Bin` (ficheros `$I`) → CSV con la ruta
    original y la hora de borrado de lo eliminado. Reconstruye qué se quiso hacer
    desaparecer y ayuda a recuperar documentos de interés (crúzalo con `$MFT` y la
    timeline). `mitre_hints`: `T1070` (Indicator Removal; la semilla no tiene subtécnica
    *File Deletion* → técnica padre) cuando el borrado sea anti-forense; si solo recuperas
    documentos relevantes, decláralo como evidencia de `T1005`/`T1074.001` o «sin técnica
    de la semilla aplicable».

---

## B. Volcado de memoria RAM Windows (`.mem`, `.dmp`)

> Antes de empezar, confirma que `detected_os` del bloque «Contexto de
> evidencia» dice `windows` (o que un probe diagnóstico ya lo confirmó). Si el
> volcado es UNIX, **no es tu caso**: detente y pide a la operadora que **ancle el
> perfil del caso a `unix`** (el re-enrutado a Agentopsy-UNIX es automático; no se
> cierra ni se reabre el caso). Ver regla 9 del system prompt.

1. **Perfil.** `volatility3` con `plugin: "windows.info.Info"` → build y perfil.
2. **Procesos.** `windows.pslist.PsList` (recorre la lista enlazada del kernel),
   `windows.pstree.PsTree` (jerarquía padre-hijo). Si `PsList` da una enumeración
   **poco fiable** (pocos procesos, símbolos parciales, sospecha de *process
   hiding*), **crúzalo con pool scan**: `windows.psscan.PsScan` (escanea `_EPROCESS`
   en el pool, ve procesos desenlazados/terminados) y `windows.psxview.PsXView`
   (compara varias fuentes de enumeración y marca lo que aparece en unas y no en
   otras). **Interpreta el cruce según el patrón — no todo hueco es ocultación:**
   - **Ausencia parcial** (`PsList` enumera bien y a un puñado de procesos solo los
     ve `PsScan`/`PsXView`): indicio de ocultación (proceso desenlazado); trátalo
     como sospechoso y correlaciónalo con inyección si `Malfind` lo corrobora
     (`mitre_hints`: `T1055`).
   - **Vacío total o casi total** (`PsList`/`PsTree` devuelven 0 o poquísimas filas
     y `PsScan` recupera cientos): eso NO es ocultación masiva — es una
     **limitación de símbolos/imagen** (ISF parcial, build raro). Diagnostica la
     causa con la salida de `windows.info.Info` (build, capas, anomalías tipo
     `PE TimeDateStamp` incoherente) y decláralo como **laguna de entorno** en el
     informe; continúa el análisis sobre `PsScan`/`PsXView` sin citar `T1055`.
     No anclas conclusiones de intrusión en un artefacto de entorno.
3. **Inyección.** `windows.malfind.Malfind` (regiones RWX/anómalas),
   `windows.hollowprocesses.HollowProcesses` cuando sospeches *process hollowing*.
4. **Red.** `windows.netscan.NetScan` → conexiones y puertos (C2, shells inversas).
   Si devuelve sockets **sin `Owner`/PID** (frecuente en volcados con símbolos
   parciales), intenta la atribución por la vía alternativa
   `windows.netstat.NetStat` antes de dar la conexión por «no atribuible»; si aun
   así no hay dueño, dilo tal cual — una IP establecida sin proceso atado es un
   dato, no una conclusión de C2.
5. **Registro residente.** `windows.registry.hivelist.HiveList` +
   `windows.registry.printkey.PrintKey` → persistencia viva en memoria. Este
   ángulo **siempre termina en el informe**: con hives legibles, sigue con
   `PrintKey` sobre las claves `Run`/`RunOnce`; si `HiveList` devuelve vacío o el
   filtrado posterior de su salida falla (un helper que rompe, un JSON ilegible),
   **declara la laguna** («registro residente no explotado: <causa>») — un ángulo
   abierto que se cae en silencio es peor que un negativo declarado.
6. **Comando.** `windows.cmdline.CmdLine`, líneas de comando de procesos
   sospechosos; vuelca regiones de un PID candidato si procede.
7. **Ficheros y documentos en memoria.** Cuando la pregunta del caso pasa por
   **qué documento/fichero estaba abierto** (casos insider, exfiltración, un
   editor u ofimática activos, un cliente cloud con algo que subir), no te quedes
   en la lista de procesos: `windows.filescan.FileScan` enumera los `FILE_OBJECT`
   residentes (coste alto en volcados grandes → artefacto + filtro con `jq` por
   extensión/ruta: `.docx`, `.pdf`, `Documents`, `Desktop`, carpetas de
   sincronización), y `windows.dumpfiles.DumpFiles` **acotado** (por `pid` del
   proceso candidato o por `virtaddr`/`physaddr` de un `FILE_OBJECT` concreto del
   `filescan`; nunca el volcado completo) recupera el contenido como artefacto
   derivado. Un documento recuperado y con hash es la pieza que convierte «proceso
   ofimático activo» en evidencia de contenido; si el volcado no lo conserva,
   declara la laguna y remite el ángulo al disco par (`$MFT`, papelera, carpeta
   del cliente cloud). `mitre_hints`: `T1567.002` solo si coincide en ventana con
   un cliente cloud activo (cadena 5).
8. **Credenciales.** Material de credenciales residente en memoria, con los plugins
   Vol3 **totalmente cualificados** y en su **namespace canónico** (sin `.registry.`):
   - `windows.hashdump.Hashdump` → hashes de la `SAM` (formato `usuario:rid:LM:NT`).
   - `windows.lsadump.Lsadump` → secretos LSA (*LSA secrets*).
   - `windows.cachedump.Cachedump` → credenciales de dominio cacheadas (*MSCACHE*).
   `mitre_hints`: `T1003` (OS Credential Dumping); `T1003.001` (LSASS Memory) cuando
   el material provenga de `lsass.exe`. Registra cada volcado con `record_finding`
   citando el `run_id`; el material crudo **no** va a tu contexto (disciplina de
   coste y redacción del gate 9 antes de un backend cloud).

   > **Vol2 no es Vol3.** Los nombres SIN prefijo `windows.` — `hashdump`,
   > `lsadump`, `cachedump` — son plugins de **Volatility 2** y **no existen** en
   > Volatility 3: emitirlos hace fallar la recuperación (símbolo/plugin
   > desconocido). Usa **siempre** el id totalmente cualificado
   > `windows.<plugin>.<Clase>` (p.ej. `windows.hashdump.Hashdump`), nunca el nombre
   > corto de Vol2. **Tampoco inventes variantes de namespace**: el id canónico es
   > `windows.hashdump.Hashdump`, **no** `windows.registry.hashdump.*` ni ninguna
   > otra ruta que no hayas visto listada por el propio Volatility.

   > **El nombre exacto lo fija el build de Volatility, no tú.** El id de plugin y
   > su disponibilidad **dependen de la versión** instalada. Si `vol` responde
   > `argument PLUGIN: invalid choice`, **no adivines** otro nombre por analogía:
   > toma el id **literal** de la lista «choose from …» que imprime ese mismo error
   > (o de `vol -h`) y usa ese. Si el plugin de credenciales **no está registrado**
   > en ese build —p.ej. una **colisión de nombres** entre `windows.<x>` y
   > `windows.registry.<x>` que rompe su registro—, decláralo como **laguna
   > explícita** en el informe («credenciales no disponibles en este build de
   > Volatility», sección *Lagunas / no concluyente*) y continúa con el resto del
   > análisis: **nunca** sustituyas por un nombre inventado (regla 4 del system
   > prompt: no inventar).

---

## Cadenas de correlación nombradas

Un hallazgo aislado es una hipótesis; dos o tres artefactos **independientes** que
coinciden en el tiempo son una conclusión. Estas son las correlaciones de alto
valor — cada eslabón cita su `tool_id` de la allowlist (los nombres tipo `run`,
`usbstor`, `amcache` son **plugins** de `regripper`, no tool_ids). Cuando varios
coinciden en la misma ventana temporal, sube la `confidence` del finding.

1. **Persistencia confirmada.** `regripper` (plugin `run`/`soft_run` sobre
   `NTUSER.DAT` / `SOFTWARE`: entrada `Run`/`RunOnce`) + `evtxecmd` (evento 4688,
   creación del proceso apuntado) + `regripper` `amcache`/`appcompatcache` (primera
   ejecución del binario) en la misma ventana ⇒ persistencia real, no ruido.
   `mitre_hints`: `T1547.001`; si es un servicio (`evtxecmd` 7045 + `regripper`
   `services`), `T1543.003`.
2. **Ejecución confirmada.** `regripper` `amcache` (o `appcompatcache`) + `evtxecmd`
   4688 del mismo binario ⇒ el binario se ejecutó, con hora. Ubica el fichero en el
   `$MFT` (`mftecmd`). `mitre_hints`: `T1059` (o subtécnica según intérprete).
3. **Logon / movimiento lateral.** `evtxecmd` sobre `Security.evtx`: 4624/4625 por
   usuario y `LogonType` (3 = red, 10 = RDP). Barrido de refuerzo con `hayabusa` /
   `chainsaw`. `mitre_hints`: `T1078` (cuentas válidas), `T1021.001` (RDP).
4. **USB conectado.** `regripper` `usbstor` + `mountdev` (hive `SYSTEM`) +
   `setupapi.dev.log` (pre-extraído con `tsk_icat`) ⇒ VID/PID, número de serie y
   primera/última conexión; crúzalo con la timeline (`tsk_mactime`).
5. **Exfiltración a nube (memoria).** `volatility3` `windows.pslist.PsList`/
   `windows.psscan.PsScan` (cliente cloud activo: S3 Browser, Dropbox, OneDrive,
   Google Drive, rclone) + `windows.netscan.NetScan` (ESTABLISHED :443 a rangos
   del proveedor en la misma ventana) + un documento/fichero en juego
   (`windows.filescan.FileScan`/`windows.dumpfiles.DumpFiles`, o el proceso
   ofimático que lo tenía abierto arrancado en la misma ventana) ⇒ hipótesis de
   exfiltración a almacenamiento cloud con confianza media. `mitre_hints`:
   `T1567`; con cliente de almacenamiento y fichero identificados, `T1567.002`.
   **Cautelas duras:** un cliente cloud instalado es actividad normal de usuario —
   sin la coincidencia temporal de los tres eslabones no subas de `low`; sockets
   sin `Owner` no atribuyen el tráfico a ese cliente (dilo); dos eslabones =
   hipótesis a seguir en el disco par (carpeta del cliente, historial web), no
   conclusión.
6. **Acceso y staging de ficheros (disco).** `lecmd`/`jlecmd` (documento abierto o
   copiado, con ruta y —si aplica— volumen extraíble) + `tsk_mactime`/`mftecmd` (el
   fichero existió y cuándo) + `rbcmd` (si acabó borrado) + `regripper` `usbstor` / `sbecmd`
   (medio extraíble o carpeta navegada) en la misma ventana ⇒ acceso y preparación de
   datos para exfiltración. `mitre_hints`: `T1083` (acceso/descubrimiento), `T1074.001`
   (staging local), `T1052.001` (si el destino es USB). **Cautela dura:** abrir o navegar
   a un fichero es actividad normal de usuario; sin la coincidencia temporal con medio
   extraíble, staging o borrado no subas de `low`, y un LNK a una unidad de red no prueba
   copia.

Registra cada correlación con `record_finding` citando el `run_id` del eslabón
principal; los demás eslabones van en el `summary`.

---

## Disciplina de coste por herramienta

Regla dura (refuerza la regla 8 del system prompt): **toda salida grande vuelve
como artefacto (`artifact_id`), nunca al contexto**. Trabaja el artefacto con `jq`
u otro filtro y trae solo el top-N a tu razonamiento.

- **`tsk_fls` con `recursive: true`** puede dar millones de filas: vuelve como
  artefacto, no pidas el árbol entero. Para la timeline usa `body_format: true` y
  pásalo a `tsk_mactime` con `date_range` acotado (p.ej. `2018-04-01..2018-04-07`),
  no el histórico completo.
- **`mftecmd` (CSV de `$MFT`)**: cientos de miles de filas. Consúltalo con `jq` por
  ruta/extensión o ventana temporal; no vuelques el CSV.
- **`hayabusa` / `chainsaw`** sobre EVTX: filtra por severidad (`min_level: high`
  en `hayabusa`) y trae solo las detecciones altas; el resto queda en el CSV.
- **`volatility3`**: emite JSON; encadénalo con `jq` (`input_path` = el artefacto)
  para quedarte con columnas concretas (PID, PPID, ruta) en vez del array completo.
  En memoria esto es crítico: `psscan` (cientos de procesos), `netscan` (cientos de
  sockets, la mayoría CLOSED) y `filescan` (miles de `FILE_OBJECT`) **nunca** se
  traen enteros al contexto — filtra `netscan` por estado (`ESTABLISHED`/`LISTEN`)
  y `filescan` por extensión/ruta antes de razonar.
- **Un plugin caro que devolvió 0 filas no se relanza con variantes** (`--physical`,
  por offset, otro PID «a ver si suena la flauta») sin una hipótesis nueva que lo
  justifique y quede escrita en el hallazgo o en la laguna. Dos ejecuciones vacías
  del mismo ángulo = laguna declarada, no una tercera ejecución.
- **Ante `invalid choice` de un plugin**, toma el id literal de la lista
  `choose from …` de ESE error y no reintentes más nombres: cada fallo vuelca la
  enum completa de plugins (~200 entradas) a tu contexto — dos intentos fallidos
  del mismo plugin son tu tope antes de declararlo laguna (regla del §B.8).
- **`bulk_extractor`**: mira primero `feature_counts`; abre un feature file solo si
  tiene hits.

---

## Buenas prácticas siempre

- Un mismo `tool_id` puede repetirse con `params` distintos: **cada ejecución es
  un `artifact_id`** — indícalo en cada hallazgo.
- Cruza fuentes: una persistencia en `Run` (registro) gana fuerza si hay un 4688
  (EVTX) y una entrada en `Amcache`/Prefetch a la misma hora. Correlación = más
  confianza.
- Ancla cada hallazgo a la marca de tiempo del **artefacto** (`observed_at`), no a
  la hora de ejecución.
- Si la salida cabe en contexto, cítala literal; si no, referencia el
  `artifact_id` y resume (apóyate en `jq`).

---

## Anexo — Playbook por herramienta

Para cada `tool_id` de la allowlist: cuándo usarla, los **params que TÚ eliges**
(Agentopsy inyecta el path de la evidencia/artefacto y el `output_dir`; **no los
pongas tú**), coste, errores comunes y cómo leer su salida.

### Particiones / imagen

- **`tsk_mmls`** — tabla de particiones de una imagen de disco. Params: `type`
  (`dos`|`gpt`|`mac`|`bsd`|`sun`, omite para autodetectar), `image_format`
  (`raw`|`ewf`|`vmdk`|`vhd`|`aff`). Coste: bajo. Error típico: «Cannot determine
  partition type» ⇒ probablemente no es imagen de disco (revisa `detected_kind`).
  Salida: `partitions[]` con `start_sector`; apunta el offset NTFS para `tsk_fls`.
- **`ewf_info`** — metadatos del contenedor `.E01`. Params: ninguno. Coste: bajo.
  Salida: `fields` (examiner, fechas, hashes de adquisición). Informativo: **no**
  es tu verificación de integridad (eso es de `EvidenceManager`).

### Sistema de ficheros / extracción quirúrgica

- **`tsk_fls`** — árbol de ficheros (incluidos borrados). Params: `partition_offset`
  (sectores, del `mmls`), `recursive`, `deleted_only`, `allocated_only`,
  `long_format`, `body_format` (para timeline), `filesystem: ntfs`. Coste:
  `recursive: true` es **grande** ⇒ artefacto + filtro. Salida: `entries[]`, o body
  file si `body_format`.
- **`tsk_mactime`** — timeline MAC(b) desde el body file de `tsk_fls`. Params:
  `date_range` (`2018-04-01..2018-04-07`), `timezone`. Coste: medio. Salida:
  `top_days`, `first_event`, `last_event`. **Acota siempre** con `date_range`.
- **`tsk_icat`** — pre-extracción quirúrgica de un fichero (hive, EVTX, `$MFT`) por
  inodo, vía handle read-only. Paso **obligatorio** antes de las tools de contenedor
  (regla 5). Params: (esquema aún no fijado en el motor; conceptualmente inodo +
  `partition_offset`). Coste: bajo. Salida: el fichero derivado como artefacto.

### Artefactos Windows (varias entregadas por contenedor)

- **`mftecmd`** — `$MFT` **pre-extraído** → CSV. Params: ninguno que elijas
  (Agentopsy monta el `$MFT` y el `output_dir`). Coste: medio/alto en `$MFT` grande
  — anúncialo. Uso: timestomping (`$SI` vs `$FN`). Lee el CSV con `jq`.
- **`regripper`** — hive **pre-extraído** → texto. Params: `plugin` (p.ej. `run`,
  `soft_run`, `services`, `samparse`, `usbstor`, `mountdev`, `amcache`,
  `appcompatcache`, `shellbags`), **o** `profile`, **o** `list: true`. No pases
  `plugin` y `profile` juntos. Coste: bajo. Salida: `raw` (texto); si `looks_empty`,
  el hive no tenía esa clave.
- **`evtxecmd`** — un `.evtx` (o dir) **pre-extraído** → CSV normalizado. Params:
  ninguno que elijas. Coste: medio. Uso: consulta puntual de IDs
  (4624/4625/4688/7045/4720). Filtra el CSV, no lo vuelques.
- **`hayabusa`** — detecciones **Sigma** sobre un dir de EVTX pre-extraídos. Params
  que eliges: `min_level` (`info`…`critical`); la ruta de salida la asigna Agentopsy.
  Coste: medio/alto en EVTX grandes — anúncialo; usa `min_level: high`. Salida:
  `summary` con contadores.
- **`chainsaw`** — hunting Sigma sobre EVTX/JSON. Params: `output_format`
  (`csv`|`json`) y al menos uno de `sigma_dir` / `rules_dir`; las rutas de salida
  las asigna Agentopsy. Coste: medio. Salida: nº de `detections`.

### EZ Tools (parsers KAPE — maletín windows)

Parsers dedicados de Eric Zimmerman (los *Modules* de KAPE) que viven en el maletín
windows y se ejecutan por el exec-agent como el resto de tools de contenedor: **misma
disciplina de custodia** (regla 5) — `tsk_fls`→`tsk_icat` y procesar solo el artefacto
derivado, nunca la imagen cruda. Todos **devuelven CSV como artefacto** → fíltralo con
`jq`/top-N (regla 8). Agentopsy inyecta el path del artefacto pre-extraído y el
`output_dir`; **no los pongas tú**.

- **`amcacheparser`** — `Amcache.hve` pre-extraído → CSV. Alternativa CSV-estructurada a
  `regripper` `plugin: amcache` para timelining a escala; `regripper` sigue siendo el
  triage rápido por clave. Params que eliges: `include_linked` (bool; añade las entradas de
  fichero enlazadas a las de programa). Uso: presencia/ejecución de binarios (cruza con
  4688/`$MFT`). Recuerda: «primera aparición» ≠ «primera ejecución».
- **`appcompatcacheparser`** — ShimCache del hive `SYSTEM` pre-extraído → CSV. Alternativa a
  `regripper` `plugin: appcompatcache`. Params: ninguno que elijas. ShimCache prueba
  **existencia/registro**, no ejecución: corrobora con Amcache/4688.
- **`sbecmd`** — ShellBags desde un **directorio** con `UsrClass.dat`/`NTUSER.DAT` → CSV.
  Alternativa a `regripper` `plugin: shellbags`. Params: ninguno que elijas. Uso: carpetas
  navegadas (incl. borradas, de red o de unidades extraíbles).
- **`recmd`** — RECmd en **modo lote** sobre hives pre-extraídos → CSV. Params que eliges:
  `batch` (**obligatorio**, el NOMBRE de un batch de los que trae el maletín, p.ej.
  `Kroll_Batch.reb`; nunca una ruta ni separadores), `is_directory` (bool; si apuntas a un
  directorio de hives en vez de a uno solo). Uso: volcar de golpe muchas claves de valor
  forense a CSV; más pesado que un `regripper` puntual — úsalo para la foto completa del
  hive, no para un valor concreto.
- **`lecmd`** — accesos directos `.lnk` (un fichero o un directorio) pre-extraídos → CSV:
  ruta objetivo, volumen y nº de serie (delata medios extraíbles), marcas del objetivo.
  Params: ninguno que elijas. Uso: qué ficheros se abrieron y desde dónde. `T1083`.
- **`jlecmd`** — Jump Lists (`AutomaticDestinations`/`CustomDestinations`) pre-extraídas →
  CSV: historial de documentos por aplicación. Params: ninguno que elijas. `T1083`.
- **`wxtcmd`** — `ActivitiesCache.db` (Windows Timeline, Win10 1803+) pre-extraída → CSV:
  app/documento y marca temporal de la actividad. Params: ninguno que elijas. Corrobora el
  acceso a ficheros; en solitario suele quedar «sin técnica de la semilla aplicable».
- **`rbcmd`** — metadatos `$I` de `$Recycle.Bin` (un fichero o un directorio) pre-extraídos
  → CSV: ruta original y hora de borrado. Params: ninguno que elijas. Uso: qué se borró y
  cuándo (cruza con `$MFT`/timeline). `T1070` (padre; sin subtécnica *File Deletion* en la
  semilla).

### IOCs / firmas

- **`bulk_extractor`** — scanners (emails, URLs, IPs, PII) sobre la imagen. Params:
  `enable_scanners` / `disable_scanners` (listas de nombres). Coste: **alto** —
  anúncialo antes («puede tardar»). Salida: `feature_counts`; abre un feature file
  solo si tiene hits.
- **`yara`** — reglas sobre ficheros/directorios **extraídos**. Params: `rules_path`
  (obligatorio), `recursive`, `print_strings`. Coste: bajo/medio. Salida:
  `matches[]` (`rule` + `target`). Aplícala sobre artefactos (`%TEMP%`, `%APPDATA%`,
  perfiles), no sobre la imagen entera.

### Memoria volátil

- **`volatility3`** — plugins `windows.*` sobre un memdump. Params: `plugin`
  (obligatorio: `windows.info.Info`, `windows.pslist.PsList`,
  `windows.pstree.PsTree`, `windows.psscan.PsScan`, `windows.psxview.PsXView`,
  `windows.malfind.Malfind`, `windows.netscan.NetScan`, `windows.netstat.NetStat`,
  `windows.cmdline.CmdLine`, `windows.filescan.FileScan`,
  `windows.dumpfiles.DumpFiles`, y para credenciales `windows.hashdump.Hashdump`,
  `windows.lsadump.Lsadump`, `windows.cachedump.Cachedump`, …), `plugin_args`
  (mapa string→string). Coste: variable. Salida: `rows` (JSON) — encadénalo con `jq`.

  > **Usa siempre el id de plugin de Volatility 3 totalmente cualificado**
  > (`windows.<plugin>.<Clase>`). Los nombres cortos de **Volatility 2** —
  > `hashdump`, `lsadump`, `cachedump`, `pslist`, `psscan`… **sin** el prefijo
  > `windows.` — **no existen** en Vol3 y hacen fallar la ejecución. Los plugins son
  > `params` del tool_id `volatility3`, no tool_ids nuevos: la allowlist no cambia.

  > **Renombres del build (deprecaciones).** Los ids de arriba son orientativos:
  > el build instalado manda. En builds recientes varios plugins de malware se
  > reubicaron bajo `windows.malware.*` (p.ej. `windows.malfind.Malfind` →
  > `windows.malware.malfind.Malfind`, ídem `psxview`, `hollowprocesses`,
  > `suspicious_threads`). Si la salida avisa «This plugin has been renamed,
  > please call windows.malware.<X>», **adopta el nombre nuevo en las siguientes
  > llamadas** (el aviso repetido es ruido de contexto y el alias viejo puede
  > desaparecer); si un id da `invalid choice`, aplica la regla del §B.8: id
  > literal del `choose from …`, nunca un nombre compuesto por analogía.

### Super-timeline (pesada, opcional)

- **`plaso_log2timeline`** — genera `.plaso` multi-fuente. Coste: **muy alto** —
  anúncialo y confirma antes. Params: (esquema aún no fijado en el motor).
- **`plaso_psort`** — filtra/exporta la timeline `.plaso` por rango. Coste: medio.
  Params: (esquema aún no fijado). Úsalo para acotar, no exportes el histórico.

### Integridad / helpers para la IA

- **`hashdeep`** — hashing recursivo de **artefactos derivados** (no de la evidencia
  base). Params: (esquema aún no fijado). Coste: bajo/medio.
- **`jq`** — filtra el JSON de otras tools antes de traerlo a tu contexto. Params:
  `filter` (p.ej. `.rows[] | {pid,ppid,path}`), `input_path` (el artefacto a
  filtrar), `raw_output`, `compact`, `slurp`. Coste: bajo. Es tu herramienta de
  disciplina de coste: top-N en vez del array entero.
