# Playbook — FORENSIA-WIN

Heurística forense por tipo de evidencia. **No es un script**: es la secuencia que
un analista humano probaría primero. Antes de cualquier herramienta, confirma que
la evidencia está **verificada** (`verified=true`).

> **Regla de oro de custodia:** las herramientas de contenedor (`regripper`,
> `evtxecmd`, `mftecmd`) **nunca** reciben la imagen cruda. Siempre:
> `tsk_fls` (localizar) → `tsk_icat` (extraer el artefacto vía handle read-only)
> → procesar **solo** ese fichero derivado.

---

## 0. Routing por tipo de evidencia (antes que nada)

FORENSIA te inyecta arriba, en «Contexto de evidencia», un `detected_kind`; cuando
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

1. **Contenedor.** `ewf_info` si es `.E01` → metadatos y hash interno; cuádralo
   con el baseline del caso.
2. **Particiones.** `tsk_mmls` → offsets y tipos. Apunta el `partition_offset` de
   la partición del sistema (NTFS).
3. **Sistema de ficheros (sin montar).**
   - `tsk_fls` con `recursive: true` → árbol completo, incluidos borrados.
   - `tsk_mactime` (bodyfile) → línea temporal MAC(b): tu columna vertebral.
4. **`$MFT`.** Localiza la `$MFT` con `tsk_fls`, extráela con `tsk_icat`, y
   procésala con `mftecmd` → CSV de creación/modificación/acceso. Cruza con la
   timeline para detectar *timestomping* (creación posterior a modificación, o
   `$STANDARD_INFORMATION` vs `$FILE_NAME` inconsistentes).
5. **Registro.** Extrae los hives (`SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`,
   `NTUSER.DAT`, `UsrClass.dat`) con `tsk_icat` y procésalos con `regripper`.
   Busca: persistencia (`Run`/`RunOnce`, `Services`, `Scheduled Tasks`), ejecución
   (`Amcache`, `ShimCache`/AppCompatCache), USB, cuentas (`SAM`), `ShellBags`.
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

---

## B. Volcado de memoria RAM Windows (`.mem`, `.dmp`)

> Antes de empezar, confirma que `detected_os` del bloque «Contexto de
> evidencia» dice `windows` (o que un probe diagnóstico ya lo confirmó). Si el
> volcado es UNIX, **no es tu caso**: detente y pide reabrir con perfil
> `unix` (lo lleva FORENSIA-UNIX). Ver regla 9 del system prompt.

1. **Perfil.** `volatility3` con `plugin: "windows.info.Info"` → build y perfil.
2. **Procesos.** `windows.pslist.PsList` (recorre la lista enlazada del kernel),
   `windows.pstree.PsTree` (jerarquía padre-hijo). Si `PsList` da una enumeración
   **poco fiable** (pocos procesos, símbolos parciales, sospecha de *process
   hiding*), **crúzalo con pool scan**: `windows.psscan.PsScan` (escanea `_EPROCESS`
   en el pool, ve procesos desenlazados/terminados) y `windows.psxview.PsXView`
   (compara varias fuentes de enumeración y marca lo que aparece en unas y no en
   otras). Un proceso presente en `PsScan`/`PsXView` pero ausente en `PsList` es un
   indicio de ocultación (proceso desenlazado); trátalo como sospechoso y
   correlaciónalo con inyección si aplica (`mitre_hints`: `T1055`).
3. **Inyección.** `windows.malfind.Malfind` (regiones RWX/anómalas),
   `windows.hollowprocesses` cuando sospeches *process hollowing*.
4. **Red.** `windows.netscan.NetScan` → conexiones y puertos (C2, shells inversas).
5. **Registro residente.** `windows.registry.hivelist.HiveList` +
   `windows.registry.printkey.PrintKey` → persistencia viva en memoria.
6. **Comando.** `windows.cmdline.CmdLine`, líneas de comando de procesos
   sospechosos; vuelca regiones de un PID candidato si procede.
7. **Credenciales.** Material de credenciales residente en memoria, con los plugins
   Vol3 **totalmente cualificados**:
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
   > corto de Vol2.

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
(FORENSIA inyecta el path de la evidencia/artefacto y el `output_dir`; **no los
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
  (FORENSIA monta el `$MFT` y el `output_dir`). Coste: medio/alto en `$MFT` grande
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
  que eliges: `min_level` (`info`…`critical`); la ruta de salida la asigna FORENSIA.
  Coste: medio/alto en EVTX grandes — anúncialo; usa `min_level: high`. Salida:
  `summary` con contadores.
- **`chainsaw`** — hunting Sigma sobre EVTX/JSON. Params: `output_format`
  (`csv`|`json`) y al menos uno de `sigma_dir` / `rules_dir`; las rutas de salida
  las asigna FORENSIA. Coste: medio. Salida: nº de `detections`.

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
  `windows.malfind.Malfind`, `windows.netscan.NetScan`, `windows.cmdline.CmdLine`,
  y para credenciales `windows.hashdump.Hashdump`, `windows.lsadump.Lsadump`,
  `windows.cachedump.Cachedump`, …), `plugin_args` (mapa string→string). Coste:
  variable. Salida: `rows` (JSON) — encadénalo con `jq`.

  > **Usa siempre el id de plugin de Volatility 3 totalmente cualificado**
  > (`windows.<plugin>.<Clase>`). Los nombres cortos de **Volatility 2** —
  > `hashdump`, `lsadump`, `cachedump`, `pslist`, `psscan`… **sin** el prefijo
  > `windows.` — **no existen** en Vol3 y hacen fallar la ejecución. Los plugins son
  > `params` del tool_id `volatility3`, no tool_ids nuevos: la allowlist no cambia.

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
