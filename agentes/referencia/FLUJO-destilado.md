# Flujo reutilizable — análisis forense post-mortem

Receta de la **Fase 1**, generalizada (sin datos de un caso concreto). Se destila
resolviendo el **Caso Murciélago**, pero el objetivo es que sirva para **cualquier análisis
forense** sobre memoria y/o imagen de disco, apoyado en el maletín de tools.

> Reglas del proyecto: [`../CLAUDE.md`](../CLAUDE.md) ·
> Bitácora: [`REGISTRO-DECISIONES.md`](REGISTRO-DECISIONES.md) ·
> Peticiones del usuario: [`PETICIONES.md`](PETICIONES.md) ·
> El caso concreto: [`FICHA-caso-murcielago.md`](FICHA-caso-murcielago.md).

> ⚠️ **Este flujo está SIN VALIDAR.** Es el esqueleto; cada paso se confirma —o se corrige—
> la primera vez que se ejecuta de verdad. Un paso solo se da por bueno cuando una salida en
> `output/` lo respalda.

---

## 🚀 Arrancar en una sesión nueva (sin contexto)

1. Leer este archivo entero. Los fallos que más cuestan están en **"Heurísticas
   aprendidas"**.
2. Leer [`PETICIONES.md`](PETICIONES.md) **hasta la última entrada**. **Manda ese documento.**
3. Leer el estado en [`README.md`](README.md) y la ficha del caso.
4. Ir al paso 0 y bajar en orden. Si algo se atasca, saltar **directo** a la entrada `↳` del
   registro.

### Reglas de trabajo del usuario

| Regla | Por qué |
|---|---|
| **Se arranca desde 0.** Lo único que se toma de Forensia son sus **tools en Docker**, como caja negra. | Las tools son herramienta, no contexto. ↳ [a1](REGISTRO-DECISIONES.md#a1-tools-y-outputs) |
| **`output/` es organización pura**: carpeta por caso y por tool, salida **cruda tal cual** (`__raw`) + legible (`__vista`) + `_run.md`. | El usuario tiene que poder abrir cualquier salida por su cuenta. ↳ [`output/README.md`](output/README.md) |
| **Se documenta la decisión MIENTRAS se hace**, no después. | Es lo que convierte el análisis en flujo; reconstruir a posteriori pierde el porqué. |
| **Una cosa a la vez** y se enseña antes de seguir. | Cada pregunta tiene su cadena de tools; mezclarlas impide saber qué respondió qué. |
| **Nada se da por respondido sin una salida que lo sostenga.** | Es un informe pericial: sin evidencia, es opinión. |
| **La hipótesis del enunciado no es un hallazgo.** Se puede refutar. | Buscar solo lo que confirma la sospecha es el sesgo clásico del perito. |
| Un método **solo sube a este flujo cuando ha funcionado**. | El flujo es la receta limpia, no el diario. |

### Mapa de problemas → registro

| Si te pasa esto… | Ve a |
|---|---|
| El **hash de la evidencia no cuadra** con el oficial | **PARAR**, no analizar como verificada; escalar (re-descarga / errata del hash). ↳ [a7](REGISTRO-DECISIONES.md#a7-hash-vmdk) |
| **No se puede abrir un `.vmdk`** (TSK exit 1 / nbd falla / libguestfs no arranca) | Es el host: amd64 emulado sin KVM/`nbd`. Analizar el disco en **Linux/KVM** o **convertir a raw** con espacio. ↳ [a8](REGISTRO-DECISIONES.md#a8-acceso-disco) |
| Un **plugin de vol tumba todo el lote** al fallar | No usar `set -e` en el lote: un plugin no soportado no debe abortar los demás. ↳ [a4](REGISTRO-DECISIONES.md#a4-arranque-ram) |
| `windows.consoles` da `NotImplementedError … 6.1 15.7601` | **No soporta Win7** en esta versión de vol. ⚠️ `windows.cmdscan` **NO vale de alternativa**: reutiliza el mismo código de `consoles` y cae igual (corregido 2026-07-17). El historial sale por disco (`$UsnJrnl`, `ConsoleHost_history`) o por `strings`/`bstrings`. |
| `vol` responde `invalid choice: windows.<algo>` | **Nombre incompleto**, no plugin ausente: el id es **módulo + clase** (`windows.registry.hashdump.Hashdump`). Confírmalo con `vol -h`. |
| Cada `vol` vuelve a **descargar/reconstruir la caché de símbolos** | Montar un **volumen persistente** para `~/.cache` (`-v forensia-vol-cache:/root/.cache`) y agrupar plugins en un solo contenedor. |

---

## 🎯 Flujo de acción validado (runbook end-to-end)

Secuencia **concreta, en el orden que funcionó** en el Caso Murciélago (RAM + disco Win7 x64).
Cada paso apunta a la ejecución `NN` de `output/` y a la heurística que lo blinda. Los comandos
son el patrón real; offsets/inodos se recalculan por caso.

**Mecanismo base:** contenedores **efímeros** de la imagen del maletín, montando `input/`(ro) y
`output/`(rw), cache de vol en volumen persistente:
`docker run --rm -v <input>:/in:ro -v <output>:/out -v forensia-vol-cache:/root/.cache forensia/toolkit-unix:1.0 <cmd>`.
Un hive volcado se analiza con el maletín *windows* (regripper): cruzar maletines es válido.

### A · Custodia (siempre lo primero)
0. `cp -c` a `input/<caso>/`; `shasum -a 256` y **comparar con el hash oficial**. Si no cuadra →
   **parar y escalar** (↳ [a7](REGISTRO-DECISIONES.md#a7-hash-vmdk)); si se sigue, dejarlo
   **escrito en el informe**. `chmod 444`. **No heredar** conclusiones ajenas (SO, timeline).

### B · Memoria (lo volátil primero — no exige convertir nada)
1. **Perfil:** `vol -f ram.raw windows.info` → SO, build, **hora del volcado**. (00–01)
2. **Contexto + preguntas de memoria en UN contenedor** (cache caliente, **sin `set -e`** ↳ h5):
   `windows.pslist`, `netscan`(P4), `cmdline`, `malfind/dlllist/handles`(P2 sobre el PID raro),
   `filescan`+`dumpfiles`(P1 — recupera documentos cacheados). (02–13, 20–21)
   ⚠️ `consoles`/`cmdscan` fallan en Win7 (límite real). `hashdump` **sí está** —
   usar `windows.registry.hashdump.Hashdump` ↳ h1.
3. **Hives desde RAM (la palanca ↳ h3):** `windows.registry.hivelist --dump` vuelca todos los
   hives a `output/`; con `regripper` → `timezone` (**fija la TZ**), `samparse` (cuentas),
   `usbstor`/`mountdev` (P3), `userassist`/`recentdocs`/`comdlg32` (P1). Responde P1/P3/cuentas
   **aunque el disco no monte**. (10, 15, 18, 19)
4. **Nube (P4):** `strings -a` (ASCII+UTF16) `| grep` IP externa + dominios; vale el **artefacto
   concreto** (una URL de fichero), no el recuento (ruido de navegador). (14)

### C · Disco (para el «cuándo» fino, borrados y contenido de ficheros)
5. **Abrir el disco.** En Mac amd64 emulado: `nbd`/libguestfs **no** van y convertir exige
   **espacio REAL** (el «disponible» de macOS engaña con el purgable ↳ h6). Con holgura:
   `qemu-img convert -f vmdk -O raw -S 4096` + `mmls` (offset de partición). Alt.: host Linux/KVM.
6. **Cadena de disco** (offset de `mmls`): `fls -o <off> -r -p disk.raw` (MFT completo, borrados
   `*`) → `icat` para leer un fichero (E1 `pass.txt`); `$Recycle.Bin` `$I` (qué fue a papelera);
   `prefetch.py -f` (ejecuciones+horas, E2/P2); `$UsnJrnl:$J` con `mftecmd` (borrados; firma
   `SDELTEMP`/`ZAP*.tmp` = SDelete). (22–25)

### D · Correlación, revisión, informe
7. **Fechar en la TZ del sistema**; una sola fuente = indicio, no prueba. **Separar perito de
   sospechoso** ↳ h4.
8. Enseñar resultados directos, una pregunta cada vez; comentarios → `PETICIONES.md`.
9. **Informe (E3)** con la estructura del §6; lo no probado, se dice. Plantilla real:
   [`entregables/INFORME-PERICIAL_caso-murcielago_v1.md`](output/murcielago/entregables/INFORME-PERICIAL_caso-murcielago_v1.md).

> **Regla transversal:** cada tool ejecutada se documenta **en el acto** (`_run.md` + `_vista` +
> hallazgo en la ficha) antes de lanzar la siguiente (regla 7 del CLAUDE.md).

---

## 0. Custodia antes que nada

**Ninguna tool toca una evidencia sin hash previo.**

1. Copiar la evidencia a `input/<caso>/` (clone si el FS lo permite; si no, `cp`).
2. `hashdeep`/`shasum` → **comparar con el hash oficial** (enunciado, acta, origen). Si no
   cuadra, **parar**: no se analiza una evidencia que no es la que dicen que es.
3. Dejar la evidencia en **solo lectura** (`chmod 444`); las tools la montan `ro`.
4. Anotar en la ficha: hash, origen, cuándo, con qué se verificó.

⚠️ **No heredar conclusiones ajenas sobre la evidencia** (SO, timeline, "ya se sabe que…").
Se determinan aquí. Si coinciden con lo que decía la fuente, eso es la validación.

## 1. Perfil del sistema (antes de preguntar nada)

Sin esto, todo lo demás flota:

- **Formato del volcado / imagen** → `file_info`, `xxd_head`.
- **SO, versión, build, arquitectura** → `volatility3` (`windows.info` / equivalente).
- **Fecha/hora del volcado y ZONA HORARIA** → crítico: fija el marco temporal de TODO el
  informe. Una cronología con la TZ mal está mal entera.
- **Usuarios del sistema** → identificar quién es "el sospechoso" y si hay más cuentas.
- Para una imagen de disco: **particiones y sistemas de archivos** → `tsk_mmls`,
  `ewf_info`/`ftkimager` si es E01, luego `tsk_fls`.

## 2. Mapa pregunta → artefacto → tool

El corazón del método: **no se elige la tool, se elige el artefacto** que responde la
pregunta, y el artefacto dice la tool. Este mapa es para un caso Windows (ajústese al SO).

| Pregunta típica | Artefacto forense | Dónde vive | Tool del maletín |
|---|---|---|---|
| Perfil del sistema, hora, TZ | estructuras kernel en RAM | memoria | `volatility3` |
| **Contraseña / credenciales** (E1) | hives SAM/SYSTEM en RAM, secretos LSA, hashes | memoria | `volatility3` (hashdump/lsadump), `strings_head` |
| Procesos y su árbol | lista de procesos, PPID | memoria | `volatility3` (pslist/pstree/psscan) |
| **TTPs / exfiltración** (P2) | procesos raros, inyección, DLLs, cmdline | memoria | `volatility3` (malfind/cmdline/dlllist), `yara`, `strings_head` |
| **Conexiones nube/webmail** (P4) | conexiones de red, DNS, URLs en memoria | memoria | `volatility3` (netscan), `strings_head`, `bulk_extractor` |
| **Comandos ejecutados** (E2) | historial de consola, ConsoleHost_history | memoria + disco | `volatility3` (consoles/cmdscan), `strings_head` |
| **Acceso a documentos** (P1) | MFT ($STANDARD_INFO/$FILE_NAME), LNK, jumplists, shellbags | **disco** | `tsk_fls`+`tsk_mactime`, `mftecmd`, `plaso_log2timeline` |
| **USB conectado + cuándo** (P3) | `USBSTOR`, `MountedDevices`, `setupapi.dev.log` | **disco** (registro) | `regripper`, `plaso_log2timeline` |
| **Fichero borrado** (E2) | `$MFT`, `$UsnJrnl`, `$Recycle.Bin`, carving | **disco** | `mftecmd`, `tsk_fls -d`, `foremost` |
| Ejecución de programas | Prefetch, Amcache, Shimcache | **disco** | `amcacheparser`, `appcompatcacheparser`, `plaso_log2timeline` |
| Eventos del sistema | EVTX (logon, servicios, PowerShell) | **disco** | `hayabusa`, `chainsaw`, `evtxecmd` |
| Timeline unificada | todo lo anterior fusionado | ambos | `plaso_log2timeline` + `plaso_psort` |
| Carving de ficheros sueltos | cabeceras conocidas | ambos | `foremost`, `bulk_extractor` |

**Herramientas del maletín** (33, ambos toolkits **en ejecución**): `file_info`, `xxd_head`,
`strings_head`, `tsk_mmls`, `tsk_fls`, `tsk_mactime`, `tsk_icat`, `ewf_info`, `ftkimager`,
`volatility3`, `bulk_extractor`, `yara`, `evtxecmd`, `hayabusa`, `chainsaw`, `mftecmd`,
`jq`, `hashdeep`, `regripper`, `plaso_psort`, `plaso_log2timeline`, `recbmp`(`recmd`),
`sbecmd`, `foremost`, `qemu_nbd`, `jlecmd`, `amcacheparser`, `appcompatcacheparser`,
`lecmd`, `wxtcmd`, `rbcmd`, `mftecmd`. (Ver captura del catálogo; confirmar argv real con
`_run.md` la primera vez que se use cada una.)

## 3. Ejecutar — una pregunta, su cadena de tools

Para **cada** ejecución, sin excepción (contrato de [`output/README.md`](output/README.md)):

1. `output/<caso>/<NN>_<tool>/` — `NN` = orden real.
2. Salida **cruda tal cual** → `<n>__raw.<ext>`. No se toca.
3. Versión legible → `<n>__vista.<ext>`. Conviven las dos.
4. `_run.md`: tool, imagen Docker, comando exacto, parámetros, duración, exit code.
5. Falle o no, **queda rastro**. Una tool sin salida en disco es una tool que no se ejecutó.
6. El hallazgo va a la ficha **apuntando a la salida** que lo sostiene.

Orden recomendado (memoria primero, es lo volátil y ya lo tenemos):
**perfil → credenciales (E1) → procesos → red (P4) → comandos (E2 parcial) → malfind (P2)**;
luego, con el disco: **MFT/timeline (P1) → USB (P3) → borrados (E2) → EVTX/ejecución**.

## 4. Correlacionar y fechar

- Fusionar en **una timeline** (`plaso`) memoria y disco: una pregunta rara vez se responde
  con un solo artefacto; se responde cuando **dos fuentes independientes coinciden**.
- Toda hora, en la **TZ del sistema** (paso 1) y anotada como tal. UTC ↔ local explícito.
- Un hallazgo con **una sola fuente** se marca como tal: es indicio, no prueba.

## 5. Revisar con el usuario

- Enseñar el resultado directo (abrir el archivo / pegar la salida).
- Una pregunta cada vez. El comentario del usuario → [`PETICIONES.md`](PETICIONES.md).

## 6. Redactar el informe (E3)

Estructura pericial (la "vista en clase"): portada e identificación · objeto y alcance ·
**cadena de custodia** (hashes) · metodología y herramientas (con versiones) · hallazgos
(cada uno con su evidencia y su hora) · respuesta explícita a P1–P4 y E1–E2 · **línea
temporal** · conclusiones · **recomendaciones** · anexos (salidas). Lo que no se pudo
responder (p. ej. por falta del disco), se dice; un informe honesto vale más que uno que
rellena huecos.

## 7. Documentar

**¿lo dijo el usuario?** → peticiones · **¿es lo que pasó y por qué?** → registro ·
**¿es un dato/hallazgo de este caso?** → ficha · **¿serviría con otro caso?** → este flujo.

---

## Heurísticas aprendidas (lo más valioso)

### 1. ⚠️ Un plugin que "no está" casi siempre es un NOMBRE mal formado

> **CORRECCIÓN 2026-07-17 (re-verificado contra el maletín).** Este apartado afirmaba que el
> build no traía los plugins de credenciales. **Es falso y costó un E1.** Comprobado
> ejecutando sobre RAM Win7 real: `windows.registry.hashdump.Hashdump` devuelve **6 cuentas
> con su NT hash, exit 0**; `lsadump` y `cachedump` también están (`vol -h` los lista). El
> `invalid choice: windows.hashdump` del caso murciélago era un **nombre incompleto**: en
> vol3 el id es **módulo + clase**. Los alias cortos siguen valiendo pero vol los retira
> tras 2026-09-25 → usa `windows.registry.hashdump.Hashdump`.

De los "dos huecos" que este caso creyó encontrar, **solo uno era real**:
- ✅ **REAL — `consoles` y `cmdscan` no soportan Win7** (`NotImplementedError: … 6.1
  15.7601`): su tabla de símbolos de conhost no cubre NT 6.1, y **`cmdscan` reutiliza el
  código de `consoles`**, así que no sirve de alternativa (el apartado de fallos decía lo
  contrario — también corregido). El historial de consola sale por disco (`$UsnJrnl`,
  `ConsoleHost_history`) o por `strings`/`bstrings` sobre la memoria.
- ❌ **FALSO — "`hashdump`/`lsadump`/`cachedump` no están"**: sí están. El volcado de hives
  `SAM`+`SYSTEM` (`hivelist --dump` + `regripper`) es una vía **complementaria** —
  excelente cuando además quieres SOFTWARE/Amcache/NTUSER— no un sustituto obligado.

**Método que queda:** un `invalid choice` es un nombre mal escrito; un rechazo por allowlist
es política nuestra. **Ninguno de los dos demuestra ausencia de capacidad.** Antes de declarar
que falta algo, ten el **error literal** del intento y contrástalo con `vol -h`.
↳ [a4](REGISTRO-DECISIONES.md#a4-arranque-ram)

### 3. ⭐ Con disco inaccesible → volcar hives de RAM y usar regripper

La palanca que rescató este caso. `windows.registry.hivelist --dump` saca **todos los hives a
disco desde la memoria** (SAM, SYSTEM, SOFTWARE, Amcache, NTUSER de cada usuario…). Con ellos y
`regripper` (maletín windows) se responde **sin tocar la imagen de disco**:
- **SYSTEM** → zona horaria (`timezone`), **USB** (`usbstor`/`mountdev`), nombre de equipo.
- **NTUSER.dat** → **documentos abiertos** (`recentdocs`, `comdlg32`), **programas ejecutados**
  (`userassist`), URLs tecleadas (`typedurls`).
- **SAM/SYSTEM** → cuentas (`samparse`). **Amcache.hve** → ejecución de binarios con SHA1.
Un hive volcado de un maletín se analiza con la tool de **otro** maletín; se documenta cuál.
↳ [a10](REGISTRO-DECISIONES.md#a10-hives-p1-p3-tz) · [a6](REGISTRO-DECISIONES.md#a6-hives-key-cuentas)

### 4. ⚠️ Separar la actividad del PERITO de la del sospechoso

En una imagen de práctica (y en casos reales) la propia **adquisición** deja huella: USB con el
kit forense, ejecución de MagnetRamCapture/DumpIt/FTK/Wintriage, el `ram.raw` guardado en una
unidad. **Atribuir eso al sospechoso es un error de informe.** Fechar la intervención y excluir
su ventana; perseguir la actividad **previa**. ↳ [a10](REGISTRO-DECISIONES.md#a10-hives-p1-p3-tz)

### 5. ⚠️ No usar `set -e` en un lote de plugins

Un plugin que sale con error (no soportado, ausente) **aborta el lote entero** y deja sin
ejecutar los siguientes. Ejecutar cada plugin de forma independiente, capturar su exit code y
seguir. ↳ [a4](REGISTRO-DECISIONES.md#a4-arranque-ram)

---

## El maletín de tools (de Forensia, en Docker)

Es lo único que se toma de allí y se usan **como caja negra** — se documentan **desde
fuera**, no leyendo su código, y **este proyecto decide cómo encadenarlas**, no se copia la
orquestación de Forensia. ↳ [a1](REGISTRO-DECISIONES.md#a1-tools-y-outputs)

| Tool | Toolkit | Cómo se invoca | Qué devuelve | Qué la rompe |
|---|---|---|---|---|
| _(se rellena a medida que se usan; una fila por tool tras su primer `_run.md`)_ | | | | |

| Script propio (en [`scripts/`](scripts/)) | Para qué |
|---|---|
| _(pendiente)_ | |

---

## Qué NO transfiere de un caso a otro

- El **SO, la build y la zona horaria** — se redeterminan siempre.
- **Qué artefacto responde qué** cambia con el SO (Windows ≠ Linux ≠ macOS): el paso 2 es
  una plantilla mental, no una tabla fija.
- Los **hashes**, nombres de evidencia y de usuario.
- **Qué preguntas** hay que responder — vienen del encargo de cada caso.
- Los parámetros concretos de cada tool (offsets, perfiles, rutas). Si no está en esta
  lista, es método.
