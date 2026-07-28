# Ficha — **Caso Murciélago**

Datos, evidencias, preguntas y hallazgos **concretos de este caso**. El método general está
en [`FLUJO.md`](FLUJO.md); el porqué de cada paso, en
[`REGISTRO-DECISIONES.md`](REGISTRO-DECISIONES.md).

> ⚠️ **Ningún valor de esta ficha vale para otro caso.** Para uno nuevo, copiar
> [`../PLANTILLAS/FICHA.md`](../PLANTILLAS/FICHA.md) y rellenarla midiendo sobre él.

---

## El caso

**Análisis de exfiltración de datos.** Filtración de **información económica confidencial**
a un competidor. Sospechoso: un empleado del **departamento financiero**, la última persona
con acceso a los documentos. Hay que analizar **la memoria volátil y la imagen de disco** de
su equipo.

Enunciado íntegro: [`refs/enunciado-tarea-UCM.pdf`](refs/enunciado-tarea-UCM.pdf)
(UCM · Máster en Ciberseguridad · Introducción a la práctica forense).

## Evidencias

| Evidencia | Estado | Ruta | SHA-256 |
|---|---|---|---|
| `ram.raw` — volcado de RAM, 5,0 GB | ✅ **disponible y verificada** | [`input/murcielago/ram.raw`](input/murcielago/ram.raw) | `a0ad93b20cd9294f9d49947e87675c12159e3d96ae0d3c5a547f232630b0b240` |
| `IE11-Win7-VMWare-disk1.vmdk` — imagen de disco, 20,4 GB (VMDK monolithicSparse) | ❌ **HASH NO COINCIDE** | [`input/murcielago/IE11-Win7-VMWare-disk1.vmdk`](input/murcielago/IE11-Win7-VMWare-disk1.vmdk) | esperado `…d7e45b38**59**7068` · obtenido `…d7e45b38**49**7068` |

> ⛔ **BLOQUEO DE CUSTODIA (2026-07-28).** El SHA-256 del `.vmdk` descargado **NO coincide**
> con el del enunciado: difieren en **un carácter** (índice 58: esperado `5`, obtenido `4`).
> - expected: `60919a3adc8450fa7e720ee68f6815d2179673c21c1844f198d7e45b38597068`
> - obtenido: `60919a3adc8450fa7e720ee68f6815d2179673c21c1844f198d7e45b38497068`
>
> Como la copia se hizo con **clone** (byte a byte), el fichero de `Downloads` **ya tiene ese
> hash**: la discrepancia es entre **el fichero descargado y el hash oficial**, no un fallo de
> copia. Regla del flujo (custodia, paso 0): **no se analiza como verificada** una evidencia
> cuyo hash no cuadra. Causas posibles: descarga corrupta/incompleta, o **errata en el hash
> del PDF**. **Decisión del usuario pendiente.** ↳ [a7](REGISTRO-DECISIONES.md#a7-hash-vmdk)

### ✅ Cadena de custodia de `ram.raw`

El hash calculado sobre nuestra copia **coincide exactamente con el hash oficial publicado
en el enunciado** (`A0AD93B2…30B0B240`). Es el anclaje bueno: no dependemos de la copia que
había en otro proyecto, sino del valor que da el profesor.

- Copiada 2026-07-28 con `cp -c` (clone APFS) desde `Forensia-AI/evidence/`.
- Verificada con `shasum -a 256` contra origen **y** contra el enunciado. ✅
- Permisos `444` (solo lectura). Las tools la montan `ro`.
- ↳ [a2](REGISTRO-DECISIONES.md#a2-evidencia-ram) · [a3](REGISTRO-DECISIONES.md#a3-objetivo-fase1)

### ⛔ Falta la imagen de disco

`IE11-Win7-VMWare-disk1.vmdk` **no está en el equipo** (buscada en `Downloads/` y en
`Forensia-AI/evidence/`). Hay que bajarla de **"Recursos para la tarea"** y dejarla en
`input/murcielago/`. Al llegar: **hash primero**, y comprobar contra el
`60919A3A…B38597068` del enunciado **antes** de tocarla con ninguna tool.

## Qué se puede responder SIN el disco

Importa tenerlo claro para no prometer de más:

| # | Pregunta | ¿Solo con RAM? |
|---|---|---|
| P1 | Acceso a documentos + fecha/hora | ⚠️ **Parcial.** La RAM da ficheros abiertos, handles y rutas en memoria — pero las **marcas de tiempo fiables** viven en la `$MFT`. |
| P2 | Exfiltración y TTPs | ⚠️ **Parcial.** Procesos, conexiones y líneas de comando sí; persistencia y artefactos de ejecución históricos, no. |
| P3 | USB conectado y cuándo | ⚠️ **Poco.** El **cuándo** está en el registro (`USBSTOR`, `setupapi.dev.log`) → **disco**. La RAM solo dará el hive cargado en memoria, con suerte. |
| P4 | Nube / webmail | ✅ **Bastante.** URLs, dominios y sesiones aún en memoria; DNS y conexiones. |
| E1 | Contraseña del usuario | ✅ **Sí.** Es lo que mejor se saca de un volcado de RAM. |
| E2 | Comandos + fichero borrado | ⚠️ **Parcial.** Historial de consola sí; confirmar el borrado y el **nombre** del fichero pide `$MFT`/`$UsnJrnl` → **disco**. |
| E3 | Informe | ⚠️ Se puede redactar, pero quedaría **cojo**, y habría que decirlo en el propio informe. |

**Conclusión:** se puede **empezar** por memoria y avanzar de verdad en E1 y P4, pero el
caso **no se cierra sin el `.vmdk`**.

## Preguntas — estado y evidencia que las sostiene

> Una fila se marca ✅ **solo** cuando hay una salida de tool en `output/` que la sostiene, y
> la fila apunta a ella. **Nada se da por respondido "porque tiene sentido".**

| # | Pregunta | Estado | Respuesta (provisional) | Lo que la sostiene |
|---|---|---|---|---|
| P1 | Acceso a documentos confidenciales + cuándo | 🟢 **respondida** | **Sí.** Los confidenciales son **`CLIENTES DEL BANCO.xls`** y **`Plan_de_cuentas.xls`** (`\IEUser\Documents\Documentacion empresa\`), **recuperados de RAM** (`dumpfiles`). Abiertos por IEUser (RecentDocs LastWrite 2021-03-23 19:24:33 UTC; .txt 17:54:24). Hora exacta por fichero → disco | `19`,`20`,`21` |
| P2 | Herramientas/técnicas (TTPs) de exfiltración | 🟡 en curso | **Leads:** creación de cuenta `testuser` admin (19:07:38, persistencia); `sshd`/`hMailServer` como canales; `key.exe` (ejecutable de red con GUI en Desktop, sin inyección visible); salida a `200.228.36.6` | `02`,`03`,`04`,`11`,`15` |
| P3 | USB conectado + cuándo | 🟢 respondida (con matiz perito/sospechoso) | **Sí, varias Kingston DataTraveler.** Previas: 2.0 el 2021-03-20 09:13 y 03-22 08:31 (posible sospechoso). Del 23-03: 3.0 → F: 17:48 y E: 19:21 = **del PERITO** (kit de adquisición). Qué se copió → disco | `18` (USBStor/MountedDevices) |
| P4 | Conexiones a nube / webmail | 🟡 en curso | **Enlace a fichero de Google Drive** en memoria (`…/file/d/0B1yljg3v3iiCdzhJVXZTa3Q0Tzg/…`, repetido). La IP `200.228.36.6` **no** aparece en strings → se cae. Falta historial de navegador (disco) para saber si fue subida/exfiltración | `03`,`14` |
| E1 | Contraseña del usuario (1,5 pts) | 🟠 no obtenida (falta cracking) | `pass.txt` (leído del disco) es una **pista**: "dumpea el hash con volatility, es fácil de romper". El maletín **no trae `hashdump`** → hash NTLM no extraído. Falta: `samdump2`/`secretsdump` sobre SAM+SYSTEM (fuera del maletín) + hashcat/john. **No se inventa** | `15`,`23` |
| E2 | Comandos de borrado + nombre del fichero (1,5 pts) | 🟢 mecanismo respondido | **Sí, ejecución de comandos anti-forense: `sdelete64.exe`** (Sysinternals SDelete, run 2×, last 2021-03-23 22:55:23 UTC). Firma en `$UsnJrnl`: `SDELTEMP`+`ZAP*.tmp` = **borrado seguro de ESPACIO LIBRE** (ocultar rastro). Los XLS confidenciales fueron a **papelera** (recuperables). ⚠️ Todo 22:5x-23:08 es **posterior al volcado** | `24`,`25` |
| E3 | Informe completo (7 pts) | 🟢 v1 redactado | Informe pericial completo en `entregables/INFORME-PERICIAL_caso-murcielago_v1.md` (objeto, custodia con el tema del hash, metodología, hallazgos por pregunta, timeline, conclusiones, recomendaciones, limitaciones) | `entregables/` |

### Identidad y sistema (confirmado)

- **Perfil:** Win7 SP1 x64, equipo **IEWIN7**, volcado 2021-03-23 **19:24:35 UTC**.
- **⭐ Zona horaria:** **Pacific (UTC−7 con DST)** → **hora local = UTC − 7**. El volcado =
  **12:24:35 hora local**. (`18` regripper timezone.)
- ⚠️ **La máquina es un equipo de PRÁCTICA/CTF** con herramientas de adquisición y ficheros
  planta (flags, leeme.txt). Hay que **separar la actividad del perito** (Magnet, DumpIt,
  Wintriage, FTK, USB F:/E: del 23-03) **de la del sospechoso**.
- **Cuentas (regripper samparse, ejec. 15):**

| RID | Usuario | Admin | Último login (UTC) | Pwd Fail | Nota |
|---|---|---|---|---|---|
| 1000 | **IEUser** | sí | 2021-03-23 17:15:22 | **19:07:38** | Usuario principal / sospechoso |
| 1002 | **sshd_server** | sí | 2021-03-23 17:15:46 | **19:07:38** | Cuenta del servicio SSH, con admin |
| 1003 | **testuser** | sí | **creada 19:07:38** | Never | ⭐ Cuenta nueva metida en Administradores |
| 500 / 501 / 1001 | Administrator / Guest / sshd | — | — | — | Deshabilitadas |

### ⭐ Línea temporal del ataque (emergente, todo UTC)

| Hora | Evento | Fuente |
|---|---|---|
| 17:15:22 | Login de IEUser (arranque de sesión) | `15` samparse |
| **19:07:38** | **Se crea `testuser` + se mete en Administradores**; pwd-fail de IEUser y sshd_server | `15` samparse |
| **19:08:10** | Arranca **`key.exe`** (×2) desde el Desktop de IEUser | `02` pslist |
| 17:54:24 | IEUser abre los `.txt` del Desktop (leeme, flag, passwords, pass…) | `19` recentdocs |
| 17:48:26 | USB Kingston 3.0 → **F:** (kit del perito) | `18` usbstor |
| 19:20:08 | Diálogos Abrir/Guardar (comdlg32) activos | `19` comdlg32 |
| **19:21:19** | USB Kingston 3.0 → **E:** (kit del perito) | `18` usbstor/mountdev |
| 19:22:55 | Se abre **`cmd.exe`** (posible borrado de ficheros) | `02` pslist |
| 19:24:25 | MagnetRAMCapture (adquisición de la RAM, a `F:\RAM\ram.raw`) | `02`,`19` |
| 19:24:33 | RecentDocs/comdlg32 LastWrite (últimos ficheros abiertos) | `19` |
| **19:24:35** | Hora del volcado (12:24:35 local UTC−7) | `01` windows.info |

> ⚠️ La franja **17:48–19:24 del 23-03** está **dominada por la adquisición forense**
> (perito). La actividad del **sospechoso** a perseguir es la **previa** (creación de
> `testuser` 19:07, `key.exe` 19:08, y las USB del 20/22-03).

### Leads calientes (a confirmar — NO son hallazgos cerrados)

| Lead | Dónde salió | Qué falta para confirmarlo |
|---|---|---|
| `key.exe` (Desktop de IEUser), posible herramienta del ataque | `02`,`04` | `malfind` (inyección) + extraer el binario del disco |
| `200.228.36.6`, posible destino de exfiltración | `03` | cruzar con URLs/strings en memoria; logs de sshd/correo (disco) |
| SSH + correo como canales de fuga | `02`,`03` | ver si se **usaron** (sesiones/logs → disco) |
| `cmd.exe` 19:22:55 → posible borrado (E2) | `02` | `cmdscan` (en curso) + `$UsnJrnl`/`$MFT` (disco) |
| Sticky Notes con posible contraseña | `02`,`04` | leer `StickyNotes.snt` de IEUser (disco) |

## Perfil del sistema — **por determinar aquí**

Del proyecto de origen venía un README con el SO ya identificado. **No se copió**
(↳ [a2](REGISTRO-DECISIONES.md#a2-evidencia-ram)): heredar sus conclusiones impide saber si
este flujo las habría encontrado. Se determinan ejecutando tools:

- [x] **Formato del volcado:** raw lineal (sin cabecera; `file` → `data`). ↳ `00_file_info/`
- [x] **SO / build / arquitectura:** **Windows 7 SP1 x64**, `7601.24384.amd64fre.win7sp1`,
      1 CPU. ↳ `01_volatility3_info/`
- [x] **Fecha/hora del volcado:** **2021-03-23 19:24:35 UTC**. ↳ `01_volatility3_info/`
- [ ] **Zona horaria del sistema** — ⚠️ **aún por sacar del registro** (`SYSTEM` hive,
      `TimeZoneInformation`). Hasta tenerla, **todas las horas se anotan en UTC**. Es
      crítica: sin ella la cronología local puede ir desplazada.
- [ ] Usuarios del sistema, y cuál es "el empleado" → pendiente (`hashdump` dará las cuentas;
      confirmar con hive `SAM`).

> ✅ **Validación del método:** este perfil coincide con el README que se decidió no copiar.
> El flujo lo re-derivó a ciegas — prueba de que es flujo, no un apaño con la respuesta ya
> puesta.

> El nombre de carpeta original (`windows7-x64-ram-dump`) ya filtraba parte de la respuesta;
> por eso aquí la carpeta se llama `murcielago/`. **El nombre de un archivo no es un
> hallazgo** y no se cita como fuente. ↳ [a3](REGISTRO-DECISIONES.md#a3-objetivo-fase1)

## Parámetros que funcionaron

| Parámetro | Valor aquí | Cómo se obtuvo | ¿Transfiere? |
|---|---|---|---|
| _(pendiente — se rellena al ejecutar)_ | | | no |

## Decisiones tomadas en este caso

- **Copiar con clone APFS y verificar por hash**, no confiar en la copia.
  ↳ [a2](REGISTRO-DECISIONES.md#a2-evidencia-ram)
- **No heredar el perfil del sistema** del proyecto de origen.
  ↳ [a2](REGISTRO-DECISIONES.md#a2-evidencia-ram)
- **Organizar por CASO, no por evidencia** (`input/murcielago/` con las dos evidencias
  dentro): el caso es la unidad de análisis, y el disco y la RAM se correlacionan entre sí.
  ↳ [a3](REGISTRO-DECISIONES.md#a3-objetivo-fase1)

## Pendientes y asunciones sin verificar

- [ ] **Conseguir el `.vmdk`** — bloquea P1, P2, P3 y E2.
- [ ] Determinar el perfil del sistema y la **zona horaria** antes de fechar nada.
- ⚠️ **Asunción a matar pronto:** que "el empleado" es el único usuario del equipo. Se
  verifica listando usuarios; no se supone.
- ⚠️ **Cuidado con la hipótesis del enunciado.** Dice que "todas las sospechas apuntan" al
  empleado. Eso es el **encargo**, no un hallazgo: el análisis tiene que poder concluir que
  no hubo exfiltración, o que fue otro. Buscar solo lo que confirma la sospecha es el error
  clásico del informe pericial — y en un informe se nota.
