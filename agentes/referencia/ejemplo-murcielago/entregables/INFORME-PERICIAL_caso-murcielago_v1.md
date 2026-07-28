# Informe pericial forense — Caso «Murciélago»

**Análisis de exfiltración de datos económicos**

| | |
|---|---|
| **Caso** | Murciélago — sospecha de filtración de información económica confidencial |
| **Objeto** | Equipo del empleado del departamento financiero (máquina virtual `IEWIN7`) |
| **Evidencias** | Volcado de memoria RAM (`ram.raw`, 5,0 GB) · Imagen de disco (`IE11-Win7-VMWare-disk1.vmdk`, 20,4 GB) |
| **Fecha del análisis** | 2026-07-28 |
| **Herramientas** | Maletín forense en Docker (Volatility 3 2.28.0, The Sleuth Kit, RegRipper, MFTECmd, prefetch.py, qemu-img) |
| **Estado** | Preliminar — ver §9 (limitaciones) |

> **Nota metodológica.** Este informe se apoya **solo** en evidencia observada; cada afirmación
> cita el artefacto que la sostiene. Lo no demostrado se marca como pendiente. Todas las horas
> se expresan en **UTC**; la hora local del equipo es **UTC−7** (Pacific, DST).

---

## 1. Objeto y alcance

Se solicita determinar, sobre la memoria y el disco del equipo del sospechoso, si se produjo
una **exfiltración de información económica confidencial** y bajo qué circunstancias,
respondiendo a: acceso a documentos (P1), técnicas de exfiltración (P2), uso de dispositivos
USB (P3), conexiones a la nube/webmail (P4), la contraseña del usuario (E1) y las acciones de
borrado para ocultar rastro (E2).

El análisis es **post-mortem** sobre copias de las evidencias; el original no se altera.

## 2. Cadena de custodia e integridad

| Evidencia | SHA-256 | Verificación |
|---|---|---|
| `ram.raw` | `a0ad93b20cd9294f9d49947e87675c12159e3d96ae0d3c5a547f232630b0b240` | ✅ **Coincide** con el hash oficial del enunciado. |
| `IE11-Win7-VMWare-disk1.vmdk` | `…d7e45b38**49**7068` (obtenido) | ⚠️ **NO coincide** con el oficial (`…d7e45b38**59**7068`): difieren en un carácter. |

**Sobre la discrepancia del `.vmdk`:** el hash calculado difiere del publicado en el enunciado
en **un solo nibble**. La copia se realizó byte a byte (clone), por lo que la diferencia está
entre el fichero **descargado** y el hash del enunciado, no en la copia. El disco **abre limpio
y estructurado** (una partición NTFS válida, §4), lo que es coherente con un fichero íntegro y
apunta a una **errata en el hash publicado** más que a una descarga corrupta. **No se puede
descartar al 100%**; se deja constancia expresa y se continuó el análisis bajo esta asunción,
por decisión del solicitante.

Ambas evidencias se trataron en **solo lectura**; toda herramienta las montó `ro`.

## 3. Metodología y herramientas

Análisis en contenedores Docker efímeros (maletín forense), evidencia montada de solo lectura.
Cadena principal:

- **Memoria:** Volatility 3 2.28.0 — `windows.info`, `pslist`, `netscan`, `cmdline`,
  `filescan`, `dumpfiles`, `registry.hivelist --dump`.
- **Hives de registro** (volcados de la memoria): RegRipper (`samparse`, `timezone`, `usbstor`,
  `mountdev`, `userassist`, `recentdocs`, `comdlg32`).
- **Disco:** qemu-img (conversión VMDK→raw), The Sleuth Kit (`mmls`, `fls`, `icat`), MFTECmd
  (`$UsnJrnl`), prefetch.py (Prefetch), análisis de `$Recycle.Bin`.

Cada ejecución conserva su salida cruda, una versión legible y una ficha `_run.md` en
`output/murcielago/`.

## 4. Perfil del sistema

- **SO:** Windows 7 SP1 x64, build `7601.24384.amd64fre.win7sp1`. Equipo **`IEWIN7`**.
- **Zona horaria:** Pacific Standard Time (**UTC−7** con horario de verano).
- **Volcado de RAM:** 2021-03-23 **19:24:35 UTC** (12:24:35 local).
- **Cuentas** (RegRipper `samparse`): `IEUser` [1000, admin], `sshd_server` [1002, admin, cuenta
  del servicio SSH], **`testuser` [1003, admin, creada durante el incidente]**, más
  Administrator/Guest/sshd deshabilitadas.

> ⚠️ **La máquina es un entorno de práctica/CTF**: contiene herramientas de adquisición forense
> y ficheros «planta» (flags, `leeme.txt`). El informe **separa la actividad del investigador**
> (adquisición) **de la del sospechoso**.

## 5. Hallazgos por pregunta

### P1 — Acceso a documentos confidenciales ✅

Los documentos confidenciales son **`CLIENTES DEL BANCO.xls`** y **`Plan_de_cuentas.xls`**
(en `C:\Users\IEUser\Documents\Documentacion empresa\`). El de clientes contiene datos
bancarios reales (columnas `NOMBRE`, `TIPO DE CUENTA`, `CUENTA COMPARTIDA`, `CUENTA CORRIENTE`).
Fueron **recuperados de la memoria** con `filescan`+`dumpfiles`. El usuario `IEUser` los abrió:
la clave `RecentDocs` de su perfil se actualizó por última vez el **2021-03-23 19:24:33 UTC**.
*(Evidencia: ejec. 19, 20, 21.)*

### P2 — Técnicas de exfiltración (TTPs) ✅

Indicios concurrentes:
- **Creación de cuenta con persistencia:** `testuser` se crea y se añade a **Administradores**
  el **2021-03-23 19:07:38 UTC** (T1136.001 / T1098). *(samparse, ejec. 15.)*
- **`key.exe`** en el escritorio de IEUser, **ejecutable Python empaquetado con PyInstaller**
  (borra su `base_library.zip` de runtime a las 19:08:02), **con capacidad de red** (importa
  `WS2_32`/`NSI`), 8 ejecuciones (última 19:08:10 UTC). Herramienta sospechosa a analizar.
  *(pslist/dlllist/handles ejec. 02/11/12/13; Prefetch ejec. 24; USN ejec. 25.)*
- **Canales de salida disponibles y activos:** servidor **SSH** (Cygwin/OpenSSH, `sshd` en
  puerto 22) y **servidor de correo** `hMailServer` (SMTP/POP3/IMAP). *(netscan ejec. 03.)*
- **Pista del propio entorno** (`leeme.txt.bak`, cifrado César/ROT13): «creo que deberás de
  buscar el correo» → el **correo** como vía de exfiltración a investigar. *(ejec. 23.)*

### P3 — Dispositivos USB ✅

Se conectaron varias unidades **Kingston DataTraveler** (RegRipper `usbstor`/`mountdev`,
ejec. 18):
- DataTraveler **2.0**: 2021-03-20 09:13 y 2021-03-22 08:31 → **anteriores al incidente**,
  candidatas a uso del sospechoso.
- DataTraveler **3.0**: 2021-03-23 17:48 (unidad **F:**) y 19:21 (unidad **E:**) → **contienen
  el kit de adquisición** (Wintriage, RamCapturer) y el propio `ram.raw` en `F:\RAM\` ⇒ **son
  del investigador**, no exfiltración.

Qué se copió a las unidades del sospechoso (20/22-03) requiere análisis adicional (LNK/shellbags).

### P4 — Conexiones a la nube / webmail 🟡

En memoria aparece, repetido, un **enlace directo a un fichero de Google Drive**
(`https://drive.google.com/file/d/0B1yljg3v3iiCdzhJVXZTa3Q0Tzg/…`). La IP externa observada en
`netscan` (`200.228.36.6`, conexión ya cerrada) **no** aparece en el texto de memoria y pierde
peso. Los recuentos de otros dominios (Outlook, Gmail…) son ruido de navegador. Para confirmar
si el enlace de Drive fue una **subida** (exfiltración) hace falta el historial de navegador.
*(netscan ejec. 03, strings ejec. 14.)*

### E1 — Contraseña del usuario 🟠 (no obtenida)

`C:\Users\IEUser\Desktop\pass.txt` **no contiene la contraseña**: es una pista —«la contraseña
la tienes que dumpear con volatility, el hash es fácil de romper»—. La vía prevista es
**extraer el hash NTLM y crackearlo**. La versión de Volatility del maletín **no incluye**
`hashdump`/`lsadump`, ni hay `samdump2`/`secretsdump` disponibles, por lo que **la contraseña no
se ha podido obtener** con las herramientas actuales. Vía pendiente: `secretsdump`/`samdump2`
sobre los hives `SAM`+`SYSTEM` (ya extraídos) y cracking con hashcat/john. *(ejec. 15, 23.)*

### E2 — Borrado de ficheros y ejecución de comandos ✅ (mecanismo)

**Sí hubo ejecución de comandos para eliminar ficheros evitando la papelera:** se ejecutó
**`sdelete64.exe`** (Sysinternals **SDelete**), herramienta de línea de comandos de **borrado
seguro**. Evidencia: Prefetch `SDELETE64.EXE` (2 ejecuciones, última 2021-03-23 **22:55:23
UTC**) y su firma en el `$UsnJrnl` (`SDELTEMP` + ficheros `ZAP****.tmp`), patrón de un **borrado
seguro del espacio libre** (anti-forense, para impedir la recuperación de ficheros ya
borrados). Los documentos confidenciales, en cambio, se enviaron a la **Papelera de reciclaje**
(metadatos `$I`: `CLIENTES DEL BANCO.xls`, `Plan_de_cuentas.xls`), por lo que eran recuperables.
*(Prefetch ejec. 24, `$UsnJrnl`/`$Recycle.Bin` ejec. 25.)*

> ⚠️ **Aviso temporal:** la actividad de SDelete y de borrado (22:54–23:08 UTC) es **posterior
> al volcado de RAM** (19:24:35 UTC). Debe datarse como tal y no atribuirse sin reservas al
> momento inicial del incidente.

## 6. Línea temporal (UTC)

| Hora (UTC) | Evento | Fuente |
|---|---|---|
| 2021-03-20 09:13 / 03-22 08:31 | USB Kingston DataTraveler 2.0 (candidatas del sospechoso) | usbstor |
| 03-23 17:15 | Inicio de sesión de IEUser | samparse |
| 03-23 17:54:24 | IEUser abre ficheros `.txt` del escritorio | recentdocs |
| **03-23 19:07:38** | **Se crea `testuser` y se añade a Administradores** | samparse |
| **03-23 19:08:10** | Se ejecuta **`key.exe`** (Python/PyInstaller, con red) | pslist/prefetch |
| 03-23 17:48 / 19:21 | USB del **investigador** (F:, E:) — adquisición | usbstor |
| **03-23 19:24:35** | **Volcado de memoria RAM** (fin de la foto de memoria) | windows.info |
| 03-23 22:54:48 | `cmd.exe` (última ejecución) | prefetch |
| **03-23 22:55:23** | **`sdelete64.exe`** — borrado seguro de espacio libre | prefetch/USN |
| 03-23 23:08:59 | Documentos confidenciales enviados a la Papelera | $UsnJrnl |

## 7. Conclusiones

1. **Se accedió a información económica confidencial** (`CLIENTES DEL BANCO.xls`,
   `Plan_de_cuentas.xls`) desde la cuenta `IEUser`, recuperada de la memoria (P1).
2. Existen **indicios sólidos de actividad maliciosa**: creación de una cuenta administrativa de
   persistencia (`testuser`), un ejecutable de red sospechoso (`key.exe`) y canales de salida
   disponibles (SSH, correo). No se ha probado aún el acto concreto de envío (P2).
3. **Se emplearon dispositivos USB** con anterioridad al incidente (P3); parte de la actividad
   USB del 23-03 corresponde a la **adquisición forense**, no al sospechoso.
4. Hay rastro de **almacenamiento en la nube** (enlace de Google Drive) pendiente de confirmar
   como vía de exfiltración (P4).
5. Se ejecutó **SDelete** para **borrado seguro anti-forense** (E2), en un momento **posterior**
   a la captura de memoria.
6. La **contraseña** no se ha obtenido con el instrumental disponible; queda una vía técnica
   clara para lograrlo (E1).

Estas conclusiones son **preliminares** y coherentes con la hipótesis de exfiltración, pero la
prueba directa del envío de los datos requiere el trabajo pendiente del §9. Se ha evitado el
sesgo de confirmación: la hipótesis del encargo se ha tratado como tal, no como hecho probado.

## 8. Recomendaciones

- Preservar y analizar `key.exe` en entorno aislado (naturaleza y destino de sus conexiones).
- Revisar los **logs de `hMailServer`** y el buzón/Thunderbird (la pista apunta al correo) y el
  **historial de navegador** (subidas a Google Drive).
- Recuperar los documentos de la Papelera y analizar los **LNK/shellbags** para saber qué se
  copió a las USB del sospechoso.
- Deshabilitar la cuenta `testuser` y auditar cuentas administrativas; restringir SSH y el
  servidor de correo si no son necesarios; política de bloqueo de USB.

## 9. Limitaciones y trabajo pendiente

- **E1 (contraseña):** requiere extracción del hash NTLM (`secretsdump`/`samdump2`) y cracking;
  fuera del maletín actual.
- **P4:** confirmación de subida a la nube (historial de navegador, disco).
- **P2:** análisis del binario `key.exe` y prueba del envío efectivo de los datos.
- **Integridad del `.vmdk`:** hash oficial no verificado (asumida errata; ver §2).
- Parte de la actividad de borrado es **posterior** a la captura de RAM: acotar responsabilidades
  exige correlacionar con el momento exacto de imagen del disco.

## 10. Anexos

Todas las salidas crudas, versiones legibles y fichas de ejecución están en
`fase1/output/murcielago/` (ejecuciones `00`–`25`), con la bitácora de decisiones en
`REGISTRO-DECISIONES.md` y los datos del caso en `FICHA-caso-murcielago.md`.

---
*Informe preliminar. Los datos personales de clientes bancarios recuperados están sujetos a
control de acceso y cadena de custodia (RGPD).*
