# Fase 1 — registro de decisiones (asistente)

Documento **del asistente**: decisiones, procedimientos, herramientas y resultados de la
Fase 1. Es el par técnico de [`PETICIONES.md`](PETICIONES.md) (lo que pide el usuario).
Cada entrada importante lleva un **ancla** (`#a…`) a la que apuntan la petición y el
[`FLUJO.md`](FLUJO.md) con `↳`.

Plantilla por entrada:

```
<a id="aN-slug"></a>
### aN · [FECHA] — <resumen corto>

- **Petición:** ↳ [PETICIONES.md](PETICIONES.md) — "<lo que pidió>"
- **Decisión:** qué se decidió y **por qué** (incluidas las alternativas descartadas).
- **Herramienta / script:** comando, función y parámetros clave.
- **Resultado:** qué salió, qué se validó y **qué queda pendiente**.
```

Reglas del registro:

- Orden **cronológico inverso**: la entrada más reciente justo debajo de la línea de abajo.
- Un fallo diagnosticado se apunta aquí **y** se añade una fila al *mapa de problemas* del
  [`FLUJO.md`](FLUJO.md).
- Lo que se consolida como método **sube al flujo**; aquí queda el relato de cómo se llegó.

---

<!-- entradas nuevas debajo, la más reciente primero -->

<a id="a12-disco"></a>
### a12 · 2026-07-28 — Disco montado (raw) → E1, E2, P1/P2 en profundidad

- **Desbloqueo:** con **51,8 GB reales** libres, `qemu-img convert vmdk→raw` (20,5 GB) **funcionó**;
  `mmls` → 1 NTFS en sector 2048. El disco **abre limpio** → refuerza que el desajuste de hash
  es **errata del PDF**, no descarga corrupta. (ejec. 17)

- **E1:** `icat` de `pass.txt` (inode 1194) → es una **PISTA**: "dumpea el hash con volatility,
  es fácil de romper". La contraseña **no está en el fichero**; la vía es hash+cracking, que el
  maletín no cubre (`hashdump` ausente). **E1 no obtenida; no se inventa.** `leeme.txt.bak` trae
  un **ROT13**: "creo que deberás de buscar el correo" → apunta al correo. (ejec. 23)

- **E2 — respondido el mecanismo:** Prefetch `SDELETE64.EXE` (run 2, last 22:55:23 UTC) +
  firma en `$UsnJrnl` (`SDELTEMP`/`ZAP*.tmp`) ⇒ **SDelete ejecutó un borrado seguro de ESPACIO
  LIBRE** (anti-forense, ocultar rastro). Los confidenciales **CLIENTES DEL BANCO.xls** y
  **Plan_de_cuentas.xls** fueron a **papelera** ($I metadata, recuperables), no wipeados.
  ⚠️ **Toda la actividad de borrado (22:5x-23:08) es POSTERIOR al volcado de RAM (19:24)** — hay
  que datarla y no atribuirla sin más al momento del incidente. (ejec. 24, 25)

- **P2:** `base_library.zip` borrado a las 19:08:02 (junto al arranque de key.exe) ⇒ **`key.exe`
  es un ejecutable Python empaquetado con PyInstaller** (extrae su runtime a temp). Dato nuevo.

- **Método (flujo):** (1) en Mac, convertir vmdk→raw necesita espacio REAL (el purgable
  engaña); con holgura, funciona. (2) `fls -r` + `icat` + `$UsnJrnl`(mftecmd) + `$Recycle.Bin`
  $I + Prefetch(prefetch.py) es la cadena de disco para "acceso/borrado de ficheros". (3) La
  firma `SDELTEMP`/`ZAP*.tmp` en USN identifica SDelete free-space wipe.

- **Higiene:** el `UsnJrnl_J.bin` (1,1 GB) se borró tras parsear; se conserva `usn.csv` (41 MB).

<a id="a11-filescan-dumpfiles"></a>
### a11 · 2026-07-28 — P1 cerrado (docs recuperados de RAM) · E1 requiere disco

- **filescan (20):** localiza en memoria `\IEUser\Documents\Documentacion empresa\`**CLIENTES
  DEL BANCO.xls** y **Plan_de_cuentas.xls**, `Desktop\pass.txt`, y `Prefetch\KEY.EXE-*.pf`.
- **dumpfiles (21):** **extrae los dos XLS de la RAM** (16 KB y 72 KB). El de clientes tiene
  columnas `NOMBRE`/`TIPO DE CUENTA`/`CUENTA CORRIENTE` → **datos bancarios reales**.
  ⇒ **P1 respondida con los ficheros reales**: la información confidencial son esos dos XLS.
- **E1:** `pass.txt` **no tiene contenido residente** (dumpfiles vacío) y `passwords.txt` no
  está cacheado ⇒ **la contraseña no sale de esta RAM; se lee del disco**. Sin `hashdump` en el
  maletín, no hay vía por hash. **Decisión: no inventar la contraseña**; E1 queda para el disco.
- **Método (flujo):** `filescan`+`dumpfiles` recupera **documentos ofimáticos cacheados en
  memoria** aunque no haya disco — muy potente para "¿a qué se accedió?". Los `.dat` extraídos
  contienen datos personales → **misma cautela que la evidencia**.
- **Nota GDPR:** se han recuperado datos personales de clientes bancarios; quedan en
  `output/21_dumpfiles/` (banco de pruebas). En un caso real, control de acceso y cadena de
  custodia sobre esos derivados.

<a id="a10-hives-p1-p3-tz"></a>
### a10 · 2026-07-28 — Hives de RAM → P1, P3, zona horaria (sin disco)

- **Contexto:** Docker recuperado tras la caída. Se ejecuta `regripper` (maletín windows) sobre
  los hives volcados de RAM (ejec. 10), en contenedores efímeros. Instantáneo.

- **Zona horaria (cierra el marco temporal):** `Pacific Standard Time`, DST activo → **UTC−7**.
  Volcado 19:24:35 UTC = **12:24:35 local**. Equipo **IEWIN7**. (ejec. 18)

- **P3 (USB) — respondida con matiz:** varias Kingston DataTraveler. **⚠️ distinción clave:**
  las 3.0 del 23-03 (F: 17:48, E: 19:21) **son del PERITO** (contienen Wintriage/RamCapturer y
  el propio `ram.raw` en `F:\RAM\`). Las 2.0 del **20 y 22-03** son las candidatas del
  sospechoso. Atribuir todo el USB al sospechoso habría sido un **error de informe**. (ejec. 18)

- **P1 (acceso a documentos) — respondida:** `RecentDocs` de IEUser incluye **"Documentacion
  empresa"** (la confidencial), más `pass.txt`/`passwords.txt` (→ E1), flags y `leeme.txt`
  (planta del CTF). LastWrite 19:24:33 UTC. (ejec. 19)

- **Hallazgo de rigor:** la máquina es un **entorno de PRÁCTICA/CTF** lleno de tooling de
  adquisición (Magnet, DumpIt, Wintriage, FTK, HashMyFiles) y ficheros planta. **Separar
  perito de sospechoso** es imprescindible; anotado en flujo y ficha.

- **E1 — nueva vía:** `pass.txt`/`passwords.txt` abiertos → se intenta **recuperar su contenido
  de la memoria** con `filescan`+`dumpfiles` (ejec. 20, en curso). Si están cacheados, da la
  contraseña sin disco ni cracking.

- **Método (sube al flujo):** cuando `hashdump` no está, **volcar los hives de RAM y usar
  regripper** cubre TZ, USB, RecentDocs, UserAssist… sin tocar el disco. Es la palanca que
  rescató el caso cuando el disco no se pudo montar.

<a id="a9-pivote-hives"></a>
### a9 · 2026-07-28 — El disco llena el Mac y tumba Docker · pivote a los hives de RAM

- **Qué pasó:** el usuario liberó espacio (macOS marcaba 82,98 GB, pero era casi todo
  **purgable**; `df` real ~22 GB). La conversión vmdk→raw consumió ese espacio real hasta
  **ENOSPC** (disco a 0). Se borró `disk.raw` (derivado; evidencia intacta) → 14 GB libres.
  El disco lleno **tumbó Docker Desktop**; se relanzó (`open -a Docker`) y tardó en volver.

- **Lección (sube al flujo):** en macOS, "espacio disponible" ≠ espacio real; el purgable
  engaña. Convertir una imagen de 40 GB en un Mac con ~20 GB reales **llena el disco y puede
  tumbar Docker**. No reintentar la conversión aquí.

- **⭐ Pivote de estrategia (clave):** **no hace falta el disco entero.** En la ejec. 10 ya se
  **volcaron 16 hives del registro DESDE LA RAM**, y responden buena parte del caso **sin
  disco ni conversión**:
  - `SYSTEM` → **P3 (USB, `USBSTOR`)** + **zona horaria** (cierra el marco temporal).
  - `NTUSER.dat` de IEUser → **P1 (documentos, `RecentDocs`/`UserAssist`)** + actividad.
  - `Amcache.hve` → **P2 (ejecución de `key.exe`** con SHA1 y hora).
  - `SAM`/`SYSTEM` → E1 (ya explotado en samparse).
  Se procesan con `regripper` (maletín windows), que sobre hives pequeños es instantáneo.

- **Estado:** bloqueado sólo por **Docker caído**; en cuanto vuelva, `regripper` sobre los
  hives (ejec. 18–20). El análisis pesado de disco (timeline completa, `$UsnJrnl` para el
  nombre exacto del fichero borrado en E2) queda para Linux/KVM o conversión con espacio real.

<a id="a8-acceso-disco"></a>
### a8 · 2026-07-28 — El disco no se puede abrir en este host (límite de entorno)

- **Decisión previa del usuario:** seguir asumiendo errata del hash y analizar el disco.
  Antes de nada, **custodia:** `.vmdk` a `444`.

- **Comprobación que apoya la hipótesis de errata:** se intentó leer la tabla de particiones.
  El objetivo doble era (1) empezar el disco y (2) ver si abre limpio (si abre, el fichero es
  válido y lo que falla es el hash del PDF, no la descarga).

- **⛔ Resultado: NINGUNA vía de acceso a disco funciona en este host.** Cuatro intentos, todos
  documentados en [`output/murcielago/16_mmls_disco/_run.md`](output/murcielago/16_mmls_disco/_run.md):
  1. **TSK `mmls` directo** sobre el vmdk → exit 1 (el TSK del maletín no trae libvmdk).
  2. **`qemu-nbd`** → `Failed to set NBD socket` (módulo `nbd` no operativo en la VM de Docker
     Desktop).
  3. **`qemu-img convert -O raw`** → **sin espacio** (vmdk 20 GB reales, ~17 GB libres).
  4. **libguestfs** (`virt-filesystems`) → `supermin exited with error status 1` (el appliance
     no arranca sin KVM, bajo emulación amd64).

- **Diagnóstico:** incompatibilidad **host de desarrollo (Mac Apple Silicon, imágenes amd64
  emuladas, sin KVM) ↔ toolkit amd64**. No es fallo del `.vmdk` ni del caso: el disco abrirá
  bien donde el maletín corra **nativo** (Linux/KVM, el despliegue real de Forensia). Por tanto
  **no se pudo confirmar por estructura** si el hash es errata o descarga corrupta — queda la
  decisión del usuario en pie, pero sin dato nuevo.

- **Sube al flujo (heurística):** las vías de montaje de disco (VMDK-en-TSK, `nbd`, convertir a
  raw, libguestfs) dependen de soporte que un Mac de desarrollo no da; **el análisis de disco
  se hace en Linux/KVM o convirtiendo a raw con espacio suficiente**. Añadido al mapa de
  problemas.

- **Estado:** memoria exprimida en lo esencial; disco **bloqueado por entorno**. Se escala al
  usuario: liberar ~15–20 GB y convertir a raw, o analizar el disco en un host Linux/KVM, o
  cerrar el informe con lo de memoria. **Nada más se ejecuta sobre el disco hasta decidir.**

<a id="a7-hash-vmdk"></a>
### a7 · 2026-07-28 — Llega el `.vmdk` · P4 (Drive) · ⛔ el hash NO cuadra

- **Petición:** ↳ [PETICIONES.md](PETICIONES.md) — copiar `IE11-Win7-VMWare-disk1.vmdk` a
  `input/`; y "creo que conté 60–70k tokens, ¿de dónde sale tu cuenta?".

- **Tokens — corrección honesta:** mis cifras por ronda (150k, 280k…) eran **estimaciones a
  ojo, no medidas, e infladas**. **No tengo contador fiable** de mis propios tokens. La fuente
  real es el **panel de uso** / `/cost`. `CONSUMO.md` reescrito para no volver a fingir
  precisión; su columna de tokens queda para el dato real del panel.

- **⛔ Hallazgo crítico — el hash del disco no coincide.** Copiado con `cp -c` (clone,
  instantáneo, 0 B extra; quedaban 26 GB). `shasum -a 256`:
  - esperado (enunciado): `…d7e45b38597068`
  - obtenido:             `…d7e45b38497068`
  - **Difieren en el índice 58** (`5` vs `4`). Como el clone es byte a byte, **el fichero de
    `Downloads` ya tiene ese hash** → la discrepancia es descarga vs enunciado, no la copia.
  - **Decisión (regla de custodia, paso 0 del flujo):** **NO analizar el disco como
    verificado.** Un perito no trabaja sobre evidencia cuya integridad no casa. Se marca la
    ficha en ❌ y se **escala al usuario**: (a) re-descargar el `.vmdk` (posible descarga
    corrupta/incompleta de 20 GB), o (b) confirmar si el hash del PDF tiene errata (difiere un
    solo nibble, típico de copia manual del hash). **No se sigue con el disco hasta decidir.**
  - **Valor para el flujo:** es la demostración de por qué el paso de hash va **antes** de
    tocar nada. El flujo lo cazó. Se añade al mapa de problemas.

- **P4 (strings, ejec. 14, sí terminó):** la IP `200.228.36.6` de netscan **no aparece** en el
  texto de memoria (0) → se cae como destino. Lo que **sí** aparece, repetido, es un **enlace a
  un fichero de Google Drive** (`…/file/d/0B1yljg3v3iiCdzhJVXZTa3Q0Tzg/…`) → lead real de P4.
  Los recuentos de dominios (outlook/gmail/onedrive) son **ruido de navegador**; vale el
  artefacto concreto, no el número.

- **Resultado:** RAM exprimida en lo esencial (perfil, cuentas, timeline, P2/E2 leads, P4
  Drive). Disco **bloqueado por hash**. Siguiente paso depende de la decisión del usuario sobre
  el `.vmdk`.

<a id="a6-hives-key-cuentas"></a>
### a6 · 2026-07-28 — E1/P2 en profundidad: hives, cuentas y key.exe

- **Petición:** ↳ [PETICIONES.md](PETICIONES.md) — perseguir E1 (contraseña vía hives), P4
  (`200.228.36.6`), P2 (`key.exe`), y luego consolidar.

- **Ejecutado:** `registry.hivelist --dump` (10, 16 hives volcados), `malfind`/`dlllist`/
  `handles` sobre key.exe (11–13), `regripper samparse` sobre el SAM volcado (15, con el
  maletín **windows**). `strings` para P4 (14) lanzado en paralelo.

- **Hallazgo mayor — el evento de las 19:07:38 UTC:** `samparse` revela que a esa hora (17
  min antes del volcado) **se creó `testuser` [1003] y se metió en Administradores**, con
  pwd-fail simultáneo de `IEUser` y `sshd_server`. 32 s después arranca `key.exe`. Esto:
  - da a **P2/E2** una **ejecución de comandos confirmada de forma indirecta** (creación de
    cuenta = `net user`/`net localgroup`) y un TTP de persistencia (T1136.001/T1098);
  - descubre que **hay más de un usuario relevante**: `sshd_server` (admin, cuenta del SSH) y
    la nueva `testuser`. Mata la asunción "IEUser es el único usuario".

- **key.exe (P2):** ejecutable `C:\Users\IEUser\Desktop\key.exe`, **con Winsock (WS2_32/NSI)**
  → capacidad de red; GUI; abre handle a `IMAGE FILE EXECUTION OPTIONS`. `malfind`: región RWX
  **vacía** → **no hay inyección concluyente**. Veredicto honesto: **sospechoso, sin cerrar**;
  para saber qué hace hay que **dumpar el binario** o cogerlo del disco.

- **E1 — hasta dónde se llega:** con el SAM+SYSTEM volcados se obtienen **cuentas, RIDs,
  fechas y grupos**, pero **NO el hash NTLM crackeable** (el maletín no trae
  `samdump2`/`secretsdump`/`hashdump`; confirmado con `command -v`). Decisión: **no inventar
  la contraseña**; E1 queda **parcial**, a cerrar con (a) SAM del disco + cracking, o (b)
  contraseña en claro en memoria (`strings`) / Sticky Notes (disco).

- **Nota de método (sube al flujo):** un **hive volcado de RAM** se puede analizar con una
  tool de **otro maletín** (aquí regripper, del windows). Cruzar maletines es válido; se
  documenta cuál se usó y por qué.

- **Resultado:** P2 y E2 avanzan fuerte (cadena de eventos + TTP); E1 topa con el límite del
  maletín; línea temporal del ataque construida en la ficha. `output/` con ejec. 10–15.
  P4 (`strings`) pendiente de terminar.

<a id="a5-primer-barrido-ram"></a>
### a5 · 2026-07-28 — Primer barrido de RAM: hallazgos y límites del maletín

- **Ejecutado** (contenedor efímero, cache de símbolos en volumen; docs en vivo por
  ejecución, regla 7): `pslist` (02), `netscan` (03), `cmdline` (04), `consoles` (05),
  `cmdscan` (06), `hashdump` (07), `lsadump` (08), `cachedump` (09).

- **Hallazgos (contexto y leads, ninguno cerrado aún):**
  - **Usuario = `IEUser`**. Máquina Win7 SP1 x64, volcado 19:24:35 UTC.
  - **P2:** `sshd.exe` (Cygwin/OpenSSH) y `hMailServer` **levantados** → dos canales de fuga.
    `key.exe` corriendo desde `C:\Users\IEUser\Desktop\key.exe` (dos instancias anidadas,
    19:08:10) → sospechoso, **a confirmar** con `malfind` + análisis del binario.
  - **P4:** única conexión externa vista → **`200.228.36.6`** (TCP CLOSED, sin PID). Resto,
    puertos locales. Falta cruzar con URLs/strings en memoria.
  - **E2:** `cmd.exe` (PID 1600) abierto **19:22:55**, 100 s antes del volcado → candidato al
    borrado de ficheros.

- **Límites REALES del maletín descubiertos (lo más valioso para el flujo):**
  1. **`consoles` y `cmdscan` no soportan Win7** (`NotImplementedError … 6.1 15.7601`;
     `cmdscan` reusa el código de `consoles`). → el **historial de consola no sale de esta
     RAM** con esta versión de vol. Bloquea la vía memoria de E2.
  2. **`hashdump`/`lsadump`/`cachedump` no existen en este build** (`invalid choice`). →
     bloquea la vía directa de E1. Camino vivo: volcar `SAM`+`SYSTEM` de memoria
     (`registry.hivelist` + dump) → `regripper`/`samdump2`, o `SAM` del disco, o Sticky Notes.
  - **Método derivado (subido al flujo, heurística 1):** comprobar la lista real de plugins
    del build **antes** de diseñar la cadena de una pregunta; no dar por hecho que un plugin
    famoso está.
  3. **`set -e` en un lote es peligroso:** el fallo de `consoles` (05) abortó 06–09; se
     relanzaron aparte. Heurística 2 del flujo.

- **Herramienta / script:** `vol` (windows.*), `docker run --rm` con volumen de cache.
- **Resultado:** perfil + contexto + leads sólidos para P2/P4; E1 y E2 **bloqueados por
  límites de tool** (documentado, con vías alternativas). `output/` con 10 ejecuciones (6 con
  resultado, 4 fallidas, todas con rastro). **Siguiente propuesto:** E1 por volcado de hives,
  P4 por `strings`/`bulk_extractor` sobre `200.228.36.6`, `malfind` sobre `key.exe`.

<a id="a4-arranque-ram"></a>
### a4 · 2026-07-28 — Arranque del análisis con la RAM: mecanismo de ejecución del maletín

- **Petición:** ↳ [PETICIONES.md](PETICIONES.md) — "empecemos por la evidencia que hay" +
  "registra los tokens que vas consumiendo desde que empezamos el análisis".

- **Comprobación previa (no se da por hecho que Docker esté arriba):** `docker ps` → los
  cinco servicios de Forensia **en ejecución** (`forensia-toolkit-unix` y
  `-windows` *healthy*). `forensia-info` lista el catálogo real de cada maletín.

- **Decisión clave — cómo se ejecutan las tools sin mezclar proyectos.** El toolkit en
  ejecución monta el `evidence/` **de Forensia** (`-> /evidence:ro`), no nuestra copia. Dos
  opciones:
  - (a) apuntar al `ram.raw` que vive en `Forensia-AI/evidence/…` (son los mismos bytes) —
    **descartada**: ata `prueba-agentes` al árbol de Forensia, justo lo que se evita.
  - (b) **lanzar contenedores nuevos y efímeros de la misma imagen** (`docker run --rm`)
    montando **nuestro** `input/murcielago` (ro) y `output/murcielago` (rw). **Elegida.**
  - **Por qué (b):** usa la imagen del maletín **como caja negra** (regla 1 del CLAUDE.md),
    no toca el stack de Forensia (no escribe en su `projects/`, no usa su `/cases`), y deja
    `prueba-agentes` **autocontenido**. Verificado: el contenedor efímero ve
    `/in/ram.raw` (5,0 GB, `0444`). Coste: la imagen es amd64 y el host arm64 → corre
    **emulada** (más lenta); aceptable para un banco de pruebas.
  - ⚠️ **Pendiente de método:** el `WARNING` de plataforma lo emite Docker, no la tool. No
    es un hallazgo; se anota en el `_run.md` y no contamina la salida cruda.

- **Ejecutado (paso 1 del flujo, perfil del sistema):**
  - **00 · file_info** — `file`+`stat`+`xxd`. Resultado: `file` → `data` (sin cabecera) →
    coherente con **raw lineal** (no crash dump ni hibernación). ✅ vol puede tratarlo como
    raw. Salida en `output/murcielago/00_file_info/`.
  - **01 · volatility3 `windows.info`** — lanzado en background (5 GB emulados: minutos).
    Determinará SO, build, arquitectura, hora del volcado y TZ **desde aquí**, sin heredar
    el README del origen ([a2](#a2-evidencia-ram)). Pendiente de resultado.

- **Tokens:** se crea [`CONSUMO.md`](CONSUMO.md) con estimación **por ronda** (no hay
  contador exacto en tiempo real; la fuente de verdad es el panel de uso). Nota importante
  registrada allí: **las tools no gastan tokens** (corren en Docker local); gasta el
  razonamiento/redacción del asistente, por eso las salidas crudas van a `output/` y no se
  pegan al chat.

- **Herramienta / script:** `docker ps/exec/run/inspect`, `forensia-info`, `file/stat/xxd`,
  `vol windows.info`.
- **Resultado:** mecanismo de ejecución validado y documentado; `00_file_info` cerrado;
  `windows.info` en curso. **Siguiente:** leer `windows.info`, fijar TZ, y encadenar
  credenciales (E1) y red (P4).

<a id="a3-objetivo-fase1"></a>
### a3 · 2026-07-28 — Objetivo de la Fase 1: resolver el "Caso Murciélago" y destilar el flujo

- **Petición:** ↳ [PETICIONES.md](PETICIONES.md) — el objetivo es responder las preguntas del
  PDF de la tarea de la UCM ([`refs/enunciado-tarea-UCM.pdf`](refs/enunciado-tarea-UCM.pdf))
  documentando las decisiones, y al final **crear un flujo reproducible para cualquier
  análisis forense**, apoyado en las tools ya disponibles (maletín de Forensia en Docker).

- **Qué pide el caso (leído del PDF):** análisis de **exfiltración de datos económicos**;
  sospechoso un empleado de finanzas. Preguntas P1 acceso a documentos + cuándo · P2 TTPs de
  exfiltración · P3 USB + cuándo · P4 nube/webmail; y evaluables **E1 contraseña del usuario
  (1,5)**, **E2 comandos de borrado + nombre del fichero (1,5)**, **E3 informe completo (7)**.
  El enunciado da **dos** evidencias con hash oficial: `ram.raw` y
  `IE11-Win7-VMWare-disk1.vmdk`.

- **Decisión 1 — el hash del enunciado valida la custodia.** El sha256 de `ram.raw` del PDF
  (`A0AD93B2…30B0B240`) es **idéntico** al que ya habíamos calculado sobre la copia
  ([a2](#a2-evidencia-ram)). Es la mejor noticia posible: la evidencia queda anclada al valor
  que publica el profesor, no a una copia de otro proyecto. Se registra como custodia buena.

- **Decisión 2 — ⛔ FALTA la imagen de disco.** `IE11-Win7-VMWare-disk1.vmdk` **no está** en
  `Downloads/` ni en `Forensia-AI/evidence/`. Es media tarea: P1, P3 y E2 dependen de
  artefactos de disco (`$MFT`, registro, `$UsnJrnl`). **No se inventa el resultado** (regla 4
  del CLAUDE.md): se anota como bloqueo, se documenta qué se puede sacar solo de RAM (E1 y P4
  sí; P1/P3/E2 parcial o no) y se pide bajarla de "Recursos para la tarea". Desglose en la
  ficha.

- **Decisión 3 — reorganizar por CASO, no por evidencia.** Se renombra `input/windows7-x64-
  ram-dump/` → `input/murcielago/` (las dos evidencias del caso viven juntas) y la ficha pasa
  a `FICHA-caso-murcielago.md`. Motivo: la unidad de análisis es **el caso**, y disco+RAM se
  correlacionan; una carpeta por evidencia rompería esa correlación. **Ventaja de fondo:** el
  nombre viejo (`windows7-x64-ram-dump`) ya **filtraba la respuesta** del perfil del sistema
  — justo lo que [a2](#a2-evidencia-ram) quería no heredar. `murcielago` es neutro. Regla que
  queda escrita: **el nombre de un archivo no es un hallazgo**; el SO se determina con tools.

- **Decisión 4 — el enunciado es el ENCARGO, no la verdad.** El PDF afirma que "todas las
  sospechas apuntan" al empleado. Eso entra en el flujo como **hipótesis a contrastar, no como
  hallazgo**: el análisis tiene que poder concluir que no hubo exfiltración o que fue otro.
  Buscar solo lo que confirma la sospecha es el sesgo de confirmación clásico del perito; se
  deja advertido en flujo y ficha.

- **Decisión 5 — el flujo se estructura como "pregunta → artefacto → tool".** No se elige la
  herramienta, se elige **el artefacto que responde la pregunta**, y el artefacto dice la
  tool. Es lo que hace el flujo **reproducible en cualquier caso** (cambia el SO, cambia el
  artefacto, pero el método no). Tabla completa en
  [`FLUJO.md`](FLUJO.md#2-mapa-pregunta--artefacto--tool), mapeada contra las **33 tools** del
  catálogo (captura del maletín: `toolkit-unix` y `toolkit-windows` en ejecución).

- **Herramienta / script:** lectura del PDF (5 págs.), `find`/`ls` para buscar el `.vmdk`,
  `mv` para reorganizar, `cp` del enunciado a `refs/`. **Ninguna tool forense todavía.**

- **Resultado:** `README.md`, `FICHA-caso-murcielago.md` y `FLUJO.md` reescritos con el
  objetivo real; enunciado en `refs/`. `output/` sigue vacío a propósito. **Pendientes que
  marcan el siguiente paso:** (1) conseguir el `.vmdk`; (2) decidir con el usuario si
  arrancamos ya el análisis **solo con RAM** (E1 y P4 son viables) o esperamos al disco para
  no trabajar en dos tandas.

<a id="a2-evidencia-ram"></a>
### a2 · 2026-07-28 — Primera evidencia: `ram.raw` (5 GB) copiada al `input/`

- **Petición:** ↳ [PETICIONES.md](PETICIONES.md) — "copia esta evidencia dentro del input"
  (`Forensia-AI/evidence/windows7-x64-ram-dump/ram.raw`).

- **Decisión 1 — copiar con `cp -c` (clone APFS), no `cp`.** El archivo son **5,0 GB** y
  quedaban 67 GB libres. El clone crea un archivo **independiente** (copy-on-write: si algo
  escribiera en uno, el otro no se entera) **sin gastar disco**. No es un symlink ni un
  hardlink: `input/` queda autocontenido, que es lo que pide su convención.
- **Verificación, no confianza:** `shasum -a 256` sobre origen y copia →
  `a0ad93b2…30b0b240` en ambos. **Idénticos.** Un clone es fiel por construcción, pero en
  algo que se llama "evidencia" el hash se calcula, no se supone.
- **Decisión 2 — `chmod 444`.** Solo lectura, a nivel de sistema de archivos: la convención
  de [`input/README.md`](input/README.md) dice que las evidencias no se modifican, y así no
  depende de que nadie se acuerde. Cuando las tools de Docker la monten, que sea `ro`
  también.

- **Decisión 3 — ⚠️ NO copiar el `README.md` que acompañaba a la evidencia.** Es la decisión
  importante de esta entrada. Ese README traía ya masticado el **SO detectado (Windows 7 SP1
  x64), la build y el `SystemTime` del volcado**, determinados por Forensia con `volatility3`.
  - **Por qué no:** copiarlo es exactamente el "mezclar contextos" que el usuario quiere
    evitar (regla 1 del [`../CLAUDE.md`](../CLAUDE.md)). Si el flujo arranca **sabiendo** la
    respuesta, no se puede saber si el flujo la habría encontrado — y el objetivo de esta
    carpeta es precisamente **destilar el flujo**, no procesar la evidencia.
  - **Qué implica:** formato, SO, arquitectura y fecha del volcado quedan **por determinar
    aquí**, ejecutando tools y guardando su salida en `output/`. Anotado como checklist
    abierto en la ficha del caso.
  - **El nombre de la carpeta ya filtra parte** (`windows7-x64-ram-dump`). Se conserva
    porque cambiarlo rompería la trazabilidad con el origen, pero **el nombre no es un
    hallazgo**: no se cita como fuente de nada.
  - **Ventaja lateral:** si el flujo concluye por su cuenta lo mismo que decía aquel README,
    eso es una **validación gratis** del flujo.

- **Herramienta / script:** `cp -c`, `shasum -a 256`, `chmod 444`. Ninguna tool forense
  todavía — por eso `output/` sigue vacío.
- **Resultado:** [`input/windows7-x64-ram-dump/ram.raw`](input/windows7-x64-ram-dump/ram.raw)
  verificado y en solo lectura; caso registrado en [`input/README.md`](input/README.md) y
  ficha creada en
  [`FICHA-windows7-x64-ram-dump.md`](FICHA-windows7-x64-ram-dump.md).
  **Pendiente:** sigue sin definirse el **objetivo de la Fase 1** — no se ejecuta ninguna
  tool hasta saber qué se persigue.

<a id="a1-tools-y-outputs"></a>
### a1 · 2026-07-28 — Maletín de tools = las de Forensia (Docker) · contrato de `output/`

- **Petición:** ↳ [PETICIONES.md](PETICIONES.md) — usar el maletín de tools de Forensia ya
  montado en Docker ("lo único que tomamos de Forensia y nada más, para que no se confunda
  ni se mezclen contextos"), y que `output/` sea "organización pura y dura" con las salidas
  de cada tool y **la versión tal cual la da la tool**.

- **Decisión 1 — las tools son la ÚNICA excepción a "cero contexto heredado".** Se reescribe
  la regla 1 del [`CLAUDE.md`](../CLAUDE.md) para que la excepción sea **explícita y
  acotada**, en vez de dejarla al criterio de cada sesión:
  - **Sí:** invocar las tools de Forensia en Docker, **como caja negra**, y recoger su salida.
  - **No:** leer su código "para entenderlas", copiar sus prompts u orquestación, heredar sus
    nombres de dominio, asumir en qué orden las encadena Forensia, o dar por buenas sus
    decisiones de producto.
  - **Por qué así:** el riesgo real no es usar la herramienta, es que **por la herramienta se
    cuele el modelo mental** del otro proyecto. La frontera se pone en el borde de la tool:
    entra la salida, no entra el diseño.
  - **Consecuencia práctica:** las tools se documentan **desde fuera** (qué devuelve, qué le
    falta, qué la rompe), observándolas al ejecutarlas. Tabla nueva en
    [`FLUJO.md`](FLUJO.md#herramientas-de-esta-fase) + sección "🧰 El maletín de tools" en el
    `CLAUDE.md`. Si una tool no llega a lo que hace falta, **se pregunta**: no se parchea ni
    se reimplementa por dentro.

- **Decisión 2 — `output/` pasa a ser un contrato, no una convención.** Regla 6 nueva en el
  `CLAUDE.md` y estructura obligatoria en [`output/README.md`](output/README.md):
  - `output/<CASO>/<NN>_<tool>/` — una carpeta por caso y por tool, **numerada por orden real
    de ejecución** (así la cadena se reconstruye sin preguntar).
  - **Se guarda la salida de CADA tool ejecutada**, aunque sea intermedia, no se use, o
    falle (entonces `_stderr.txt` + exit code). *Ejecución sin rastro = ejecución que no pasó.*
  - **`__raw` = tal cual lo devuelve la tool.** Sin recortar, reordenar, reformatear, resumir
    ni "arreglar" el JSON. Cualquier transformación produce **otro archivo**; el crudo no se
    edita nunca.
  - **`__vista`** = versión legible para el usuario. **Conviven las dos**: la legible nunca
    sustituye a la cruda, y el `_run.md` dice cómo se pasó de una a otra.
  - `_run.md` por ejecución: tool, imagen Docker, **comando exacto**, parámetros, duración,
    exit code. Con plantilla, para que no se escriba a ojo.
  - `entregables/` aparte, con versión en el nombre — separa "lo que produjo una tool" de
    "lo que se le enseña al usuario".
  - **Criterio de fondo:** el usuario tiene que poder **abrir cualquier salida por su
    cuenta**, sin pedírsela al asistente y sin volver a ejecutar nada.

- **Herramienta / script:** ninguno — edición de documentación.
- **Resultado:** `CLAUDE.md` (regla 1 reescrita, regla 6 nueva, sección del maletín),
  `output/README.md` (estructura + plantilla de `_run.md`), `FLUJO.md` (regla de trabajo,
  paso 3 con el procedimiento por tool, tabla de tools). **Pendiente:** el nombre y la
  invocación real de cada tool del maletín — se rellenan la primera vez que se ejecute cada
  una; y sigue pendiente definir el **objetivo de la Fase 1**.

<a id="a0-estructura"></a>
### a0 · 2026-07-28 — Nace la carpeta: estructura de documentación desde 0

- **Petición:** ↳ [PETICIONES.md](PETICIONES.md) — recrear la organización de `prueba-dwg`
  (flujo + toma de decisiones + `CLAUDE.md`) en una carpeta nueva, **solo la organización y
  las instrucciones**, para montar un flujo de agentes sin el contexto de Forensia.
- **Decisión:**
  - Carpeta `workspace/prueba-agentes/`, **hermana** de `prueba-dwg` y fuera de
    `Forensia-AI` — la separación física es lo que garantiza el "desde 0".
  - Se copia el **patrón de telaraña** de `prueba-dwg`, no su contenido: `CLAUDE.md` con
    reglas + índice, y por fase un cuarteto `README` (estado) · `FLUJO` (receta
    reutilizable) · `PETICIONES` (usuario) · `REGISTRO-DECISIONES` (asistente), más
    `FICHA-<CASO>.md` para lo que no transfiere entre casos.
  - Se arranca **con `fase1/` desde el principio** (decisión del usuario), no con raíz
    plana, para que abrir fases nuevas sea copiar y no reorganizar.
  - Se añade [`../PLANTILLAS/`](../PLANTILLAS/) con los documentos en blanco: abrir una
    fase o un caso nuevo es copiar de ahí, así la estructura no se degrada con el tiempo.
  - **Descartado** traer del original todo lo específico de DWG/Blender (regla del MCP,
    fases 1–3, fichas de casas, heurísticas de render): aquí no aplica nada de eso.
  - Reglas que **sí** se conservan porque son de método, no de dominio: documentar toda
    decisión, orden cronológico inverso, una cosa a la vez, si no está definido se
    pregunta, enseñar resultados directos, y que el flujo solo recoja lo que ya funcionó.
- **Herramienta / script:** ninguno — creación de carpetas y ficheros Markdown.
- **Resultado:** estructura creada y vacía de contenido de dominio. **Pendiente:** definir
  con el usuario el **objetivo de la Fase 1** y sus entregables, para rellenar el
  `README.md` y los pasos 3–4 del [`FLUJO.md`](FLUJO.md).
